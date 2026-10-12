package compensation_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestCompensationRevisionReleaseRechecksHeadRevocationAndExpiryAfterRealDecrypt(t *testing.T) {
	for _, change := range []string{"head", "revoke", "mfa_expire", "grant_expire"} {
		t.Run(change, func(t *testing.T) {
			financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				employee := financeEmployee(t, f, false)
				p, _, _ := financeVersionedDraft(t, f, employee, 3)
				financeRevokeBroad(t, f, f.FinR, "compensation.read")
				target := &authz.ObjectReference{Kind: "compensation_proposal", ID: p.ID}
				var grant authz.Result
				if change == "grant_expire" {
					var err error
					grant, err = f.Authz.Issue(context.Background(), authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{SubjectID: f.FinR.SubjectID, Capability: "compensation.read", Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Minute).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: target, AuthorityID: f.AuthorityIDs["compensation.read/financial"], ExpectedRevision: financeEpoch(t, f)})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					grant = financeGrant(t, f, f.FinR, employee, "compensation.read", target)
				}
				arrived, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				f.FinancialKMS.BlockNextDecrypt(arrived, release)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				type result struct {
					view compensation.ChangesView
					err  error
				}
				results := make(chan result, 1)
				go func() {
					view, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 2})
					results <- result{view, err}
				}()
				select {
				case <-arrived:
				case early := <-results:
					t.Fatal("authorized revision page did not reach real external decrypt", early.err)
				case <-ctx.Done():
					t.Fatal("revision decrypt gate timeout")
				}
				switch change {
				case "head":
					_, err := f.Compensation.EditProposal(ctx, financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", Revision: p.Revision, After: financeTerms("424242"), Reason: "SYNTHETIC_CHANGED_DURING_HISTORY", Members: []compensation.CorrectionMember{}})
					if err != nil {
						t.Fatal("head writer was blocked by a revision read transaction during KMS", err)
					}
				case "revoke":
					financeRevoke(t, f, grant)
				case "mfa_expire":
					f.Now = f.Now.Add(11 * time.Minute)
				case "grant_expire":
					f.Now = f.Now.Add(2 * time.Minute)
				}
				unblock()
				select {
				case result := <-results:
					financeZeroChanges(t, result.view, result.err)
					if change == "head" && !errors.Is(result.err, fault.Conflict) {
						t.Fatal("changed head did not reject the prepared exact snapshot", result.err)
					}
				case <-ctx.Done():
					t.Fatal("revision release recheck timeout")
				}
			})
		})
	}
}

// These wrappers retain the real store, native transaction, cipher, guard, and
// mandatory audit. They expose the callback/COMMIT distinction and simulate only
// loss of the storage acknowledgement after a transaction actually committed.
type financeCommitBoundaryStore struct {
	compensation.Store
	LoseAcknowledgement bool
	CallbackSucceeded   bool
	Committed           bool
}

func (s *financeCommitBoundaryStore) WithCompensationTx(ctx context.Context, org string, fn func(compensation.Tx) error) error {
	err := s.Store.WithCompensationTx(ctx, org, func(tx compensation.Tx) error {
		err := fn(tx)
		s.CallbackSucceeded = err == nil
		return err
	})
	if err != nil {
		return err
	}
	s.Committed = true
	if s.LoseAcknowledgement {
		return fault.Unavailable
	}
	return nil
}

func financeDeferredAuditCommitFailure(t *testing.T, f *testsupport.Fixture) {
	t.Helper()
	ctx := context.Background()
	for _, query := range []string{
		"CREATE TABLE finance_commit_parent(id TEXT PRIMARY KEY)",
		"CREATE TABLE finance_commit_child(id TEXT NOT NULL REFERENCES finance_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)",
	} {
		if err := f.Exec(ctx, query, query); err != nil {
			t.Fatal("install native deferred commit failure", err)
		}
	}
	if f.Backend == "sqlite" {
		if err := f.Exec(ctx, "CREATE TRIGGER finance_commit_failure AFTER INSERT ON audit_event WHEN NEW.operation IN('OP-COMP-02','OP-COMP-04') AND NEW.outcome='allowed' BEGIN INSERT INTO finance_commit_child(id) VALUES('missing_parent'); END", ""); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := f.Exec(ctx, "", "CREATE FUNCTION finance_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation IN('OP-COMP-02','OP-COMP-04') AND NEW.outcome='allowed' THEN INSERT INTO finance_commit_child(id) VALUES('missing_parent'); END IF; RETURN NEW; END $$"); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(ctx, "", "CREATE TRIGGER finance_commit_failure AFTER INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION finance_commit_failure()"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCompensationRevisionCommitAndAuditFailuresReturnZeroDTO(t *testing.T) {
	for _, boundary := range []string{"audit", "deferred_commit", "lost_commit_acknowledgement"} {
		for _, operation := range []string{"edit", "revision_read"} {
			t.Run(boundary+"/"+operation, func(t *testing.T) {
				financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
					ctx := context.Background()
					employee := financeEmployee(t, f, false)
					p, _, _ := financeVersionedDraft(t, f, employee, 3)
					before := financeFacts(t, f, employee)
					original, err := f.Repo.CompensationProposal(ctx, f.OrgID, p.ID)
					if err != nil {
						t.Fatal(err)
					}
					audits := f.Count(t, "audit_event")
					switch boundary {
					case "audit":
						if err := f.Exec(ctx, "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
							t.Fatal(err)
						}
					case "deferred_commit":
						financeDeferredAuditCommitFailure(t, f)
					}
					store := &financeCommitBoundaryStore{Store: f.Repo, LoseAcknowledgement: boundary == "lost_commit_acknowledgement"}
					f.Compensation.Store = store
					request := financeRequest(f.CompW)
					if operation == "edit" {
						result, err := f.Compensation.EditProposal(ctx, request, p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", Revision: p.Revision, After: financeTerms("9007199254740999"), Reason: "SYNTHETIC_UNCERTAIN_COMMIT_BODY", Members: []compensation.CorrectionMember{}})
						if err == nil || !reflect.DeepEqual(result, compensation.Result{}) {
							t.Fatal("failed or uncertain command returned a candidate successful result", result, err)
						}
					} else {
						request = financeRequest(f.FinR)
						view, err := f.Compensation.Changes(ctx, request, employee, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 2})
						financeZeroChanges(t, view, err)
					}
					current, err := f.Repo.CompensationProposal(ctx, f.OrgID, p.ID)
					if err != nil {
						t.Fatal(err)
					}
					if boundary == "lost_commit_acknowledgement" {
						if !store.CallbackSucceeded || !store.Committed || f.Count(t, "audit_event") != audits+1 {
							t.Fatal("uncertain-boundary test did not actually commit its mandatory native audit")
						}
						if operation == "edit" {
							receipt, found, err := f.Repo.CompensationReceipt(ctx, f.OrgID, f.CompW.SubjectID, "OP-COMP-04", request.Key)
							if err != nil || !found || receipt.Result.Proposal != nil || receipt.Result.Revision != "4" || current.Revision != 4 {
								t.Fatal("lost acknowledgement did not leave the real committed safe receipt and revision", receipt, current, err)
							}
						} else if !reflect.DeepEqual(current, original) {
							t.Fatal("committed history audit mutated the proposal")
						}
					} else {
						if store.Committed || store.CallbackSucceeded != (boundary == "deferred_commit") {
							t.Fatal("native failure occurred at the wrong audit/COMMIT boundary", store.CallbackSucceeded, store.Committed)
						}
						if !reflect.DeepEqual(current, original) {
							t.Fatal("failed native transaction moved the proposal head")
						}
						financeUnchanged(t, f, employee, before)
						if boundary == "deferred_commit" && (f.Count(t, "audit_event") != audits || f.Count(t, "finance_commit_child") != 0) {
							t.Fatal("deferred failure committed an audit or part of the command")
						}
					}
				})
			})
		}
	}
}
