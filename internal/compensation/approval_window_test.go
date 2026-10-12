package compensation_test

import (
	"context"
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

// The whole employee-chain dependency is deliberately unavailable to this read;
// all canonical owner, scoped SQL, payload, audit, and release work remains native.
type financeApprovalWindowStore struct {
	compensation.Store
	ApprovalIDs []string
}

func (s *financeApprovalWindowStore) CompensationEvents(context.Context, string, string) ([]compensation.EventRecord, error) {
	return nil, fault.Unavailable
}

func (s *financeApprovalWindowStore) CompensationApprovalEvents(ctx context.Context, org, approval string, scope compensation.Scope, limit int) ([]compensation.EventRecord, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	s.ApprovalIDs = append(s.ApprovalIDs, approval)
	return s.Store.CompensationApprovalEvents(ctx, org, approval, scope, limit)
}

func TestCompensationApprovalPageReadsOnlyPagedApprovalAndSQLVisibleEvents(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms("100"), Reason: "SYNTHETIC_UNPAGED_ROOT"})
		root := financeCurrent(t, f, employee, "2026-12-31")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-01-01", CompRevision: root.CompRevision, BeforeTermID: new(root.CurrentTerm.ID), After: financeTerms("120"), Reason: "SYNTHETIC_UNPAGED_JAN"})
		jan := financeCurrent(t, f, employee, "2027-01-01")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-02-01", CompRevision: jan.CompRevision, BeforeTermID: new(jan.CurrentTerm.ID), After: financeTerms("130"), Reason: "SYNTHETIC_UNPAGED_FEB"})
		feb := financeCurrent(t, f, employee, "2027-02-01")
		corrected := financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "correction", CompRevision: feb.CompRevision, Reason: "SYNTHETIC_PAGED_CORRECTION", Members: []compensation.CorrectionMember{
			{MemberKey: "jan", Action: "replace", OriginalEventID: jan.CurrentTerm.EventID, EffectiveDate: "2027-01-01", BeforeRef: &compensation.BeforeRef{TermID: new(root.CurrentTerm.ID)}, After: financeTerms("125")},
			{MemberKey: "feb", Action: "replace", OriginalEventID: feb.CurrentTerm.EventID, EffectiveDate: "2027-02-01", BeforeRef: &compensation.BeforeRef{MemberKey: new("jan")}, After: financeTerms("130")},
		}})
		if len(corrected.Members) != 2 {
			t.Fatal("native correction did not create both immutable members", corrected)
		}
		first, err := f.Repo.CompensationEvent(ctx, f.OrgID, corrected.Members[0].EventID)
		if err != nil {
			t.Fatal(err)
		}
		second, err := f.Repo.CompensationEvent(ctx, f.OrgID, corrected.Members[1].EventID)
		if err != nil {
			t.Fatal(err)
		}
		visible, err := f.Repo.CompensationApprovalEvents(ctx, f.OrgID, first.ApprovalID, compensation.Scope{Broad: true}, 1)
		if err != nil || len(visible) != 1 || visible[0].ID != first.ID {
			t.Fatal("native approval event LIMIT did not bound its result", visible, err)
		}
		visible, err = f.Repo.CompensationApprovalEvents(ctx, f.OrgID, first.ApprovalID, compensation.Scope{Events: []string{second.ID}}, 1)
		if err != nil || len(visible) != 1 || !reflect.DeepEqual(visible[0], second) {
			t.Fatal("exact event SQL scope was applied after LIMIT or skipped the authorized member", visible, err)
		}
		store := &financeApprovalWindowStore{Store: f.Repo}
		f.Compensation.Store = store
		query := compensation.ChangesQuery{RecordKind: "approvals", ProposalID: corrected.ID, Limit: 1}
		page, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
		if err != nil || len(page.Approvals) != 1 || len(page.Approvals[0].Events) != 2 || len(page.Approvals[0].Members) != 2 || page.Approvals[0].Reason != "SYNTHETIC_PAGED_CORRECTION" || page.NextCursor != "" || len(page.Revisions) != 0 || len(store.ApprovalIDs) != 1 || store.ApprovalIDs[0] != first.ApprovalID {
			t.Fatal("approval read depended on the full chain or fetched unpaged approval events", page, store.ApprovalIDs, err)
		}
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		financeGrant(t, f, f.FinR, employee, "compensation.read", &authz.ObjectReference{Kind: "compensation_event", ID: second.ID})
		store.ApprovalIDs = nil
		calls := f.FinancialKMS.Calls.Load()
		page, err = f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
		if err != nil || len(page.Approvals) != 1 || len(page.Approvals[0].Events) != 1 || page.Approvals[0].Events[0].ID != second.ID || page.Approvals[0].Events[0].Before != nil || page.Approvals[0].Events[0].After != nil || page.Approvals[0].Reason != "" || page.Approvals[0].DecisionReason != "" || len(page.Approvals[0].Members) != 0 || len(store.ApprovalIDs) != 1 || f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("exact approval fragment read hidden events, group reasons, or independently unauthorized terms", page, err)
		}
	})
}

func TestCompensationApprovalReadDoesNotDecryptDecisionAfterBroadGrantExpiry(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms("314159"), Reason: "SYNTHETIC_EXPIRING_DECISION"})
		current := financeCurrent(t, f, employee, "2026-01-01")
		event, err := f.Repo.CompensationEvent(ctx, f.OrgID, current.CurrentTerm.EventID)
		if err != nil {
			t.Fatal(err)
		}
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		for _, target := range []*authz.ObjectReference{
			{Kind: "compensation_event", ID: event.ID},
			{Kind: "compensation_term", ID: current.CurrentTerm.ID},
		} {
			financeGrant(t, f, f.FinR, employee, "compensation.read", target)
		}
		_, err = f.Authz.Issue(ctx, authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{
			SubjectID: f.FinR.SubjectID, Capability: "compensation.read", Category: "financial",
			Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management",
			ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Minute).Format(time.RFC3339Nano),
			MFARequired: true, AuthorityID: f.AuthorityIDs["compensation.read/financial"], ExpectedRevision: financeEpoch(t, f),
		})
		if err != nil {
			t.Fatal(err)
		}
		arrived := make(chan struct{})
		unblock := make(chan struct{})
		f.FinancialKMS.BlockNextDecrypt(arrived, unblock)
		type result struct {
			view compensation.ChangesView
			err  error
		}
		done := make(chan result, 1)
		var once sync.Once
		defer once.Do(func() { close(unblock) })
		go func() {
			view, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "approvals", Limit: 1})
			done <- result{view, err}
		}()
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("authorized term decrypt did not reach the controlled KMS")
		}
		calls := f.FinancialKMS.Calls.Load()
		f.Now = f.Now.Add(2 * time.Minute)
		once.Do(func() { close(unblock) })
		var got result
		select {
		case got = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("approval read did not finish after KMS release")
		}
		if got.err == nil || !reflect.DeepEqual(got.view, compensation.ChangesView{}) {
			t.Fatal("expired broad read returned an approval projection", got.view, got.err)
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("expired broad read decrypted the shared decision payload")
		}
		snapshot, err := f.Repo.Security(ctx, f.FinR.Hash, f.OrgID, employee)
		if err != nil || !snapshot.AllowsObject("compensation.read", "financial", employee, "compensation_management", f.Now, authz.ObjectReference{Kind: "compensation_event", ID: event.ID}) || snapshot.Allows("compensation.read", "financial", employee, "compensation_management", f.Now) {
			t.Fatal("test did not preserve exact event read after only broad read expired", err)
		}
	})
}
