package authz_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func financialAuthorityObjects(t *testing.T, f *testsupport.Fixture, employee string) []authz.ObjectReference {
	t.Helper()
	ctx := context.Background()
	request := func(actor testsupport.Credential) compensation.Request {
		return compensation.Request{TokenHash: actor.Hash, Purpose: "compensation_management", Key: value.NewID(), RequestID: value.NewID()}
	}
	amount := "9007199254740993"
	made, err := f.Compensation.CreateProposal(ctx, request(f.CompW), employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: &compensation.Terms{Currency: "USD", Scale: 2, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}, Reason: "SYNTHETIC_FINANCIAL_GRANT", Members: []compensation.CorrectionMember{}})
	if err != nil {
		t.Fatal("financial proposal setup:", err)
	}
	submitted, err := f.Compensation.TransitionProposal(ctx, request(f.CompW), made.ID, compensation.TransitionCommand{Action: "submit", Revision: made.Revision, CompRevision: made.CompRevision})
	if err != nil {
		t.Fatal("financial submit setup:", err)
	}
	if _, err := f.Compensation.TransitionProposal(ctx, request(f.CompApprover), made.ID, compensation.TransitionCommand{Action: "approve", Revision: submitted.Revision, CompRevision: submitted.CompRevision, DecisionReason: "SYNTHETIC_INDEPENDENT_APPROVAL"}); err != nil {
		t.Fatal("financial independent approval setup:", err)
	}
	schedule, err := f.Repo.CompensationSchedule(ctx, f.OrgID, employee, compensation.CurrentQuery{AsOf: "2026-01-01", FutureLimit: 100})
	if err != nil || len(schedule) != 1 {
		t.Fatal("financial approved schedule setup:", schedule, err)
	}
	return []authz.ObjectReference{{Kind: "compensation_proposal", ID: made.ID}, {Kind: "compensation_event", ID: schedule[0].EventID}, {Kind: "compensation_term", ID: schedule[0].TermID}}
}

func financialIssueCommand(t *testing.T, f *testsupport.Fixture, employee string, ref authz.ObjectReference) authz.IssueCommand {
	t.Helper()
	query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	var epoch int64
	if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	return authz.IssueCommand{SubjectID: f.Reader.SubjectID, Capability: "compensation.read", Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: &ref, AuthorityID: f.AuthorityIDs["compensation.read/financial"], ExpectedRevision: strconv.FormatInt(epoch, 10)}
}

func TestFinancialGrantIssueCanonicalOwnersAndExactMetadataRoundTrip(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee, otherEmployee := makeEmployee(t, f), makeEmployee(t, f)
		refs := financialAuthorityObjects(t, f, employee)
		command := financialIssueCommand(t, f, employee, refs[0])
		if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
			t.Fatal("grant must not manufacture target financial duties:", err)
		}
		if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'compensation.read','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'compensation.read','org',$3)", f.OrgID, f.Reader.SubjectID, f.OrgID); err != nil {
			t.Fatal(err)
		}
		before := f.FinancialKMS.Calls.Load()
		f.FinancialKMS.Fail.Store(true)
		for _, ref := range refs {
			command = financialIssueCommand(t, f, otherEmployee, ref)
			if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
				t.Fatal("exact financial grant crossed canonical employee:", ref, err)
			}
			if _, err := f.Repo.Object(ctx, f.OtherOrgID, ref); !errors.Is(err, fault.NotFound) {
				t.Fatal("canonical financial resolver crossed org:", ref, err)
			}
			command = financialIssueCommand(t, f, employee, ref)
			made, err := f.Authz.Issue(ctx, managementRequest(f), command)
			if err != nil {
				t.Fatal("exact financial grant issue:", ref, err)
			}
			stored, err := f.Repo.Grant(ctx, f.OrgID, made.ID)
			if err != nil || stored.ObjectRef == nil || *stored.ObjectRef != ref || stored.Category != "financial" || stored.RelationBound {
				t.Fatal("financial grant exact stored metadata lost:", stored, err)
			}
			page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{SubjectID: f.Reader.SubjectID, Capability: "compensation.read", Category: "financial", Purpose: "compensation_management", ObjectKind: ref.Kind, ObjectID: ref.ID, Limit: 1})
			if err != nil || len(page.Items) != 1 || page.Items[0].ID != made.ID || page.NextCursor != nil {
				t.Fatal("financial exact metadata filter failed:", page, err)
			}
			snapshot, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
			if err != nil || !snapshot.AllowsObject("compensation.read", "financial", employee, "compensation_management", f.Now, ref) || snapshot.Allows("compensation.read", "financial", employee, "compensation_management", f.Now) || snapshot.AllowsObject("compensation.approve", "financial", employee, "compensation_management", f.Now, ref) || snapshot.AllowsObject("sensitive.export", "financial", employee, "compensation_management", f.Now, ref) {
				t.Fatal("persisted financial exact read elevated to aggregate/approval/export:", err)
			}
		}
		if f.FinancialKMS.Calls.Load() != before {
			t.Fatal("financial grant issue/list/qualification must use metadata, not financial KMS")
		}
		if err := f.Exec(ctx, "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now), f.Reader.Hash); err != nil {
			t.Fatal(err)
		}
		snapshot, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
		if err != nil || snapshot.AllowsObject("compensation.read", "financial", employee, "compensation_management", f.Now, refs[0]) {
			t.Fatal("persisted financial read ignored current MFA boundary:", err)
		}
	})
}
