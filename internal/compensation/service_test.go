package compensation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func financeBackends(t *testing.T, run func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, testsupport.NewHarness(t, backend)) })
	}
}
func financeRequest(who testsupport.Credential) compensation.Request {
	return compensation.Request{TokenHash: who.Hash, Purpose: "compensation_management", Key: value.NewID(), RequestID: value.NewID()}
}
func financeEmployee(t *testing.T, f *testsupport.Fixture, other bool) string {
	t.Helper()
	who, org := f.Owner, f.OrgID
	if other {
		who, org = f.OtherOwner, f.OtherOrgID
	}
	r, err := f.Service.Create(context.Background(), f.Request(who), org, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_FINANCE_EMPLOYEE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}
func financeTerms(amount string) *compensation.Terms {
	return &compensation.Terms{Currency: "USD", Scale: 2, AmountMinor: new(amount), Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}
}
func financeCurrent(t *testing.T, f *testsupport.Fixture, employee, date string) compensation.CurrentView {
	t.Helper()
	v, err := f.Compensation.Current(context.Background(), financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: date, FutureLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func financeDraft(t *testing.T, f *testsupport.Fixture, employee string, c compensation.ProposalCommand) compensation.Result {
	if c.Members == nil {
		c.Members = []compensation.CorrectionMember{}
	}
	if c.Kind == "correction" && c.EffectiveDate == "" && len(c.Members) > 0 {
		c.EffectiveDate = c.Members[0].EffectiveDate
	}
	t.Helper()
	r, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), employee, c)
	if err != nil || r.Status != "draft" {
		t.Fatal("create real draft:", r, err)
	}
	return r
}
func financeTransition(t *testing.T, f *testsupport.Fixture, p compensation.Result, action, basis string) compensation.Result {
	t.Helper()
	who := f.CompW
	if action == "approve" || action == "reject" {
		who = f.CompApprover
	}
	decision := "SYNTHETIC_DECISION_" + action
	if action == "submit" {
		decision = ""
	}
	r, err := f.Compensation.TransitionProposal(context.Background(), financeRequest(who), p.ID, compensation.TransitionCommand{Action: action, Revision: p.Revision, CompRevision: basis, DecisionReason: decision})
	if err != nil {
		t.Fatal(action, r, err)
	}
	return r
}
func financeApprove(t *testing.T, f *testsupport.Fixture, employee string, c compensation.ProposalCommand) compensation.Result {
	t.Helper()
	p := financeDraft(t, f, employee, c)
	p = financeTransition(t, f, p, "submit", c.CompRevision)
	return financeTransition(t, f, p, "approve", c.CompRevision)
}
func financeAmount(t *testing.T, v compensation.CurrentView, want string) {
	t.Helper()
	if want == "" {
		if v.CurrentTerm != nil {
			t.Fatal("unestablished salary must be null", v)
		}
		return
	}
	if v.CurrentTerm == nil || v.CurrentTerm.Terms.AmountMinor == nil || *v.CurrentTerm.Terms.AmountMinor != want {
		t.Fatalf("want exact %s got %+v", want, v)
	}
}
func financeHistory(t *testing.T, f *testsupport.Fixture, employee string) compensation.ChangesView {
	t.Helper()
	v, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "approvals", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func financeFacts(t *testing.T, f *testsupport.Fixture, employee string) any {
	t.Helper()
	ctx := context.Background()
	a, err := f.Repo.CompensationAggregate(ctx, f.OrgID, employee)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.Repo.CompensationEvents(ctx, f.OrgID, employee)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.Repo.CompensationSchedule(ctx, f.OrgID, employee, compensation.CurrentQuery{AsOf: "2026-01-01", FutureLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, table := range []string{"compensation_aggregate", "compensation_proposal", "compensation_proposal_revision", "compensation_approval", "compensation_event", "compensation_terms_version", "compensation_payload", "compensation_correction_group", "compensation_correction_member", "compensation_schedule_projection", "compensation_command_receipt"} {
		counts[table] = f.Count(t, table)
	}
	return struct {
		A      compensation.Aggregate
		E      []compensation.EventRecord
		S      []compensation.ScheduleRecord
		Counts map[string]int
	}{a, e, s, counts}
}
func financeUnchanged(t *testing.T, f *testsupport.Fixture, employee string, before any) {
	t.Helper()
	if !reflect.DeepEqual(before, financeFacts(t, f, employee)) {
		t.Fatal("rejected operation changed approved facts or schedule")
	}
}
func financeEpoch(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	q := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		q = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	var n int64
	if err := f.Repo.DB.QueryRow(q, f.OrgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(n, 10)
}
func financeGrant(t *testing.T, f *testsupport.Fixture, who testsupport.Credential, employee, cap string, target *authz.ObjectReference) authz.Result {
	t.Helper()
	r, err := f.Authz.Issue(context.Background(), authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{SubjectID: who.SubjectID, Capability: cap, Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: target, AuthorityID: f.AuthorityIDs[cap+"/financial"], ExpectedRevision: financeEpoch(t, f)})
	if err != nil {
		t.Fatal("real approved financial grant:", err)
	}
	return r
}
func financeRevoke(t *testing.T, f *testsupport.Fixture, g authz.Result) {
	t.Helper()
	_, err := f.Authz.Revoke(context.Background(), authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, g.ID, authz.RevokeCommand{ExpectedRevision: g.Revision, ExpectedAuthEpoch: financeEpoch(t, f), Reason: "policy_change"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompensationInitialFutureAndExactAmountConsumer(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		ctx := context.Background()
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("9007199254740993"), Reason: "SYNTHETIC_INITIAL_REASON"})
		financeAmount(t, financeCurrent(t, f, employee, "2026-12-31"), "")
		p = financeTransition(t, f, p, "submit", basis)
		financeAmount(t, financeCurrent(t, f, employee, "2026-12-31"), "")
		before := financeFacts(t, f, employee)
		_, err := f.Compensation.EditProposal(ctx, financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, Revision: p.Revision, After: financeTerms("1"), Reason: "SYNTHETIC_ILLEGAL_EDIT", Members: []compensation.CorrectionMember{}})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("submitted payload mutable:", err)
		}
		financeUnchanged(t, f, employee, before)
		p = financeTransition(t, f, p, "approve", basis)
		v := financeCurrent(t, f, employee, "2026-12-31")
		financeAmount(t, v, "9007199254740993")
		encoded, err := json.Marshal(v)
		if err != nil || !bytes.Contains(encoded, []byte(`"amount_minor":"9007199254740993"`)) {
			t.Fatal("money JSON lost exact string", string(encoded), err)
		}
		p2 := financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-01-01", CompRevision: v.CompRevision, BeforeTermID: new(v.CurrentTerm.ID), After: financeTerms("120"), Reason: "SYNTHETIC_FUTURE_REASON"})
		financeAmount(t, financeCurrent(t, f, employee, "2026-12-31"), "9007199254740993")
		financeAmount(t, financeCurrent(t, f, employee, "2027-01-01"), "120")
		financeAmount(t, financeCurrent(t, f, employee, "2025-12-31"), "")
		if len(financeCurrent(t, f, employee, "2026-12-31").FutureTerms) != 1 {
			t.Fatal("approved future terms not separated")
		}
		before = financeFacts(t, f, employee)
		_, err = f.Compensation.EditProposal(ctx, financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: p2.CompRevision, Revision: p.Revision, After: financeTerms("1"), Reason: "SYNTHETIC_ILLEGAL_EDIT", Members: []compensation.CorrectionMember{}})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("approved patch accepted:", err)
		}
		_, err = f.Compensation.TransitionProposal(ctx, financeRequest(f.CompApprover), p.ID, compensation.TransitionCommand{Action: "approve", Revision: p.Revision, CompRevision: p2.CompRevision, DecisionReason: "SYNTHETIC_DUPLICATE"})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("duplicate approval accepted:", err)
		}
		financeUnchanged(t, f, employee, before)
		for _, action := range []string{"reject", "withdraw"} {
			v = financeCurrent(t, f, employee, "2027-01-01")
			q := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-03-01", CompRevision: v.CompRevision, BeforeTermID: new(v.CurrentTerm.ID), After: financeTerms("999"), Reason: "SYNTHETIC_TERMINAL"})
			q = financeTransition(t, f, q, "submit", v.CompRevision)
			financeTransition(t, f, q, action, v.CompRevision)
			financeAmount(t, financeCurrent(t, f, employee, "2027-03-01"), "120")
		}
	})
}

func TestCompensationCompleteCorrectionAndReverseReinitialConsumer(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_ORIGINAL_100"})
		v := financeCurrent(t, f, employee, "2026-12-31")
		t0 := v.CurrentTerm.ID
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-01-01", CompRevision: v.CompRevision, BeforeTermID: new(t0), After: financeTerms("120"), Reason: "SYNTHETIC_ORIGINAL_120"})
		v = financeCurrent(t, f, employee, "2027-01-01")
		e1 := v.CurrentTerm.EventID
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-02-01", CompRevision: v.CompRevision, BeforeTermID: new(v.CurrentTerm.ID), After: financeTerms("130"), Reason: "SYNTHETIC_ORIGINAL_130"})
		v = financeCurrent(t, f, employee, "2027-02-01")
		e2 := v.CurrentTerm.EventID
		original := financeHistory(t, f, employee)
		before := financeFacts(t, f, employee)
		members := []compensation.CorrectionMember{{MemberKey: "jan", Action: "replace", OriginalEventID: e1, EffectiveDate: "2027-01-01", BeforeRef: &compensation.BeforeRef{TermID: new(t0)}, After: financeTerms("125")}}
		incomplete := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "correction", CompRevision: v.CompRevision, Reason: "SYNTHETIC_INCOMPLETE", Members: members})
		incomplete = financeTransition(t, f, incomplete, "submit", v.CompRevision)
		before = financeFacts(t, f, employee)
		_, err := f.Compensation.TransitionProposal(context.Background(), financeRequest(f.CompApprover), incomplete.ID, compensation.TransitionCommand{Action: "approve", Revision: incomplete.Revision, CompRevision: v.CompRevision, DecisionReason: "SYNTHETIC_INCOMPLETE_DECISION"})
		if !errors.Is(err, compensation.DependencyIncomplete) {
			t.Fatal("incomplete downstream correction must reject entire group:", err)
		}
		financeUnchanged(t, f, employee, before)
		members = append(members, compensation.CorrectionMember{MemberKey: "feb", Action: "replace", OriginalEventID: e2, EffectiveDate: "2027-02-01", BeforeRef: &compensation.BeforeRef{MemberKey: new("jan")}, After: financeTerms("130")})
		corrected := financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "correction", CompRevision: v.CompRevision, Reason: "SYNTHETIC_FULL_CORRECTION", Members: members})
		if len(corrected.Members) != 2 || corrected.Members[0].EventID == "" || corrected.Members[1].EventID == "" {
			t.Fatal("server did not resolve member references", corrected)
		}
		financeAmount(t, financeCurrent(t, f, employee, "2026-12-31"), "100")
		financeAmount(t, financeCurrent(t, f, employee, "2027-01-01"), "125")
		financeAmount(t, financeCurrent(t, f, employee, "2027-02-01"), "130")
		history := financeHistory(t, f, employee)
		for _, old := range original.Approvals {
			found := false
			for _, now := range history.Approvals {
				if now.ID == old.ID {
					found = reflect.DeepEqual(old, now)
				}
			}
			if !found {
				t.Fatal("correction rewrote original reason/approver/before-after", old)
			}
		}
		events, err := f.Repo.CompensationEvents(context.Background(), f.OrgID, employee)
		if err != nil {
			t.Fatal(err)
		}
		superseded := map[string]bool{}
		for _, e := range events {
			if e.CorrectsEventID != nil {
				superseded[*e.CorrectsEventID] = true
			}
		}
		reverse := []compensation.CorrectionMember{}
		for i, e := range events {
			if !superseded[e.ID] && e.Kind != "correction_reversal" {
				reverse = append(reverse, compensation.CorrectionMember{MemberKey: "reverse_" + strconv.Itoa(i), Action: "reverse", OriginalEventID: e.ID, EffectiveDate: e.EffectiveDate})
			}
		}
		v = financeCurrent(t, f, employee, "2027-02-01")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "correction", CompRevision: v.CompRevision, Reason: "SYNTHETIC_COMPLETE_REVERSE", Members: reverse})
		v = financeCurrent(t, f, employee, "2027-02-01")
		financeAmount(t, v, "")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-06-01", CompRevision: v.CompRevision, After: financeTerms("200"), Reason: "SYNTHETIC_REINITIAL"})
		financeAmount(t, financeCurrent(t, f, employee, "2027-02-01"), "200")
		if len(financeHistory(t, f, employee).Approvals) != len(original.Approvals)+3 {
			t.Fatal("reverse/reinitial deleted immutable approvals")
		}
	})
}

func TestCompensationAuthorizationPrecedesKMSAndIndependentApproval(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		other := financeEmployee(t, f, true)
		ctx := context.Background()
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_SECURITY"})
		p = financeTransition(t, f, p, "submit", basis)
		f.FinancialKMS.Fail.Store(true)
		calls := f.FinancialKMS.Calls.Load()
		for _, who := range []testsupport.Credential{f.Owner, f.Manager, f.Reader, f.Observer, f.Stranger, f.OtherOwner} {
			v, err := f.Compensation.Current(ctx, financeRequest(who), employee, compensation.CurrentQuery{AsOf: "2026-12-31"})
			if err == nil || v.CurrentTerm != nil {
				t.Fatal("ordinary actor got financial contents", err)
			}
		}
		request := financeRequest(f.FinR)
		request.Purpose = "interview_followup"
		if _, err := f.Compensation.Current(ctx, request, employee, compensation.CurrentQuery{AsOf: "2026-12-31"}); err == nil {
			t.Fatal("wrong purpose allowed")
		}
		if _, err := f.Compensation.Current(ctx, financeRequest(f.FinR), other, compensation.CurrentQuery{AsOf: "2026-12-31"}); err == nil {
			t.Fatal("cross organization allowed")
		}
		if _, err := f.Compensation.TransitionProposal(ctx, financeRequest(f.FinR), p.ID, compensation.TransitionCommand{Action: "approve", Revision: p.Revision, CompRevision: basis, DecisionReason: "SYNTHETIC_READER_APPROVE"}); err == nil {
			t.Fatal("reader approved")
		}
		if _, err := f.Compensation.Export(ctx, financeRequest(f.FinR), compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: "compensation_proposal", ID: p.ID, ExpectedRevision: p.Revision}}}, func(compensation.ExportEvent) error { t.Fatal("reader exported"); return nil }); err == nil {
			t.Fatal("read implied export")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("unauthorized operations reached financial KMS")
		}
		f.FinancialKMS.Fail.Store(false)
		// Approved capability and grant still cannot authorize default self-approval.
		if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'compensation.approve','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'compensation.approve','org',$3)", f.OrgID, f.CompW.SubjectID, f.OrgID); err != nil {
			t.Fatal(err)
		}
		financeGrant(t, f, f.CompW, employee, "compensation.approve", nil)
		before := financeFacts(t, f, employee)
		if _, err := f.Compensation.TransitionProposal(ctx, financeRequest(f.CompW), p.ID, compensation.TransitionCommand{Action: "approve", Revision: p.Revision, CompRevision: basis, DecisionReason: "SYNTHETIC_SELF_APPROVAL"}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("default self approval allowed", err)
		}
		financeUnchanged(t, f, employee, before)
		f.Now = f.Now.Add(11 * time.Minute)
		calls = f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.Current(ctx, financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2026-12-31"}); err == nil {
			t.Fatal("expired MFA allowed")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("expired MFA reached KMS")
		}
	})
}

func TestCompensationSameBasisCompetingApprovalsCommitOne(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		proposals := make([]compensation.Result, 2)
		for i := range proposals {
			p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms(strconv.Itoa(100 + i)), Reason: "SYNTHETIC_COMPETING"})
			proposals[i] = financeTransition(t, f, p, "submit", basis)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, p := range proposals {
			go func() {
				<-start
				_, err := f.Compensation.TransitionProposal(context.Background(), financeRequest(f.CompApprover), p.ID, compensation.TransitionCommand{Action: "approve", Revision: p.Revision, CompRevision: basis, DecisionReason: "SYNTHETIC_COMPETING_APPROVAL"})
				results <- err
			}()
		}
		close(start)
		success := 0
		for range 2 {
			err := <-results
			if err == nil {
				success++
			} else if !errors.Is(err, fault.Conflict) && !errors.Is(err, fault.Unavailable) {
				t.Fatal("unsafe concurrency error", err)
			}
		}
		if success != 1 {
			t.Fatalf("same aggregate basis committed %d approvals", success)
		}
		if len(financeHistory(t, f, employee).Approvals) != 1 {
			t.Fatal("losing approval appended facts")
		}
	})
}

func TestCompensationMalformedValuesReferencesAndFutureRootRejectAtomically(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		for _, terms := range []*compensation.Terms{financeTerms("9223372036854775808"), financeTerms("1.0"), {Currency: "USD", Scale: 3, AmountMinor: new("100"), Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross"}, {Scale: 2, AmountMinor: new("100"), Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross"}, {Currency: "USD", Scale: 2, AmountMinor: new("100")}, {Currency: "USD", Scale: 2, AmountMinor: new("100"), Rate: new("1"), Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross"}} {
			before := financeFacts(t, f, employee)
			_, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: terms, Reason: "SYNTHETIC_INVALID", Members: []compensation.CorrectionMember{}})
			if !errors.Is(err, fault.Invalid) {
				t.Fatal("invalid money/context accepted", terms, err)
			}
			financeUnchanged(t, f, employee, before)
		}
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2027-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_FUTURE_INITIAL"})
		v := financeCurrent(t, f, employee, "2026-12-31")
		financeAmount(t, v, "")
		before := financeFacts(t, f, employee)
		if _, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: v.CompRevision, After: financeTerms("200"), Reason: "SYNTHETIC_DUPLICATE_INITIAL", Members: []compensation.CorrectionMember{}}); !errors.Is(err, fault.Conflict) {
			t.Fatal("future initial did not block duplicate", err)
		}
		financeUnchanged(t, f, employee, before)
		root := financeCurrent(t, f, employee, "2027-01-01").CurrentTerm
		for _, members := range [][]compensation.CorrectionMember{
			{{MemberKey: "a", Action: "replace", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01", BeforeRef: &compensation.BeforeRef{MemberKey: new("a")}, After: financeTerms("125")}},
			{{MemberKey: "a", Action: "replace", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01", BeforeRef: &compensation.BeforeRef{MemberKey: new("missing")}, After: financeTerms("125")}},
			{{MemberKey: "a", Action: "reverse", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01"}, {MemberKey: "a", Action: "reverse", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01"}},
			{{MemberKey: "a", Action: "replace", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01", BeforeRef: &compensation.BeforeRef{MemberKey: new("a"), TermID: new(root.ID)}, After: financeTerms("125")}},
		} {
			_, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), employee, compensation.ProposalCommand{Kind: "correction", EffectiveDate: "2027-01-01", CompRevision: v.CompRevision, Members: members, Reason: "SYNTHETIC_INVALID_MEMBERS"})
			if err == nil {
				t.Fatal("invalid duplicate/incomplete/selfcycle ref accepted")
			}
			financeUnchanged(t, f, employee, before)
		}
		another := financeEmployee(t, f, false)
		b := financeCurrent(t, f, another, "2026-12-31").CompRevision
		for _, cmd := range []compensation.ProposalCommand{
			{Kind: "adjustment", EffectiveDate: "2027-02-01", CompRevision: b, BeforeTermID: new(root.ID), After: financeTerms("200"), Reason: "SYNTHETIC_CROSSOWNER_BEFORE", Members: []compensation.CorrectionMember{}},
			{Kind: "correction", EffectiveDate: "2027-01-01", CompRevision: b, Members: []compensation.CorrectionMember{{MemberKey: "a", Action: "reverse", OriginalEventID: root.EventID, EffectiveDate: "2027-01-01"}}, Reason: "SYNTHETIC_CROSSOWNER_ORIGINAL"},
		} {
			before := financeFacts(t, f, another)
			calls := f.FinancialKMS.Calls.Load()
			_, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), another, cmd)
			if err == nil {
				t.Fatal("crossowner refs accepted")
			}
			financeUnchanged(t, f, another, before)
			if f.FinancialKMS.Calls.Load() != calls {
				t.Fatal("crossowner metadata reject reached KMS")
			}
		}
	})
}

func financeRevokeBroad(t *testing.T, f *testsupport.Fixture, who testsupport.Credential, cap string) {
	t.Helper()
	q := "SELECT id,revision FROM access_grant WHERE org_id=? AND subject_id=? AND capability=? AND category='financial' AND scope_kind='org' AND revoked=0"
	if f.Backend == "postgres" {
		q = "SELECT id,revision FROM access_grant WHERE org_id=$1 AND subject_id=$2 AND capability=$3 AND category='financial' AND scope_kind='org' AND revoked=false"
	}
	var id string
	var n int64
	if err := f.Repo.DB.QueryRow(q, f.OrgID, who.SubjectID, cap).Scan(&id, &n); err != nil {
		t.Fatal(err)
	}
	financeRevoke(t, f, authz.Result{ID: id, Revision: strconv.FormatInt(n, 10)})
}

func TestCompensationExactEventHistoryBeforeLimitAndTermExportSeparation(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_HIDDEN_OLD_REASON"})
		old := financeCurrent(t, f, employee, "2026-12-31").CurrentTerm
		v := financeCurrent(t, f, employee, "2026-12-31")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-01-01", CompRevision: v.CompRevision, BeforeTermID: new(old.ID), After: financeTerms("120"), Reason: "SYNTHETIC_EXACT_REASON"})
		selected := financeCurrent(t, f, employee, "2027-01-01").CurrentTerm
		v = financeCurrent(t, f, employee, "2027-01-01")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-02-01", CompRevision: v.CompRevision, BeforeTermID: new(selected.ID), After: financeTerms("130"), Reason: "SYNTHETIC_HIDDEN_NEW_REASON"})
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		grant := financeGrant(t, f, f.FinR, employee, "compensation.read", &authz.ObjectReference{Kind: "compensation_event", ID: selected.EventID})
		history, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "approvals", Limit: 1})
		if err != nil || len(history.Approvals) != 1 || len(history.Approvals[0].Events) != 1 || history.Approvals[0].Events[0].ID != selected.EventID || history.NextCursor != "" {
			t.Fatal("exact scope must filter before limit without hidden pagination", history, err)
		}
		if history.Approvals[0].Reason != "" || history.Approvals[0].DecisionReason != "" || len(history.Approvals[0].Members) != 0 || history.Approvals[0].Events[0].MemberKey != "" {
			t.Fatal("exact event fragment exposed shared approval reason or correction group context", history)
		}
		raw, _ := json.Marshal(history)
		if bytes.Contains(raw, []byte("SYNTHETIC_HIDDEN")) || bytes.Contains(raw, []byte(old.EventID)) {
			t.Fatal("exact event grant leaked unrelated approval reason/event", string(raw))
		}
		if _, err := f.Compensation.Current(context.Background(), financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2027-01-01"}); err == nil {
			t.Fatal("exact event implied entire aggregate current read")
		}
		financeRevoke(t, f, grant)
		calls := f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "approvals", Limit: 1}); err == nil {
			t.Fatal("revoked event remained readable")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("revoked exact event reached decrypt")
		}
		financeRevokeBroad(t, f, f.FinExporter, "compensation.read")
		financeRevokeBroad(t, f, f.FinExporter, "sensitive.export")
		target := &authz.ObjectReference{Kind: "compensation_term", ID: selected.ID}
		read := financeGrant(t, f, f.FinExporter, employee, "compensation.read", target)
		command := compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: target.Kind, ID: target.ID, ExpectedRevision: selected.Revision}}}
		if _, err := f.Compensation.Export(context.Background(), financeRequest(f.FinExporter), command, func(compensation.ExportEvent) error { t.Fatal("read-only exact term exported"); return nil }); err == nil {
			t.Fatal("exact read implied export")
		}
		export := financeGrant(t, f, f.FinExporter, employee, "sensitive.export", target)
		command.Objects[0].ExpectedRevision = "9223372036854775807"
		calls = f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.Export(context.Background(), financeRequest(f.FinExporter), command, func(compensation.ExportEvent) error { t.Fatal("stale expected revision released export"); return nil }); !errors.Is(err, fault.Conflict) {
			t.Fatal("export ignored exact revision", err)
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("stale term revision reached KMS")
		}
		command.Objects[0].ExpectedRevision = selected.Revision
		var stream bytes.Buffer
		_, err = f.Compensation.Export(context.Background(), financeRequest(f.FinExporter), command, func(e compensation.ExportEvent) error { stream.Write(e.EncodedJSON); return nil })
		if err != nil || !bytes.Contains(stream.Bytes(), []byte(`"120"`)) || !bytes.Contains(stream.Bytes(), []byte(`"complete"`)) {
			t.Fatal("exact term export failed", stream.String(), err)
		}
		if bytes.Contains(stream.Bytes(), []byte("SYNTHETIC_")) || bytes.Contains(stream.Bytes(), []byte(old.ID)) {
			t.Fatal("term export included unrelated reasons/history", stream.String())
		}
		financeRevoke(t, f, read)
		calls = f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.Export(context.Background(), financeRequest(f.FinExporter), command, func(compensation.ExportEvent) error { t.Fatal("export without current read released"); return nil }); err == nil {
			t.Fatal("export granted without read")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("revoked term read reached KMS")
		}
		financeRevoke(t, f, export)
	})
}

func TestCompensationCurrentRechecksRevocationDuringRealDecrypt(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_REVOKED_INFLIGHT"})
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		grant := financeGrant(t, f, f.FinR, employee, "compensation.read", nil)
		arrived, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		f.FinancialKMS.BlockNextDecrypt(arrived, release)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		type result struct {
			v   compensation.CurrentView
			err error
		}
		results := make(chan result, 1)
		go func() {
			v, err := f.Compensation.Current(ctx, financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2026-12-31"})
			results <- result{v, err}
		}()
		select {
		case <-arrived:
		case early := <-results:
			t.Fatal("authorized current did not reach real decrypt", early.err)
		case <-ctx.Done():
			t.Fatal("decrypt gate timeout")
		}
		financeRevoke(t, f, grant)
		unblock()
		select {
		case r := <-results:
			if r.err == nil || r.v.CurrentTerm != nil || len(r.v.FutureTerms) != 0 {
				t.Fatal("revocation during decrypt released plaintext", r)
			}
		case <-ctx.Done():
			t.Fatal("release recheck timeout")
		}
	})
}

func TestCompensationKMSAndAuditFailureRollbackAndNoRelease(t *testing.T) {
	for _, failure := range []string{"kms", "audit"} {
		t.Run(failure, func(t *testing.T) {
			financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				employee := financeEmployee(t, f, false)
				basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
				p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_FAULT"})
				p = financeTransition(t, f, p, "submit", basis)
				before := financeFacts(t, f, employee)
				if failure == "kms" {
					f.FinancialKMS.Fail.Store(true)
				} else if err := f.Exec(context.Background(), "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
					t.Fatal(err)
				}
				r, err := f.Compensation.TransitionProposal(context.Background(), financeRequest(f.CompApprover), p.ID, compensation.TransitionCommand{Action: "approve", Revision: p.Revision, CompRevision: basis, DecisionReason: "SYNTHETIC_FAULT_APPROVE"})
				if err == nil || r.ID != "" {
					t.Fatal("failed audit/KMS approval reported success", r, err)
				}
				financeUnchanged(t, f, employee, before)
			})
		})
	}
	for _, failure := range []string{"kms", "audit"} {
		t.Run("read/"+failure, func(t *testing.T) {
			financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				employee := financeEmployee(t, f, false)
				basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
				financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_READ_FAULT"})
				if failure == "kms" {
					f.FinancialKMS.Fail.Store(true)
				} else if err := f.Exec(context.Background(), "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
					t.Fatal(err)
				}
				v, err := f.Compensation.Current(context.Background(), financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2026-12-31"})
				if err == nil || v.CurrentTerm != nil || len(v.FutureTerms) != 0 {
					t.Fatal("failed read audit/KMS released salary", v, err)
				}
			})
		})
	}
}

func TestCompensationDraftRevisionAndDisabledPolicyConsumer(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_DRAFT_OLD"})
		cmd := compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, Revision: p.Revision, After: financeTerms("101"), Reason: "SYNTHETIC_DRAFT_NEW", Members: []compensation.CorrectionMember{}}
		next, err := f.Compensation.EditProposal(context.Background(), financeRequest(f.CompW), p.ID, cmd)
		if err != nil || next.Revision == p.Revision {
			t.Fatal("draft edit did not append revision", next, err)
		}
		before := financeFacts(t, f, employee)
		if _, err := f.Compensation.EditProposal(context.Background(), financeRequest(f.CompW), p.ID, cmd); !errors.Is(err, fault.Conflict) {
			t.Fatal("stale draft revision overwrote newer proposal", err)
		}
		financeUnchanged(t, f, employee, before)
		history, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 100})
		if err != nil || len(history.Proposals) != 1 || history.Proposals[0].Reason != cmd.Reason || len(history.Revisions) != 2 {
			t.Fatal("draft revisions not reloaded immutably", history, err)
		}
		if history.Revisions[0].Revision != next.Revision || history.Revisions[0].Command.Reason != cmd.Reason || history.Revisions[0].Command.After == nil || *history.Revisions[0].Command.After.AmountMinor != "101" || history.Revisions[1].Revision != p.Revision || history.Revisions[1].Command.Reason != "SYNTHETIC_DRAFT_OLD" || history.Revisions[1].Command.After == nil || *history.Revisions[1].Command.After.AmountMinor != "100" || history.NextCursor != "" {
			t.Fatal("revision page overwrote immutable draft values or lost its final page", history)
		}
		financeAmount(t, financeCurrent(t, f, employee, "2026-12-31"), "")
		for _, date := range []string{"2026-02-30", "2026-13-01"} {
			_, err := f.Compensation.CreateProposal(context.Background(), financeRequest(f.CompW), employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: date, CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_INVALID_DATE", Members: []compensation.CorrectionMember{}})
			if !errors.Is(err, fault.Invalid) {
				t.Fatal("invalid Gregorian date accepted", date, err)
			}
			financeUnchanged(t, f, employee, before)
		}
		f.Compensation.Policy.Enabled = false
		calls := f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.Current(context.Background(), financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2026-12-31"}); err == nil {
			t.Fatal("disabled policy allowed finance")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("disabled finance reached KMS")
		}
	})
}

func TestCompensationExactProposalPermissionsPermitOnlyExistingDraftWork(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		if basis != "0" {
			t.Fatal("unestablished aggregate must expose B0", basis)
		}
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_EXACT_PROPOSAL"})
		financeRevokeBroad(t, f, f.CompW, "compensation.read")
		financeRevokeBroad(t, f, f.CompW, "compensation.propose")
		target := &authz.ObjectReference{Kind: "compensation_proposal", ID: p.ID}
		read := financeGrant(t, f, f.CompW, employee, "compensation.read", target)
		propose := financeGrant(t, f, f.CompW, employee, "compensation.propose", target)
		query := compensation.ChangesQuery{RecordKind: "proposals", ProposalID: p.ID, Limit: 1}
		view, err := f.Compensation.Changes(ctx, financeRequest(f.CompW), employee, query)
		if err != nil || len(view.Proposals) != 1 || view.CompRevision != basis {
			t.Fatal("exact proposal could not load current basis", view, err)
		}
		permissions := map[string]bool{}
		for _, hint := range view.Proposals[0].Permissions {
			if hint.Category != "financial" {
				t.Fatal("unexpected proposal permission category", hint)
			}
			permissions[hint.Capability] = true
		}
		if len(permissions) != 2 || !permissions["compensation.read"] || !permissions["compensation.propose"] {
			t.Fatal("proposal hints broadened exact read/propose", permissions)
		}
		if _, err := f.Compensation.Current(ctx, financeRequest(f.CompW), employee, compensation.CurrentQuery{AsOf: "2026-12-31"}); err == nil {
			t.Fatal("exact proposal permitted aggregate read")
		}
		next, err := f.Compensation.EditProposal(ctx, financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", Revision: p.Revision, CompRevision: view.CompRevision, After: financeTerms("101"), Reason: "SYNTHETIC_EXACT_EDIT", Members: []compensation.CorrectionMember{}})
		if err != nil {
			t.Fatal("exact proposal read/propose could not edit existing initial", err)
		}
		next = financeTransition(t, f, next, "submit", view.CompRevision)
		before := financeFacts(t, f, employee)
		calls := f.FinancialKMS.Calls.Load()
		if _, err := f.Compensation.CreateProposal(ctx, financeRequest(f.CompW), employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("200"), Reason: "SYNTHETIC_EXACT_NO_CREATE", Members: []compensation.CorrectionMember{}}); err == nil {
			t.Fatal("exact proposal propose implied aggregate create")
		}
		if _, err := f.Compensation.TransitionProposal(ctx, financeRequest(f.CompW), next.ID, compensation.TransitionCommand{Action: "approve", Revision: next.Revision, CompRevision: basis, DecisionReason: "SYNTHETIC_EXACT_NO_APPROVE"}); err == nil {
			t.Fatal("exact propose implied approve")
		}
		if _, err := f.Compensation.Export(ctx, financeRequest(f.CompW), compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: target.Kind, ID: target.ID, ExpectedRevision: next.Revision}}}, func(compensation.ExportEvent) error { t.Fatal("exact proposal read/propose exported"); return nil }); err == nil {
			t.Fatal("exact propose implied export")
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("denied exact-scope actions reached KMS")
		}
		financeUnchanged(t, f, employee, before)
		financeRevoke(t, f, propose)
		view, err = f.Compensation.Changes(ctx, financeRequest(f.CompW), employee, query)
		if err != nil || len(view.Proposals) != 1 {
			t.Fatal("revoking propose removed independent read", view, err)
		}
		for _, hint := range view.Proposals[0].Permissions {
			if hint.Capability != "compensation.read" {
				t.Fatal("revoked proposal action hint persisted", hint)
			}
		}
		financeRevoke(t, f, read)
		calls = f.FinancialKMS.Calls.Load()
		view, err = f.Compensation.Changes(ctx, financeRequest(f.CompW), employee, query)
		if err == nil || len(view.Proposals) != 0 {
			t.Fatal("revoked exact proposal read returned payload/hints", view, err)
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("revoked exact proposal reached KMS")
		}
	})
}

func TestCompensationExpiredExactProposalGrantDiscardsPermissions(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_EXPIRED_EXACT"})
		financeRevokeBroad(t, f, f.CompW, "compensation.read")
		financeRevokeBroad(t, f, f.CompW, "compensation.propose")
		target := &authz.ObjectReference{Kind: "compensation_proposal", ID: p.ID}
		_, err := f.Authz.Issue(ctx, authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{SubjectID: f.CompW.SubjectID, Capability: "compensation.read", Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Minute).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: target, AuthorityID: f.AuthorityIDs["compensation.read/financial"], ExpectedRevision: financeEpoch(t, f)})
		if err != nil {
			t.Fatal(err)
		}
		query := compensation.ChangesQuery{RecordKind: "proposals", ProposalID: p.ID, Limit: 1}
		view, err := f.Compensation.Changes(ctx, financeRequest(f.CompW), employee, query)
		if err != nil || len(view.Proposals) != 1 {
			t.Fatal("unexpired exact grant not readable", view, err)
		}
		f.Now = f.Now.Add(2 * time.Minute)
		calls := f.FinancialKMS.Calls.Load()
		view, err = f.Compensation.Changes(ctx, financeRequest(f.CompW), employee, query)
		if err == nil || len(view.Proposals) != 0 {
			t.Fatal("expired exact grant returned contents/permissions", view, err)
		}
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("expired exact grant reached KMS")
		}
	})
}
