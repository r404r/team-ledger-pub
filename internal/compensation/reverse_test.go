package compensation_test

import (
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestCompensationReverseRetainsApprovedResultWithoutCreatingTerms(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms("100"), Reason: "SYNTHETIC_RETAINED_ROOT"})
		root := financeCurrent(t, f, employee, "2026-10-12")
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2027-01-01", CompRevision: root.CompRevision, BeforeTermID: new(root.CurrentTerm.ID), After: financeTerms("120"), Reason: "SYNTHETIC_REVERSE_TARGET"})
		target := financeCurrent(t, f, employee, "2027-01-01")
		approved := financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "correction", EffectiveDate: "2027-01-01", CompRevision: target.CompRevision, Reason: "SYNTHETIC_REVERSE_TAIL", Members: []compensation.CorrectionMember{{MemberKey: "reverse_tail", Action: "reverse", OriginalEventID: target.CurrentTerm.EventID, EffectiveDate: "2027-01-01"}}})
		financeAmount(t, financeCurrent(t, f, employee, "2027-01-01"), "100")
		if f.Count(t, "compensation_terms_version") != 2 {
			t.Fatal("reversal must retain the two original terms without creating a third")
		}
		assertHistory := func() {
			t.Helper()
			var found, original bool
			for _, approval := range financeHistory(t, f, employee).Approvals {
				for _, event := range approval.Events {
					if event.ID == target.CurrentTerm.EventID {
						original = event.After != nil && event.After.Terms.AmountMinor != nil && *event.After.Terms.AmountMinor == "120"
					}
					if approval.ProposalID != approved.ID || event.Kind != "correction_reversal" {
						continue
					}
					found = true
					if event.AfterTermID == nil || *event.AfterTermID != root.CurrentTerm.ID || event.After == nil || event.After.Terms.AmountMinor == nil || *event.After.Terms.AmountMinor != "100" {
						t.Fatal("immutable reversal must reference the resulting retained terms", event)
					}
				}
			}
			if !found || !original {
				t.Fatal("reversal or original approved history disappeared")
			}
		}
		assertHistory()
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "adjustment", EffectiveDate: "2028-01-01", CompRevision: approved.CompRevision, BeforeTermID: new(root.CurrentTerm.ID), After: financeTerms("140"), Reason: "SYNTHETIC_LATER_ADJUSTMENT"})
		financeAmount(t, financeCurrent(t, f, employee, "2028-01-01"), "140")
		assertHistory()
	})
}
