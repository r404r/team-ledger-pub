package compensation_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestCompensationProposalListDoesNotDecryptHistory(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		basis := financeCurrent(t, f, employee, "2026-12-31").CompRevision
		p := financeDraft(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, After: financeTerms("100"), Reason: "SYNTHETIC_REVISION_1"})
		for revision := 2; revision <= 105; revision++ {
			var err error
			p, err = f.Compensation.EditProposal(context.Background(), financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: basis, Revision: p.Revision, After: financeTerms(strconv.Itoa(99 + revision)), Reason: "SYNTHETIC_REVISION_" + strconv.Itoa(revision), Members: []compensation.CorrectionMember{}})
			if err != nil {
				t.Fatal(err)
			}
		}
		before := f.FinancialKMS.Calls.Load()
		view, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "proposals", Limit: 1})
		if err != nil || len(view.Proposals) != 1 || view.Proposals[0].Revision != "105" || view.Proposals[0].Reason != "SYNTHETIC_REVISION_105" {
			t.Fatal("current draft list did not retain its exact latest revision", err)
		}
		if calls := f.FinancialKMS.Calls.Load() - before; calls > 1 {
			t.Fatalf("one current draft row decrypted %d revisions; historic bodies require explicit bounded history pages", calls)
		}
	})
}
