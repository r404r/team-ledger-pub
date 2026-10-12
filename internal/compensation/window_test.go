package compensation_test

import (
	"context"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestCompensationCurrentWindowRemainsBoundedAfterLongApprovedHistory(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		var before *string
		basis := "0"
		start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 105; i++ {
			date := start.AddDate(0, i, 0).Format(time.DateOnly)
			kind := "adjustment"
			if i == 0 {
				kind = "initial"
			}
			financeApprove(t, f, employee, compensation.ProposalCommand{Kind: kind, EffectiveDate: date, BeforeTermID: before, CompRevision: basis, After: financeTerms(date[0:4]), Reason: "SYNTHETIC_BOUNDED_HISTORY"})
			current := financeCurrent(t, f, employee, date)
			before, basis = new(current.CurrentTerm.ID), current.CompRevision
		}
		rows, err := f.Repo.CompensationSchedule(context.Background(), f.OrgID, employee, compensation.CurrentQuery{AsOf: "2026-01-01", FutureLimit: 100})
		if err != nil || len(rows) != 101 || rows[0].EffectiveDate != "2026-01-01" || rows[100].EffectiveDate != start.AddDate(0, 100, 0).Format(time.DateOnly) {
			t.Fatal("current read loaded more than one current term plus 100 future terms", len(rows), err)
		}
		window, err := f.Repo.CompensationSchedule(context.Background(), f.OrgID, employee, compensation.CurrentQuery{AsOf: "2027-01-01", FutureLimit: 3})
		if err != nil || len(window) != 4 || window[0].EffectiveDate != "2027-01-01" || window[3].EffectiveDate != "2027-04-01" {
			t.Fatal("database window loaded or reordered historical/future records outside its finite query", window, err)
		}
		view, err := f.Compensation.Current(context.Background(), financeRequest(f.FinR), employee, compensation.CurrentQuery{AsOf: "2027-01-01", FutureLimit: 3})
		if err != nil || view.CurrentTerm == nil || view.CurrentTerm.EffectiveDate != "2027-01-01" || len(view.FutureTerms) != 3 {
			t.Fatal("bounded consumer did not locate the exact current interval", view, err)
		}
		for i, term := range view.FutureTerms {
			if term.EffectiveDate != start.AddDate(0, 13+i, 0).Format(time.DateOnly) {
				t.Fatal("future window skipped or reordered an approved term", term)
			}
		}
	})
}
