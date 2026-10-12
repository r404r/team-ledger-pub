package compensation_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestBonusPaginationBindsEmployeeQueryRevisionAndAuthorization(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		for revision, amount := range []string{"100", "200"} {
			_, err := f.Compensation.CreateBonusTarget(ctx, bonusRequest(f.BonusTargetW), employee, compensation.BonusTargetCommand{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", BonusRevision: strconv.Itoa(revision), InitialState: "confirmed", Target: compensation.BonusTargetPayload{Basis: "annual_plan", Amount: bonusMoney(amount), Reason: "SYNTHETIC_TARGET"}})
			if err != nil {
				t.Fatal(err)
			}
		}
		query := compensation.BonusQuery{RecordKind: "targets", Limit: 1}
		first, err := f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, query)
		if err != nil || len(first.Targets) != 1 || first.NextCursor == "" {
			t.Fatal("first page", first, err)
		}
		query.Cursor = first.NextCursor
		second, err := f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, query)
		if err != nil || len(second.Targets) != 1 || second.Targets[0].ID == first.Targets[0].ID || second.NextCursor != "" {
			t.Fatal("second page", second, err)
		}
		query.PeriodStart = "2026-02-01"
		if _, err = f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, query); !errors.Is(err, fault.Invalid) {
			t.Fatal("cursor escaped bound query", err)
		}
	})
}
