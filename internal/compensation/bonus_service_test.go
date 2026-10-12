package compensation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func bonusRequest(who testsupport.Credential) compensation.Request {
	return compensation.Request{TokenHash: who.Hash, Purpose: "compensation_management", Key: value.NewID(), RequestID: value.NewID()}
}

func bonusMoney(amount string) compensation.BonusMoney {
	return compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: amount}
}

func TestBonusCompleteWorkflowAndIndependentCapabilities(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		if _, err := f.Compensation.CreateBonusTarget(ctx, bonusRequest(f.BonusW), employee, compensation.BonusTargetCommand{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", BonusRevision: "0", InitialState: "confirmed", Target: compensation.BonusTargetPayload{Basis: "annual_plan", Amount: bonusMoney("100"), Reason: "SYNTHETIC_TARGET"}}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("bonus proposer maintained target", err)
		}
		target, err := f.Compensation.CreateBonusTarget(ctx, bonusRequest(f.BonusTargetW), employee, compensation.BonusTargetCommand{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", BonusRevision: "0", InitialState: "confirmed", Target: compensation.BonusTargetPayload{Basis: "annual_plan", Amount: bonusMoney("100"), Reason: "SYNTHETIC_TARGET"}})
		if err != nil || target.State != "confirmed" || target.BonusRevision != "1" {
			t.Fatal("target", target, err)
		}
		award, err := f.Compensation.CreateBonusAward(ctx, bonusRequest(f.BonusW), employee, compensation.BonusAwardCommand{BonusRevision: "1", TargetID: &target.ID, Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "performance", Reason: "SYNTHETIC_AWARD", Amount: bonusMoney("100")}})
		if err != nil {
			t.Fatal("award", err)
		}
		award, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusW), award.ID, compensation.BonusAwardTransition{Action: "submit", Revision: award.Revision, BonusRevision: award.BonusRevision})
		if err != nil {
			t.Fatal("submit", err)
		}
		if _, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusW), award.ID, compensation.BonusAwardTransition{Action: "approve", Revision: award.Revision, BonusRevision: award.BonusRevision, DecisionReason: "SYNTHETIC_SELF"}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("self/non-approver approval accepted", err)
		}
		award, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusApprover), award.ID, compensation.BonusAwardTransition{Action: "approve", Revision: award.Revision, BonusRevision: award.BonusRevision, DecisionReason: "SYNTHETIC_APPROVED"})
		if err != nil || award.State != "approved" || award.BonusRevision != "4" {
			t.Fatal("approve", award, err)
		}

		paymentCommand := compensation.BonusPaymentCommand{BonusRevision: "4", BusinessSource: "fixture_payroll", ExternalFactID: "fact-001", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt-001", Reason: "SYNTHETIC_PAID", Amount: bonusMoney("40"), AwardID: &award.ID}
		request := bonusRequest(f.BonusPayW)
		payment, err := f.Compensation.RecordBonusPayment(ctx, request, employee, paymentCommand)
		if err != nil || payment.BonusRevision != "5" {
			t.Fatal("payment", payment, err)
		}
		replayed, err := f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, paymentCommand)
		if err != nil || replayed.ID != payment.ID {
			t.Fatal("business replay", replayed, err)
		}
		changed := paymentCommand
		changed.Amount = bonusMoney("41")
		if _, err = f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, changed); !errors.Is(err, fault.Conflict) {
			t.Fatal("business key mismatch", err)
		}

		correction, err := f.Compensation.CreateBonusAward(ctx, bonusRequest(f.BonusW), employee, compensation.BonusAwardCommand{BonusRevision: "5", CorrectsAwardID: &award.ID, Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "performance", Reason: "SYNTHETIC_CORRECTION", Amount: bonusMoney("120")}})
		if err != nil {
			t.Fatal("correction", err)
		}
		correction, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusW), correction.ID, compensation.BonusAwardTransition{Action: "submit", Revision: correction.Revision, BonusRevision: correction.BonusRevision})
		if err != nil {
			t.Fatal("correction submit", err)
		}
		correction, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusApprover), correction.ID, compensation.BonusAwardTransition{Action: "approve", Revision: correction.Revision, BonusRevision: correction.BonusRevision, DecisionReason: "SYNTHETIC_CORRECTION_APPROVED"})
		if err != nil || correction.BonusRevision != "8" {
			t.Fatal("correction approve", correction, err)
		}
		view, err := f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, compensation.BonusQuery{Limit: 100})
		if err != nil || len(view.Balances) != 1 || view.Balances[0].EffectiveAwardID != correction.ID || view.Balances[0].ApprovedMinor != "120" || view.Balances[0].PaidMinor != "40" || view.Balances[0].BalanceMinor != "80" {
			t.Fatal("replacement read", view.Balances, err)
		}
		extension, err := f.Compensation.AppendCompensationExtension(ctx, bonusRequest(f.CompensationExtensionW), employee, compensation.BonusExtensionCommand{CompRevision: "0", SchemaType: "compensation_memo/v1", SchemaVersion: 1, Payload: compensation.CompensationMemo{Memo: "SYNTHETIC_PRIVATE_MEMO"}})
		if err != nil || extension.CompRevision != "1" {
			t.Fatal("extension", extension, err)
		}
		if _, err = f.Compensation.AppendCompensationExtension(ctx, bonusRequest(f.CompW), employee, compensation.BonusExtensionCommand{CompRevision: "1", SchemaType: "compensation_memo/v1", SchemaVersion: 1, Payload: compensation.CompensationMemo{Memo: "SYNTHETIC_FORBIDDEN"}}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("compensation proposer wrote extension", err)
		}
	})
}

func TestBonusPaymentAnomaliesAndReversalBoundary(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		award, err := f.Compensation.CreateBonusAward(ctx, bonusRequest(f.BonusW), employee, compensation.BonusAwardCommand{BonusRevision: "0", Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "spot", Reason: "SYNTHETIC", Amount: bonusMoney("9007199254740993")}})
		if err != nil {
			t.Fatal(err)
		}
		award, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusW), award.ID, compensation.BonusAwardTransition{Action: "submit", Revision: award.Revision, BonusRevision: award.BonusRevision})
		if err != nil {
			t.Fatal(err)
		}
		award, err = f.Compensation.TransitionBonusAward(ctx, bonusRequest(f.BonusApprover), award.ID, compensation.BonusAwardTransition{Action: "approve", Revision: award.Revision, BonusRevision: award.BonusRevision, DecisionReason: "SYNTHETIC"})
		if err != nil {
			t.Fatal(err)
		}
		pay, err := f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, compensation.BonusPaymentCommand{BonusRevision: "3", BusinessSource: "fixture_payroll", ExternalFactID: "large", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt", Reason: "SYNTHETIC", Amount: bonusMoney("9007199254740993"), AwardID: &award.ID})
		if err != nil {
			t.Fatal(err)
		}
		reversal := compensation.BonusPaymentCommand{BonusRevision: "4", BusinessSource: "fixture_payroll", ExternalFactID: "reverse", Kind: "reversal", PaidDate: "2026-02-02", EvidenceReference: "receipt-r", Reason: "SYNTHETIC", Amount: bonusMoney("1"), OriginalPaymentID: &pay.ID}
		if _, err = f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, reversal); err != nil {
			t.Fatal(err)
		}
		reversal.BonusRevision = "5"
		reversal.ExternalFactID = "reverse-too-much"
		reversal.Amount = bonusMoney("9007199254740993")
		if _, err = f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, reversal); !errors.Is(err, fault.Invalid) {
			t.Fatal("over reversal", err)
		}
		view, err := f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, compensation.BonusQuery{Limit: 100})
		if err != nil || len(view.Balances) != 1 || view.Balances[0].PaidMinor != "9007199254740992" || view.Balances[0].BalanceMinor != "1" {
			t.Fatal(view.Balances, err)
		}
	})
}

func TestBonusReadRechecksRevocationAfterRealDecrypt(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		employee := financeEmployee(t, f, false)
		if _, err := f.Compensation.CreateBonusTarget(ctx, bonusRequest(f.BonusTargetW), employee, compensation.BonusTargetCommand{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", BonusRevision: "0", InitialState: "confirmed", Target: compensation.BonusTargetPayload{Basis: "annual_plan", Amount: bonusMoney("100"), Reason: "SYNTHETIC_RELEASE"}}); err != nil {
			t.Fatal(err)
		}
		arrived, release := make(chan struct{}), make(chan struct{})
		f.FinancialKMS.BlockNextDecrypt(arrived, release)
		type outcome struct {
			view compensation.BonusView
			err  error
		}
		finished := make(chan outcome, 1)
		go func() {
			view, err := f.Compensation.Bonuses(ctx, bonusRequest(f.FinR), employee, compensation.BonusQuery{Limit: 100})
			finished <- outcome{view: view, err: err}
		}()
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("bonus read did not reach real decrypt")
		}
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		close(release)
		select {
		case got := <-finished:
			if got.err == nil || got.view.EmployeeID != "" || len(got.view.Targets) != 0 {
				t.Fatal("revoked bonus read released decrypted financial body", got.view, got.err)
			}
		case <-ctx.Done():
			t.Fatal("bonus release recheck timed out")
		}
	})
}
