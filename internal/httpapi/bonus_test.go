package httpapi_test

import (
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestBonusHTTPExactWorkflowStrictInputAndReadback(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), 201, &employee)
			targetCommand := compensation.BonusTargetCommand{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", BonusRevision: "0", InitialState: "confirmed", Target: compensation.BonusTargetPayload{Basis: "annual_plan", Amount: compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: "9007199254740993"}, Reason: "SYNTHETIC_TARGET"}}
			body := structureJSON(t, targetCommand)
			bad := strings.Replace(body, `"amount_minor":"9007199254740993"`, `"amount_minor":"9007199254740993","amount_minor":"1"`, 1)
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusTargetW, "POST", "/api/v1/employees/"+employee.ID+"/bonus-targets", bad, value.NewID()), 422, nil)
			var target compensation.BonusResult
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusTargetW, "POST", "/api/v1/employees/"+employee.ID+"/bonus-targets", body, value.NewID()), 201, &target)
			awardCommand := compensation.BonusAwardCommand{BonusRevision: target.BonusRevision, TargetID: &target.ID, Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "performance", Reason: "SYNTHETIC_AWARD", Amount: targetCommand.Target.Amount}}
			var award compensation.BonusResult
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusW, "POST", "/api/v1/employees/"+employee.ID+"/bonus-awards", structureJSON(t, awardCommand), value.NewID()), 201, &award)
			var submitted compensation.BonusResult
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusW, "POST", "/api/v1/bonus-awards/"+award.ID+"/transitions", structureJSON(t, compensation.BonusAwardTransition{Action: "submit", Revision: award.Revision, BonusRevision: award.BonusRevision}), value.NewID()), 200, &submitted)
			var approved compensation.BonusResult
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusApprover, "POST", "/api/v1/bonus-awards/"+award.ID+"/transitions", structureJSON(t, compensation.BonusAwardTransition{Action: "approve", Revision: submitted.Revision, BonusRevision: submitted.BonusRevision, DecisionReason: "SYNTHETIC_APPROVED"}), value.NewID()), 200, &approved)
			pay := compensation.BonusPaymentCommand{BonusRevision: approved.BonusRevision, BusinessSource: "fixture_payroll", ExternalFactID: "http-fact", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt-http", Reason: "SYNTHETIC_PAID", Amount: compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: "40"}, AwardID: &award.ID}
			var payment compensation.BonusResult
			apiSend(t, f, financeHTTPRequest(t, f, f.BonusPayW, "POST", "/api/v1/employees/"+employee.ID+"/bonus-payments", structureJSON(t, pay), value.NewID()), 201, &payment)
			var view compensation.BonusView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", "/api/v1/employees/"+employee.ID+"/bonuses?period_start=2026-01-01&period_end=2026-12-31&limit=50", "", ""), 200, &view)
			if view.BonusRevision != "5" || len(view.Targets) != 1 || len(view.Awards) != 1 || len(view.Payments) != 1 || len(view.Balances) != 1 || view.Balances[0].ApprovedMinor != "9007199254740993" || view.Balances[0].PaidMinor != "40" {
				t.Fatalf("exact bonus HTTP projection: %#v", view)
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", "/api/v1/employees/"+employee.ID+"/bonuses?record_kind=unknown", "", ""), 422, nil)
		})
	}
}
