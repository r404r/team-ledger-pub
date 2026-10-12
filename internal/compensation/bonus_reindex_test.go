package compensation_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestBonusHMACReindexBlocksWritersResumesAndPreservesBusinessReplay(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		award, err := f.Compensation.CreateBonusAward(ctx, bonusRequest(f.BonusW), employee, compensation.BonusAwardCommand{BonusRevision: "0", Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "spot", Reason: "SYNTHETIC", Amount: bonusMoney("100")}})
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
		command := compensation.BonusPaymentCommand{BonusRevision: "3", BusinessSource: "fixture_payroll", ExternalFactID: "reindex-stable", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt", Reason: "SYNTHETIC", Amount: bonusMoney("40"), AwardID: &award.ID}
		original, err := f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, command)
		if err != nil {
			t.Fatal(err)
		}
		key2 := bytes.Repeat([]byte{92}, 32)
		f.Compensation.BonusHMACKeyIDs[2] = "bonus-payment-v2"
		f.Compensation.BonusHMACKeys[2] = key2
		approval := compensation.BonusHMACMaintenanceApproval{ApprovedBySubjectID: f.BonusApprover.SubjectID, RequestID: value.NewID(), ApprovalDigest: bytes.Repeat([]byte{93}, 32)}
		if err = f.Compensation.ReindexBonusPaymentHMAC(ctx, f.OrgID, 2, "bonus-payment-v2", 1, approval); !errors.Is(err, fault.Unavailable) {
			t.Fatal("injected interruption must block", err)
		}
		var state, keyID string
		var active int64
		queryState := "SELECT state,active_version,active_key_id FROM hmac_index_state WHERE org_id=?"
		if f.Backend == "postgres" {
			queryState = "SELECT state,active_version,active_key_id FROM hmac_index_state WHERE org_id=$1"
		}
		if err = f.Repo.DB.QueryRow(queryState, f.OrgID).Scan(&state, &active, &keyID); err != nil || state != "blocked" || active != 1 || keyID != "bonus-payment-v1" {
			t.Fatal("failed reindex flipped active epoch", state, active, keyID, err)
		}
		blocked := command
		blocked.BonusRevision = "4"
		blocked.ExternalFactID = "writer-during-stop"
		if _, err = f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, blocked); !errors.Is(err, fault.Unavailable) {
			t.Fatal("writer escaped stop-write state", err)
		}
		if err = f.Compensation.ReindexBonusPaymentHMAC(ctx, f.OrgID, 2, "bonus-payment-v2", 0, approval); err != nil {
			t.Fatal("resume", err)
		}
		if err = f.Repo.DB.QueryRow(queryState, f.OrgID).Scan(&state, &active, &keyID); err != nil || state != "ready" || active != 2 || keyID != "bonus-payment-v2" {
			t.Fatal("completed reindex state", state, active, keyID, err)
		}
		f.Compensation.BonusHMACActive = 2
		replayed, err := f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, command)
		if err != nil || replayed.ID != original.ID {
			t.Fatal("new epoch must resolve original fact", replayed, err)
		}
		delete(f.Compensation.BonusHMACKeys, 2)
		if _, err = f.Compensation.RecordBonusPayment(ctx, bonusRequest(f.BonusPayW), employee, command); !errors.Is(err, fault.Unavailable) {
			t.Fatal("missing active key must fail closed", err)
		}
	})
}
