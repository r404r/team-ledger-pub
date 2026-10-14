package compensation

import (
	"context"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

// ReindexBonusPaymentHMAC is an offline, stop-write maintenance operation. The
// interruption limit exists only to prove resumability; production callers use zero.
func (s *Service) ReindexBonusPaymentHMAC(ctx context.Context, org string, targetVersion int64, targetKeyID string, interruptAfter int, approval BonusHMACMaintenanceApproval) error {
	store, ok := s.Store.(BonusHMACMaintenanceStore)
	key := s.BonusHMACKeys[targetVersion]
	if !ok || s.BonusHMACStaging == nil && len(key) < 32 || targetVersion < 1 || !safeText(targetKeyID, 128, true) || interruptAfter < 0 || !value.ValidID(approval.ApprovedBySubjectID) || !value.ValidID(approval.RequestID) || len(approval.ApprovalDigest) != 32 {
		return fault.Unavailable
	}
	return store.ReindexBonusPaymentHMAC(ctx, org, targetVersion, targetKeyID, interruptAfter, approval, func(payment BonusPaymentRecord) ([]byte, error) {
		var payload bonusPaymentPayload
		if err := s.openBonus(ctx, store, org, payment.ID, payment.PayloadID, payment.EmployeeID, "bonus_payment", "bonus.payment.v1", &payload); err != nil {
			return nil, err
		}
		frame, err := bonusBusinessFrame(org, payment.EmployeeID, payload.BusinessSource, payload.ExternalFactID)
		if err != nil {
			return nil, err
		}
		if s.BonusHMACStaging != nil {
			value, err := s.BonusHMACStaging(ctx, approval.ApprovalDigest, frame)
			if err != nil || int64(value.Version) != targetVersion || value.KeyID != targetKeyID || len(value.Digest) != 32 {
				clear(value.Digest)
				return nil, fault.Unavailable
			}
			return value.Digest, nil
		}
		return messageHMAC(key, frame), nil
	})
}

func bonusBusinessFrame(org, employee, source, external string) ([]byte, error) {
	if !safeText(source, 64, true) || !safeText(external, 200, true) {
		return nil, fault.Unavailable
	}
	return framedMessage("teamledger/bonus-payment-business-key/v1", org, employee, source, external), nil
}

func bonusBusinessDigest(key []byte, org, employee, source, external string) ([]byte, error) {
	if len(key) < 32 {
		return nil, fault.Unavailable
	}
	frame, err := bonusBusinessFrame(org, employee, source, external)
	if err != nil {
		return nil, err
	}
	return messageHMAC(key, frame), nil
}
