package compensation

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (s *Service) bonusReplay(ctx context.Context, store BonusStore, q Request, a authz.Snapshot, operation, employee string, command any) (BonusResult, []byte, bool, error) {
	digest, err := s.bonusCommandDigest(q, a, operation, employee, command)
	if err != nil {
		return BonusResult{}, nil, false, err
	}
	result, found, ok, err := store.BonusCommandReceipt(ctx, a.OrgID, a.SubjectID, operation, q.Key)
	if err != nil || !ok {
		return BonusResult{}, digest, false, err
	}
	result, err = bonusReceiptMatch(result, found, digest)
	return result, digest, true, err
}

func (s *Service) commitBonus(ctx context.Context, q Request, before authz.Snapshot, employee, capability string, write BonusWrite) (BonusResult, error) {
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	err = store.WithBonusTx(ctx, before.OrgID, func(tx BonusTx) error {
		if err := tx.LockSubjects(ctx, before.OrgID, []string{before.SubjectID}); err != nil {
			return err
		}
		if err := tx.LockBonusEmployee(ctx, before.OrgID, employee); err != nil {
			return err
		}
		if write.ExpectedCompRevision != nil {
			if err := tx.LockCompensationEmployee(ctx, before.OrgID, employee); err != nil {
				return err
			}
		}
		current, err := tx.Security(ctx, q.TokenHash, before.OrgID, employee)
		if err != nil {
			return err
		}
		if !current.Valid(s.clock()) || current.SubjectID != before.SubjectID || current.AuthEpoch != before.AuthEpoch || !s.allows(current, "compensation.read", employee) || !s.allows(current, capability, employee) {
			return fault.Forbidden
		}
		latest, err := tx.BonusSnapshot(ctx, before.OrgID, employee)
		if err != nil {
			return err
		}
		if latest.Aggregate.Revision != write.ExpectedBonusRevision {
			return fault.Conflict
		}
		if write.ExpectedCompRevision != nil {
			comp, err := tx.CompensationAggregate(ctx, before.OrgID, employee)
			if err != nil {
				return err
			}
			if comp.Revision != *write.ExpectedCompRevision {
				return fault.Conflict
			}
		}
		return tx.CommitBonus(ctx, write)
	})
	if err != nil {
		return BonusResult{}, err
	}
	return write.Result, nil
}

func (s *Service) CreateBonusTarget(ctx context.Context, q Request, employee string, command BonusTargetCommand) (BonusResult, error) {
	const operation = "OP-BONUS-02"
	if err := s.validateBonusEnabled(); err != nil {
		return BonusResult{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	if err = s.require(a, employee, nil, "bonus.target.manage"); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	basis, err := parseBonusRevision(command.BonusRevision)
	if err != nil || validateBonusPeriod(command.PeriodStart, command.PeriodEnd) != nil || validateBonusMoney(s.Policy, command.Target.Amount, true) != nil || !safeText(command.Target.Basis, 64, true) || !safeText(command.Target.Reason, 4096, true) || command.InitialState != "draft" && command.InitialState != "confirmed" {
		return BonusResult{}, fault.Invalid
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, employee, command); ok || err != nil {
		return result, err
	} else {
		snapshot, err := store.BonusSnapshot(ctx, a.OrgID, employee)
		if err != nil {
			return BonusResult{}, err
		}
		if snapshot.Aggregate.Revision != basis {
			return BonusResult{}, fault.Conflict
		}
		id, version := value.NewID(), value.NewID()
		payload, err := s.seal(ctx, binding(a.OrgID, employee, id, version, "bonus_target", "bonus.target.v1"), bonusTargetPayload{Target: command.Target})
		if err != nil {
			return BonusResult{}, err
		}
		now := s.clock()
		target := &BonusTargetRecord{OrgID: a.OrgID, EmployeeID: employee, ID: id, State: command.InitialState, VersionID: version, PayloadID: payload.ID, PeriodStart: command.PeriodStart, PeriodEnd: command.PeriodEnd, ActorSubjectID: a.SubjectID, Revision: 1, BasisRevision: basis + 1, RecordedAt: now}
		result := BonusResult{ID: id, Revision: "1", BonusRevision: number(basis + 1), State: command.InitialState}
		write := BonusWrite{Aggregate: BonusAggregateRecord{OrgID: a.OrgID, EmployeeID: employee, Revision: basis + 1}, ExpectedBonusRevision: basis, Target: target, Payloads: []Payload{payload}, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, "bonus.target.manage", write)
	}
}

func (s *Service) TransitionBonusTarget(ctx context.Context, q Request, id string, command BonusTargetTransition) (BonusResult, error) {
	const operation = "OP-BONUS-07"
	if err := s.validateBonusEnabled(); err != nil {
		return BonusResult{}, err
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	a, err := s.session(ctx, s.Store, q, "", "")
	if err != nil {
		return BonusResult{}, err
	}
	// Target lookup is intentionally owner-scoped in storage; an absent or
	// unauthorized ID remains indistinguishable.
	target, employee, err := s.findBonusTarget(ctx, store, a, id)
	if err != nil {
		return BonusResult{}, err
	}
	a, err = s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	if err = s.require(a, employee, nil, "bonus.target.manage"); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	revision, err := revision(command.Revision)
	basis, basisErr := parseBonusRevision(command.BonusRevision)
	next, stateErr := NextBonusTargetState(target.State, command.Action)
	if err != nil || basisErr != nil || stateErr != nil || !safeText(command.Reason, 4096, true) || revision != target.Revision || basis != target.BasisRevision {
		if stateErr != nil {
			return BonusResult{}, stateErr
		}
		return BonusResult{}, fault.Conflict
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, id, command); ok || err != nil {
		return result, err
	} else {
		var old bonusTargetPayload
		if err = s.openBonus(ctx, store, a.OrgID, target.ID, target.PayloadID, employee, "bonus_target", "bonus.target.v1", &old); err != nil {
			return BonusResult{}, err
		}
		version := value.NewID()
		payload, err := s.seal(ctx, binding(a.OrgID, employee, id, version, "bonus_target", "bonus.target.v1"), bonusTargetPayload{Target: old.Target, TransitionReason: command.Reason})
		if err != nil {
			return BonusResult{}, err
		}
		target.State, target.VersionID, target.PayloadID, target.Revision, target.BasisRevision, target.ActorSubjectID, target.RecordedAt = next, version, payload.ID, revision+1, basis+1, a.SubjectID, s.clock()
		result := BonusResult{ID: id, Revision: number(target.Revision), BonusRevision: number(basis + 1), State: next}
		write := BonusWrite{Aggregate: BonusAggregateRecord{OrgID: a.OrgID, EmployeeID: employee, Revision: basis + 1}, ExpectedBonusRevision: basis, Target: &target, ExpectedTargetRevision: revision, Payloads: []Payload{payload}, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, "bonus.target.manage", write)
	}
}

func (s *Service) CreateBonusAward(ctx context.Context, q Request, employee string, command BonusAwardCommand) (BonusResult, error) {
	const operation = "OP-BONUS-03"
	return s.writeBonusAward(ctx, q, operation, employee, "", BonusAwardEditCommand{BonusRevision: command.BonusRevision, TargetID: command.TargetID, CorrectsAwardID: command.CorrectsAwardID, Award: command.Award})
}

func (s *Service) EditBonusAward(ctx context.Context, q Request, id string, command BonusAwardEditCommand) (BonusResult, error) {
	const operation = "OP-BONUS-04"
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	a, err := s.session(ctx, s.Store, q, "", "")
	if err != nil {
		return BonusResult{}, err
	}
	_, employee, err := s.findBonusAward(ctx, store, a, id)
	if err != nil {
		return BonusResult{}, err
	}
	return s.writeBonusAward(ctx, q, operation, employee, id, command)
}

func (s *Service) writeBonusAward(ctx context.Context, q Request, operation, employee, id string, command BonusAwardEditCommand) (BonusResult, error) {
	if err := s.validateBonusEnabled(); err != nil {
		return BonusResult{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	if err = s.require(a, employee, nil, "bonus.propose"); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	basis, err := parseBonusRevision(command.BonusRevision)
	if err != nil || validateBonusPeriod(command.Award.PeriodStart, command.Award.PeriodEnd) != nil || validateBonusMoney(s.Policy, command.Award.Amount, true) != nil || !finiteName(command.Award.Category) || !safeText(command.Award.Reason, 4096, true) {
		return BonusResult{}, fault.Invalid
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	snapshot, err := store.BonusSnapshot(ctx, a.OrgID, employee)
	if err != nil || snapshot.Aggregate.Revision != basis {
		if err != nil {
			return BonusResult{}, err
		}
		return BonusResult{}, fault.Conflict
	}
	if command.TargetID != nil {
		target, ok := bonusRecordByID(snapshot.Targets, *command.TargetID, func(v BonusTargetRecord) string { return v.ID })
		if !ok || target.EmployeeID != employee {
			return BonusResult{}, fault.Invalid
		}
	}
	if command.CorrectsAwardID != nil {
		corrected, ok := bonusRecordByID(snapshot.Awards, *command.CorrectsAwardID, func(v BonusAwardRecord) string { return v.ID })
		if !ok || corrected.EmployeeID != employee || corrected.State != "approved" {
			return BonusResult{}, fault.Invalid
		}
	}
	var current BonusAwardRecord
	expected := int64(0)
	if id == "" {
		id = value.NewID()
	} else {
		current, _ = bonusRecordByID(snapshot.Awards, id, func(v BonusAwardRecord) string { return v.ID })
		expected, err = revision(command.Revision)
		if current.ID == "" || current.State != "draft" || current.Revision != expected || current.AuthorSubjectID != a.SubjectID {
			return BonusResult{}, fault.Conflict
		}
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, id, command); ok || err != nil {
		return result, err
	} else {
		version := value.NewID()
		payload, err := s.seal(ctx, binding(a.OrgID, employee, id, version, "bonus_award", "bonus.award.v1"), bonusAwardPayload{Award: command.Award, TargetID: command.TargetID, CorrectsAwardID: command.CorrectsAwardID})
		if err != nil {
			return BonusResult{}, err
		}
		now := s.clock()
		author := a.SubjectID
		if current.AuthorSubjectID != "" {
			author = current.AuthorSubjectID
		}
		award := &BonusAwardRecord{OrgID: a.OrgID, EmployeeID: employee, ID: id, State: "draft", VersionID: version, PayloadID: payload.ID, AuthorSubjectID: author, PeriodStart: command.Award.PeriodStart, PeriodEnd: command.Award.PeriodEnd, TargetID: command.TargetID, CorrectsAwardID: command.CorrectsAwardID, Revision: expected + 1, BasisRevision: basis + 1, RecordedAt: now}
		result := BonusResult{ID: id, Revision: number(award.Revision), BonusRevision: number(basis + 1), State: "draft"}
		write := BonusWrite{Aggregate: BonusAggregateRecord{OrgID: a.OrgID, EmployeeID: employee, Revision: basis + 1}, ExpectedBonusRevision: basis, Award: award, ExpectedAwardRevision: expected, Payloads: []Payload{payload}, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, "bonus.propose", write)
	}
}

func (s *Service) TransitionBonusAward(ctx context.Context, q Request, id string, command BonusAwardTransition) (BonusResult, error) {
	const operation = "OP-BONUS-05"
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	a, err := s.session(ctx, s.Store, q, "", "")
	if err != nil {
		return BonusResult{}, err
	}
	award, employee, err := s.findBonusAward(ctx, store, a, id)
	if err != nil {
		return BonusResult{}, err
	}
	a, err = s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	capability := "bonus.propose"
	if command.Action == "approve" || command.Action == "reject" {
		capability = "bonus.approve"
	}
	if err = s.require(a, employee, nil, capability); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	rev, revErr := revision(command.Revision)
	basis, basisErr := parseBonusRevision(command.BonusRevision)
	next, stateErr := NextBonusAwardState(award.State, command.Action, award.AuthorSubjectID, a.SubjectID)
	if stateErr != nil {
		return BonusResult{}, stateErr
	}
	if revErr != nil || basisErr != nil || rev != award.Revision || basis != award.BasisRevision || !safeText(command.DecisionReason, 4096, command.Action == "approve" || command.Action == "reject") {
		return BonusResult{}, fault.Conflict
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, id, command); ok || err != nil {
		return result, err
	} else {
		var payload bonusAwardPayload
		if err = s.openBonus(ctx, store, a.OrgID, award.ID, award.PayloadID, employee, "bonus_award", "bonus.award.v1", &payload); err != nil {
			return BonusResult{}, err
		}
		if next == "approved" && award.CorrectsAwardID != nil {
			snapshot, e := store.BonusSnapshot(ctx, a.OrgID, employee)
			if e != nil {
				return BonusResult{}, e
			}
			for _, candidate := range snapshot.Awards {
				if candidate.CorrectsAwardID != nil && *candidate.CorrectsAwardID == *award.CorrectsAwardID && candidate.State == "approved" {
					return BonusResult{}, fault.Conflict
				}
			}
			corrected, ok := bonusRecordByID(snapshot.Awards, *award.CorrectsAwardID, func(v BonusAwardRecord) string { return v.ID })
			if !ok || corrected.State != "approved" {
				return BonusResult{}, fault.Conflict
			}
		}
		version := value.NewID()
		sealed, e := s.seal(ctx, binding(a.OrgID, employee, id, version, "bonus_award", "bonus.award.v1"), payload)
		if e != nil {
			return BonusResult{}, e
		}
		award.State, award.VersionID, award.PayloadID, award.Revision, award.BasisRevision, award.RecordedAt = next, version, sealed.ID, rev+1, basis+1, s.clock()
		payloads := []Payload{sealed}
		var approval *BonusApprovalRecord
		if next == "approved" {
			approvalID := value.NewID()
			decision, e := s.seal(ctx, binding(a.OrgID, employee, approvalID, approvalID, "bonus_decision", "bonus.decision.v1"), bonusDecisionPayload{Reason: command.DecisionReason})
			if e != nil {
				return BonusResult{}, e
			}
			approval = &BonusApprovalRecord{OrgID: a.OrgID, EmployeeID: employee, ID: approvalID, AwardID: id, AwardVersionID: version, ApproverSubjectID: a.SubjectID, PayloadID: decision.ID, AwardRevision: award.Revision, BasisRevision: basis, BonusRevision: basis + 1, RecordedAt: s.clock()}
			award.ApprovalID = &approvalID
			payloads = append(payloads, decision)
		}
		result := BonusResult{ID: id, Revision: number(award.Revision), BonusRevision: number(basis + 1), State: next}
		write := BonusWrite{Aggregate: BonusAggregateRecord{OrgID: a.OrgID, EmployeeID: employee, Revision: basis + 1}, ExpectedBonusRevision: basis, Award: &award, ExpectedAwardRevision: rev, Approval: approval, Payloads: payloads, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, capability, write)
	}
}

func (s *Service) RecordBonusPayment(ctx context.Context, q Request, employee string, command BonusPaymentCommand) (BonusResult, error) {
	const operation = "OP-BONUS-06"
	if err := s.validateBonusEnabled(); err != nil {
		return BonusResult{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	if err = s.require(a, employee, nil, "bonus.payment.record"); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	basis, err := parseBonusRevision(command.BonusRevision)
	if err != nil || validateBonusMoney(s.Policy, command.Amount, true) != nil || !value.ValidDate(command.PaidDate) || !safeText(command.EvidenceReference, 200, true) || !safeText(command.Reason, 4096, true) || command.Kind != "payment" && command.Kind != "reversal" || !contains(s.Policy.ControlledBonusSources, command.BusinessSource) || !safeText(command.ExternalFactID, 200, true) {
		return BonusResult{}, fault.Invalid
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	active, keyID, err := store.BonusHMACReady(ctx, a.OrgID)
	if err != nil || active != s.BonusHMACActive || keyID == "" || s.BonusHMACKeyIDs[active] != keyID {
		return BonusResult{}, fault.Unavailable
	}
	businessDigest, err := s.bonusBusinessDigest(ctx, a.OrgID, employee, command.BusinessSource, command.ExternalFactID, active)
	if err != nil {
		return BonusResult{}, err
	}
	if existing, ok, e := store.BonusPaymentByDigest(ctx, a.OrgID, employee, keyID, active, businessDigest); e != nil {
		return BonusResult{}, e
	} else if ok {
		var payload bonusPaymentPayload
		if e = s.openBonus(ctx, store, a.OrgID, existing.ID, existing.PayloadID, employee, "bonus_payment", "bonus.payment.v1", &payload); e != nil {
			return BonusResult{}, e
		}
		if !equalBonusCommandPayload(payload, command) {
			return BonusResult{}, fault.Conflict
		}
		return BonusResult{ID: existing.ID, Revision: "1", BonusRevision: number(existing.BasisRevision), State: existing.Kind}, nil
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, employee, command); ok || err != nil {
		return result, err
	} else {
		snapshot, e := store.BonusSnapshot(ctx, a.OrgID, employee)
		if e != nil {
			return BonusResult{}, e
		}
		if snapshot.Aggregate.Revision != basis {
			return BonusResult{}, fault.Conflict
		}
		if command.AwardID != nil {
			award, ok := bonusRecordByID(snapshot.Awards, *command.AwardID, func(v BonusAwardRecord) string { return v.ID })
			if !ok || award.EmployeeID != employee {
				return BonusResult{}, fault.Invalid
			}
		}
		id := value.NewID()
		payloadValue := bonusPaymentPayload{BusinessSource: command.BusinessSource, ExternalFactID: command.ExternalFactID, Kind: command.Kind, PaidDate: command.PaidDate, EvidenceReference: command.EvidenceReference, Reason: command.Reason, Amount: command.Amount, AwardID: command.AwardID, OriginalPaymentID: command.OriginalPaymentID}
		sealed, e := s.seal(ctx, binding(a.OrgID, employee, id, id, "bonus_payment", "bonus.payment.v1"), payloadValue)
		if e != nil {
			return BonusResult{}, e
		}
		record := &BonusPaymentRecord{OrgID: a.OrgID, EmployeeID: employee, ID: id, PayloadID: sealed.ID, Kind: command.Kind, PaidDate: command.PaidDate, BusinessSource: command.BusinessSource, AwardID: command.AwardID, OriginalPaymentID: command.OriginalPaymentID, BusinessKeyID: keyID, BusinessKeyVersion: active, BusinessDigest: businessDigest, BasisRevision: basis + 1, RecordedAt: s.clock()}
		facts := make([]BonusPaymentFact, 0, len(snapshot.Payments)+1)
		for _, p := range snapshot.Payments {
			var old bonusPaymentPayload
			if e = s.openBonus(ctx, store, a.OrgID, p.ID, p.PayloadID, employee, "bonus_payment", "bonus.payment.v1", &old); e != nil {
				return BonusResult{}, e
			}
			facts = append(facts, BonusPaymentFact{ID: p.ID, EmployeeID: employee, Kind: p.Kind, Currency: old.Amount.Currency, Scale: old.Amount.Scale, AmountMinor: old.Amount.AmountMinor, PaidDate: p.PaidDate, AwardID: p.AwardID, OriginalPaymentID: p.OriginalPaymentID})
		}
		facts = append(facts, BonusPaymentFact{ID: id, EmployeeID: employee, Kind: command.Kind, Currency: command.Amount.Currency, Scale: command.Amount.Scale, AmountMinor: command.Amount.AmountMinor, PaidDate: command.PaidDate, AwardID: command.AwardID, OriginalPaymentID: command.OriginalPaymentID})
		awardFacts := make([]BonusAwardFact, 0, len(snapshot.Awards))
		approvedAt := make(map[string]string, len(snapshot.Approvals))
		for _, approval := range snapshot.Approvals {
			approvedAt[approval.AwardID] = approval.RecordedAt.UTC().Format(time.RFC3339Nano)
		}
		for _, award := range snapshot.Awards {
			var old bonusAwardPayload
			if e = s.openBonus(ctx, store, a.OrgID, award.ID, award.PayloadID, employee, "bonus_award", "bonus.award.v1", &old); e != nil {
				return BonusResult{}, e
			}
			awardFacts = append(awardFacts, BonusAwardFact{ID: award.ID, EmployeeID: employee, State: award.State, Currency: old.Award.Amount.Currency, Scale: old.Award.Amount.Scale, AmountMinor: old.Award.Amount.AmountMinor, CorrectsAwardID: award.CorrectsAwardID, ApprovedAt: approvedAt[award.ID]})
		}
		if _, _, e = BuildBonusProjection(awardFacts, facts); e != nil {
			return BonusResult{}, e
		}
		result := BonusResult{ID: id, Revision: "1", BonusRevision: number(basis + 1), State: command.Kind}
		write := BonusWrite{Aggregate: BonusAggregateRecord{OrgID: a.OrgID, EmployeeID: employee, Revision: basis + 1}, ExpectedBonusRevision: basis, Payment: record, Payloads: []Payload{sealed}, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, "bonus.payment.record", write)
	}
}

func (s *Service) AppendCompensationExtension(ctx context.Context, q Request, employee string, command BonusExtensionCommand) (BonusResult, error) {
	const operation = "OP-BONUS-08"
	if err := s.validateBonusEnabled(); err != nil {
		return BonusResult{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return BonusResult{}, err
	}
	if err = s.require(a, employee, nil, "compensation.extension.manage"); err != nil {
		return BonusResult{}, s.denied(ctx, q, a, operation, err)
	}
	basis, err := compRevision(command.CompRevision)
	if err != nil || command.SchemaType != "compensation_memo/v1" || command.SchemaVersion != 1 || ValidateCompensationMemo(command.Payload) != nil {
		return BonusResult{}, fault.Invalid
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusResult{}, err
	}
	if result, digest, ok, err := s.bonusReplay(ctx, store, q, a, operation, employee, command); ok || err != nil {
		return result, err
	} else {
		comp, e := s.Store.CompensationAggregate(ctx, a.OrgID, employee)
		if e != nil {
			return BonusResult{}, e
		}
		if comp.Revision != basis {
			return BonusResult{}, fault.Conflict
		}
		snapshot, e := store.BonusSnapshot(ctx, a.OrgID, employee)
		if e != nil {
			return BonusResult{}, e
		}
		revision := int64(1)
		if command.SupersedesID != nil {
			old, ok := bonusRecordByID(snapshot.Extensions, *command.SupersedesID, func(v BonusExtensionRecord) string { return v.ID })
			if !ok || old.SchemaType != command.SchemaType {
				return BonusResult{}, fault.Invalid
			}
			revision = old.Revision + 1
		}
		id := value.NewID()
		sealed, e := s.seal(ctx, binding(a.OrgID, employee, id, id, "compensation_extension", "compensation_memo/v1"), command.Payload)
		if e != nil {
			return BonusResult{}, e
		}
		record := &BonusExtensionRecord{OrgID: a.OrgID, EmployeeID: employee, ID: id, PayloadID: sealed.ID, SchemaType: command.SchemaType, SchemaVersion: 1, Revision: revision, BasisRevision: basis + 1, SupersedesID: command.SupersedesID, RecordedAt: s.clock()}
		result := BonusResult{ID: id, Revision: number(revision), BonusRevision: number(snapshot.Aggregate.Revision), CompRevision: number(basis + 1), State: "appended"}
		write := BonusWrite{Aggregate: snapshot.Aggregate, ExpectedBonusRevision: snapshot.Aggregate.Revision, ExpectedCompRevision: &basis, Extension: record, Payloads: []Payload{sealed}, Operation: operation, CommandKey: q.Key, CommandDigest: digest, Result: result, Audit: s.audit(q, a, employee, operation, "allowed")}
		return s.commitBonus(ctx, q, a, employee, "compensation.extension.manage", write)
	}
}

func (s *Service) findBonusTarget(ctx context.Context, store BonusStore, a authz.Snapshot, id string) (BonusTargetRecord, string, error) {
	if !value.ValidID(id) {
		return BonusTargetRecord{}, "", fault.Invalid
	}
	finder, ok := store.(interface {
		BonusTarget(context.Context, string, string) (BonusTargetRecord, error)
	})
	if !ok {
		return BonusTargetRecord{}, "", fault.Unavailable
	}
	target, err := finder.BonusTarget(ctx, a.OrgID, id)
	if err != nil {
		return BonusTargetRecord{}, "", err
	}
	return target, target.EmployeeID, nil
}
func (s *Service) findBonusAward(ctx context.Context, store BonusStore, a authz.Snapshot, id string) (BonusAwardRecord, string, error) {
	if !value.ValidID(id) {
		return BonusAwardRecord{}, "", fault.Invalid
	}
	finder, ok := store.(interface {
		BonusAward(context.Context, string, string) (BonusAwardRecord, error)
	})
	if !ok {
		return BonusAwardRecord{}, "", fault.Unavailable
	}
	award, err := finder.BonusAward(ctx, a.OrgID, id)
	if err != nil {
		return BonusAwardRecord{}, "", err
	}
	return award, award.EmployeeID, nil
}
