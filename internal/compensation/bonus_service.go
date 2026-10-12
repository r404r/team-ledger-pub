package compensation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

type bonusTargetPayload struct {
	Target           BonusTargetPayload `json:"target"`
	TransitionReason string             `json:"transition_reason"`
}

type bonusAwardPayload struct {
	Award           BonusAwardPayload `json:"award"`
	TargetID        *string           `json:"target_id"`
	CorrectsAwardID *string           `json:"corrects_award_id"`
}

type bonusDecisionPayload struct {
	Reason string `json:"reason"`
}

type bonusPaymentPayload struct {
	BusinessSource, ExternalFactID, Kind, PaidDate, EvidenceReference, Reason string
	Amount                                                                    BonusMoney
	AwardID, OriginalPaymentID                                                *string
}

func (s *Service) bonusStore() (BonusStore, error) {
	store, ok := s.Store.(BonusStore)
	if !ok {
		return nil, fault.Unavailable
	}
	return store, nil
}

func validateBonusMoney(policy Policy, m BonusMoney, positive bool) error {
	scale, ok := policy.Currencies[m.Currency]
	money, err := value.ParseMoney(m.Currency, m.Scale, m.AmountMinor)
	if !ok || scale != m.Scale || err != nil || positive && money.Minor <= 0 {
		return fault.Invalid
	}
	return nil
}

func validateBonusPeriod(start, end string) error {
	if !value.ValidDate(start) || !value.ValidDate(end) || end < start {
		return fault.Invalid
	}
	return nil
}

func (s *Service) validateBonusEnabled() error {
	if !s.Policy.Enabled || len(s.Policy.ControlledBonusSources) == 0 {
		return fault.Unavailable
	}
	return nil
}

func (s *Service) bonusBusinessDigest(org, employee, source, external string, version int64) ([]byte, error) {
	key := s.BonusHMACKeys[version]
	if !contains(s.Policy.ControlledBonusSources, source) {
		return nil, fault.Unavailable
	}
	return bonusBusinessDigest(key, org, employee, source, external)
}

func framedHMAC(key []byte, domain string, parts ...string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	var size [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		mac.Write(size[:])
		mac.Write([]byte(part))
	}
	return mac.Sum(nil)
}

func (s *Service) bonusCommandDigest(q Request, a authz.Snapshot, operation, target string, command any) ([]byte, error) {
	return s.digest(q, a, operation, target, command)
}

func (s *Service) openBonus(ctx context.Context, reader BonusReader, org, recordID, payloadID, employee, kind, schema string, out any) error {
	payload, err := reader.BonusPayload(ctx, org, payloadID)
	if err != nil {
		return err
	}
	raw, err := s.Cipher.Open(ctx, binding(org, employee, recordID, payload.Envelope.Context.VersionID, kind, schema), payload.Envelope)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return fault.Unavailable
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return fault.Unavailable
	}
	return nil
}

func bonusRecordByID[T any](records []T, id string, identify func(T) string) (T, bool) {
	for _, record := range records {
		if identify(record) == id {
			return record, true
		}
	}
	var zero T
	return zero, false
}

func (s *Service) releaseBonus(ctx context.Context, store BonusStore, q Request, before authz.Snapshot, employee string, basis readBasis, bonusRevision int64) error {
	return store.WithBonusTx(ctx, before.OrgID, func(tx BonusTx) error {
		if err := tx.LockSubjects(ctx, before.OrgID, []string{before.SubjectID}); err != nil {
			return err
		}
		if err := tx.LockBonusEmployee(ctx, before.OrgID, employee); err != nil {
			return err
		}
		if err := tx.LockCompensationEmployee(ctx, before.OrgID, employee); err != nil {
			return err
		}
		current, err := tx.Security(ctx, q.TokenHash, before.OrgID, employee)
		if err != nil {
			return err
		}
		if !current.Valid(s.clock()) || current.SubjectID != before.SubjectID || current.AuthEpoch != before.AuthEpoch || current.SubjectEpoch != before.SubjectEpoch || current.SessionEpoch != before.SessionEpoch || current.Timezone != before.Timezone || !s.allows(current, "compensation.read", employee) {
			return fault.Forbidden
		}
		day, err := businessDay(current, s.clock())
		if err != nil {
			return err
		}
		graph, err := tx.GraphState(ctx, before.OrgID)
		if err != nil {
			return err
		}
		comp, err := tx.CompensationAggregate(ctx, before.OrgID, employee)
		if err != nil {
			return err
		}
		bonus, err := tx.BonusAggregate(ctx, before.OrgID, employee)
		if err != nil {
			return err
		}
		if day != basis.Day || graph.Revision != basis.Graph || comp.Revision != basis.Aggregate || bonus.Revision != bonusRevision {
			return fault.Conflict
		}
		return tx.Audit(ctx, s.audit(q, current, employee, "OP-BONUS-01", "allowed"))
	})
}

func (s *Service) Bonuses(ctx context.Context, q Request, employee string, query BonusQuery) (BonusView, error) {
	if query.Limit < 1 || query.Limit > 100 || query.Cursor != "" && query.RecordKind == "" {
		return BonusView{}, fault.Invalid
	}
	if query.RecordKind != "" && query.RecordKind != "targets" && query.RecordKind != "awards" && query.RecordKind != "payments" && query.RecordKind != "extensions" {
		return BonusView{}, fault.Invalid
	}
	if err := s.validateBonusEnabled(); err != nil {
		return BonusView{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return BonusView{}, err
	}
	store, err := s.bonusStore()
	if err != nil {
		return BonusView{}, err
	}
	basis, err := s.basis(ctx, a, employee)
	if err != nil {
		return BonusView{}, err
	}
	aggregate, err := store.BonusAggregate(ctx, a.OrgID, employee)
	if err != nil {
		return BonusView{}, err
	}
	cursorBinding, err := s.bonusCursorBinding(a, employee, query, aggregate.Revision, q.TokenHash)
	if err != nil {
		return BonusView{}, err
	}
	after := ""
	if query.Cursor != "" {
		after, err = s.parseCursor(query.Cursor, cursorBinding)
		if err != nil {
			return BonusView{}, err
		}
	}
	snapshot := BonusSnapshot{Aggregate: aggregate, Targets: []BonusTargetRecord{}, Awards: []BonusAwardRecord{}, Approvals: []BonusApprovalRecord{}, Payments: []BonusPaymentRecord{}, Extensions: []BonusExtensionRecord{}}
	more := false
	if query.RecordKind == "" {
		for _, kind := range []string{"targets", "awards", "payments", "extensions"} {
			page, pageErr := store.BonusSnapshotPage(ctx, a.OrgID, employee, BonusPageQuery{Kind: kind, PeriodStart: query.PeriodStart, PeriodEnd: query.PeriodEnd, RecordID: query.RecordID, Limit: query.Limit})
			if pageErr != nil {
				err = pageErr
				break
			}
			if page.More {
				err = fault.Invalid
				break
			}
			if page.Snapshot.Aggregate.Revision != aggregate.Revision {
				err = fault.Conflict
				break
			}
			snapshot.Targets = append(snapshot.Targets, page.Snapshot.Targets...)
			snapshot.Awards = append(snapshot.Awards, page.Snapshot.Awards...)
			snapshot.Approvals = append(snapshot.Approvals, page.Snapshot.Approvals...)
			snapshot.Payments = append(snapshot.Payments, page.Snapshot.Payments...)
			snapshot.Extensions = append(snapshot.Extensions, page.Snapshot.Extensions...)
		}
	} else {
		var page BonusSnapshotPage
		page, err = store.BonusSnapshotPage(ctx, a.OrgID, employee, BonusPageQuery{Kind: query.RecordKind, PeriodStart: query.PeriodStart, PeriodEnd: query.PeriodEnd, RecordID: query.RecordID, After: after, Limit: query.Limit})
		snapshot, more = page.Snapshot, page.More
	}
	if err != nil {
		return BonusView{}, err
	}
	view := BonusView{EmployeeID: employee, BonusRevision: number(snapshot.Aggregate.Revision), CompRevision: number(basis.Aggregate), AuthorizationUntil: s.authorizationUntil(a), Targets: []BonusTargetView{}, Awards: []BonusAwardView{}, Payments: []BonusPaymentView{}, Balances: []BonusBalance{}, Anomalies: []BonusAnomaly{}, Extensions: []BonusExtensionView{}, Permissions: []Permission{}}
	for _, capability := range []string{"compensation.read", "bonus.target.manage", "bonus.propose", "bonus.approve", "bonus.payment.record", "compensation.extension.manage"} {
		if s.allows(a, capability, employee) {
			view.Permissions = append(view.Permissions, Permission{Capability: capability, Category: "financial"})
		}
	}
	// A selected record kind is already filtered and keyset-paged in SQL.
	approvalByAward := make(map[string]BonusApprovalRecord, len(snapshot.Approvals))
	for _, approval := range snapshot.Approvals {
		approvalByAward[approval.AwardID] = approval
	}
	awardFacts := make([]BonusAwardFact, 0, len(snapshot.Awards))
	for _, target := range snapshot.Targets {
		if query.RecordKind != "" && query.RecordKind != "targets" || query.RecordID != "" && query.RecordID != target.ID || query.PeriodStart != "" && target.PeriodEnd < query.PeriodStart || query.PeriodEnd != "" && target.PeriodStart > query.PeriodEnd {
			continue
		}
		if !s.allows(a, "compensation.read", employee) {
			return BonusView{}, fault.NotFound
		}
		var payload bonusTargetPayload
		if err = s.openBonus(ctx, store, a.OrgID, target.ID, target.PayloadID, employee, "bonus_target", "bonus.target.v1", &payload); err != nil {
			return BonusView{}, err
		}
		view.Targets = append(view.Targets, BonusTargetView{ID: target.ID, EmployeeID: employee, PeriodStart: target.PeriodStart, PeriodEnd: target.PeriodEnd, State: target.State, Revision: number(target.Revision), BonusRevision: number(target.BasisRevision), RecordedAt: target.RecordedAt.UTC().Format(time.RFC3339Nano), Target: payload.Target})
	}
	for _, award := range snapshot.Awards {
		if !s.allows(a, "compensation.read", employee) {
			return BonusView{}, fault.NotFound
		}
		var payload bonusAwardPayload
		if err = s.openBonus(ctx, store, a.OrgID, award.ID, award.PayloadID, employee, "bonus_award", "bonus.award.v1", &payload); err != nil {
			return BonusView{}, err
		}
		approval := approvalByAward[award.ID]
		decision := ""
		approvedAt := ""
		if approval.ID != "" {
			if !s.allows(a, "compensation.read", employee) {
				return BonusView{}, fault.NotFound
			}
			var d bonusDecisionPayload
			if err = s.openBonus(ctx, store, a.OrgID, approval.ID, approval.PayloadID, employee, "bonus_decision", "bonus.decision.v1", &d); err != nil {
				return BonusView{}, err
			}
			decision, approvedAt = d.Reason, approval.RecordedAt.UTC().Format(time.RFC3339Nano)
		}
		awardFacts = append(awardFacts, BonusAwardFact{ID: award.ID, EmployeeID: employee, State: award.State, Currency: payload.Award.Amount.Currency, Scale: payload.Award.Amount.Scale, AmountMinor: payload.Award.Amount.AmountMinor, CorrectsAwardID: award.CorrectsAwardID, ApprovedAt: approvedAt})
		if query.RecordKind != "" && query.RecordKind != "awards" || query.RecordID != "" && query.RecordID != award.ID || query.PeriodStart != "" && award.PeriodEnd < query.PeriodStart || query.PeriodEnd != "" && award.PeriodStart > query.PeriodEnd {
			continue
		}
		view.Awards = append(view.Awards, BonusAwardView{ID: award.ID, EmployeeID: employee, State: award.State, Revision: number(award.Revision), BonusRevision: number(award.BasisRevision), AuthorSubjectID: award.AuthorSubjectID, RecordedAt: award.RecordedAt.UTC().Format(time.RFC3339Nano), TargetID: award.TargetID, CorrectsAwardID: award.CorrectsAwardID, ApprovalID: award.ApprovalID, Award: payload.Award, DecisionReason: decision})
	}
	paymentFacts := make([]BonusPaymentFact, 0, len(snapshot.Payments))
	paymentViews := make(map[string]int, len(snapshot.Payments))
	for _, payment := range snapshot.Payments {
		if !s.allows(a, "compensation.read", employee) {
			return BonusView{}, fault.NotFound
		}
		var payload bonusPaymentPayload
		if err = s.openBonus(ctx, store, a.OrgID, payment.ID, payment.PayloadID, employee, "bonus_payment", "bonus.payment.v1", &payload); err != nil {
			return BonusView{}, err
		}
		paymentFacts = append(paymentFacts, BonusPaymentFact{ID: payment.ID, EmployeeID: employee, Kind: payment.Kind, Currency: payload.Amount.Currency, Scale: payload.Amount.Scale, AmountMinor: payload.Amount.AmountMinor, PaidDate: payment.PaidDate, AwardID: payment.AwardID, OriginalPaymentID: payment.OriginalPaymentID})
		if query.RecordKind != "" && query.RecordKind != "payments" || query.RecordID != "" && query.RecordID != payment.ID || query.PeriodStart != "" && payment.PaidDate < query.PeriodStart || query.PeriodEnd != "" && payment.PaidDate > query.PeriodEnd {
			continue
		}
		v := BonusPaymentView{ID: payment.ID, EmployeeID: employee, Kind: payment.Kind, PaidDate: payment.PaidDate, RecordedAt: payment.RecordedAt.UTC().Format(time.RFC3339Nano), AwardID: payment.AwardID, OriginalPaymentID: payment.OriginalPaymentID, Amount: payload.Amount, EvidenceReference: payload.EvidenceReference, Reason: payload.Reason, Anomalies: []string{}}
		view.Payments = append(view.Payments, v)
		paymentViews[payment.ID] = len(view.Payments) - 1
	}
	if query.RecordKind == "" {
		view.Balances, view.Anomalies, err = BuildBonusProjection(awardFacts, paymentFacts)
		if err != nil {
			return BonusView{}, fault.Unavailable
		}
		for _, anomaly := range view.Anomalies {
			if index, ok := paymentViews[anomaly.PaymentID]; ok {
				view.Payments[index].Anomalies = append(view.Payments[index].Anomalies, anomaly.Kind)
			}
		}
	}
	for _, extension := range snapshot.Extensions {
		if query.RecordKind != "" && query.RecordKind != "extensions" || query.RecordID != "" && query.RecordID != extension.ID {
			continue
		}
		if !s.allows(a, "compensation.read", employee) {
			return BonusView{}, fault.NotFound
		}
		var payload CompensationMemo
		if err = s.openBonus(ctx, store, a.OrgID, extension.ID, extension.PayloadID, employee, "compensation_extension", "compensation_memo/v1", &payload); err != nil {
			return BonusView{}, err
		}
		view.Extensions = append(view.Extensions, BonusExtensionView{ID: extension.ID, EmployeeID: employee, SchemaType: extension.SchemaType, SchemaVersion: int(extension.SchemaVersion), Revision: number(extension.Revision), CompRevision: number(extension.BasisRevision), RecordedAt: extension.RecordedAt.UTC().Format(time.RFC3339Nano), SupersedesID: extension.SupersedesID, Payload: payload})
	}
	sort.Slice(view.Targets, func(i, j int) bool {
		return view.Targets[i].RecordedAt < view.Targets[j].RecordedAt || view.Targets[i].RecordedAt == view.Targets[j].RecordedAt && view.Targets[i].ID < view.Targets[j].ID
	})
	sort.Slice(view.Awards, func(i, j int) bool {
		return view.Awards[i].RecordedAt < view.Awards[j].RecordedAt || view.Awards[i].RecordedAt == view.Awards[j].RecordedAt && view.Awards[i].ID < view.Awards[j].ID
	})
	sort.Slice(view.Payments, func(i, j int) bool {
		return view.Payments[i].PaidDate < view.Payments[j].PaidDate || view.Payments[i].PaidDate == view.Payments[j].PaidDate && view.Payments[i].ID < view.Payments[j].ID
	})
	sort.Slice(view.Extensions, func(i, j int) bool {
		return view.Extensions[i].RecordedAt < view.Extensions[j].RecordedAt || view.Extensions[i].RecordedAt == view.Extensions[j].RecordedAt && view.Extensions[i].ID < view.Extensions[j].ID
	})
	next := ""
	if more {
		switch query.RecordKind {
		case "targets":
			last := view.Targets[len(view.Targets)-1]
			next = last.RecordedAt + "|" + last.ID
		case "awards":
			last := view.Awards[len(view.Awards)-1]
			next = last.RecordedAt + "|" + last.ID
		case "payments":
			last := view.Payments[len(view.Payments)-1]
			next = last.PaidDate + "T00:00:00Z|" + last.ID
		case "extensions":
			last := view.Extensions[len(view.Extensions)-1]
			next = last.RecordedAt + "|" + last.ID
		}
	}
	if next != "" {
		view.NextCursor, err = s.signCursor(cursorBinding, next)
		if err != nil {
			return BonusView{}, err
		}
	}
	if err = s.releaseBonus(ctx, store, q, a, employee, basis, snapshot.Aggregate.Revision); err != nil {
		return BonusView{}, err
	}
	return view, nil
}

func equalBonusCommandPayload(payload bonusPaymentPayload, command BonusPaymentCommand) bool {
	left, _ := json.Marshal(payload)
	right, _ := json.Marshal(bonusPaymentPayload{BusinessSource: command.BusinessSource, ExternalFactID: command.ExternalFactID, Kind: command.Kind, PaidDate: command.PaidDate, EvidenceReference: command.EvidenceReference, Reason: command.Reason, Amount: command.Amount, AwardID: command.AwardID, OriginalPaymentID: command.OriginalPaymentID})
	return hmac.Equal(left, right)
}

func parseBonusRevision(v string) (int64, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != v {
		return 0, fault.Invalid
	}
	return n, nil
}

func bonusReceiptMatch(result BonusResult, found []byte, expected []byte) (BonusResult, error) {
	if !hmac.Equal(found, expected) {
		return BonusResult{}, fault.Conflict
	}
	return result, nil
}
