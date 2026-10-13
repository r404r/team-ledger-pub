package compensation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func (s *Service) batchSession(ctx context.Context, req Request, org string, write bool) (authz.Snapshot, error) {
	if s == nil || s.Batches == nil || s.Store == nil || !value.ValidID(org) {
		return authz.Snapshot{}, fault.Invalid
	}
	a, err := s.session(ctx, s.Store, req, org, "")
	if err != nil {
		return authz.Snapshot{}, err
	}
	now := s.clock()
	if !a.Allows("compensation.read", "financial", "", purpose, now) {
		return authz.Snapshot{}, s.denied(ctx, req, a, "OP-COMP-06", fault.NotFound)
	}
	if write && !a.Allows("compensation.propose", "financial", "", purpose, now) {
		return authz.Snapshot{}, s.denied(ctx, req, a, "OP-COMP-07", fault.Forbidden)
	}
	return a, nil
}

func (s *Service) financialDigest(domain string, raw []byte) ([]byte, error) {
	if len(s.DigestKey) < 32 || domain == "" {
		return nil, fault.Unavailable
	}
	mac := hmac.New(sha256.New, s.DigestKey)
	_, _ = mac.Write([]byte("teamledger-financial-digest\x00" + domain + "\x00"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil), nil
}

func (s *Service) batchCommandReceipt(ctx context.Context, org, subject, operation, key, requestID string, command any) (BatchCommandReceipt, *BatchRecord, error) {
	if !value.ValidID(key) || !value.ValidID(requestID) {
		return BatchCommandReceipt{}, nil, fault.Invalid
	}
	raw, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Command   any    `json:"command"`
	}{Operation: operation, Command: command})
	if err != nil {
		return BatchCommandReceipt{}, nil, fault.Invalid
	}
	digest, err := s.financialDigest("batch-command:"+operation, raw)
	clear(raw)
	if err != nil {
		return BatchCommandReceipt{}, nil, err
	}
	receipt := BatchCommandReceipt{SubjectID: subject, Operation: operation, Key: key, RequestID: requestID, Digest: append([]byte(nil), digest...), RecordedAt: s.clock()}
	existing, found, err := s.Batches.AdjustmentBatchReceipt(ctx, org, subject, operation, key)
	if err != nil {
		return BatchCommandReceipt{}, nil, err
	}
	if !found {
		return receipt, nil, nil
	}
	if !hmac.Equal(existing.Digest, digest) {
		return BatchCommandReceipt{}, nil, fault.Conflict
	}
	batch, err := s.Batches.AdjustmentBatch(ctx, org, existing.BatchID)
	return receipt, &batch, err
}

func (s *Service) CreateAdjustmentBatch(ctx context.Context, req Request, org string, command CreateBatchCommand) (BatchView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return BatchView{}, err
	}
	if ValidateCreateBatch(command) != nil {
		return BatchView{}, fault.Invalid
	}
	command.SpecialReasons = s.Policy.SpecialReasonCatalog
	receipt, replay, err := s.batchCommandReceipt(ctx, org, snapshot.SubjectID, "OP-COMP-07", req.Key, req.RequestID, command)
	if err != nil {
		return BatchView{}, err
	}
	if replay != nil {
		return s.batchView(ctx, req, snapshot, *replay)
	}
	record, err := s.Batches.CreateAdjustmentBatch(ctx, org, snapshot.SubjectID, value.NewID(), value.NewID(), command, receipt, s.clock())
	if err != nil {
		return BatchView{}, err
	}
	return s.batchView(ctx, req, snapshot, record)
}

func (s *Service) AdjustmentBatch(ctx context.Context, req Request, org, id string) (BatchView, error) {
	snapshot, err := s.batchSession(ctx, req, org, false)
	if err != nil {
		return BatchView{}, err
	}
	if !value.ValidID(id) {
		return BatchView{}, fault.Invalid
	}
	record, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return BatchView{}, err
	}
	return s.batchView(ctx, req, snapshot, record)
}

func (s *Service) AdjustmentBatches(ctx context.Context, req Request, org string, year int, typ string, limit int) ([]BatchView, error) {
	snapshot, err := s.batchSession(ctx, req, org, false)
	if err != nil {
		return nil, err
	}
	if year != 0 && (year < 2000 || year > 9999) || typ != "" && typ != BatchNormal && typ != BatchSpecial {
		return nil, fault.Invalid
	}
	records, err := s.Batches.AdjustmentBatches(ctx, org, year, typ, limit)
	if err != nil {
		return nil, err
	}
	views := make([]BatchView, 0, len(records))
	for _, record := range records {
		view, err := s.batchView(ctx, req, snapshot, record)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Service) ReplaceAdjustmentBatchLines(ctx context.Context, req Request, org, id string, command ReplaceBatchLinesCommand) (BatchView, error) {
	return s.replaceAdjustmentBatchLines(ctx, req, org, id, command, "OP-COMP-09")
}

func (s *Service) replaceAdjustmentBatchLines(ctx context.Context, req Request, org, id string, command ReplaceBatchLinesCommand, operation string) (BatchView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return BatchView{}, err
	}
	expected, err := revision(command.Revision)
	if err != nil || !value.ValidID(id) {
		return BatchView{}, fault.Invalid
	}
	receipt, replay, err := s.batchCommandReceipt(ctx, org, snapshot.SubjectID, operation, req.Key, req.RequestID, struct {
		BatchID string                   `json:"batch_id"`
		Command ReplaceBatchLinesCommand `json:"command"`
	}{BatchID: id, Command: command})
	if err != nil {
		return BatchView{}, err
	}
	if replay != nil {
		return s.batchView(ctx, req, snapshot, *replay)
	}
	batch, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return BatchView{}, err
	}
	if batch.Revision != expected || batch.State != "draft" && batch.State != "activation_conflict" {
		return BatchView{}, fault.Conflict
	}
	if command.CandidateID != "" {
		if len(command.Lines) != 0 || !value.ValidID(command.CandidateID) {
			return BatchView{}, fault.Invalid
		}
		candidate, err := s.Batches.AdjustmentImportCandidate(ctx, org, command.CandidateID)
		if err != nil {
			return BatchView{}, err
		}
		if candidate.BatchID != batch.ID || candidate.SubjectID != snapshot.SubjectID || candidate.BaseRevision != batch.Revision || candidate.State != "valid" || !s.clock().Before(candidate.ExpiresAt) {
			return BatchView{}, fault.Conflict
		}
		raw, err := s.Cipher.Open(ctx, batchImportBinding(org, candidate.ID), candidate.Envelope)
		if err != nil {
			return BatchView{}, fault.Unavailable
		}
		var payload batchImportPayload
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&payload)
		clear(raw)
		if err != nil || len(payload.Errors) != 0 {
			return BatchView{}, fault.Unavailable
		}
		command.Lines = payload.Lines
	}
	reasons := map[string]bool(nil)
	if batch.AdjustmentType == BatchSpecial {
		reasons = make(map[string]bool, len(s.Policy.SpecialReasonCatalog))
		for code := range s.Policy.SpecialReasonCatalog {
			reasons[code] = true
		}
	}
	normalized, _, err := ValidateBatchLines(batch.AdjustmentType, int(batch.CycleYear), batch.DefaultEffectiveDate, command.Lines, reasons)
	if err != nil {
		return BatchView{}, fault.Invalid
	}
	payloads := make([]BatchPayloadRecord, 0, len(normalized))
	lines := make([]BatchLineRecord, 0, len(normalized))
	for i := range normalized {
		line := normalized[i]
		if err := s.require(snapshot, line.EmployeeID, nil, "compensation.propose"); err != nil {
			return BatchView{}, err
		}
		employee, err := s.Store.Employee(ctx, line.EmployeeID)
		if err != nil || employee.OrgID != org {
			return BatchView{}, fault.Invalid
		}
		basis, err := s.resolveBatchBasis(ctx, batch, line.BatchLineCommand)
		if err != nil {
			return BatchView{}, err
		}
		line.Basis = basis
		id := value.NewID()
		binding := batchLineBinding(org, line.EmployeeID, id)
		raw, err := json.Marshal(line.BatchLineCommand)
		if err != nil || len(raw) > 16384 {
			clear(raw)
			return BatchView{}, fault.Invalid
		}
		envelope, err := s.Cipher.Seal(ctx, binding, raw)
		clear(raw)
		if err != nil {
			return BatchView{}, fault.Unavailable
		}
		payloads = append(payloads, BatchPayloadRecord{OrgID: org, ID: id, BatchID: batch.ID, BatchRevision: batch.Revision + 1, EmployeeID: line.EmployeeID, Envelope: envelope, CreatedAt: s.clock()})
		lines = append(lines, BatchLineRecord{OrgID: org, BatchID: batch.ID, BatchRevision: batch.Revision + 1, ID: id, EmployeeID: line.EmployeeID, PayloadID: id, Result: line.Result, Ordinal: int64(i)})
	}
	updated, err := s.Batches.ReplaceAdjustmentBatchLines(ctx, batch, payloads, lines, command.CandidateID, receipt)
	if err != nil {
		return BatchView{}, err
	}
	return s.batchView(ctx, req, snapshot, updated)
}

type batchImportPayload struct {
	Lines  []BatchLineCommand `json:"lines"`
	Errors []string           `json:"errors"`
}

func (s *Service) ImportAdjustmentWorkbook(ctx context.Context, req Request, org, id, expectedRevision string, raw []byte) (ImportCandidateView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return ImportCandidateView{}, err
	}
	baseRevision, err := revision(expectedRevision)
	if err != nil || !value.ValidID(id) || !value.ValidID(req.Key) {
		return ImportCandidateView{}, fault.Invalid
	}
	batch, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return ImportCandidateView{}, err
	}
	if batch.Revision != baseRevision || batch.State != "draft" && batch.State != "activation_conflict" {
		return ImportCandidateView{}, fault.Conflict
	}
	digest, err := s.financialDigest("batch-import", raw)
	if err != nil {
		return ImportCandidateView{}, err
	}
	if previous, previousErr := s.Batches.AdjustmentImportCandidate(ctx, org, req.Key); previousErr == nil {
		if previous.BatchID != id || previous.SubjectID != snapshot.SubjectID || previous.BaseRevision != baseRevision || !hmac.Equal(previous.Digest, digest) {
			return ImportCandidateView{}, fault.Conflict
		}
		return s.importCandidateView(ctx, req, snapshot, previous)
	} else if !errors.Is(previousErr, fault.NotFound) {
		return ImportCandidateView{}, previousErr
	}
	lines, parseErr := ParseAdjustmentWorkbook(raw, batch.AdjustmentType)
	if parseErr == nil {
		reasons := map[string]bool(nil)
		if batch.AdjustmentType == BatchSpecial {
			reasons = make(map[string]bool, len(s.Policy.SpecialReasonCatalog))
			for code := range s.Policy.SpecialReasonCatalog {
				reasons[code] = true
			}
		}
		normalized, _, validationErr := ValidateBatchLines(batch.AdjustmentType, int(batch.CycleYear), batch.DefaultEffectiveDate, lines, reasons)
		parseErr = validationErr
		if parseErr == nil {
			lines = make([]BatchLineCommand, 0, len(normalized))
			for _, line := range normalized {
				lines = append(lines, line.BatchLineCommand)
			}
		}
	}
	payload := batchImportPayload{Lines: lines, Errors: []string{}}
	state := "valid"
	if parseErr != nil {
		var safetyError *WorkbookSafetyError
		if errors.As(parseErr, &safetyError) {
			return ImportCandidateView{}, fault.Invalid
		}
		payload.Lines = []BatchLineCommand{}
		payload.Errors = []string{parseErr.Error()}
		state = "invalid"
	}
	plain, err := json.Marshal(payload)
	if err != nil || len(plain) > 1<<20 {
		clear(plain)
		return ImportCandidateView{}, fault.Invalid
	}
	envelope, err := s.Cipher.Seal(ctx, batchImportBinding(org, req.Key), plain)
	clear(plain)
	if err != nil {
		return ImportCandidateView{}, fault.Unavailable
	}
	now := s.clock()
	candidate := ImportCandidateRecord{OrgID: org, ID: req.Key, BatchID: id, SubjectID: snapshot.SubjectID, State: state, BaseRevision: baseRevision, LineCount: int64(len(lines)), Digest: append([]byte(nil), digest...), Envelope: envelope, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	receipt := BatchCommandReceipt{SubjectID: snapshot.SubjectID, Operation: "OP-COMP-08", Key: req.Key, RequestID: req.RequestID, Digest: append([]byte(nil), digest...), BatchID: id, ResultRevision: baseRevision, RecordedAt: now}
	candidate, err = s.Batches.CreateAdjustmentImportCandidate(ctx, candidate, receipt)
	if err != nil {
		return ImportCandidateView{}, err
	}
	return s.importCandidateView(ctx, req, snapshot, candidate)
}

func (s *Service) TransitionAdjustmentBatch(ctx context.Context, req Request, org, id string, command BatchTransitionCommand) (BatchView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return BatchView{}, err
	}
	expected, err := revision(command.Revision)
	if err != nil || !value.ValidID(id) || command.Action != "submit" && command.Action != "withdraw" {
		return BatchView{}, fault.Invalid
	}
	operation := "OP-COMP-10"
	receipt, replay, err := s.batchCommandReceipt(ctx, org, snapshot.SubjectID, operation, req.Key, req.RequestID, struct {
		BatchID string                 `json:"batch_id"`
		Command BatchTransitionCommand `json:"command"`
	}{BatchID: id, Command: command})
	if err != nil {
		return BatchView{}, err
	}
	if replay != nil {
		return s.batchView(ctx, req, snapshot, *replay)
	}
	batch, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return BatchView{}, err
	}
	if batch.Revision != expected || batch.State != "draft" && !(command.Action == "submit" && batch.State == "activation_blocked") {
		return BatchView{}, fault.Conflict
	}
	lines, err := s.Batches.AdjustmentBatchLines(ctx, org, id, batch.Revision)
	if err != nil || command.Action == "submit" && len(lines) == 0 {
		return BatchView{}, fault.Invalid
	}
	digest, err := s.batchManifestDigest(ctx, batch, lines)
	if err != nil {
		return BatchView{}, err
	}
	if command.Action == "submit" && command.ManifestDigest != digest {
		return BatchView{}, fault.Conflict
	}
	if command.Action == "withdraw" {
		updated, err := s.Batches.TransitionAdjustmentBatch(ctx, batch, command.Action, digest, snapshot.SubjectID, receipt, s.clock())
		if err != nil {
			return BatchView{}, err
		}
		return s.batchView(ctx, req, snapshot, updated)
	}
	if err = s.activateAdjustmentBatch(ctx, req, snapshot, batch, lines, digest, receipt); err != nil {
		var activationFault *fault.Fault
		if errors.As(err, &activationFault) && (activationFault == fault.Conflict || activationFault.Status == 503) {
			state := "activation_blocked"
			if activationFault == fault.Conflict {
				state = "activation_conflict"
			}
			if markErr := s.Batches.MarkAdjustmentBatchActivationFailure(ctx, batch, state, batch.ActivationSubjectID, req.RequestID, s.clock()); markErr != nil {
				return BatchView{}, markErr
			}
		}
		return BatchView{}, err
	}
	updated, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return BatchView{}, err
	}
	return s.batchView(ctx, req, snapshot, updated)
}

type adjustmentActivationTx interface {
	Tx
	FinalizeAdjustmentBatch(context.Context, string, string, int64, string, string, BatchCommandReceipt, time.Time) error
	LinkAdjustmentBatchEvents(context.Context, string, string, string, []EventRecord, bool) error
	ValidateAdjustmentBatchCorrectionRoot(context.Context, string, string, string, []CorrectionMember) error
	LockSalaryRangeBasis(context.Context, string, string, int64, string) error
	RecordAdjustmentBatchCorrection(context.Context, BatchRecord, string, string, string, BatchCommandReceipt, time.Time) (BatchCorrectionRecord, error)
}

func (s *Service) revalidateBatchAuthorization(ctx context.Context, tx Tx, req Request, initial authz.Snapshot, employees []string) (authz.Snapshot, error) {
	current, err := s.session(ctx, tx, req, initial.OrgID, "")
	if err != nil {
		return current, err
	}
	if current.OrgID != initial.OrgID || current.SubjectID != initial.SubjectID || current.AuthEpoch != initial.AuthEpoch || current.SubjectEpoch != initial.SubjectEpoch || current.SessionEpoch != initial.SessionEpoch || current.Timezone != initial.Timezone {
		return current, fault.Forbidden
	}
	now := s.clock()
	if !current.Allows("compensation.read", "financial", "", purpose, now) || !current.Allows("compensation.propose", "financial", "", purpose, now) {
		return current, fault.Forbidden
	}
	for _, employee := range employees {
		if err = s.require(current, employee, nil, "compensation.propose"); err != nil {
			return current, err
		}
	}
	return current, nil
}

func (s *Service) activateAdjustmentBatch(ctx context.Context, req Request, snapshot authz.Snapshot, batch BatchRecord, lines []BatchLineRecord, digest string, receipt BatchCommandReceipt) error {
	type item struct {
		record  BatchLineRecord
		command BatchLineCommand
	}
	items := make([]item, 0, len(lines))
	employees := make([]string, 0, len(lines))
	for _, line := range lines {
		if err := s.require(snapshot, line.EmployeeID, nil, "compensation.propose"); err != nil {
			return err
		}
		payload, err := s.Batches.AdjustmentBatchPayload(ctx, batch.OrgID, line.PayloadID)
		if err != nil {
			return err
		}
		raw, err := s.Cipher.Open(ctx, batchLineBinding(batch.OrgID, line.EmployeeID, line.PayloadID), payload.Envelope)
		if err != nil {
			return fault.Unavailable
		}
		var command BatchLineCommand
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&command)
		clear(raw)
		if err != nil {
			return fault.Unavailable
		}
		items = append(items, item{record: line, command: command})
		currentBasis, err := s.resolveBatchBasis(ctx, batch, command)
		if err != nil {
			return err
		}
		if currentBasis != command.Basis {
			return fault.Conflict
		}
		employees = append(employees, line.EmployeeID)
	}
	sort.Strings(employees)
	now := s.clock()
	return s.Store.WithCompensationTx(ctx, batch.OrgID, func(tx Tx) error {
		activation, ok := tx.(adjustmentActivationTx)
		if !ok {
			return fault.Unavailable
		}
		if err := tx.LockSubjects(ctx, batch.OrgID, []string{snapshot.SubjectID, batch.ActivationSubjectID}); err != nil {
			return err
		}
		for _, employee := range employees {
			if err := tx.LockCompensationEmployee(ctx, batch.OrgID, employee); err != nil {
				return err
			}
		}
		current, err := s.revalidateBatchAuthorization(ctx, tx, req, snapshot, employees)
		if err != nil {
			return err
		}
		for _, entry := range items {
			rangeRevision, err := strconv.ParseInt(entry.command.Basis.SalaryRangeRevision, 10, 64)
			if err != nil || rangeRevision < 1 {
				return fault.Conflict
			}
			effective := entry.command.EffectiveDate
			if batch.AdjustmentType == BatchSpecial {
				effective = entry.command.EffectiveMonth + "-01"
			}
			if err := activation.LockSalaryRangeBasis(ctx, batch.OrgID, entry.command.Basis.SalaryRangeID, rangeRevision, effective); err != nil {
				return err
			}
		}
		for _, entry := range items {
			currentBasis, err := s.resolveBatchBasis(ctx, batch, entry.command)
			if err != nil {
				return err
			}
			if currentBasis != entry.command.Basis {
				return fault.Conflict
			}
		}
		for _, entry := range items {
			if err := s.activateAdjustmentLine(ctx, activation, current, batch, entry.command, now); err != nil {
				return err
			}
		}
		return activation.FinalizeAdjustmentBatch(ctx, batch.OrgID, batch.ID, batch.Revision, digest, batch.ActivationSubjectID, receipt, now)
	})
}

func (s *Service) activateAdjustmentLine(ctx context.Context, tx adjustmentActivationTx, snapshot authz.Snapshot, batch BatchRecord, line BatchLineCommand, now time.Time) error {
	serviceSnapshot := snapshot
	serviceSnapshot.SubjectID = batch.ActivationSubjectID
	effective := line.EffectiveDate
	if batch.AdjustmentType == BatchSpecial {
		effective = line.EffectiveMonth + "-01"
	}
	schedule, err := tx.CompensationSchedule(ctx, batch.OrgID, line.EmployeeID, CurrentQuery{AsOf: effective, FutureLimit: 100})
	if err != nil {
		return err
	}
	var beforeID *string
	var before Terms
	if len(schedule) > 0 && schedule[0].EffectiveDate <= effective && (schedule[0].ValidTo == nil || effective < *schedule[0].ValidTo) {
		beforeID = new(schedule[0].TermID)
		term, err := tx.CompensationTerm(ctx, batch.OrgID, schedule[0].TermID)
		if err != nil {
			return err
		}
		if err = s.open(ctx, tx, batch.OrgID, term.PayloadID, binding(batch.OrgID, line.EmployeeID, term.ID, term.ID, "compensation_terms", "compensation.terms.v1"), &before); err != nil {
			return err
		}
	}
	if len(schedule) > 1 {
		return fault.Conflict
	}
	if before.AmountMinor == nil {
		if line.SalaryBefore != "0" {
			return fault.Conflict
		}
	} else if before.Currency != line.Currency || before.Scale != 0 || *before.AmountMinor != line.SalaryBefore || before.Unit != "month" || before.PaymentFrequency != "monthly" || before.TaxBasis != "gross" {
		return fault.Conflict
	}
	increase, err := ParseMoney(line.IncreaseAmount)
	if err != nil {
		return fault.Invalid
	}
	if increase == 0 {
		return nil
	}
	aggregate, err := tx.CompensationAggregate(ctx, batch.OrgID, line.EmployeeID)
	if err != nil {
		return err
	}
	afterAmount := line.SalaryAfter
	after := &Terms{Currency: line.Currency, Scale: 0, AmountMinor: &afterAmount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []Component{}}
	kind := "initial"
	if beforeID != nil {
		kind = "adjustment"
	}
	command := ProposalCommand{Kind: kind, EffectiveDate: effective, CompRevision: number(aggregate.Revision), BeforeTermID: beforeID, After: after, Reason: batch.BusinessCode, Members: []CorrectionMember{}}
	proposalID, submittedID := value.NewID(), value.NewID()
	submittedPayload, err := s.seal(ctx, binding(batch.OrgID, line.EmployeeID, proposalID, submittedID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: command})
	if err != nil {
		return err
	}
	submitted := ProposalRecord{OrgID: batch.OrgID, EmployeeID: line.EmployeeID, ID: proposalID, Kind: kind, Status: "submitted", AuthorSubjectID: snapshot.SubjectID, RevisionID: submittedID, PayloadID: submittedID, EffectiveDate: effective, BeforeTermID: beforeID, Revision: 1, BasisRevision: aggregate.Revision, RecordedAt: now}
	submittedRevision := RevisionRecord{OrgID: batch.OrgID, EmployeeID: line.EmployeeID, ID: submittedID, ProposalID: proposalID, PayloadID: submittedID, Status: "submitted", Kind: kind, EffectiveDate: effective, ActorSubjectID: snapshot.SubjectID, BeforeTermID: beforeID, Revision: 1, BasisRevision: aggregate.Revision, RecordedAt: now}
	if err = tx.CommitCompensation(ctx, Write{Aggregate: aggregate, ExpectedCompRevision: aggregate.Revision, Proposal: submitted, Revision: submittedRevision, Payloads: []Payload{submittedPayload}}); err != nil {
		return err
	}
	approvedID := value.NewID()
	approved, approvedRevision := revisionWrite(submitted, serviceSnapshot.SubjectID, command, "approved", 2, approvedID, aggregate.Revision, now)
	write := Write{Aggregate: aggregate, ExpectedCompRevision: aggregate.Revision, Proposal: approved, ExpectedProposalRevision: 1, Revision: approvedRevision}
	existing, err := tx.CompensationEvents(ctx, batch.OrgID, line.EmployeeID)
	if err != nil {
		return err
	}
	result := Result{ID: proposalID, Revision: "2", CompRevision: number(aggregate.Revision), Status: "approved", Members: []MemberMapping{}}
	if err = s.prepareApproval(ctx, serviceSnapshot, submitted, command, "batch_activation", existing, &write, &result); err != nil {
		return err
	}
	approvedPayload, err := s.seal(ctx, binding(batch.OrgID, line.EmployeeID, proposalID, approvedID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: command, DecisionReason: "batch_activation"})
	if err != nil {
		return err
	}
	write.Payloads = append(write.Payloads, approvedPayload)
	if err = tx.CommitCompensation(ctx, write); err != nil {
		return err
	}
	return tx.LinkAdjustmentBatchEvents(ctx, batch.OrgID, batch.ID, line.EmployeeID, write.Events, true)
}

func (s *Service) CorrectAdjustmentBatch(ctx context.Context, req Request, org, id string, command BatchCorrectionCommand) (BatchCorrectionView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return BatchCorrectionView{}, err
	}
	if !value.ValidID(id) || !value.ValidID(req.Key) || len(command.Lines) == 0 || len(command.Lines) > 500 || len(command.Reason) == 0 || len(command.Reason) > 4096 {
		return BatchCorrectionView{}, fault.Invalid
	}
	reader, ok := s.Batches.(BatchCorrectionReader)
	if !ok {
		return BatchCorrectionView{}, fault.Unavailable
	}
	batch, err := s.Batches.AdjustmentBatch(ctx, org, id)
	if err != nil {
		return BatchCorrectionView{}, err
	}
	if batch.State != "activated" {
		return BatchCorrectionView{}, fault.Conflict
	}
	byEmployee := make(map[string]BatchCorrectionLine, len(command.Lines))
	employees := make([]string, 0, len(command.Lines))
	for _, line := range command.Lines {
		if !value.ValidID(line.EmployeeID) || len(line.Members) == 0 {
			return BatchCorrectionView{}, fault.Invalid
		}
		if _, duplicate := byEmployee[line.EmployeeID]; duplicate {
			return BatchCorrectionView{}, fault.Invalid
		}
		if err = s.require(snapshot, line.EmployeeID, nil, "compensation.propose"); err != nil {
			return BatchCorrectionView{}, err
		}
		byEmployee[line.EmployeeID] = line
		employees = append(employees, line.EmployeeID)
	}
	raw, err := json.Marshal(struct {
		BatchID string                 `json:"batch_id"`
		Command BatchCorrectionCommand `json:"command"`
	}{BatchID: id, Command: command})
	if err != nil {
		return BatchCorrectionView{}, fault.Invalid
	}
	sum, err := s.financialDigest("batch-correction", raw)
	clear(raw)
	if err != nil {
		return BatchCorrectionView{}, err
	}
	digest := hex.EncodeToString(sum)
	if previous, previousErr := reader.AdjustmentBatchCorrection(ctx, org, req.Key); previousErr == nil {
		if previous.CorrectsBatchID != id || previous.SubjectID != snapshot.SubjectID || previous.ManifestDigest != digest {
			return BatchCorrectionView{}, fault.Conflict
		}
		return batchCorrectionView(previous), nil
	} else if !errors.Is(previousErr, fault.NotFound) {
		return BatchCorrectionView{}, previousErr
	}
	sort.Strings(employees)
	now := s.clock()
	receipt := BatchCommandReceipt{SubjectID: snapshot.SubjectID, Operation: "OP-COMP-10", Key: req.Key, RequestID: req.RequestID, Digest: append([]byte(nil), sum...), BatchID: id, ResultRevision: batch.Revision, RecordedAt: now}
	var correction BatchCorrectionRecord
	err = s.Store.WithCompensationTx(ctx, org, func(tx Tx) error {
		activation, ok := tx.(adjustmentActivationTx)
		if !ok {
			return fault.Unavailable
		}
		if err := tx.LockSubjects(ctx, org, []string{snapshot.SubjectID, batch.ActivationSubjectID}); err != nil {
			return err
		}
		current, err := s.revalidateBatchAuthorization(ctx, tx, req, snapshot, employees)
		if err != nil {
			return err
		}
		for _, employee := range employees {
			if err := tx.LockCompensationEmployee(ctx, org, employee); err != nil {
				return err
			}
			if err := activation.ValidateAdjustmentBatchCorrectionRoot(ctx, org, id, employee, byEmployee[employee].Members); err != nil {
				return err
			}
			if err := s.activateBatchCorrectionLine(ctx, activation, current, batch, byEmployee[employee], command.Reason, now); err != nil {
				return err
			}
		}
		correction, err = activation.RecordAdjustmentBatchCorrection(ctx, batch, req.Key, digest, snapshot.SubjectID, receipt, now)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return BatchCorrectionView{}, err
	}
	return batchCorrectionView(correction), nil
}

func (s *Service) activateBatchCorrectionLine(ctx context.Context, tx adjustmentActivationTx, snapshot authz.Snapshot, batch BatchRecord, line BatchCorrectionLine, reason string, now time.Time) error {
	serviceSnapshot := snapshot
	serviceSnapshot.SubjectID = batch.ActivationSubjectID
	aggregate, err := tx.CompensationAggregate(ctx, batch.OrgID, line.EmployeeID)
	if err != nil {
		return err
	}
	command := ProposalCommand{Kind: "correction", EffectiveDate: line.Members[0].EffectiveDate, CompRevision: number(aggregate.Revision), Reason: reason, Members: line.Members}
	if err = validateCommand(s.Policy, command); err != nil {
		return err
	}
	if err = s.references(ctx, tx, serviceSnapshot, line.EmployeeID, command); err != nil {
		return err
	}
	existing, err := tx.CompensationEvents(ctx, batch.OrgID, line.EmployeeID)
	if err != nil {
		return err
	}
	proposalID, submittedID := value.NewID(), value.NewID()
	submittedPayload, err := s.seal(ctx, binding(batch.OrgID, line.EmployeeID, proposalID, submittedID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: command})
	if err != nil {
		return err
	}
	submitted := ProposalRecord{OrgID: batch.OrgID, EmployeeID: line.EmployeeID, ID: proposalID, Kind: "correction", Status: "submitted", AuthorSubjectID: snapshot.SubjectID, RevisionID: submittedID, PayloadID: submittedID, EffectiveDate: command.EffectiveDate, Revision: 1, BasisRevision: aggregate.Revision, RecordedAt: now}
	submittedRevision := RevisionRecord{OrgID: batch.OrgID, EmployeeID: line.EmployeeID, ID: submittedID, ProposalID: proposalID, PayloadID: submittedID, Status: "submitted", Kind: "correction", EffectiveDate: command.EffectiveDate, ActorSubjectID: snapshot.SubjectID, Revision: 1, BasisRevision: aggregate.Revision, RecordedAt: now}
	if err = tx.CommitCompensation(ctx, Write{Aggregate: aggregate, ExpectedCompRevision: aggregate.Revision, Proposal: submitted, Revision: submittedRevision, Payloads: []Payload{submittedPayload}}); err != nil {
		return err
	}
	approvedID := value.NewID()
	approved, approvedRevision := revisionWrite(submitted, batch.ActivationSubjectID, command, "approved", 2, approvedID, aggregate.Revision, now)
	write := Write{Aggregate: aggregate, ExpectedCompRevision: aggregate.Revision, Proposal: approved, ExpectedProposalRevision: 1, Revision: approvedRevision}
	result := Result{ID: proposalID, Revision: "2", CompRevision: number(aggregate.Revision), Status: "approved", Members: []MemberMapping{}}
	if err = s.prepareApproval(ctx, serviceSnapshot, submitted, command, "batch_correction", existing, &write, &result); err != nil {
		return err
	}
	approvedPayload, err := s.seal(ctx, binding(batch.OrgID, line.EmployeeID, proposalID, approvedID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: command, DecisionReason: "batch_correction"})
	if err != nil {
		return err
	}
	write.Payloads = append(write.Payloads, approvedPayload)
	if err = tx.CommitCompensation(ctx, write); err != nil {
		return err
	}
	if err = tx.LinkAdjustmentBatchEvents(ctx, batch.OrgID, batch.ID, line.EmployeeID, write.Events, false); err != nil {
		return err
	}
	return nil
}

func batchCorrectionView(record BatchCorrectionRecord) BatchCorrectionView {
	return BatchCorrectionView{ID: record.ID, BusinessCode: record.BusinessCode, CorrectsBatchID: record.CorrectsBatchID, State: "activated", ManifestDigest: record.ManifestDigest, ActivatedAt: record.ActivatedAt.Format(time.RFC3339Nano)}
}

func (s *Service) batchCorrectionMembers(ctx context.Context, batch BatchRecord, employee, rootEventID string) ([]CorrectionMember, error) {
	events, err := s.Store.CompensationEvents(ctx, batch.OrgID, employee)
	if err != nil {
		return nil, err
	}
	active, err := activeEvents(events)
	if err != nil {
		return nil, err
	}
	root := -1
	for index := range active {
		if active[index].ID == rootEventID {
			root = index
			break
		}
	}
	if root < 0 {
		return []CorrectionMember{}, nil
	}
	members := make([]CorrectionMember, 0, len(active)-root)
	for index := root; index < len(active); index++ {
		event := active[index]
		if event.AfterTermID == nil {
			return nil, fault.Unavailable
		}
		term, err := s.Store.CompensationTerm(ctx, batch.OrgID, *event.AfterTermID)
		if err != nil {
			return nil, err
		}
		var after Terms
		if err = s.open(ctx, s.Store, batch.OrgID, term.PayloadID, binding(batch.OrgID, employee, term.ID, term.ID, "compensation_terms", "compensation.terms.v1"), &after); err != nil {
			return nil, err
		}
		memberKey := "batch_" + strconv.Itoa(index-root+1)
		member := CorrectionMember{MemberKey: memberKey, Action: "replace", OriginalEventID: event.ID, EffectiveDate: event.EffectiveDate, After: &after}
		if index == root {
			if event.BeforeTermID != nil {
				member.BeforeRef = &BeforeRef{TermID: event.BeforeTermID}
			}
		} else {
			previous := members[len(members)-1].MemberKey
			member.BeforeRef = &BeforeRef{MemberKey: &previous}
		}
		members = append(members, member)
	}
	return members, nil
}

func (s *Service) batchView(ctx context.Context, req Request, snapshot authz.Snapshot, batch BatchRecord) (BatchView, error) {
	lineRevision := batch.Revision
	if batch.State == "activated" || batch.State == "withdrawn" {
		lineRevision--
	}
	lines, err := s.Batches.AdjustmentBatchLines(ctx, batch.OrgID, batch.ID, lineRevision)
	if err != nil {
		return BatchView{}, err
	}
	for _, record := range lines {
		if err := s.require(snapshot, record.EmployeeID, nil); err != nil {
			return BatchView{}, err
		}
	}
	view := BatchView{ID: batch.ID, BusinessCode: batch.BusinessCode, CycleYear: int(batch.CycleYear), AdjustmentType: batch.AdjustmentType, LegalEntityID: batch.LegalEntityID, DefaultEffectiveDate: batch.DefaultEffectiveDate, State: batch.State, Revision: strconv.FormatInt(batch.Revision, 10), ManifestDigest: batch.ManifestDigest, Lines: make([]BatchLineView, 0, len(lines))}
	commands := make([]BatchLineCommand, 0, len(lines))
	for _, record := range lines {
		payload, err := s.Batches.AdjustmentBatchPayload(ctx, batch.OrgID, record.PayloadID)
		if err != nil {
			return BatchView{}, err
		}
		binding := batchLineBinding(batch.OrgID, record.EmployeeID, record.PayloadID)
		raw, err := s.Cipher.Open(ctx, binding, payload.Envelope)
		if err != nil {
			return BatchView{}, fault.Unavailable
		}
		var line BatchLineCommand
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&line)
		clear(raw)
		if err != nil {
			return BatchView{}, fault.Unavailable
		}
		commands = append(commands, line)
		lineView := BatchLineView{BatchLineCommand: line, Result: record.Result}
		if batch.State == "activated" && record.Result == "changed" {
			eventID, err := s.Batches.AdjustmentBatchOriginalEvent(ctx, batch.OrgID, batch.ID, record.EmployeeID)
			if err != nil {
				return BatchView{}, err
			}
			lineView.OriginalAdjustmentEventID = eventID
			lineView.CorrectionMembers, err = s.batchCorrectionMembers(ctx, batch, record.EmployeeID, eventID)
			if err != nil {
				return BatchView{}, err
			}
		}
		if batch.AdjustmentType == BatchSpecial {
			countAsOf, err := businessDay(snapshot, s.clock())
			if err != nil {
				return BatchView{}, err
			}
			countDate, err := time.Parse("2006-01-02", countAsOf)
			if err != nil {
				return BatchView{}, fault.Unavailable
			}
			counts, err := s.Batches.AdjustmentBatchCounts(ctx, batch.OrgID, record.EmployeeID, countDate.Year())
			if err != nil {
				return BatchView{}, err
			}
			counts.CountAsOfDate = countAsOf
			lineView.AdjustmentCounts = counts
		}
		view.Lines = append(view.Lines, lineView)
	}
	if len(commands) > 0 {
		_, totals, err := ValidateBatchLines(batch.AdjustmentType, int(batch.CycleYear), batch.DefaultEffectiveDate, commands, reasonsFromLines(commands))
		if err != nil {
			return BatchView{}, fault.Unavailable
		}
		view.IncreaseTotalsByCurrency = totals
	}
	if (batch.State == "draft" || batch.State == "activation_blocked") && len(lines) > 0 {
		digest, err := s.batchManifestDigest(ctx, batch, lines)
		if err != nil {
			return BatchView{}, err
		}
		view.ManifestDigest = digest
	}
	fresh, err := s.batchSession(ctx, req, batch.OrgID, false)
	if err != nil || fresh.SubjectID != snapshot.SubjectID || fresh.OrgID != snapshot.OrgID {
		if err != nil {
			return BatchView{}, err
		}
		return BatchView{}, fault.Unauthenticated
	}
	for _, record := range lines {
		if err := s.require(fresh, record.EmployeeID, nil); err != nil {
			return BatchView{}, err
		}
	}
	return view, nil
}

func (s *Service) batchManifestDigest(ctx context.Context, batch BatchRecord, lines []BatchLineRecord) (string, error) {
	canonical := struct {
		ID, Code, Type, Entity string
		Year, Revision         int64
		Lines                  []BatchLineCommand
	}{ID: batch.ID, Code: batch.BusinessCode, Type: batch.AdjustmentType, Entity: batch.LegalEntityID, Year: batch.CycleYear, Revision: batch.Revision, Lines: make([]BatchLineCommand, 0, len(lines))}
	for _, line := range lines {
		payload, err := s.Batches.AdjustmentBatchPayload(ctx, batch.OrgID, line.PayloadID)
		if err != nil {
			return "", err
		}
		raw, err := s.Cipher.Open(ctx, batchLineBinding(batch.OrgID, line.EmployeeID, line.PayloadID), payload.Envelope)
		if err != nil {
			return "", fault.Unavailable
		}
		var command BatchLineCommand
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&command)
		clear(raw)
		if err != nil {
			return "", fault.Unavailable
		}
		canonical.Lines = append(canonical.Lines, command)
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fault.Unavailable
	}
	digest, err := s.financialDigest("batch-manifest", raw)
	clear(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func batchLineBinding(org, employee, id string) sensitive.Context {
	return sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: id, VersionID: id, ObjectKind: "compensation_batch_line", Purpose: "financial", SchemaType: "compensation.batch_line.v1", SchemaVersion: 1}
}

func reasonsFromLines(lines []BatchLineCommand) map[string]bool {
	out := make(map[string]bool)
	for _, line := range lines {
		out[line.ReasonCode] = true
	}
	return out
}

func (s *Service) resolveBatchBasis(ctx context.Context, batch BatchRecord, line BatchLineCommand) (BatchLineBasis, error) {
	effective := line.EffectiveDate
	if batch.AdjustmentType == BatchSpecial {
		effective = line.EffectiveMonth + "-01"
	}
	if _, err := time.Parse("2006-01-02", effective); err != nil {
		return BatchLineBasis{}, fault.Invalid
	}
	staffCode, ok := organization.NormalizeStaffCode(line.StaffCode)
	if !ok || len(s.DigestKey) < 32 {
		return BatchLineBasis{}, fault.Invalid
	}
	mac := hmac.New(sha256.New, s.DigestKey)
	_, _ = mac.Write([]byte("staff-code\x00" + batch.OrgID + "\x00" + staffCode))
	workforce, err := s.Batches.AdjustmentWorkforceBasis(ctx, batch.OrgID, line.EmployeeID, mac.Sum(nil), effective)
	if err != nil {
		return BatchLineBasis{}, err
	}
	if workforce.LegalEntityID != batch.LegalEntityID || workforce.JobFamilyID == "" || workforce.CareerLevelID == "" {
		return BatchLineBasis{}, fault.Conflict
	}
	rangeStore, err := s.salaryRangeStore()
	if err != nil {
		return BatchLineBasis{}, err
	}
	ranges, err := rangeStore.SalaryRanges(ctx, batch.OrgID, SalaryRangeQuery{LegalEntityID: workforce.LegalEntityID, Location: workforce.Location, JobFamilyID: workforce.JobFamilyID, CareerLevelID: workforce.CareerLevelID, Currency: line.Currency, AsOf: effective})
	if err != nil {
		return BatchLineBasis{}, err
	}
	if len(ranges) != 1 {
		return BatchLineBasis{}, fault.Conflict
	}
	basis := BatchLineBasis{
		IdentifierID: workforce.IdentifierID, IdentifierRevision: strconv.FormatInt(workforce.IdentifierRevision, 10),
		EmploymentID: workforce.EmploymentID, EmploymentRevision: strconv.FormatInt(workforce.EmploymentRevision, 10),
		AssignmentID: workforce.AssignmentID, AssignmentRevision: strconv.FormatInt(workforce.AssignmentRevision, 10),
		SalaryRangeID: ranges[0].ID, SalaryRangeRevision: strconv.FormatInt(ranges[0].Revision, 10),
	}
	schedule, err := s.Store.CompensationSchedule(ctx, batch.OrgID, line.EmployeeID, CurrentQuery{AsOf: effective, FutureLimit: 1})
	if err != nil {
		return BatchLineBasis{}, err
	}
	if len(schedule) == 0 || schedule[0].EffectiveDate > effective || schedule[0].ValidTo != nil && effective >= *schedule[0].ValidTo {
		if line.SalaryBefore != "0" {
			return BatchLineBasis{}, fault.Conflict
		}
		return basis, nil
	}
	term, err := s.Store.CompensationTerm(ctx, batch.OrgID, schedule[0].TermID)
	if err != nil {
		return BatchLineBasis{}, err
	}
	view, err := s.projectTerm(ctx, term)
	if err != nil || view.Terms.Currency != line.Currency || view.Terms.Scale != 0 || view.Terms.AmountMinor == nil || *view.Terms.AmountMinor != line.SalaryBefore {
		return BatchLineBasis{}, fault.Conflict
	}
	basis.TermID, basis.TermRevision = term.ID, strconv.FormatInt(term.Version, 10)
	return basis, nil
}

func batchImportBinding(org, id string) sensitive.Context {
	return sensitive.Context{OrgID: org, RecordID: id, VersionID: id, ObjectKind: "compensation_batch_import", Purpose: "financial", SchemaType: "compensation.batch_import.v1", SchemaVersion: 1}
}

func (s *Service) importCandidateView(ctx context.Context, req Request, initial authz.Snapshot, candidate ImportCandidateRecord) (ImportCandidateView, error) {
	raw, err := s.Cipher.Open(ctx, batchImportBinding(candidate.OrgID, candidate.ID), candidate.Envelope)
	if err != nil {
		return ImportCandidateView{}, fault.Unavailable
	}
	var payload batchImportPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&payload)
	clear(raw)
	if err != nil {
		return ImportCandidateView{}, fault.Unavailable
	}
	fresh, err := s.batchSession(ctx, req, candidate.OrgID, true)
	if err != nil {
		return ImportCandidateView{}, err
	}
	if fresh.SubjectID != initial.SubjectID || fresh.OrgID != initial.OrgID || fresh.AuthEpoch != initial.AuthEpoch || fresh.SubjectEpoch != initial.SubjectEpoch || fresh.SessionEpoch != initial.SessionEpoch || fresh.Timezone != initial.Timezone {
		return ImportCandidateView{}, fault.Forbidden
	}
	for _, line := range payload.Lines {
		if err = s.require(fresh, line.EmployeeID, nil, "compensation.propose"); err != nil {
			return ImportCandidateView{}, err
		}
	}
	return ImportCandidateView{ID: candidate.ID, BatchID: candidate.BatchID, BaseRevision: strconv.FormatInt(candidate.BaseRevision, 10), State: candidate.State, LineCount: int(candidate.LineCount), Lines: payload.Lines, Errors: payload.Errors, ExpiresAt: candidate.ExpiresAt.Format(time.RFC3339Nano)}, nil
}
