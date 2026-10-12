package assessment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

const resultExportLimit = 8 * 1024 * 1024

type resultExportEnvelope struct {
	Kind     string      `json:"kind"`
	ExportID string      `json:"export_id"`
	Status   string      `json:"status"`
	Reason   string      `json:"reason,omitempty"`
	Result   *ResultView `json:"assessment_result,omitempty"`
}
type preparedResult struct {
	object ExportObject
	result Result
	view   ResultView
}

func encodeResultExport(value resultExportEnvelope) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fault.Unavailable
	}
	return append(encoded, '\n'), nil
}
func (s *Service) resultExportDigest(q Request, a authz.Snapshot, command ExportCommand) ([]byte, error) {
	if len(s.DigestKey) < sha256.Size || !value.ValidID(q.Key) {
		return nil, fault.Invalid
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return nil, fault.Invalid
	}
	defer clear(encoded)
	mac := hmac.New(sha256.New, s.DigestKey)
	mac.Write([]byte("TEAMLEDGER-ASSESSMENT-EXPORT\x00V1\x00"))
	for _, part := range []string{a.OrgID, a.SubjectID, q.Purpose, string(encoded)} {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	return mac.Sum(nil), nil
}
func (s *Service) canExportResult(a authz.Snapshot, employee string) bool {
	now := s.clock()
	return a.Allows("assessment.read", "metadata", employee, "interview_followup", now) && a.Allows("sensitive.export", "metadata", employee, "interview_followup", now)
}
func (s *Service) guardResultExport(ctx context.Context, store ExportStore, q Request, initial authz.Snapshot, records []preparedResult, outcome string) error {
	return store.WithAssessmentExportTx(ctx, initial.OrgID, func(tx ExportTx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		for _, record := range records {
			current, err := tx.Security(ctx, q.TokenHash, initial.OrgID, record.result.EmployeeID)
			if err != nil || current.SubjectID != initial.SubjectID || current.SubjectEpoch != initial.SubjectEpoch || current.SessionEpoch != initial.SessionEpoch || !s.canExportResult(current, record.result.EmployeeID) {
				return fault.Forbidden
			}
			latest, _, err := tx.AssessmentResult(ctx, initial.OrgID, record.result.ID)
			if err != nil || latest.Revision != record.result.Revision || latest.Status != record.result.Status || latest.Status == "invalidated" || latest.Status == "discarded" || !hmac.Equal(latest.SourceDigest, record.result.SourceDigest) {
				return fault.Conflict
			}
		}
		if outcome != "" {
			return tx.Audit(ctx, s.audit(q, initial, "", "OP-SEC-05", outcome))
		}
		return nil
	})
}
func buildResultEvents(id string, records []preparedResult) ([][]byte, error) {
	events := make([][]byte, 0, len(records)+2)
	header, _ := encodeResultExport(resultExportEnvelope{Kind: "header", ExportID: id, Status: "prepared"})
	events = append(events, header)
	total := len(header)
	for index := range records {
		encoded, err := encodeResultExport(resultExportEnvelope{Kind: "assessment_result", ExportID: id, Status: "ok", Result: &records[index].view})
		if err != nil {
			return nil, err
		}
		total += len(encoded)
		if total > resultExportLimit {
			return nil, fault.Invalid
		}
		events = append(events, encoded)
	}
	complete, _ := encodeResultExport(resultExportEnvelope{Kind: "complete", ExportID: id, Status: "complete"})
	total += len(complete)
	if total > resultExportLimit {
		return nil, fault.Invalid
	}
	return append(events, complete), nil
}
func (s *Service) ExportResults(ctx context.Context, q Request, command ExportCommand, emit func(ExportEvent) error) (string, error) {
	store, ok := s.Store.(ExportStore)
	if !ok {
		return "", fault.Unavailable
	}
	initial, err := s.session(ctx, store, q, "", "")
	if err != nil {
		return "", err
	}
	if q.Purpose != "interview_followup" || command.Format != "ndjson" || len(command.Objects) < 1 || len(command.Objects) > 100 || emit == nil {
		return "", fault.Invalid
	}
	digest, err := s.resultExportDigest(q, initial, command)
	if err != nil {
		return "", err
	}
	seen := map[string]struct{}{}
	records := make([]preparedResult, 0, len(command.Objects))
	for _, object := range command.Objects {
		revision, parseErr := parseRevision(object.ExpectedRevision)
		if parseErr != nil || revision < 1 || object.Kind != "assessment_result" || !value.ValidID(object.ID) {
			return "", fault.Invalid
		}
		if _, duplicate := seen[object.ID]; duplicate {
			return "", fault.Invalid
		}
		seen[object.ID] = struct{}{}
		result, envelope, readErr := store.AssessmentResult(ctx, initial.OrgID, object.ID)
		if readErr != nil || result.Status == "invalidated" || result.Status == "discarded" {
			return "", s.denied(ctx, q, initial, "OP-SEC-05", fault.NotFound)
		}
		current, securityErr := store.Security(ctx, q.TokenHash, initial.OrgID, result.EmployeeID)
		if securityErr != nil || current.SubjectID != initial.SubjectID || !s.canExportResult(current, result.EmployeeID) {
			return "", s.denied(ctx, q, initial, "OP-SEC-05", fault.Forbidden)
		}
		if result.Revision != revision {
			return "", fault.Conflict
		}
		plaintext, openErr := s.Cipher.Open(ctx, envelope.Context, envelope)
		if openErr != nil {
			return "", fault.Unavailable
		}
		var document ResultDocument
		decodeErr := json.Unmarshal(plaintext, &document)
		clear(plaintext)
		if decodeErr != nil {
			return "", fault.Unavailable
		}
		result.Document = document
		records = append(records, preparedResult{object, result, ResultView{ID: result.ID, JobID: result.JobID, Status: result.Status, Revision: strconv.FormatInt(result.Revision, 10), Document: document, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt}})
	}
	exportID := value.NewID()
	if _, err = buildResultEvents(exportID, records); err != nil {
		return "", err
	}
	err = store.WithAssessmentExportTx(ctx, initial.OrgID, func(tx ExportTx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		for _, record := range records {
			current, e := tx.Security(ctx, q.TokenHash, initial.OrgID, record.result.EmployeeID)
			if e != nil || current.SubjectID != initial.SubjectID || !s.canExportResult(current, record.result.EmployeeID) {
				return fault.Forbidden
			}
			latest, _, e := tx.AssessmentResult(ctx, initial.OrgID, record.result.ID)
			if e != nil || latest.Revision != record.result.Revision || latest.Status != record.result.Status || !hmac.Equal(latest.SourceDigest, record.result.SourceDigest) {
				return fault.Conflict
			}
		}
		if prior, found, e := tx.ExportReceipt(ctx, initial.OrgID, initial.SubjectID, q.Purpose, q.Key); e != nil {
			return e
		} else if found {
			if !hmac.Equal(prior.Digest, digest) {
				return fault.Mismatch
			}
			exportID = prior.ExportID
		} else if e = tx.SaveExportReceipt(ctx, initial.OrgID, initial.SubjectID, q.Purpose, q.Key, organization.ExportReceipt{Digest: digest, ExportID: exportID}, s.clock()); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, initial, "", "OP-SEC-05", "allowed"))
	})
	if err != nil {
		return "", s.denied(ctx, q, initial, "OP-SEC-05", err)
	}
	events, err := buildResultEvents(exportID, records)
	if err != nil {
		return "", err
	}
	for index, encoded := range events {
		guard := records
		if index > 0 && index <= len(records) {
			guard = records[index-1 : index]
		}
		if err = s.guardResultExport(ctx, store, q, initial, guard, ""); err != nil {
			return exportID, s.denied(ctx, q, initial, "OP-SEC-05", err)
		}
		if err = emit(ExportEvent{EncodedJSON: encoded}); err != nil {
			_ = s.guardResultExport(context.WithoutCancel(ctx), store, q, initial, nil, "partial")
			return exportID, err
		}
	}
	return exportID, nil
}
