package interview

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

const exportOperation = "OP-SEC-05"
const exportByteLimit = 8 * 1024 * 1024

// An export holds only bounded transient plaintext. The receipt contains no
// content: replay must pass the same current checks and decrypt again.
type exportRecord struct {
	object    ExportObject
	employee  string
	revision  string
	version   *Version
	action    *ActionRecord
	interview *Record
	event     ExportEvent
}

func encodeExportEvent(event *ExportEvent) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return fault.Unavailable
	}
	event.EncodedJSON = append(raw, '\n')
	return nil
}

func emitExportEvent(event *ExportEvent, emit func(ExportEvent) error) error {
	defer clear(event.EncodedJSON)
	if err := emit(*event); err != nil {
		return fault.Unavailable
	}
	return nil
}

func (s *Service) exportPermission(a authz.Snapshot, record exportRecord) error {
	if !s.clock().Before(a.MFAUntil) {
		return fault.NotFound
	}
	switch record.object.Kind {
	case "note_version":
		v := record.version
		return s.require(a, v.EmployeeID, v.Category, versionLine(*v), "note.read", "sensitive.export")
	case "action_item":
		v := record.action
		return s.require(a, v.EmployeeID, "shared", actionLine(*v), "action.read", "sensitive.export")
	case "interview":
		v := record.interview
		return s.require(a, v.EmployeeID, "metadata", interviewLine(*v), "interview.read", "sensitive.export")
	}
	return fault.Invalid
}

func (s *Service) validateExportRecord(ctx context.Context, tx Tx, a authz.Snapshot, record exportRecord) error {
	if err := s.exportPermission(a, record); err != nil {
		return err
	}
	switch record.object.Kind {
	case "note_version":
		return s.validateVersion(ctx, tx, a, *record.version)
	case "action_item":
		return s.validateAction(ctx, tx, a, *record.action)
	case "interview":
		current, err := tx.Interview(ctx, a.OrgID, record.interview.ID)
		if err != nil {
			return err
		}
		if current.OrgID != a.OrgID || current.EmployeeID != record.employee {
			return fault.NotFound
		}
		if err = s.require(a, current.EmployeeID, "metadata", interviewLine(current), "interview.read", "sensitive.export"); err != nil {
			return err
		}
		if current.Number != record.interview.Number {
			return fault.Conflict
		}
		return nil
	}
	return fault.Invalid
}

func exportFailureReason(err error) string {
	switch {
	case errors.Is(err, fault.Unauthenticated), errors.Is(err, fault.Forbidden), errors.Is(err, fault.NotFound):
		return "ACCESS_LOST"
	case errors.Is(err, fault.Conflict):
		return "REVISION_STALE"
	case errors.Is(err, fault.AuditUnavailable):
		return "AUDIT_UNAVAILABLE"
	default:
		return "DEPENDENCY_UNAVAILABLE"
	}
}

// Partial audit deliberately does not require the permission that just vanished.
// Its organization and actor are pinned to the authorized preparation, never to
// a new session organization. Client cancellation must not erase this outcome.
func (s *Service) exportPartial(ctx context.Context, q Request, a authz.Snapshot, id, reason string, cause error, emit func(ExportEvent) error) error {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	auditErr := s.Store.WithInterviewTx(auditCtx, a.OrgID, func(tx Tx) error {
		return tx.Audit(auditCtx, s.audit(q, a, "", exportOperation, "partial"))
	})
	event := ExportEvent{Kind: "partial", ExportID: id, Status: "partial", Reason: reason}
	if err := encodeExportEvent(&event); err == nil {
		_ = emitExportEvent(&event, emit)
	}
	if auditErr != nil {
		return fault.AuditUnavailable
	}
	switch {
	case errors.Is(cause, fault.Unauthenticated):
		return fault.Unauthenticated
	case errors.Is(cause, fault.NotFound):
		return fault.NotFound
	case errors.Is(cause, fault.Forbidden):
		return fault.Forbidden
	case errors.Is(cause, fault.Conflict):
		return fault.Conflict
	case errors.Is(cause, fault.AuditUnavailable):
		return fault.AuditUnavailable
	default:
		return fault.Unavailable
	}
}

func (s *Service) Export(ctx context.Context, q Request, cmd ExportCommand, emit func(ExportEvent) error) (string, error) {
	a, err := s.session(ctx, s.Store, q, "", "")
	if err != nil {
		return "", s.denied(ctx, q, a, exportOperation, err)
	}
	if emit == nil || cmd.Format != "ndjson" || len(cmd.Objects) == 0 || len(cmd.Objects) > 100 || !value.ValidID(q.Key) {
		return "", fault.Invalid
	}
	targets := make(map[authz.ObjectReference]struct{}, len(cmd.Objects))
	// Canonical decimal revisions and IDs are checked before loading any object.
	for _, object := range cmd.Objects {
		if object.Kind != "note_version" && object.Kind != "action_item" && object.Kind != "interview" {
			return "", fault.Invalid
		}
		if !value.ValidID(object.ID) {
			return "", fault.Invalid
		}
		if _, err = revision(object.ExpectedRevision, false); err != nil {
			return "", err
		}
		target := ref(object.Kind, object.ID)
		if _, duplicate := targets[target]; duplicate {
			return "", fault.Invalid
		}
		targets[target] = struct{}{}
	}
	records := make([]exportRecord, 0, len(cmd.Objects))
	snapshots := make(map[string]authz.Snapshot)
	employees := make([]string, 0, len(cmd.Objects))
	graph, err := s.Store.GraphState(ctx, a.OrgID)
	if err != nil {
		return "", err
	}
	initialDay, err := day(a, s.clock())
	if err != nil {
		return "", err
	}
	// The entire requested set passes canonical read/export/MFA checks before
	// any digest or receipt. Receipt mismatch precedes revision qualification.
	for _, object := range cmd.Objects {
		record := exportRecord{object: object}
		switch object.Kind {
		case "note_version":
			v, e := s.Store.InterviewVersion(ctx, a.OrgID, object.ID)
			if e != nil {
				return "", s.denied(ctx, q, a, exportOperation, e)
			}
			if v.OrgID != a.OrgID || v.ID != object.ID {
				return "", s.denied(ctx, q, a, exportOperation, fault.NotFound)
			}
			record.version, record.employee, record.revision = &v, v.EmployeeID, number(v.Number)
		case "action_item":
			v, e := s.Store.InterviewAction(ctx, a.OrgID, object.ID)
			if e != nil {
				return "", s.denied(ctx, q, a, exportOperation, e)
			}
			if v.OrgID != a.OrgID || v.ID != object.ID {
				return "", s.denied(ctx, q, a, exportOperation, fault.NotFound)
			}
			record.action, record.employee, record.revision = &v, v.EmployeeID, number(v.Number)
		case "interview":
			v, e := s.Store.Interview(ctx, a.OrgID, object.ID)
			if e != nil {
				return "", s.denied(ctx, q, a, exportOperation, e)
			}
			if v.OrgID != a.OrgID || v.ID != object.ID {
				return "", s.denied(ctx, q, a, exportOperation, fault.NotFound)
			}
			record.interview, record.employee, record.revision = &v, v.EmployeeID, number(v.Number)
		}
		current, exists := snapshots[record.employee]
		if !exists {
			current, err = s.session(ctx, s.Store, q, a.OrgID, record.employee)
			if err != nil {
				return "", s.denied(ctx, q, a, exportOperation, err)
			}
			if current.OrgID != a.OrgID || current.SubjectID != a.SubjectID || current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch || current.SessionEpoch != a.SessionEpoch {
				return "", s.denied(ctx, q, a, exportOperation, fault.Forbidden)
			}
			snapshots[record.employee] = current
			employees = append(employees, record.employee)
		}
		if err = s.exportPermission(current, record); err != nil {
			return "", s.denied(ctx, q, a, exportOperation, err)
		}
		records = append(records, record)
	}
	sort.Strings(employees)
	anchor := employees[0]
	a = snapshots[anchor]
	digest, err := s.digest(q, a, exportOperation, "", cmd)
	if err != nil {
		return "", err
	}
	currentByEmployee := make(map[string]authz.Snapshot, len(employees))
	validate := func(tx Tx, anchorCurrent authz.Snapshot, prepared bool) error {
		// The caller locks the smallest employee first; acquire all remaining
		// guards in the same total order under the authorization guard.
		for _, employee := range employees[1:] {
			if e := tx.LockInterviewEmployee(ctx, a.OrgID, employee); e != nil {
				return e
			}
		}
		currentGraph, e := tx.GraphState(ctx, a.OrgID)
		if e != nil {
			return e
		}
		if currentGraph.Revision != graph.Revision {
			return fault.Conflict
		}
		for _, employee := range employees {
			current := anchorCurrent
			if employee != anchor {
				current, e = s.session(ctx, tx, q, a.OrgID, employee)
				if e != nil {
					return e
				}
			}
			previous := snapshots[employee]
			if current.OrgID != previous.OrgID || current.SubjectID != previous.SubjectID || current.AuthEpoch != previous.AuthEpoch || current.SubjectEpoch != previous.SubjectEpoch || current.SessionEpoch != previous.SessionEpoch || current.Timezone != previous.Timezone {
				return fault.Forbidden
			}
			currentDay, e := day(current, s.clock())
			if e != nil {
				return e
			}
			if currentDay != initialDay {
				return fault.Forbidden
			}
			currentByEmployee[employee] = current
		}
		for _, record := range records {
			current := currentByEmployee[record.employee]
			if prepared {
				if e := s.validateExportRecord(ctx, tx, current, record); e != nil {
					return e
				}
			} else if e := s.exportPermission(current, record); e != nil {
				return e
			}
		}
		return nil
	}
	_, replay, err := s.Store.InterviewReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key)
	if err != nil {
		return "", err
	}
	var receipt Result
	if replay {
		err = s.Store.WithInterviewTx(ctx, a.OrgID, func(tx Tx) error {
			if e := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); e != nil {
				return e
			}
			if e := tx.LockInterviewEmployee(ctx, a.OrgID, anchor); e != nil {
				return e
			}
			current, e := s.session(ctx, tx, q, a.OrgID, anchor)
			if e != nil {
				return e
			}
			if e = validate(tx, current, false); e != nil {
				return e
			}
			saved, found, e := tx.InterviewReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key)
			if e != nil {
				return e
			}
			if !found {
				return fault.Conflict
			}
			receipt, e = receiptMatch(saved, digest)
			return e
		})
		if err != nil {
			return "", s.denied(ctx, q, a, exportOperation, err)
		}
	}
	var exportID string
	if replay {
		if !value.ValidID(receipt.ID) {
			return "", fault.Unavailable
		}
		exportID = receipt.ID
	} else {
		exportID = value.NewID()
	}
	// Both new preparations and matching replays pin actual content revisions.
	// A mismatched original command has already failed without touching KMS.
	for _, record := range records {
		if record.object.ExpectedRevision != record.revision {
			return "", fault.Conflict
		}
	}
	defer func() {
		for index := range records {
			clear(records[index].event.EncodedJSON)
		}
	}()
	size := 0
	for index := range records {
		record := &records[index]
		current := snapshots[record.employee]
		event := ExportEvent{Kind: "object", ExportID: exportID}
		switch record.object.Kind {
		case "note_version":
			view, e := s.prepareNote(ctx, s.Store, current, *record.version)
			if e != nil {
				return "", s.denied(ctx, q, a, exportOperation, e)
			}
			record.version.NoteView = view
			event.NoteVersion = &record.version.NoteView
		case "action_item":
			view, e := s.prepareAction(ctx, s.Store, current, *record.action)
			if e != nil {
				return "", s.denied(ctx, q, a, exportOperation, e)
			}
			record.action.ActionView = view
			event.ActionItem = &record.action.ActionView
		case "interview":
			// Export only the independently authorized metadata object, never notes.
			event.Interview = &record.interview.InterviewView
		}
		if err = encodeExportEvent(&event); err != nil {
			return "", err
		}
		record.event = event
		size += len(event.EncodedJSON)
		if size > exportByteLimit {
			return "", fault.Invalid
		}
	}
	header := ExportEvent{Kind: "header", ExportID: exportID, Status: "prepared"}
	complete := ExportEvent{Kind: "complete", ExportID: exportID, Status: "complete"}
	// Reserve a complete attempt plus the largest safe partial terminal: a
	// writer may fail after having written some or all of the complete bytes.
	reserve := ExportEvent{Kind: "partial", ExportID: exportID, Status: "partial", Reason: "DEPENDENCY_UNAVAILABLE"}
	for _, event := range []*ExportEvent{&header, &complete, &reserve} {
		if err = encodeExportEvent(event); err != nil {
			return "", err
		}
		defer clear(event.EncodedJSON)
		size += len(event.EncodedJSON)
	}
	if size > exportByteLimit {
		return "", fault.Invalid
	}
	err = s.release(ctx, q, a, anchor, exportOperation, func(tx Tx, current authz.Snapshot) error {
		if e := validate(tx, current, true); e != nil {
			return e
		}
		saved, exists, e := tx.InterviewReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key)
		if e != nil {
			return e
		}
		if exists {
			result, e := receiptMatch(saved, digest)
			if e != nil {
				return e
			}
			if !value.ValidID(result.ID) {
				return fault.Unavailable
			}
			exportID = result.ID
			return nil
		}
		return tx.SaveInterviewReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key, Receipt{Digest: digest, Result: Result{ID: exportID}})
	})
	if err != nil {
		return "", s.denied(ctx, q, a, exportOperation, err)
	}
	if header.ExportID != exportID {
		// A concurrently prepared identical command supplies the winning ID. UUID
		// lengths are fixed, so this necessary re-encoding cannot change the bound.
		clear(header.EncodedJSON)
		clear(complete.EncodedJSON)
		header.ExportID, complete.ExportID = exportID, exportID
		if err = encodeExportEvent(&header); err != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
		}
		defer clear(header.EncodedJSON)
		if err = encodeExportEvent(&complete); err != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
		}
		defer clear(complete.EncodedJSON)
		for index := range records {
			event := &records[index].event
			clear(event.EncodedJSON)
			event.ExportID = exportID
			if err = encodeExportEvent(event); err != nil {
				return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
			}
		}
	}
	validatePrepared := func(tx Tx, current authz.Snapshot) error {
		return validate(tx, current, true)
	}
	if err = s.release(ctx, q, a, anchor, exportOperation, validatePrepared); err != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
	}
	if err = emitExportEvent(&header, emit); err != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", err, emit)
	}
	for index := range records {
		if err = s.release(ctx, q, a, anchor, exportOperation, validatePrepared); err != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
		}
		if err = emitExportEvent(&records[index].event, emit); err != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", err, emit)
		}
	}
	if err = s.release(ctx, q, a, anchor, exportOperation, validatePrepared); err != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, exportFailureReason(err), err, emit)
	}
	if err = emitExportEvent(&complete, emit); err != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", err, emit)
	}
	return exportID, nil
}
