package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

// WithTx owns the native authorization guard and transaction lifetime. The
// callback here is deliberately typed to the interview contract, not aliased.
func (r *Repository) WithInterviewTx(ctx context.Context, org string, fn func(interview.Tx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}
func (t *transaction) LockInterviewEmployee(ctx context.Context, org, employee string) error {
	if org != t.org {
		return fault.NotFound
	}
	if t.backend == "sqlite" {
		result, err := t.tx.ExecContext(ctx, "UPDATE employee SET profile_revision=profile_revision WHERE org_id=? AND id=?", org, employee)
		return interviewAffected(result, err, fault.NotFound)
	}
	var revision int64
	err := t.tx.QueryRowContext(ctx, "SELECT profile_revision FROM employee WHERE org_id=$1 AND id=$2 FOR UPDATE", org, employee).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound
	}
	return safeError(err)
}
func interviewAffected(result sql.Result, err, missing error) error {
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	if n != 1 {
		return missing
	}
	return nil
}
func interviewNext(next, expected int64) bool {
	return expected >= 0 && expected < math.MaxInt64 && next == expected+1
}
func (t *transaction) interviewTime(at *time.Time) any {
	if at == nil {
		return nil
	}
	return t.bindTime(*at)
}

func (t *transaction) CommitInterview(ctx context.Context, w interview.Write) error {
	if w.Interview != nil && (w.Interview.OrgID != t.org || !interviewNext(w.Interview.Number, w.ExpectedInterviewRevision)) {
		return fault.Invalid
	}
	if w.Head != nil && (w.Head.OrgID != t.org || w.Version == nil || !interviewNext(w.Head.Revision, w.ExpectedHeadRevision)) {
		return fault.Invalid
	}
	if w.Version != nil && (w.Version.OrgID != t.org || w.Head == nil || w.Version.HeadID != w.Head.ID || w.Version.InterviewID != w.Head.InterviewID || w.Version.EmployeeID != w.Head.EmployeeID || w.Version.Category != w.Head.Category || w.Version.Number != w.Head.Revision) {
		return fault.Invalid
	}
	if w.Action != nil && (w.Action.OrgID != t.org || w.Event == nil || !interviewNext(w.Action.Number, w.ExpectedActionRevision)) {
		return fault.Invalid
	}
	if w.Event != nil && (w.Event.OrgID != t.org || w.Action == nil || w.Event.ActionID != w.Action.ID || w.Event.InterviewID != w.Action.InterviewID || w.Event.EmployeeID != w.Action.EmployeeID || w.Event.Number != w.Action.Number || w.Event.Status != w.Action.Status || w.Event.PayloadID != w.Action.PayloadID) {
		return fault.Invalid
	}
	if w.Transition != nil && (w.Transition.OrgID != t.org || w.Interview == nil || w.Transition.InterviewID != w.Interview.ID || w.Transition.EmployeeID != w.Interview.EmployeeID || w.Transition.Revision != w.Interview.Number || w.Transition.Status != w.Interview.Status) {
		return fault.Invalid
	}
	if len(w.Sources) != 0 && (w.Version == nil) == (w.Event == nil) {
		return fault.Invalid
	}

	// Deferred native FKs permit the immutable owner/payload cycles. CAS wins
	// before immutable rows are inserted, and any failure rolls back the bundle.
	if w.Interview != nil {
		v := w.Interview
		if w.ExpectedInterviewRevision == 0 {
			result, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO interview(org_id,id,employee_id,status,revision,scheduled_at,actual_started_at,actual_ended_at,backfilled,author_subject_id,recorded_at,reason_payload_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING"), v.OrgID, v.ID, v.EmployeeID, v.Status, v.Number, t.bindTime(v.ScheduledAt), t.interviewTime(v.ActualStartedAt), t.interviewTime(v.ActualEndedAt), v.Backfilled, v.AuthorSubjectID, t.bindTime(v.RecordedAt), interviewReason(w.Transition))
			if err = interviewAffected(result, err, fault.Conflict); err != nil {
				return err
			}
			for ordinal, party := range v.Participants {
				var subject, employee any
				if party.Kind == "subject" {
					subject = party.ID
				} else if party.Kind == "employee" {
					employee = party.ID
				} else {
					return fault.Invalid
				}
				_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO interview_participant(org_id,interview_id,ordinal,kind,subject_id,employee_id) VALUES(?,?,?,?,?,?)"), t.org, v.ID, ordinal, party.Kind, subject, employee)
				if err != nil {
					return safeError(err)
				}
			}
		} else {
			query := "UPDATE interview SET status=?,revision=?,actual_started_at=?,actual_ended_at=?"
			args := []any{v.Status, v.Number, t.interviewTime(v.ActualStartedAt), t.interviewTime(v.ActualEndedAt)}
			if w.Transition != nil {
				query += ",reason_payload_id=?"
				args = append(args, interviewReason(w.Transition))
			}
			if w.Transition != nil && w.Transition.Backfilled {
				if !v.Backfilled || v.Status != "completed" {
					return fault.Invalid
				}
				query += ",backfilled=?"
				args = append(args, true)
			}
			query += " WHERE org_id=? AND id=? AND employee_id=? AND revision=?"
			args = append(args, v.OrgID, v.ID, v.EmployeeID, w.ExpectedInterviewRevision)
			if w.Transition != nil && w.Transition.Backfilled {
				query += " AND status='scheduled' AND backfilled=false"
			}
			result, err := t.tx.ExecContext(ctx, t.structureSQL(query), args...)
			if err = interviewAffected(result, err, fault.Conflict); err != nil {
				return err
			}
		}
	}
	if w.Head != nil {
		h := w.Head
		var result sql.Result
		var err error
		if w.ExpectedHeadRevision == 0 {
			result, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO note_head(org_id,id,interview_id,employee_id,category,revision,acl_epoch,draft_version_id,published_version_id) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING"), h.OrgID, h.ID, h.InterviewID, h.EmployeeID, h.Category, h.Revision, h.ACLEpoch, nullable(h.DraftID), nullable(h.PublishedID))
		} else {
			result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE note_head SET revision=?,acl_epoch=?,draft_version_id=?,published_version_id=? WHERE org_id=? AND id=? AND interview_id=? AND employee_id=? AND category=? AND revision=?"), h.Revision, h.ACLEpoch, nullable(h.DraftID), nullable(h.PublishedID), h.OrgID, h.ID, h.InterviewID, h.EmployeeID, h.Category, w.ExpectedHeadRevision)
		}
		if err = interviewAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	}
	if w.Version != nil {
		v := w.Version
		_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO note_version(org_id,id,head_id,interview_id,employee_id,category,version_no,status,payload_id,supersedes_version_id,author_subject_id,recorded_at,content_digest,source_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.ID, v.HeadID, v.InterviewID, v.EmployeeID, v.Category, v.Number, v.Status, v.PayloadID, structureDateArg(v.SupersedesVersionID), v.AuthorSubjectID, t.bindTime(v.RecordedAt), v.ContentDigest, v.SourceEpoch)
		if err != nil {
			return safeError(err)
		}
	}
	if w.Action != nil {
		a := w.Action
		var result sql.Result
		var err error
		if w.ExpectedActionRevision == 0 {
			var subject, employee any
			if a.Owner.Kind == "subject" {
				subject = a.Owner.ID
			} else if a.Owner.Kind == "employee" {
				employee = a.Owner.ID
			} else {
				return fault.Invalid
			}
			result, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO action_item(org_id,id,interview_id,employee_id,category,revision,status,owner_kind,owner_subject_id,owner_employee_id,due_date,payload_id,author_subject_id,recorded_at) VALUES(?,?,?,?,'shared',?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING"), a.OrgID, a.ID, a.InterviewID, a.EmployeeID, a.Number, a.Status, a.Owner.Kind, subject, employee, structureDateArg(a.DueDate), a.PayloadID, w.Event.AuthorSubjectID, t.bindTime(a.RecordedAt))
		} else {
			// Owner and due date are creation facts and survive terminal transitions.
			result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE action_item SET revision=?,status=?,payload_id=? WHERE org_id=? AND id=? AND interview_id=? AND employee_id=? AND revision=?"), a.Number, a.Status, a.PayloadID, a.OrgID, a.ID, a.InterviewID, a.EmployeeID, w.ExpectedActionRevision)
		}
		if err = interviewAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	}
	if w.Event != nil {
		e := w.Event
		_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO action_item_event(org_id,id,action_item_id,interview_id,employee_id,status,revision,payload_id,author_subject_id,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)"), e.OrgID, e.ID, e.ActionID, e.InterviewID, e.EmployeeID, e.Status, e.Number, e.PayloadID, e.AuthorSubjectID, t.bindTime(e.RecordedAt))
		if err != nil {
			return safeError(err)
		}
	}
	if w.Transition != nil {
		e := w.Transition
		_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO interview_event(org_id,id,interview_id,employee_id,status,revision,actual_started_at,actual_ended_at,backfilled,reason_payload_id,author_subject_id,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), e.OrgID, e.ID, e.InterviewID, e.EmployeeID, e.Status, e.Revision, t.interviewTime(e.ActualStartedAt), t.interviewTime(e.ActualEndedAt), e.Backfilled, nullable(e.PayloadID), e.AuthorSubjectID, t.bindTime(e.RecordedAt))
		if err != nil {
			return safeError(err)
		}
	}
	for _, payload := range w.Payloads {
		if err := t.insertInterviewPayload(ctx, payload, w); err != nil {
			return err
		}
	}
	for _, fact := range w.Sources {
		if err := t.insertInterviewSource(ctx, fact, w); err != nil {
			return err
		}
	}
	return nil
}
func interviewReason(event *interview.TransitionEvent) any {
	if event == nil {
		return nil
	}
	return nullable(event.PayloadID)
}
func (t *transaction) insertInterviewPayload(ctx context.Context, p interview.Payload, w interview.Write) error {
	e := p.Envelope
	c := e.Context
	if c.OrgID != t.org {
		return fault.Invalid
	}
	var head, version, action, actionEvent, interviewID, interviewEvent, category any
	owners := 0
	if w.Version != nil && w.Version.PayloadID == p.ID {
		v := w.Version
		if c.EmployeeID != v.EmployeeID || c.RecordID != v.HeadID || c.VersionID != v.ID {
			return fault.Invalid
		}
		if c.ObjectKind != "interview_note_"+v.Category {
			return fault.Invalid
		}
		category = v.Category
		head, version, owners = v.HeadID, v.ID, owners+1
	}
	if w.Event != nil && w.Event.PayloadID == p.ID {
		v := w.Event
		if c.EmployeeID != v.EmployeeID || c.RecordID != v.ActionID || c.VersionID != p.ID {
			return fault.Invalid
		}
		action, actionEvent, owners = v.ActionID, v.ID, owners+1
	}
	if w.Transition != nil && w.Transition.PayloadID == p.ID {
		v := w.Transition
		if c.EmployeeID != v.EmployeeID || c.RecordID != v.InterviewID || c.VersionID != p.ID {
			return fault.Invalid
		}
		interviewID, interviewEvent, owners = v.InterviewID, v.ID, owners+1
	}
	if owners != 1 {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO interview_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at,head_id,note_version_id,action_item_id,action_event_id,interview_id,interview_event_id,category) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), c.OrgID, c.EmployeeID, p.ID, c.RecordID, c.VersionID, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, t.bindTime(p.RecordedAt), head, version, action, actionEvent, interviewID, interviewEvent, category)
	return safeError(err)
}
func (t *transaction) insertInterviewSource(ctx context.Context, fact interview.SourceFact, w interview.Write) error {
	version, err := strconv.ParseInt(fact.ExpectedVersion, 10, 64)
	if err != nil || version < 1 || strconv.FormatInt(version, 10) != fact.ExpectedVersion || fact.Kind != "note_version" {
		return fault.Invalid
	}
	var note, event any
	var employee string
	if w.Version != nil {
		note, employee = w.Version.ID, w.Version.EmployeeID
	} else if w.Event != nil {
		event, employee = w.Event.ID, w.Event.EmployeeID
	} else {
		return fault.Invalid
	}
	if fact.EmployeeID != employee {
		return fault.Invalid
	}
	// Recheck the immutable tuple natively while holding the employee guard;
	// changed source epochs or unpublished/cross-employee sources cannot commit.
	result, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO source_reference(org_id,id,employee_id,owner_note_version_id,owner_action_event_id,source_note_version_id,category,expected_version,source_epoch,source_status) SELECT ?,?,?,?,?,?,?,?,?, 'published' FROM note_version WHERE org_id=? AND id=? AND employee_id=? AND category=? AND version_no=? AND source_epoch=? AND status='published'"), t.org, value.NewID(), employee, note, event, fact.ID, fact.Category, version, fact.Epoch, t.org, fact.ID, employee, fact.Category, version, fact.Epoch)
	return interviewAffected(result, err, fault.Conflict)
}
func (t *transaction) SaveInterviewReceipt(ctx context.Context, org, subject, operation, key string, receipt interview.Receipt) error {
	if org != t.org {
		return fault.Invalid
	}
	// Result has only metadata fields; encrypted content is never cached here.
	result, err := json.Marshal(receipt.Result)
	if err != nil {
		return fault.Invalid
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO interview_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_json,recorded_at) VALUES(?,?,?,?,?,1,?,?)"), org, subject, operation, key, receipt.Digest, string(result), t.bindTime(time.Now()))
	return safeError(err)
}
