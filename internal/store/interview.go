package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
)

var _ interview.Store = (*Repository)(nil)
var _ interview.Tx = (*transaction)(nil)

func (r *Repository) Interview(ctx context.Context, org, id string) (interview.Record, error) {
	return r.read().Interview(ctx, org, id)
}
func (r *Repository) InterviewEvents(ctx context.Context, org, id string) ([]interview.TransitionEvent, error) {
	return r.read().InterviewEvents(ctx, org, id)
}
func (r *Repository) InterviewHead(ctx context.Context, org, id, category string) (interview.Head, bool, error) {
	return r.read().InterviewHead(ctx, org, id, category)
}
func (r *Repository) InterviewVersion(ctx context.Context, org, id string) (interview.Version, error) {
	return r.read().InterviewVersion(ctx, org, id)
}
func (r *Repository) InterviewAction(ctx context.Context, org, id string) (interview.ActionRecord, error) {
	return r.read().InterviewAction(ctx, org, id)
}
func (r *Repository) InterviewPayload(ctx context.Context, org, id string) (interview.Payload, error) {
	return r.read().InterviewPayload(ctx, org, id)
}
func (r *Repository) InterviewSources(ctx context.Context, org, owner string) ([]interview.SourceFact, error) {
	return r.read().InterviewSources(ctx, org, owner)
}
func (r *Repository) InterviewReceipt(ctx context.Context, org, subject, operation, key string) (interview.Receipt, bool, error) {
	return r.read().InterviewReceipt(ctx, org, subject, operation, key)
}
func (r *Repository) InterviewParty(ctx context.Context, org string, party interview.Party, active bool, day string) (bool, error) {
	return r.read().InterviewParty(ctx, org, party, active, day)
}
func (r *Repository) InterviewList(ctx context.Context, org, employee string, query interview.ListQuery, scope interview.Scope, from, to time.Time, after string, limit int) ([]interview.Record, error) {
	return r.read().InterviewList(ctx, org, employee, query, scope, from, to, after, limit)
}
func (r *Repository) InterviewVersions(ctx context.Context, org, id, category string, scope interview.Scope, after string, limit int) ([]interview.Version, error) {
	return r.read().InterviewVersions(ctx, org, id, category, scope, after, limit)
}
func (r *Repository) InterviewActions(ctx context.Context, org, id string, scope interview.Scope, after string, limit int) ([]interview.ActionRecord, error) {
	return r.read().InterviewActions(ctx, org, id, scope, after, limit)
}

const interviewColumns = "i.org_id,i.id,i.employee_id,i.status,i.revision,i.scheduled_at,i.actual_started_at,i.actual_ended_at,i.backfilled,i.author_subject_id,i.recorded_at"
const interviewVersionColumns = "v.org_id,v.id,v.head_id,v.interview_id,v.employee_id,v.category,v.version_no,v.status,v.payload_id,v.supersedes_version_id,v.author_subject_id,v.recorded_at,v.content_digest,v.source_epoch"

func scanInterview(row grantScanner) (interview.Record, error) {
	var v interview.Record
	var scheduled, recorded dbTime
	var start, end nullDBTime
	err := row.Scan(&v.OrgID, &v.ID, &v.EmployeeID, &v.Status, &v.Number, &scheduled, &start, &end, &v.Backfilled, &v.AuthorSubjectID, &recorded)
	v.Revision = strconv.FormatInt(v.Number, 10)
	v.ScheduledAt, v.RecordedAt = scheduled.Time, recorded.Time
	v.ActualStartedAt, v.ActualEndedAt = timePtr(start), timePtr(end)
	v.Participants = make([]interview.Party, 0)
	return v, err
}
func scanInterviewVersion(row grantScanner) (interview.Version, error) {
	var v interview.Version
	var recorded dbTime
	var supersedes sql.NullString
	err := row.Scan(&v.OrgID, &v.ID, &v.HeadID, &v.InterviewID, &v.EmployeeID, &v.Category, &v.Number, &v.Status, &v.PayloadID, &supersedes, &v.AuthorSubjectID, &recorded, &v.ContentDigest, &v.SourceEpoch)
	v.VersionNo, v.RecordedAt, v.SupersedesVersionID = strconv.FormatInt(v.Number, 10), recorded.Time, stringPtr(supersedes)
	v.SourceRefs = make([]interview.SourceRef, 0)
	return v, err
}
func (r reader) Interview(ctx context.Context, org, id string) (interview.Record, error) {
	v, err := scanInterview(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+interviewColumns+" FROM interview i WHERE i.org_id=? AND i.id=?"), org, id))
	if errors.Is(err, sql.ErrNoRows) {
		return interview.Record{}, fault.NotFound
	}
	if err != nil {
		return interview.Record{}, safeError(err)
	}
	if err = r.interviewParticipants(ctx, &v); err != nil {
		return interview.Record{}, err
	}
	return v, nil
}
func (r reader) InterviewEvents(ctx context.Context, org, id string) ([]interview.TransitionEvent, error) {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,id,interview_id,employee_id,status,revision,actual_started_at,actual_ended_at,backfilled,reason_payload_id,author_subject_id,recorded_at FROM interview_event WHERE org_id=? AND interview_id=? ORDER BY revision,id LIMIT 4"), org, id)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	events := make([]interview.TransitionEvent, 0, 3)
	for rows.Next() {
		var event interview.TransitionEvent
		var start, end nullDBTime
		var recorded dbTime
		var payload sql.NullString
		if err = rows.Scan(&event.OrgID, &event.ID, &event.InterviewID, &event.EmployeeID, &event.Status, &event.Revision, &start, &end, &event.Backfilled, &payload, &event.AuthorSubjectID, &recorded); err != nil {
			return nil, safeError(err)
		}
		event.ActualStartedAt, event.ActualEndedAt = timePtr(start), timePtr(end)
		event.PayloadID, event.RecordedAt = payload.String, recorded.Time
		events = append(events, event)
		if len(events) > 3 {
			return nil, fault.Unavailable
		}
	}
	return events, safeError(rows.Err())
}
func (r reader) interviewParticipants(ctx context.Context, v *interview.Record) error {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT kind,subject_id,employee_id FROM interview_participant WHERE org_id=? AND interview_id=? ORDER BY ordinal LIMIT 21"), v.OrgID, v.ID)
	if err != nil {
		return safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var p interview.Party
		var subject, employee sql.NullString
		if err = rows.Scan(&p.Kind, &subject, &employee); err != nil {
			return safeError(err)
		}
		if p.Kind == "subject" {
			p.ID = subject.String
		} else {
			p.ID = employee.String
		}
		v.Participants = append(v.Participants, p)
		if len(v.Participants) > 20 {
			return fault.Unavailable
		}
	}
	return safeError(rows.Err())
}
func (r reader) InterviewHead(ctx context.Context, org, id, category string) (interview.Head, bool, error) {
	var h interview.Head
	var draft, published sql.NullString
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT org_id,id,interview_id,employee_id,category,revision,acl_epoch,draft_version_id,published_version_id FROM note_head WHERE org_id=? AND interview_id=? AND category=?"), org, id, category).Scan(&h.OrgID, &h.ID, &h.InterviewID, &h.EmployeeID, &h.Category, &h.Revision, &h.ACLEpoch, &draft, &published)
	if errors.Is(err, sql.ErrNoRows) {
		return h, false, nil
	}
	h.DraftID, h.PublishedID = draft.String, published.String
	return h, err == nil, safeError(err)
}
func (r reader) InterviewVersion(ctx context.Context, org, id string) (interview.Version, error) {
	v, err := scanInterviewVersion(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+interviewVersionColumns+" FROM note_version v WHERE v.org_id=? AND v.id=?"), org, id))
	if errors.Is(err, sql.ErrNoRows) {
		return interview.Version{}, fault.NotFound
	}
	if err != nil {
		return interview.Version{}, safeError(err)
	}
	facts, err := r.InterviewSources(ctx, org, id)
	if err != nil {
		return interview.Version{}, err
	}
	for _, fact := range facts {
		v.SourceRefs = append(v.SourceRefs, fact.SourceRef)
	}
	return v, nil
}
func (r reader) interviewActionColumns() string {
	return "a.org_id,a.id,a.interview_id,a.employee_id,a.revision,a.status,a.owner_kind,a.owner_subject_id,a.owner_employee_id," + r.dateColumn("a.due_date") + ",a.payload_id,a.recorded_at"
}
func scanInterviewAction(row grantScanner) (interview.ActionRecord, error) {
	var a interview.ActionRecord
	var subject, employee, due sql.NullString
	var recorded dbTime
	err := row.Scan(&a.OrgID, &a.ID, &a.InterviewID, &a.EmployeeID, &a.Number, &a.Status, &a.Owner.Kind, &subject, &employee, &due, &a.PayloadID, &recorded)
	if a.Owner.Kind == "subject" {
		a.Owner.ID = subject.String
	} else {
		a.Owner.ID = employee.String
	}
	a.Revision, a.RecordedAt, a.DueDate = strconv.FormatInt(a.Number, 10), recorded.Time, stringPtr(due)
	a.SourceRefs = make([]interview.SourceRef, 0)
	a.Events = make([]interview.ActionEventView, 0)
	a.EventRecords = make([]interview.Event, 0)
	return a, err
}
func (r reader) InterviewAction(ctx context.Context, org, id string) (interview.ActionRecord, error) {
	a, err := scanInterviewAction(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+r.interviewActionColumns()+" FROM action_item a WHERE a.org_id=? AND a.id=?"), org, id))
	if errors.Is(err, sql.ErrNoRows) {
		return interview.ActionRecord{}, fault.NotFound
	}
	if err != nil {
		return interview.ActionRecord{}, safeError(err)
	}
	if err = r.interviewActionEvents(ctx, &a); err != nil {
		return interview.ActionRecord{}, err
	}
	return a, nil
}
func (r reader) interviewActionEvents(ctx context.Context, a *interview.ActionRecord) error {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,id,action_item_id,interview_id,employee_id,status,revision,payload_id,author_subject_id,recorded_at FROM action_item_event WHERE org_id=? AND action_item_id=? ORDER BY revision,id LIMIT 4"), a.OrgID, a.ID)
	if err != nil {
		return safeError(err)
	}
	for rows.Next() {
		var e interview.Event
		var recorded dbTime
		if err = rows.Scan(&e.OrgID, &e.ID, &e.ActionID, &e.InterviewID, &e.EmployeeID, &e.Status, &e.Number, &e.PayloadID, &e.AuthorSubjectID, &recorded); err != nil {
			rows.Close()
			return safeError(err)
		}
		e.Revision, e.RecordedAt = strconv.FormatInt(e.Number, 10), recorded.Time
		a.EventRecords = append(a.EventRecords, e)
		a.Events = append(a.Events, e.ActionEventView)
		if len(a.EventRecords) > 3 {
			rows.Close()
			return fault.Unavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return safeError(err)
	}
	// Sources are immutable facts belonging to events, not the mutable action pointer.
	for _, event := range a.EventRecords {
		facts, err := r.InterviewSources(ctx, a.OrgID, event.ID)
		if err != nil {
			return err
		}
		for _, fact := range facts {
			a.SourceRefs = append(a.SourceRefs, fact.SourceRef)
		}
	}
	return nil
}
func (r reader) InterviewPayload(ctx context.Context, org, id string) (interview.Payload, error) {
	var p interview.Payload
	var recorded dbTime
	e := &p.Envelope
	c := &e.Context
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM interview_payload WHERE org_id=? AND id=?"), org, id).Scan(&p.ID, &c.OrgID, &c.EmployeeID, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &c.SchemaVersion, &e.FormatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &e.Key.Version, &e.Key.Data, &e.SealedBytes, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return interview.Payload{}, fault.NotFound
	}
	p.RecordedAt = recorded.Time
	return p, safeError(err)
}
func (r reader) InterviewSources(ctx context.Context, org, owner string) ([]interview.SourceFact, error) {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT source_note_version_id,employee_id,category,expected_version,source_epoch FROM source_reference WHERE org_id=? AND (owner_note_version_id=? OR owner_action_event_id=?) ORDER BY source_note_version_id LIMIT 11"), org, owner, owner)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	facts := make([]interview.SourceFact, 0)
	for rows.Next() {
		var fact interview.SourceFact
		var expected int64
		if err = rows.Scan(&fact.ID, &fact.EmployeeID, &fact.Category, &expected, &fact.Epoch); err != nil {
			return nil, safeError(err)
		}
		fact.Kind, fact.ExpectedVersion = "note_version", strconv.FormatInt(expected, 10)
		facts = append(facts, fact)
		if len(facts) > 10 {
			return nil, fault.Unavailable
		}
	}
	return facts, safeError(rows.Err())
}
func (r reader) InterviewReceipt(ctx context.Context, org, subject, operation, key string) (interview.Receipt, bool, error) {
	var receipt interview.Receipt
	var result string
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT digest,result_json FROM interview_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?"), org, subject, operation, key).Scan(&receipt.Digest, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return interview.Receipt{}, false, safeError(err)
	}
	if err = json.Unmarshal([]byte(result), &receipt.Result); err != nil {
		return interview.Receipt{}, false, fault.Unavailable
	}
	return receipt, true, nil
}
func (r reader) InterviewParty(ctx context.Context, org string, party interview.Party, active bool, day string) (bool, error) {
	var query string
	args := []any{org, party.ID}
	switch party.Kind {
	case "subject":
		query = "SELECT EXISTS(SELECT 1 FROM subject s WHERE s.org_id=? AND s.id=?"
		if active {
			query += " AND s.active AND (NOT EXISTS(SELECT 1 FROM subject_employee se WHERE se.org_id=s.org_id AND se.subject_id=s.id) OR EXISTS(SELECT 1 FROM subject_employee se JOIN employee e ON e.org_id=se.org_id AND e.id=se.employee_id WHERE se.org_id=s.org_id AND se.subject_id=s.id AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?)))"
			args = append(args, day, day)
		}
	case "employee":
		query = "SELECT EXISTS(SELECT 1 FROM employee e WHERE e.org_id=? AND e.id=?"
		if active {
			query += " AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?)"
			args = append(args, day, day)
		}
	default:
		return false, fault.Invalid
	}
	query += ")"
	var found bool
	err := r.db.QueryRowContext(ctx, r.structureSQL(query), args...).Scan(&found)
	return found, safeError(err)
}

// Scope is expressed in SQL before keyset pagination and LIMIT. IDs are always
// bound values; only the fixed canonical lineage columns below form predicates.
func interviewScope(scope interview.Scope, columns []string, ids [][]string, args *[]any) string {
	if scope.Broad {
		return "1=1"
	}
	predicates := make([]string, 0, len(columns))
	for i, column := range columns {
		if len(ids[i]) == 0 {
			continue
		}
		predicates = append(predicates, column+" IN ("+structurePlaceholders(len(ids[i]))+")")
		for _, id := range ids[i] {
			*args = append(*args, id)
		}
	}
	if len(predicates) == 0 {
		return "1=0"
	}
	return "(" + strings.Join(predicates, " OR ") + ")"
}
func (r reader) InterviewList(ctx context.Context, org, employee string, query interview.ListQuery, scope interview.Scope, from, to time.Time, after string, limit int) ([]interview.Record, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	args := []any{org, employee}
	predicate := "i.org_id=? AND i.employee_id=?"
	if !from.IsZero() {
		predicate += " AND COALESCE(i.actual_started_at,i.scheduled_at)>=?"
		args = append(args, r.bindTime(from))
	}
	if !to.IsZero() {
		predicate += " AND COALESCE(i.actual_started_at,i.scheduled_at)<?"
		args = append(args, r.bindTime(to))
	}
	if query.Status != "" {
		predicate += " AND i.status=?"
		args = append(args, query.Status)
	}
	predicate += " AND " + interviewScope(scope, []string{"i.id"}, [][]string{scope.Interviews}, &args)
	if after != "" {
		predicate += " AND i.id>?"
		args = append(args, after)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+interviewColumns+" FROM interview i WHERE "+predicate+" ORDER BY i.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	items := make([]interview.Record, 0)
	for rows.Next() {
		item, err := scanInterview(rows)
		if err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safeError(err)
	}
	for i := range items {
		if err = r.interviewParticipants(ctx, &items[i]); err != nil {
			return nil, err
		}
	}
	return items, nil
}
func (r reader) InterviewVersions(ctx context.Context, org, id, category string, scope interview.Scope, after string, limit int) ([]interview.Version, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	args := []any{org, id, category}
	predicate := "v.org_id=? AND v.interview_id=? AND v.category=? AND " + interviewScope(scope, []string{"v.interview_id", "v.head_id", "v.id"}, [][]string{scope.Interviews, scope.Heads, scope.Versions}, &args)
	if after != "" {
		predicate += " AND v.id>?"
		args = append(args, after)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+interviewVersionColumns+" FROM note_version v WHERE "+predicate+" ORDER BY v.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	items := make([]interview.Version, 0)
	for rows.Next() {
		item, err := scanInterviewVersion(rows)
		if err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safeError(err)
	}
	for i := range items {
		facts, err := r.InterviewSources(ctx, org, items[i].ID)
		if err != nil {
			return nil, err
		}
		for _, fact := range facts {
			items[i].SourceRefs = append(items[i].SourceRefs, fact.SourceRef)
		}
	}
	return items, nil
}
func (r reader) InterviewActions(ctx context.Context, org, id string, scope interview.Scope, after string, limit int) ([]interview.ActionRecord, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	args := []any{org, id}
	predicate := "a.org_id=? AND a.interview_id=? AND " + interviewScope(scope, []string{"a.interview_id", "a.id"}, [][]string{scope.Interviews, scope.Actions}, &args)
	if after != "" {
		predicate += " AND a.id>?"
		args = append(args, after)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+r.interviewActionColumns()+" FROM action_item a WHERE "+predicate+" ORDER BY a.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	items := make([]interview.ActionRecord, 0)
	for rows.Next() {
		item, err := scanInterviewAction(rows)
		if err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safeError(err)
	}
	for i := range items {
		if err = r.interviewActionEvents(ctx, &items[i]); err != nil {
			return nil, err
		}
	}
	return items, nil
}
