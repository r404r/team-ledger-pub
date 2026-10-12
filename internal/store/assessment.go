package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (r *Repository) WithAssessmentTx(ctx context.Context, org string, fn func(assessment.Tx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}

func (r *Repository) AssessmentPolicy(ctx context.Context, org, employee string) (assessment.Policy, bool, error) {
	return r.read().AssessmentPolicy(ctx, org, employee)
}
func (t *transaction) AssessmentPolicy(ctx context.Context, org, employee string) (assessment.Policy, bool, error) {
	return t.reader.AssessmentPolicy(ctx, org, employee)
}
func (r reader) AssessmentPolicy(ctx context.Context, org, employee string) (assessment.Policy, bool, error) {
	return r.assessmentPolicyQuery(ctx, "interview_policy", "", org, employee, 0)
}

func (r reader) assessmentPolicyQuery(ctx context.Context, table, suffix, org, employee string, revision int64) (assessment.Policy, bool, error) {
	querySQLite := "SELECT revision,cadence_unit,cadence_count,anchor_date,timezone,due_offset_days,local_due_time,window_through,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at FROM " + table + " WHERE org_id=? AND employee_id=?" + suffix
	queryPostgres := "SELECT revision,cadence_unit,cadence_count,anchor_date::text,timezone,due_offset_days,local_due_time,window_through::text,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at FROM " + table + " WHERE org_id=$1 AND employee_id=$2" + suffix
	args := []any{org, employee}
	if revision != 0 {
		querySQLite += " AND revision=?"
		queryPostgres += " AND revision=$3"
		args = append(args, revision)
	}
	var out assessment.Policy
	var cadenceCount, dueOffset int
	var pauseRaw, requiredRaw string
	var updated dbTime
	err := r.db.QueryRowContext(ctx, r.sql(querySQLite, queryPostgres), args...).Scan(&out.Revision, &out.Cadence.Unit, &cadenceCount, &out.AnchorDate, &out.Timezone, &dueOffset, &out.LocalDueTime, &out.WindowThrough, &pauseRaw, &out.Purpose, &out.AIMode, &requiredRaw, &out.UpdatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil || json.Unmarshal([]byte(pauseRaw), &out.PauseIntervals) != nil || json.Unmarshal([]byte(requiredRaw), &out.RequiredFields) != nil {
		return out, false, fault.Unavailable
	}
	out.OrgID, out.EmployeeID, out.Cadence.Count, out.DueOffsetDays, out.UpdatedAt = org, employee, cadenceCount, dueOffset, updated.Time
	return out, true, nil
}

func (r *Repository) AssessmentWindows(ctx context.Context, org, employee string, revision int64) ([]assessment.Window, error) {
	return r.read().AssessmentWindows(ctx, org, employee, revision)
}
func (t *transaction) AssessmentWindows(ctx context.Context, org, employee string, revision int64) ([]assessment.Window, error) {
	return t.reader.AssessmentWindows(ctx, org, employee, revision)
}
func (r reader) AssessmentWindows(ctx context.Context, org, employee string, revision int64) ([]assessment.Window, error) {
	rows, err := r.db.QueryContext(ctx, r.sql("SELECT id,policy_revision,local_start,local_end,start_at,end_at,due_at,paused FROM followup_window WHERE org_id=? AND employee_id=? AND policy_revision=? ORDER BY start_at,id LIMIT 1001", "SELECT id,policy_revision,local_start::text,local_end::text,start_at,end_at,due_at,paused FROM followup_window WHERE org_id=$1 AND employee_id=$2 AND policy_revision=$3 ORDER BY start_at,id LIMIT 1001"), org, employee, revision)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []assessment.Window{}
	for rows.Next() {
		var window assessment.Window
		var start, end, due dbTime
		if err = rows.Scan(&window.ID, &window.PolicyRevision, &window.LocalStart, &window.LocalEnd, &start, &end, &due, &window.Paused); err != nil {
			return nil, safeError(err)
		}
		window.OrgID, window.EmployeeID, window.StartAt, window.EndAt, window.DueAt = org, employee, start.Time, end.Time, due.Time
		out = append(out, window)
	}
	if err = rows.Err(); err != nil || len(out) > 1000 {
		return nil, fault.Unavailable
	}
	return out, nil
}

func (r *Repository) AssessmentWindow(ctx context.Context, org, employee, id string) (assessment.Window, error) {
	return r.read().AssessmentWindow(ctx, org, employee, id)
}
func (t *transaction) AssessmentWindow(ctx context.Context, org, employee, id string) (assessment.Window, error) {
	return t.reader.AssessmentWindow(ctx, org, employee, id)
}
func (r reader) AssessmentWindow(ctx context.Context, org, employee, id string) (assessment.Window, error) {
	var out assessment.Window
	var start, end, due dbTime
	err := r.db.QueryRowContext(ctx, r.sql("SELECT policy_revision,local_start,local_end,start_at,end_at,due_at,paused FROM followup_window WHERE org_id=? AND employee_id=? AND id=?", "SELECT policy_revision,local_start::text,local_end::text,start_at,end_at,due_at,paused FROM followup_window WHERE org_id=$1 AND employee_id=$2 AND id=$3"), org, employee, id).Scan(&out.PolicyRevision, &out.LocalStart, &out.LocalEnd, &start, &end, &due, &out.Paused)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	out.OrgID, out.EmployeeID, out.ID, out.StartAt, out.EndAt, out.DueAt = org, employee, id, start.Time, end.Time, due.Time
	return out, nil
}

func (r *Repository) AssessmentInterviewFacts(ctx context.Context, org, employee string, window assessment.Window, includeNotes bool) ([]assessment.InterviewFact, error) {
	return r.read().AssessmentInterviewFacts(ctx, org, employee, window, includeNotes)
}
func (t *transaction) AssessmentInterviewFacts(ctx context.Context, org, employee string, window assessment.Window, includeNotes bool) ([]assessment.InterviewFact, error) {
	return t.reader.AssessmentInterviewFacts(ctx, org, employee, window, includeNotes)
}
func (r reader) AssessmentInterviewFacts(ctx context.Context, org, employee string, window assessment.Window, includeNotes bool) ([]assessment.InterviewFact, error) {
	start, end := r.bindTime(window.StartAt), r.bindTime(window.EndAt)
	query := "SELECT i.id,i.status,i.scheduled_at,i.actual_started_at IS NOT NULL,COALESCE(i.actual_started_at,i.scheduled_at),i.actual_ended_at IS NOT NULL,COALESCE(i.actual_ended_at,i.scheduled_at),i.backfilled,CASE WHEN ? THEN EXISTS(SELECT 1 FROM note_head h WHERE h.org_id=i.org_id AND h.interview_id=i.id AND h.employee_id=i.employee_id AND h.category='shared' AND h.published_version_id IS NOT NULL) ELSE 0 END FROM interview i WHERE i.org_id=? AND i.employee_id=? AND ((i.scheduled_at>=? AND i.scheduled_at<?) OR (i.actual_started_at>=? AND i.actual_started_at<?)) ORDER BY i.id LIMIT 1001"
	args := []any{includeNotes, org, employee, start, end, start, end}
	if r.backend == "postgres" {
		query = "SELECT i.id,i.status,i.scheduled_at,i.actual_started_at IS NOT NULL,COALESCE(i.actual_started_at,i.scheduled_at),i.actual_ended_at IS NOT NULL,COALESCE(i.actual_ended_at,i.scheduled_at),i.backfilled,CASE WHEN $1 THEN EXISTS(SELECT 1 FROM note_head h WHERE h.org_id=i.org_id AND h.interview_id=i.id AND h.employee_id=i.employee_id AND h.category='shared' AND h.published_version_id IS NOT NULL) ELSE false END FROM interview i WHERE i.org_id=$2 AND i.employee_id=$3 AND ((i.scheduled_at>=$4 AND i.scheduled_at<$5) OR (i.actual_started_at>=$4 AND i.actual_started_at<$5)) ORDER BY i.id LIMIT 1001"
		args = []any{includeNotes, org, employee, start, end}
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []assessment.InterviewFact{}
	for rows.Next() {
		var fact assessment.InterviewFact
		var scheduled, started, ended dbTime
		var hasStarted, hasEnded bool
		if err = rows.Scan(&fact.ID, &fact.Status, &scheduled, &hasStarted, &started, &hasEnded, &ended, &fact.Backfilled, &fact.HasPublishedSharedNote); err != nil {
			return nil, safeError(err)
		}
		fact.ScheduledAt = scheduled.Time
		if hasStarted {
			fact.ActualStartedAt = &started.Time
		}
		if hasEnded {
			fact.ActualEndedAt = &ended.Time
		}
		out = append(out, fact)
	}
	if err = rows.Err(); err != nil || len(out) > 1000 {
		return nil, fault.Unavailable
	}
	return out, nil
}

func (r *Repository) AssessmentActionFacts(ctx context.Context, org, employee string, allowed bool) ([]assessment.ActionFact, error) {
	return r.read().AssessmentActionFacts(ctx, org, employee, allowed)
}
func (t *transaction) AssessmentActionFacts(ctx context.Context, org, employee string, allowed bool) ([]assessment.ActionFact, error) {
	return t.reader.AssessmentActionFacts(ctx, org, employee, allowed)
}
func (r reader) AssessmentActionFacts(ctx context.Context, org, employee string, allowed bool) ([]assessment.ActionFact, error) {
	if !allowed {
		return []assessment.ActionFact{}, nil
	}
	rows, err := r.db.QueryContext(ctx, r.sql("SELECT a.status,a.due_date,i.actual_started_at FROM action_item a JOIN interview i ON i.org_id=a.org_id AND i.employee_id=a.employee_id AND i.id=a.interview_id WHERE a.org_id=? AND a.employee_id=? AND i.actual_started_at IS NOT NULL ORDER BY a.id LIMIT 1001", "SELECT a.status,a.due_date::text,i.actual_started_at FROM action_item a JOIN interview i ON i.org_id=a.org_id AND i.employee_id=a.employee_id AND i.id=a.interview_id WHERE a.org_id=$1 AND a.employee_id=$2 AND i.actual_started_at IS NOT NULL ORDER BY a.id LIMIT 1001"), org, employee)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []assessment.ActionFact{}
	for rows.Next() {
		var fact assessment.ActionFact
		var due sql.NullString
		var occurred dbTime
		if err = rows.Scan(&fact.Status, &due, &occurred); err != nil {
			return nil, safeError(err)
		}
		fact.OccurredAt = occurred.Time
		if due.Valid {
			fact.DueDate = &due.String
		}
		out = append(out, fact)
	}
	if err = rows.Err(); err != nil || len(out) > 1000 {
		return nil, fault.Unavailable
	}
	return out, nil
}

func (r *Repository) AssessmentReceipt(ctx context.Context, org, subject, key string) (assessment.Receipt, bool, error) {
	return r.read().AssessmentReceipt(ctx, org, subject, key)
}
func (t *transaction) AssessmentReceipt(ctx context.Context, org, subject, key string) (assessment.Receipt, bool, error) {
	return t.reader.AssessmentReceipt(ctx, org, subject, key)
}
func (r reader) AssessmentReceipt(ctx context.Context, org, subject, key string) (assessment.Receipt, bool, error) {
	var out assessment.Receipt
	var employee string
	var revision int64
	err := r.db.QueryRowContext(ctx, r.sql("SELECT digest,employee_id,result_revision FROM assessment_command_receipt WHERE org_id=? AND subject_id=? AND operation='OP-AI-01' AND key=?", "SELECT digest,employee_id,result_revision FROM assessment_command_receipt WHERE org_id=$1 AND subject_id=$2 AND operation='OP-AI-01' AND key=$3"), org, subject, key).Scan(&out.Digest, &employee, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, safeError(err)
	}
	policy, found, err := r.assessmentPolicyQuery(ctx, "interview_policy_version", "", org, employee, revision)
	if err != nil || !found {
		return out, false, fault.Unavailable
	}
	out.Policy = policy
	return out, true, nil
}

func (t *transaction) SaveAssessmentPolicy(ctx context.Context, policy assessment.Policy, windows []assessment.Window) error {
	if policy.OrgID != t.org || policy.Revision < 1 || len(windows) == 0 || len(windows) > 1000 {
		return fault.Invalid
	}
	pauses, err := json.Marshal(append([]assessment.PauseInterval{}, policy.PauseIntervals...))
	if err != nil {
		return fault.Invalid
	}
	required, err := json.Marshal(append([]string{}, policy.RequiredFields...))
	if err != nil {
		return fault.Invalid
	}
	args := []any{policy.OrgID, policy.EmployeeID, policy.Revision, policy.Cadence.Unit, policy.Cadence.Count, policy.AnchorDate, policy.Timezone, policy.DueOffsetDays, policy.LocalDueTime, policy.WindowThrough, string(pauses), policy.Purpose, policy.AIMode, string(required), policy.UpdatedBy, t.bindTime(policy.UpdatedAt)}
	insertSQLite := "INSERT INTO interview_policy_version(org_id,employee_id,revision,cadence_unit,cadence_count,anchor_date,timezone,due_offset_days,local_due_time,window_through,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	insertPostgres := "INSERT INTO interview_policy_version(org_id,employee_id,revision,cadence_unit,cadence_count,anchor_date,timezone,due_offset_days,local_due_time,window_through,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"
	if _, err = t.tx.ExecContext(ctx, t.sql(insertSQLite, insertPostgres), args...); err != nil {
		return safeError(err)
	}
	if _, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO interview_policy(org_id,employee_id,revision,cadence_unit,cadence_count,anchor_date,timezone,due_offset_days,local_due_time,window_through,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(org_id,employee_id) DO UPDATE SET revision=excluded.revision,cadence_unit=excluded.cadence_unit,cadence_count=excluded.cadence_count,anchor_date=excluded.anchor_date,timezone=excluded.timezone,due_offset_days=excluded.due_offset_days,local_due_time=excluded.local_due_time,window_through=excluded.window_through,pause_json=excluded.pause_json,purpose=excluded.purpose,ai_mode=excluded.ai_mode,required_fields_json=excluded.required_fields_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at", "INSERT INTO interview_policy(org_id,employee_id,revision,cadence_unit,cadence_count,anchor_date,timezone,due_offset_days,local_due_time,window_through,pause_json,purpose,ai_mode,required_fields_json,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(org_id,employee_id) DO UPDATE SET revision=excluded.revision,cadence_unit=excluded.cadence_unit,cadence_count=excluded.cadence_count,anchor_date=excluded.anchor_date,timezone=excluded.timezone,due_offset_days=excluded.due_offset_days,local_due_time=excluded.local_due_time,window_through=excluded.window_through,pause_json=excluded.pause_json,purpose=excluded.purpose,ai_mode=excluded.ai_mode,required_fields_json=excluded.required_fields_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at"), args...); err != nil {
		return safeError(err)
	}
	for _, window := range windows {
		state, reason := "disabled", ""
		if policy.AIMode == "manual_approved" {
			state = "awaiting_manual_input"
		} else if policy.AIMode == "periodic_structured_v1" {
			state, reason = "blocked", "automation_not_enabled"
		}
		_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO followup_window(org_id,employee_id,id,policy_revision,local_start,local_end,start_at,end_at,due_at,paused,automation_state,block_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", "INSERT INTO followup_window(org_id,employee_id,id,policy_revision,local_start,local_end,start_at,end_at,due_at,paused,automation_state,block_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"), policy.OrgID, policy.EmployeeID, window.ID, policy.Revision, window.LocalStart, window.LocalEnd, t.bindTime(window.StartAt), t.bindTime(window.EndAt), t.bindTime(window.DueAt), window.Paused, state, nullable(reason))
		if err != nil {
			return safeError(err)
		}
	}
	return nil
}

func (t *transaction) SaveAssessmentReceipt(ctx context.Context, org, subject, key string, receipt assessment.Receipt) error {
	if org != t.org || len(receipt.Digest) != 32 || receipt.Policy.OrgID != org || receipt.Policy.Revision < 1 {
		return fault.Invalid
	}
	result, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_command_receipt(org_id,subject_id,operation,key,digest,employee_id,result_revision,recorded_at) VALUES(?,?,'OP-AI-01',?,?,?,?,?)", "INSERT INTO assessment_command_receipt(org_id,subject_id,operation,key,digest,employee_id,result_revision,recorded_at) VALUES($1,$2,'OP-AI-01',$3,$4,$5,$6,$7)"), org, subject, key, receipt.Digest, receipt.Policy.EmployeeID, receipt.Policy.Revision, t.bindTime(receipt.Policy.UpdatedAt))
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return fault.Unavailable
	}
	return nil
}
