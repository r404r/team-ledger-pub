package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
)

var _ compensation.Store = (*Repository)(nil)
var _ compensation.Tx = (*transaction)(nil)

func (r *Repository) CompensationAggregate(c context.Context, o, e string) (compensation.Aggregate, error) {
	return r.read().CompensationAggregate(c, o, e)
}
func (r *Repository) CompensationProposal(c context.Context, o, id string) (compensation.ProposalRecord, error) {
	return r.read().CompensationProposal(c, o, id)
}
func (r *Repository) CompensationRevisions(c context.Context, o, id string, before int64, limit int) ([]compensation.RevisionRecord, error) {
	return r.read().CompensationRevisions(c, o, id, before, limit)
}
func (r *Repository) CompensationApproval(c context.Context, o, id string) (compensation.ApprovalRecord, error) {
	return r.read().CompensationApproval(c, o, id)
}
func (r *Repository) CompensationEvent(c context.Context, o, id string) (compensation.EventRecord, error) {
	return r.read().CompensationEvent(c, o, id)
}
func (r *Repository) CompensationTerm(c context.Context, o, id string) (compensation.TermRecord, error) {
	return r.read().CompensationTerm(c, o, id)
}
func (r *Repository) CompensationEvents(c context.Context, o, e string) ([]compensation.EventRecord, error) {
	return r.read().CompensationEvents(c, o, e)
}
func (r *Repository) CompensationApprovalEvents(c context.Context, o, id string, scope compensation.Scope, limit int) ([]compensation.EventRecord, error) {
	return r.read().CompensationApprovalEvents(c, o, id, scope, limit)
}
func (r *Repository) CompensationSchedule(c context.Context, o, e string, q compensation.CurrentQuery) ([]compensation.ScheduleRecord, error) {
	return r.read().CompensationSchedule(c, o, e, q)
}
func (r *Repository) CompensationPayload(c context.Context, o, id string) (compensation.Payload, error) {
	return r.read().CompensationPayload(c, o, id)
}
func (r *Repository) CompensationReceipt(c context.Context, o, s, op, k string) (compensation.Receipt, bool, error) {
	return r.read().CompensationReceipt(c, o, s, op, k)
}
func (r *Repository) CompensationProposals(c context.Context, o, e string, q compensation.ChangesQuery, s compensation.Scope, f, t time.Time, a string, l int) ([]compensation.ProposalRecord, error) {
	return r.read().CompensationProposals(c, o, e, q, s, f, t, a, l)
}
func (r *Repository) CompensationApprovals(c context.Context, o, e string, q compensation.ChangesQuery, s compensation.Scope, f, t time.Time, a string, l int) ([]compensation.ApprovalRecord, error) {
	return r.read().CompensationApprovals(c, o, e, q, s, f, t, a, l)
}

func compensationReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound
	}
	return safeError(err)
}
func (r reader) CompensationAggregate(ctx context.Context, org, employee string) (compensation.Aggregate, error) {
	a := compensation.Aggregate{OrgID: org, EmployeeID: employee}
	err := r.db.QueryRowContext(ctx, r.sql("SELECT revision FROM compensation_aggregate WHERE org_id=? AND employee_id=?", "SELECT revision FROM compensation_aggregate WHERE org_id=$1 AND employee_id=$2"), org, employee).Scan(&a.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return a, nil
	}
	return a, safeError(err)
}
func (r reader) compensationProposalColumns() string {
	return "p.org_id,p.employee_id,p.id,p.kind,p.status,p.author_subject_id,p.revision_id,p.payload_id," + r.dateColumn("p.effective_date") + ",p.before_term_id,p.revision,p.basis_revision,p.recorded_at,p.approval_id"
}
func scanCompensationProposal(row grantScanner) (compensation.ProposalRecord, error) {
	var v compensation.ProposalRecord
	var at dbTime
	err := row.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.Kind, &v.Status, &v.AuthorSubjectID, &v.RevisionID, &v.PayloadID, &v.EffectiveDate, &v.BeforeTermID, &v.Revision, &v.BasisRevision, &at, &v.ApprovalID)
	v.RecordedAt = at.Time
	return v, compensationReadError(err)
}
func (r reader) CompensationProposal(ctx context.Context, org, id string) (compensation.ProposalRecord, error) {
	return scanCompensationProposal(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+r.compensationProposalColumns()+" FROM compensation_proposal p WHERE p.org_id=? AND p.id=?"), org, id))
}
func (r reader) CompensationRevisions(ctx context.Context, org, id string, before int64, limit int) ([]compensation.RevisionRecord, error) {
	if before < 0 || limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	predicate := "org_id=? AND proposal_id=?"
	args := []any{org, id}
	if before != 0 {
		predicate += " AND revision<?"
		args = append(args, before)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,proposal_id,payload_id,status,kind,"+r.dateColumn("effective_date")+",actor_subject_id,before_term_id,revision,basis_revision,recorded_at FROM compensation_proposal_revision WHERE "+predicate+" ORDER BY revision DESC LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.RevisionRecord, 0, limit)
	for rows.Next() {
		var v compensation.RevisionRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.ProposalID, &v.PayloadID, &v.Status, &v.Kind, &v.EffectiveDate, &v.ActorSubjectID, &v.BeforeTermID, &v.Revision, &v.BasisRevision, &at); err != nil {
			return nil, safeError(err)
		}
		v.RecordedAt = at.Time
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}

const compensationApprovalColumns = "a.org_id,a.employee_id,a.id,a.proposal_id,a.proposal_revision_id,a.approver_subject_id,a.author_subject_id,a.payload_id,a.proposal_revision,a.basis_revision,a.comp_revision,a.recorded_at"

func scanCompensationApproval(row grantScanner) (compensation.ApprovalRecord, error) {
	var v compensation.ApprovalRecord
	var at dbTime
	err := row.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.ProposalID, &v.ProposalRevisionID, &v.ApproverSubjectID, &v.AuthorSubjectID, &v.PayloadID, &v.ProposalRevision, &v.BasisRevision, &v.CompRevision, &at)
	v.RecordedAt = at.Time
	return v, compensationReadError(err)
}
func (r reader) CompensationApproval(ctx context.Context, org, id string) (compensation.ApprovalRecord, error) {
	return scanCompensationApproval(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+compensationApprovalColumns+" FROM compensation_approval a WHERE a.org_id=? AND a.id=?"), org, id))
}
func (r reader) compensationEventColumns() string {
	return "org_id,employee_id,id,approval_id,kind," + r.dateColumn("effective_date") + ",member_key,before_term_id,after_term_id,corrects_event_id,sequence"
}
func scanCompensationEvent(row grantScanner) (compensation.EventRecord, error) {
	var v compensation.EventRecord
	err := row.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.ApprovalID, &v.Kind, &v.EffectiveDate, &v.MemberKey, &v.BeforeTermID, &v.AfterTermID, &v.CorrectsEventID, &v.Sequence)
	return v, compensationReadError(err)
}
func (r reader) CompensationEvent(ctx context.Context, org, id string) (compensation.EventRecord, error) {
	return scanCompensationEvent(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+r.compensationEventColumns()+" FROM compensation_event WHERE org_id=? AND id=?"), org, id))
}
func (r reader) CompensationEvents(ctx context.Context, org, employee string) ([]compensation.EventRecord, error) {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+r.compensationEventColumns()+" FROM compensation_event WHERE org_id=? AND employee_id=? ORDER BY sequence,id"), org, employee)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.EventRecord, 0)
	for rows.Next() {
		v, e := scanCompensationEvent(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}
func (r reader) CompensationApprovalEvents(ctx context.Context, org, approval string, scope compensation.Scope, limit int) ([]compensation.EventRecord, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	predicate := "org_id=? AND approval_id=?"
	args := []any{org, approval}
	if !scope.Broad {
		if len(scope.Events) == 0 {
			return []compensation.EventRecord{}, nil
		}
		predicate += " AND id IN (" + structurePlaceholders(len(scope.Events)) + ")"
		for _, id := range scope.Events {
			args = append(args, id)
		}
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+r.compensationEventColumns()+" FROM compensation_event WHERE "+predicate+" ORDER BY sequence,id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.EventRecord, 0, limit)
	for rows.Next() {
		v, err := scanCompensationEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}
func (r reader) CompensationTerm(ctx context.Context, org, id string) (compensation.TermRecord, error) {
	var v compensation.TermRecord
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,event_id,approval_id,payload_id,"+r.dateColumn("effective_date")+",version_no FROM compensation_terms_version WHERE org_id=? AND id=?"), org, id).Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.EventID, &v.ApprovalID, &v.PayloadID, &v.EffectiveDate, &v.Version)
	return v, compensationReadError(err)
}
func scanCompensationSchedule(row grantScanner) (compensation.ScheduleRecord, error) {
	var v compensation.ScheduleRecord
	err := row.Scan(&v.OrgID, &v.EmployeeID, &v.EffectiveDate, &v.ValidTo, &v.TermID, &v.EventID, &v.Revision)
	return v, compensationReadError(err)
}
func (r reader) CompensationSchedule(ctx context.Context, org, employee string, q compensation.CurrentQuery) ([]compensation.ScheduleRecord, error) {
	if q.FutureLimit < 1 || q.FutureLimit > 100 {
		return nil, fault.Invalid
	}
	columns := "org_id,employee_id," + r.dateColumn("effective_date") + "," + r.dateColumn("valid_to") + ",term_id,event_id,revision"
	// Both seeks use the (org_id, employee_id, effective_date) primary key.
	// Only the immediately preceding interval can cover as_of in a projection
	// rebuilt from the approved chain; never scan or allocate its entire history.
	out := make([]compensation.ScheduleRecord, 0, q.FutureLimit+1)
	current, err := scanCompensationSchedule(r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+columns+" FROM compensation_schedule_projection WHERE org_id=? AND employee_id=? AND effective_date<=? ORDER BY effective_date DESC,term_id LIMIT 1"), org, employee, q.AsOf))
	if err == nil {
		out = append(out, current)
	} else if !errors.Is(err, fault.NotFound) {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+columns+" FROM compensation_schedule_projection WHERE org_id=? AND employee_id=? AND effective_date>? ORDER BY effective_date,term_id LIMIT ?"), org, employee, q.AsOf, q.FutureLimit)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanCompensationSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}
func (r reader) CompensationPayload(ctx context.Context, org, id string) (compensation.Payload, error) {
	var p compensation.Payload
	var at dbTime
	e := &p.Envelope
	c := &e.Context
	err := r.db.QueryRowContext(ctx, r.sql("SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM compensation_payload WHERE org_id=? AND id=?", "SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM compensation_payload WHERE org_id=$1 AND id=$2"), org, id).Scan(&p.ID, &c.OrgID, &c.EmployeeID, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &c.SchemaVersion, &e.FormatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &e.Key.Version, &e.Key.Data, &e.SealedBytes, &at)
	p.RecordedAt = at.Time
	return p, compensationReadError(err)
}
func (r reader) CompensationReceipt(ctx context.Context, org, subject, operation, key string) (compensation.Receipt, bool, error) {
	var v compensation.Receipt
	var result string
	err := r.db.QueryRowContext(ctx, r.sql("SELECT digest,result_json FROM compensation_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?", "SELECT digest,result_json FROM compensation_command_receipt WHERE org_id=$1 AND subject_id=$2 AND operation=$3 AND key=$4"), org, subject, operation, key).Scan(&v.Digest, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, safeError(err)
	}
	if json.Unmarshal([]byte(result), &v.Result) != nil || v.Result.Proposal != nil {
		return compensation.Receipt{}, false, fault.Unavailable
	}
	return v, true, nil
}

// Only exact proposal grants enter proposal history. Event grants select an
// approval containing that event; the domain redacts its other events/terms.
func compensationHistoryScope(scope compensation.Scope, approval bool, args *[]any) string {
	if scope.Broad {
		return "1=1"
	}
	ids := scope.Proposals
	column := "p.id"
	if approval {
		ids = scope.Events
		column = "e.id"
	}
	if len(ids) == 0 {
		return "1=0"
	}
	for _, id := range ids {
		*args = append(*args, id)
	}
	predicate := column + " IN (" + structurePlaceholders(len(ids)) + ")"
	if approval {
		return "EXISTS (SELECT 1 FROM compensation_event e WHERE e.org_id=a.org_id AND e.employee_id=a.employee_id AND e.approval_id=a.id AND " + predicate + ")"
	}
	return predicate
}
func (r reader) compensationHistoryPredicate(org, employee string, q compensation.ChangesQuery, scope compensation.Scope, from, to time.Time, after string, approval bool) (string, []any, error) {
	alias := "p"
	if approval {
		alias = "a"
	}
	args := []any{org, employee}
	p := alias + ".org_id=? AND " + alias + ".employee_id=?"
	if !from.IsZero() {
		p += " AND " + alias + ".recorded_at>=?"
		args = append(args, r.bindTime(from))
	}
	if !to.IsZero() {
		p += " AND " + alias + ".recorded_at<?"
		args = append(args, r.bindTime(to))
	}
	if q.ProposalID != "" {
		column := alias + ".id"
		if approval {
			column = "a.proposal_id"
		}
		p += " AND " + column + "=?"
		args = append(args, q.ProposalID)
	}
	if q.Status != "" {
		if approval {
			if q.Status != "approved" {
				p += " AND 1=0"
			}
		} else {
			p += " AND p.status=?"
			args = append(args, q.Status)
		}
	}
	if q.RecordKind != "" && ((approval && q.RecordKind != "approvals") || (!approval && q.RecordKind != "proposals")) {
		p += " AND 1=0"
	}
	p += " AND " + compensationHistoryScope(scope, approval, &args)
	if after != "" {
		parts := strings.SplitN(after, "|", 2)
		if len(parts) != 2 || parts[1] == "" {
			return "", nil, fault.Invalid
		}
		at, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return "", nil, fault.Invalid
		}
		p += " AND (" + alias + ".recorded_at>? OR (" + alias + ".recorded_at=? AND " + alias + ".id>?))"
		args = append(args, r.bindTime(at), r.bindTime(at), parts[1])
	}
	return p, args, nil
}
func (r reader) CompensationProposals(ctx context.Context, org, employee string, q compensation.ChangesQuery, scope compensation.Scope, from, to time.Time, after string, limit int) ([]compensation.ProposalRecord, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	p, args, err := r.compensationHistoryPredicate(org, employee, q, scope, from, to, after, false)
	if err != nil {
		return nil, err
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+r.compensationProposalColumns()+" FROM compensation_proposal p WHERE "+p+" ORDER BY p.recorded_at,p.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.ProposalRecord, 0)
	for rows.Next() {
		v, e := scanCompensationProposal(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}
func (r reader) CompensationApprovals(ctx context.Context, org, employee string, q compensation.ChangesQuery, scope compensation.Scope, from, to time.Time, after string, limit int) ([]compensation.ApprovalRecord, error) {
	if limit < 1 || limit > 101 {
		return nil, fault.Invalid
	}
	p, args, err := r.compensationHistoryPredicate(org, employee, q, scope, from, to, after, true)
	if err != nil {
		return nil, err
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT "+compensationApprovalColumns+" FROM compensation_approval a WHERE "+p+" ORDER BY a.recorded_at,a.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.ApprovalRecord, 0)
	for rows.Next() {
		v, e := scanCompensationApproval(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, safeError(rows.Err())
}
