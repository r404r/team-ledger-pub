package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

var _ authz.Store = (*Repository)(nil)
var _ authz.Tx = (*transaction)(nil)

func (r *Repository) Authorities(ctx context.Context, org, subject string, now time.Time) ([]authz.Authority, error) {
	return r.read().Authorities(ctx, org, subject, now)
}
func (r *Repository) Grant(ctx context.Context, org, id string) (authz.GrantDTO, error) {
	return r.read().Grant(ctx, org, id)
}
func (r *Repository) VisibleGrants(ctx context.Context, org string, authorities []authz.Authority, filter authz.Filter, after string, now time.Time) ([]authz.GrantDTO, error) {
	return r.read().VisibleGrants(ctx, org, authorities, filter, after, now)
}
func (r *Repository) Qualified(ctx context.Context, org, subject, capability string, scope authz.Scope, now time.Time) (bool, error) {
	return r.read().Qualified(ctx, org, subject, capability, scope, now)
}
func (r *Repository) ScopeCovered(ctx context.Context, org string, outer, inner authz.Scope, now time.Time) (bool, error) {
	return r.read().ScopeCovered(ctx, org, outer, inner, now)
}
func (r *Repository) RelationQualified(ctx context.Context, org, subject string, scope authz.Scope, ref authz.RelationReference, now time.Time) (bool, error) {
	return r.read().RelationQualified(ctx, org, subject, scope, ref, now)
}
func (r *Repository) OwnsScope(ctx context.Context, org string, scope authz.Scope, now time.Time) (bool, error) {
	return r.read().OwnsScope(ctx, org, scope, now)
}
func (r *Repository) GrantReceipt(ctx context.Context, org, subject, operation, key string) (authz.Receipt, bool, error) {
	return r.read().GrantReceipt(ctx, org, subject, operation, key)
}

func (r *Repository) WithGrantTx(ctx context.Context, org string, fn func(authz.Tx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}

func (t *transaction) LockSubjects(ctx context.Context, org string, subjects []string) error {
	if org != t.org {
		return fault.NotFound
	}
	ids := append([]string(nil), subjects...)
	sort.Strings(ids)
	previous := ""
	for _, id := range ids {
		if id == previous {
			continue
		}
		if !value.ValidID(id) {
			return fault.Invalid
		}
		previous = id
		var epoch int64
		err := t.tx.QueryRowContext(ctx, t.sql("SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2 FOR UPDATE"), org, id).Scan(&epoch)
		if errors.Is(err, sql.ErrNoRows) {
			return fault.Forbidden
		}
		if err != nil {
			return safeError(err)
		}
	}
	return nil
}

func (r reader) bindTime(at time.Time) any {
	if r.backend == "sqlite" {
		return at.UTC().UnixMicro()
	}
	return at.UTC().Truncate(time.Microsecond)
}

func (r reader) Authorities(ctx context.Context, org, subject string, now time.Time) ([]authz.Authority, error) {
	rows, err := r.db.QueryContext(ctx, r.sql(
		"SELECT id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version FROM delegation_authority WHERE org_id=? AND manager_subject_id=? AND valid_from<=? AND expires_at>? ORDER BY id LIMIT 1001",
		"SELECT id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version FROM delegation_authority WHERE org_id=$1 AND manager_subject_id=$2 AND valid_from<=$3 AND expires_at>$4 ORDER BY id COLLATE \"C\" LIMIT 1001"), org, subject, r.bindTime(now), r.bindTime(now))
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := make([]authz.Authority, 0)
	for rows.Next() {
		var a authz.Authority
		var from, to, approved dbTime
		if err := rows.Scan(&a.ID, &a.Capability, &a.Category, &a.Scope.Kind, &a.Scope.ID, &a.Purpose, &from, &to, &a.MFARequired, &a.ApprovedBy, &approved, &a.PolicyVersion); err != nil {
			return nil, safeError(err)
		}
		a.ValidFrom, a.ExpiresAt, a.ApprovedAt = from.Time, to.Time, approved.Time
		items = append(items, a)
		if len(items) > 1000 {
			return nil, fault.Unavailable
		}
	}
	return items, safeError(rows.Err())
}

const grantColumns = "g.id,g.org_id,g.subject_id,g.capability,g.category,g.scope_kind,g.scope_id,g.purpose,g.valid_from,g.expires_at,g.mfa_required,g.relation_bound,g.revision,g.revoked,g.authority_id,a.policy_version,a.approved_by,a.approved_at,g.issued_by,g.issued_at,g.revoked_by,g.revoked_at,g.revoke_reason,g.relation_kind,g.reporting_line_id,g.job_assignment_id,g.relation_actor_employee_id,g.object_kind,g.object_ref"
const grantJoin = " FROM access_grant g LEFT JOIN delegation_authority a ON a.org_id=g.org_id AND a.id=g.authority_id"

type grantScanner interface{ Scan(...any) error }
type nullDBTime struct {
	time.Time
	Valid bool
}

func (t *nullDBTime) Scan(value any) error {
	if value == nil {
		t.Valid = false
		return nil
	}
	var parsed dbTime
	if err := parsed.Scan(value); err != nil {
		return err
	}
	t.Time, t.Valid = parsed.Time, true
	return nil
}
func stringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}
func timePtr(v nullDBTime) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}
func scanGrant(row grantScanner, now time.Time) (authz.GrantDTO, error) {
	var g authz.GrantDTO
	var revision int64
	var revoked bool
	var from, to dbTime
	var authority, policy, approver, issuer, revoker, reason sql.NullString
	var relationKind, reportingID, assignmentID, actorID, objectKind, objectID sql.NullString
	var approved, issued, revokedAt nullDBTime
	err := row.Scan(&g.ID, &g.OrgID, &g.SubjectID, &g.Capability, &g.Category, &g.Scope.Kind, &g.Scope.ID, &g.Purpose, &from, &to, &g.MFARequired, &g.RelationBound, &revision, &revoked, &authority, &policy, &approver, &approved, &issuer, &issued, &revoker, &revokedAt, &reason, &relationKind, &reportingID, &assignmentID, &actorID, &objectKind, &objectID)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.GrantDTO{}, fault.NotFound
	}
	if err != nil {
		return authz.GrantDTO{}, safeError(err)
	}
	if revision < 1 {
		return authz.GrantDTO{}, fault.Unavailable
	}
	g.Revision, g.ValidFrom, g.ExpiresAt = strconv.FormatInt(revision, 10), from.Time, to.Time
	g.AuthorityID, g.PolicyVersion, g.ApprovedBy, g.ApprovedAt = stringPtr(authority), stringPtr(policy), stringPtr(approver), timePtr(approved)
	g.IssuedBy, g.IssuedAt = stringPtr(issuer), timePtr(issued)
	g.RevokedBy, g.RevokedAt, g.RevokeReason = stringPtr(revoker), timePtr(revokedAt), stringPtr(reason)
	g.RelationActorEmployeeID = actorID.String
	if relationKind.Valid {
		id := assignmentID.String
		if relationKind.String == "reporting_line" {
			id = reportingID.String
		}
		g.RelationRef = &authz.RelationReference{Kind: relationKind.String, ID: id}
	}
	if objectKind.Valid {
		g.ObjectRef = &authz.ObjectReference{Kind: objectKind.String, ID: objectID.String}
	}
	switch {
	case revoked:
		g.Status = "revoked"
	case now.Before(g.ValidFrom):
		g.Status = "future"
	case !now.Before(g.ExpiresAt):
		g.Status = "expired"
	default:
		g.Status = "current"
	}
	return g, nil
}

func (r reader) Grant(ctx context.Context, org, id string) (authz.GrantDTO, error) {
	q := "SELECT " + grantColumns + grantJoin + r.sql(" WHERE g.org_id=? AND g.id=?", " WHERE g.org_id=$1 AND g.id=$2")
	g, err := scanGrant(r.db.QueryRowContext(ctx, q, org, id), time.Now().UTC())
	return r.grantApprovals(ctx, g, err)
}

func (r reader) OwnsScope(ctx context.Context, org string, scope authz.Scope, now time.Time) (bool, error) {
	if scope.Kind == "org" {
		return scope.ID == org, nil
	}
	day, err := r.organizationDate(ctx, org, now)
	if err != nil {
		return false, err
	}
	var q string
	switch scope.Kind {
	case "employee":
		q = r.sql(
			"SELECT EXISTS(SELECT 1 FROM employee e JOIN employee_lifecycle_history l ON l.org_id=e.org_id AND l.employee_id=e.id WHERE e.org_id=? AND e.id=? AND l.valid_from<=? AND (l.valid_to IS NULL OR l.valid_to>?))",
			"SELECT EXISTS(SELECT 1 FROM employee e JOIN employee_lifecycle_history l ON l.org_id=e.org_id AND l.employee_id=e.id WHERE e.org_id=$1 AND e.id=$2 AND l.valid_from<=$3::date AND (l.valid_to IS NULL OR l.valid_to>$4::date))",
		)
	case "department":
		q = r.sql(
			"SELECT EXISTS(SELECT 1 FROM org_unit u JOIN org_unit_version v ON v.org_id=u.org_id AND v.org_unit_id=u.id WHERE u.org_id=? AND u.id=? AND u.kind='department' AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?))",
			"SELECT EXISTS(SELECT 1 FROM org_unit u JOIN org_unit_version v ON v.org_id=u.org_id AND v.org_unit_id=u.id WHERE u.org_id=$1 AND u.id=$2 AND u.kind='department' AND v.valid_from<=$3::date AND (v.valid_to IS NULL OR v.valid_to>$4::date))",
		)
	default:
		return false, nil
	}
	var found bool
	err = r.db.QueryRowContext(ctx, q, org, scope.ID, day, day).Scan(&found)
	return found, safeError(err)
}

func (r reader) organizationDate(ctx context.Context, org string, now time.Time) (string, error) {
	var timezone string
	err := r.db.QueryRowContext(ctx, r.sql("SELECT timezone FROM organization WHERE id=?", "SELECT timezone FROM organization WHERE id=$1"), org).Scan(&timezone)
	if err != nil {
		return "", safeError(err)
	}
	zone, err := time.LoadLocation(timezone)
	if err != nil || timezone == "" {
		return "", fault.Unavailable
	}
	return now.In(zone).Format("2006-01-02"), nil
}

func (r reader) ScopeCovered(ctx context.Context, org string, outer, inner authz.Scope, now time.Time) (bool, error) {
	if authz.Covers(outer, inner, org) {
		return true, nil
	}
	if outer.Kind != "department" || inner.Kind != "employee" {
		return false, nil
	}
	day, err := r.organizationDate(ctx, org, now)
	if err != nil {
		return false, err
	}
	var found bool
	q := r.sql(
		"SELECT EXISTS(SELECT 1 FROM job_assignment a JOIN org_unit d ON d.org_id=a.org_id AND d.id=a.department_id AND d.kind='department' JOIN org_unit_version dv ON dv.org_id=d.org_id AND dv.org_unit_id=d.id JOIN employee_lifecycle_history e ON e.org_id=a.org_id AND e.employee_id=a.employee_id WHERE a.org_id=? AND a.department_id=? AND a.employee_id=? AND a.valid_from<=? AND (a.valid_to IS NULL OR a.valid_to>?) AND dv.valid_from<=? AND (dv.valid_to IS NULL OR dv.valid_to>?) AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?))",
		"SELECT EXISTS(SELECT 1 FROM job_assignment a JOIN org_unit d ON d.org_id=a.org_id AND d.id=a.department_id AND d.kind='department' JOIN org_unit_version dv ON dv.org_id=d.org_id AND dv.org_unit_id=d.id JOIN employee_lifecycle_history e ON e.org_id=a.org_id AND e.employee_id=a.employee_id WHERE a.org_id=$1 AND a.department_id=$2 AND a.employee_id=$3 AND a.valid_from<=$4::date AND (a.valid_to IS NULL OR a.valid_to>$5::date) AND dv.valid_from<=$6::date AND (dv.valid_to IS NULL OR dv.valid_to>$7::date) AND e.valid_from<=$8::date AND (e.valid_to IS NULL OR e.valid_to>$9::date))")
	err = r.db.QueryRowContext(ctx, q, org, outer.ID, inner.ID, day, day, day, day, day, day).Scan(&found)
	return found, safeError(err)
}

func (r reader) Qualified(ctx context.Context, org, subject, capability string, scope authz.Scope, now time.Time) (bool, error) {
	rows, err := r.db.QueryContext(ctx, r.sql(
		"SELECT a.scope_kind,a.scope_id FROM subject s JOIN capability_assignment a ON a.org_id=s.org_id AND a.subject_id=s.id WHERE s.org_id=? AND s.id=? AND s.active=1 AND a.capability=? LIMIT 1001",
		"SELECT a.scope_kind,a.scope_id FROM subject s JOIN capability_assignment a ON a.org_id=s.org_id AND a.subject_id=s.id WHERE s.org_id=$1 AND s.id=$2 AND s.active=true AND a.capability=$3 LIMIT 1001"), org, subject, capability)
	if err != nil {
		return false, safeError(err)
	}
	var assignments []authz.Scope
	for rows.Next() {
		var a authz.Scope
		if err := rows.Scan(&a.Kind, &a.ID); err != nil {
			rows.Close()
			return false, safeError(err)
		}
		assignments = append(assignments, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, safeError(err)
	}
	if len(assignments) > 1000 {
		return false, fault.Unavailable
	}
	for _, a := range assignments {
		ok, err := r.ScopeCovered(ctx, org, a, scope, now)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func (r reader) RelationQualified(ctx context.Context, org, subject string, scope authz.Scope, ref authz.RelationReference, now time.Time) (bool, error) {
	if ref.Kind != "reporting_line" && ref.Kind != "job_assignment" || !value.ValidID(ref.ID) {
		return false, nil
	}
	var actor string
	err := r.db.QueryRowContext(ctx, r.sql(
		"SELECT se.employee_id FROM subject_employee se JOIN subject s ON s.org_id=se.org_id AND s.id=se.subject_id WHERE se.org_id=? AND se.subject_id=? AND s.active=1",
		"SELECT se.employee_id FROM subject_employee se JOIN subject s ON s.org_id=se.org_id AND s.id=se.subject_id WHERE se.org_id=$1 AND se.subject_id=$2 AND s.active=true"), org, subject).Scan(&actor)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, safeError(err)
	}
	tenure, found, err := r.relationTenure(ctx, org, ref)
	if err != nil || !found {
		return false, err
	}
	day, err := r.organizationDate(ctx, org, now)
	if err != nil {
		return false, err
	}
	if !tenure.Current(day) {
		return false, nil
	}
	return ref.Kind == "reporting_line" && scope.Kind == "employee" && scope.ID == tenure.EmployeeID && actor == tenure.ManagerEmployeeID ||
		ref.Kind == "job_assignment" && scope.Kind == "department" && scope.ID == tenure.DepartmentID && actor == tenure.EmployeeID, nil
}

// SQL coverage is applied before the limit, so hidden rows do not consume a page
// or reveal a count. IDs are canonical UUIDs ordered with matching byte collation.
func (r reader) VisibleGrants(ctx context.Context, org string, authorities []authz.Authority, filter authz.Filter, after string, now time.Time) ([]authz.GrantDTO, error) {
	if len(authorities) == 0 || len(authorities) > 1000 || filter.Limit < 1 || filter.Limit > 100 {
		return nil, fault.Invalid
	}
	args := make([]any, 0, 8+len(authorities)*5)
	bind := func(v any) string {
		args = append(args, v)
		if r.backend == "postgres" {
			return "$" + strconv.Itoa(len(args))
		}
		return "?"
	}
	var q strings.Builder
	day := ""
	q.WriteString("SELECT " + grantColumns + grantJoin + " WHERE g.org_id=" + bind(org) + " AND (")
	for i, a := range authorities {
		if i != 0 {
			q.WriteString(" OR ")
		}
		q.WriteString("(g.capability=" + bind(a.Capability) + " AND g.category=" + bind(a.Category) + " AND g.purpose=" + bind(a.Purpose))
		switch a.Scope.Kind {
		case "employee":
			q.WriteString(" AND g.scope_kind='employee' AND g.scope_id=" + bind(a.Scope.ID))
		case "department":
			if day == "" {
				var err error
				day, err = r.organizationDate(ctx, org, now)
				if err != nil {
					return nil, err
				}
			}
			departmentID := bind(a.Scope.ID)
			q.WriteString(" AND ((g.scope_kind='department' AND g.scope_id=" + departmentID + ") OR (g.scope_kind='employee' AND EXISTS(SELECT 1 FROM job_assignment ja JOIN org_unit d ON d.org_id=ja.org_id AND d.id=ja.department_id AND d.kind='department' JOIN org_unit_version dv ON dv.org_id=d.org_id AND dv.org_unit_id=d.id JOIN employee_lifecycle_history e ON e.org_id=ja.org_id AND e.employee_id=ja.employee_id WHERE ja.org_id=g.org_id AND ja.employee_id=g.employee_id AND ja.department_id=" + bind(a.Scope.ID) + " AND ja.valid_from<=" + bind(day) + " AND (ja.valid_to IS NULL OR ja.valid_to>" + bind(day) + ") AND dv.valid_from<=" + bind(day) + " AND (dv.valid_to IS NULL OR dv.valid_to>" + bind(day) + ") AND e.valid_from<=" + bind(day) + " AND (e.valid_to IS NULL OR e.valid_to>" + bind(day) + "))))")
		case "org":
			if a.Scope.ID != org {
				q.WriteString(" AND 1=0")
			} else {
				q.WriteString(" AND (g.scope_kind IN ('employee','department') OR (g.scope_kind='org' AND g.scope_id=" + bind(org) + "))")
			}
		default:
			q.WriteString(" AND 1=0")
		}
		q.WriteByte(')')
	}
	q.WriteByte(')')
	for _, part := range []struct{ column, value string }{{"subject_id", filter.SubjectID}, {"scope_kind", filter.ScopeKind}, {"scope_id", filter.ScopeID}, {"category", filter.Category}, {"purpose", filter.Purpose}, {"id", filter.GrantID}, {"capability", filter.Capability}, {"object_kind", filter.ObjectKind}, {"object_ref", filter.ObjectID}} {
		if part.value != "" {
			q.WriteString(" AND g." + part.column + "=" + bind(part.value))
		}
	}
	if after != "" {
		q.WriteString(r.sql(" AND g.id>", " AND g.id COLLATE \"C\"> ") + bind(after))
	}
	switch filter.State {
	case "revoked":
		q.WriteString(r.sql(" AND g.revoked=1", " AND g.revoked=true"))
	case "future":
		q.WriteString(r.sql(" AND g.revoked=0", " AND g.revoked=false") + " AND g.valid_from>" + bind(r.bindTime(now)))
	case "expired":
		q.WriteString(r.sql(" AND g.revoked=0", " AND g.revoked=false") + " AND g.expires_at<=" + bind(r.bindTime(now)))
	case "current":
		q.WriteString(r.sql(" AND g.revoked=0", " AND g.revoked=false") + " AND g.valid_from<=" + bind(r.bindTime(now)) + " AND g.expires_at>" + bind(r.bindTime(now)))
	}
	q.WriteString(r.sql(" ORDER BY g.id LIMIT ", " ORDER BY g.id COLLATE \"C\" LIMIT ") + bind(filter.Limit+1))
	rows, err := r.db.QueryContext(ctx, q.String(), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := make([]authz.GrantDTO, 0, filter.Limit+1)
	for rows.Next() {
		g, err := scanGrant(rows, now)
		if err != nil {
			return nil, err
		}
		items = append(items, g)
	}
	if err := rows.Err(); err != nil {
		return nil, safeError(err)
	}
	if err := rows.Close(); err != nil {
		return nil, safeError(err)
	}
	var ids []string
	for _, item := range items {
		if item.Capability == "note.publish" || item.Capability == "action.write" {
			ids = append(ids, item.ID)
		}
	}
	approvals, err := r.sourceApprovals(ctx, org, ids)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].ApprovedSourceRefs = approvals[items[i].ID].refs
		if items[i].ApprovedSourceRefs == nil {
			items[i].ApprovedSourceRefs = []authz.ObjectReference{}
		}
	}
	return items, nil
}

func (t *transaction) InsertGrant(ctx context.Context, g authz.GrantDTO) error {
	if g.OrgID != t.org || g.AuthorityID == nil || g.IssuedBy == nil || g.IssuedAt == nil {
		return fault.Invalid
	}
	if g.Category == "financial" && (g.RelationBound || g.RelationRef != nil) {
		return fault.Invalid
	}
	var employee, department, relationKind, reportingID, assignmentID, actor any
	if g.Scope.Kind == "employee" {
		employee = g.Scope.ID
	} else if g.Scope.Kind == "department" {
		department = g.Scope.ID
	}
	if g.RelationBound {
		if g.RelationRef == nil {
			return fault.Invalid
		}
		var actorID string
		err := t.tx.QueryRowContext(ctx, t.sql("SELECT employee_id FROM subject_employee WHERE org_id=? AND subject_id=?", "SELECT employee_id FROM subject_employee WHERE org_id=$1 AND subject_id=$2"), g.OrgID, g.SubjectID).Scan(&actorID)
		if errors.Is(err, sql.ErrNoRows) {
			return fault.Forbidden
		}
		if err != nil {
			return safeError(err)
		}
		actor, relationKind = actorID, g.RelationRef.Kind
		switch g.RelationRef.Kind {
		case "reporting_line":
			reportingID = g.RelationRef.ID
		case "job_assignment":
			assignmentID = g.RelationRef.ID
		default:
			return fault.Invalid
		}
	} else if g.RelationRef != nil {
		return fault.Invalid
	}
	var objectKind, objectID, objectEmployee, interviewID, headID, versionID, actionID, proposalID, eventID, termID any
	if g.ObjectRef != nil {
		if !authz.ValidObjectReference(*g.ObjectRef) || !authz.ObjectPair(g.Capability, g.Category, g.ObjectRef.Kind) || !value.ValidID(g.ObjectEmployeeID) {
			return fault.Invalid
		}
		objectKind, objectID, objectEmployee = g.ObjectRef.Kind, g.ObjectRef.ID, g.ObjectEmployeeID
		switch g.ObjectRef.Kind {
		case "interview":
			interviewID = g.ObjectRef.ID
		case "note_head":
			headID = g.ObjectRef.ID
		case "note_version":
			versionID = g.ObjectRef.ID
		case "action_item":
			actionID = g.ObjectRef.ID
		case "compensation_proposal":
			proposalID = g.ObjectRef.ID
		case "compensation_event":
			eventID = g.ObjectRef.ID
		case "compensation_term":
			termID = g.ObjectRef.ID
		}
	}
	_, err := t.tx.ExecContext(ctx, t.sql(
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required,authority_id,issued_by,issued_at,department_id,relation_bound,relation_kind,reporting_line_id,job_assignment_id,relation_actor_employee_id,object_kind,object_ref,object_employee_id,interview_id,note_head_id,note_version_id,action_item_id,compensation_proposal_id,compensation_event_id,compensation_term_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required,authority_id,issued_by,issued_at,department_id,relation_bound,relation_kind,reporting_line_id,job_assignment_id,relation_actor_employee_id,object_kind,object_ref,object_employee_id,interview_id,note_head_id,note_version_id,action_item_id,compensation_proposal_id,compensation_event_id,compensation_term_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)"), g.ID, g.OrgID, g.SubjectID, g.Capability, g.Category, g.Scope.Kind, g.Scope.ID, employee, g.Purpose, t.bindTime(g.ValidFrom), t.bindTime(g.ExpiresAt), g.MFARequired, *g.AuthorityID, *g.IssuedBy, t.bindTime(*g.IssuedAt), department, g.RelationBound, relationKind, reportingID, assignmentID, actor, objectKind, objectID, objectEmployee, interviewID, headID, versionID, actionID, proposalID, eventID, termID)
	if err != nil {
		return safeError(err)
	}
	for _, ref := range g.ApprovedSourceRefs {
		result, err := t.tx.ExecContext(ctx, t.sql(
			"INSERT INTO access_grant_source_approval(org_id,grant_id,source_note_version_id,employee_id,source_category) SELECT org_id,?,id,employee_id,category FROM note_version WHERE org_id=? AND id=? AND employee_id=? AND status='published'",
			"INSERT INTO access_grant_source_approval(org_id,grant_id,source_note_version_id,employee_id,source_category) SELECT org_id,$1,id,employee_id,category FROM note_version WHERE org_id=$2 AND id=$3 AND employee_id=$4 AND status='published'"), g.ID, g.OrgID, ref.ID, g.Scope.ID)
		if err != nil {
			return safeError(err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return safeError(err)
		}
		if count != 1 {
			return fault.Forbidden
		}
	}
	return nil
}

func (t *transaction) RevokeGrant(ctx context.Context, org, id string, revision int64, actor string, at time.Time, reason string) error {
	if org != t.org {
		return fault.NotFound
	}
	result, err := t.tx.ExecContext(ctx, t.sql(
		"UPDATE access_grant SET revoked=1,revision=revision+1,revoked_by=?,revoked_at=?,revoke_reason=? WHERE org_id=? AND id=? AND revision=? AND revoked=0",
		"UPDATE access_grant SET revoked=true,revision=revision+1,revoked_by=$1,revoked_at=$2,revoke_reason=$3 WHERE org_id=$4 AND id=$5 AND revision=$6 AND revoked=false"), actor, t.bindTime(at), reason, org, id, revision)
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	if n != 1 {
		return fault.Conflict
	}
	return nil
}

func (t *transaction) BumpEpoch(ctx context.Context, org string, expected int64) (int64, error) {
	if org != t.org {
		return 0, fault.NotFound
	}
	result, err := t.tx.ExecContext(ctx, t.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch=?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND auth_epoch=$2"), org, expected)
	if err != nil {
		return 0, safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, safeError(err)
	}
	if n != 1 {
		return 0, fault.Conflict
	}
	return expected + 1, nil
}

func (r reader) GrantReceipt(ctx context.Context, org, subject, operation, key string) (authz.Receipt, bool, error) {
	var receipt authz.Receipt
	var revision, epoch int64
	var version int
	err := r.db.QueryRowContext(ctx, r.sql("SELECT digest,digest_key_version,result_id,result_revision,result_status,result_auth_epoch FROM grant_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?", "SELECT digest,digest_key_version,result_id,result_revision,result_status,result_auth_epoch FROM grant_command_receipt WHERE org_id=$1 AND subject_id=$2 AND operation=$3 AND key=$4"), org, subject, operation, key).Scan(&receipt.Digest, &version, &receipt.Result.ID, &revision, &receipt.Result.Status, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return authz.Receipt{}, false, safeError(err)
	}
	if version != 1 || len(receipt.Digest) != 32 || revision <= 0 || epoch <= 0 {
		return authz.Receipt{}, false, fault.Unavailable
	}
	receipt.Result.Revision, receipt.Result.AuthEpoch = strconv.FormatInt(revision, 10), strconv.FormatInt(epoch, 10)
	return receipt, true, nil
}

func (t *transaction) SaveGrantReceipt(ctx context.Context, org, subject, operation, key string, receipt authz.Receipt) error {
	revision, valid := value.Revision(receipt.Result.Revision)
	epoch, validEpoch := value.Revision(receipt.Result.AuthEpoch)
	if org != t.org || !valid || !validEpoch {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO grant_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision,result_status,result_auth_epoch) VALUES(?,?,?,?,?,1,?,?,?,?)", "INSERT INTO grant_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision,result_status,result_auth_epoch) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9)"), org, subject, operation, key, receipt.Digest, receipt.Result.ID, revision, receipt.Result.Status, epoch)
	return safeError(err)
}

func grantAudit(a authz.Audit) organization.Audit {
	return organization.Audit{ID: a.ID, OrgID: a.OrgID, SubjectID: a.SubjectID, GrantID: a.GrantID, Operation: a.Operation, Purpose: a.Purpose, RequestID: a.RequestID, Outcome: a.Outcome, At: a.At}
}
func (t *transaction) GrantAudit(ctx context.Context, a authz.Audit) error {
	return t.Audit(ctx, grantAudit(a))
}
func (r *Repository) GrantAuditDenied(ctx context.Context, a authz.Audit) error {
	return r.AuditDenied(ctx, grantAudit(a))
}

// Employee and department row locks follow the already acquired organization
// and canonical subject guards. SQLite's first guard UPDATE owns the writer lock.
func (t *transaction) LockScope(ctx context.Context, org string, scope authz.Scope) error {
	if org != t.org {
		return fault.NotFound
	}
	if scope.Kind != "employee" && scope.Kind != "department" {
		if scope.Kind == "org" && scope.ID == org {
			return nil
		}
		return fault.Forbidden
	}
	if t.backend == "sqlite" {
		var found bool
		q := "SELECT EXISTS(SELECT 1 FROM employee WHERE org_id=? AND id=?)"
		if scope.Kind == "department" {
			q = "SELECT EXISTS(SELECT 1 FROM org_unit WHERE org_id=? AND id=? AND kind='department')"
		}
		if err := t.tx.QueryRowContext(ctx, q, org, scope.ID).Scan(&found); err != nil {
			return safeError(err)
		}
		if !found {
			return fault.Forbidden
		}
		return nil
	}
	var id string
	q := "SELECT id FROM employee WHERE org_id=$1 AND id=$2 FOR UPDATE"
	if scope.Kind == "department" {
		q = "SELECT id FROM org_unit WHERE org_id=$1 AND id=$2 AND kind='department' FOR UPDATE"
	}
	err := t.tx.QueryRowContext(ctx, q, org, scope.ID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.Forbidden
	}
	return safeError(err)
}

func (t *transaction) Grant(ctx context.Context, org, id string) (authz.GrantDTO, error) {
	q := "SELECT " + grantColumns + grantJoin + t.sql(" WHERE g.org_id=? AND g.id=?", " WHERE g.org_id=$1 AND g.id=$2 FOR UPDATE OF g")
	g, err := scanGrant(t.tx.QueryRowContext(ctx, q, org, id), time.Now().UTC())
	return t.reader.grantApprovals(ctx, g, err)
}

func (t *transaction) Employee(ctx context.Context, id string) (organization.Employee, error) {
	if t.backend == "sqlite" {
		return t.reader.Employee(ctx, id)
	}
	var employee organization.Employee
	var to sql.NullString
	err := t.tx.QueryRowContext(ctx, "SELECT org_id,id,profile_head_id,profile_revision,to_char(valid_from,'YYYY-MM-DD'),to_char(valid_to,'YYYY-MM-DD') FROM employee WHERE id=$1 FOR UPDATE", id).Scan(&employee.OrgID, &employee.ID, &employee.HeadID, &employee.Revision, &employee.Lifecycle.ValidFrom, &to)
	if errors.Is(err, sql.ErrNoRows) {
		return organization.Employee{}, fault.NotFound
	}
	if err != nil {
		return organization.Employee{}, safeError(err)
	}
	if to.Valid {
		employee.Lifecycle.ValidTo = &to.String
	}
	return employee, nil
}
