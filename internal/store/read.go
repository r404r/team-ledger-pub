package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (r *Repository) Security(ctx context.Context, hash []byte, org, employee string) (authz.Snapshot, error) {
	return r.read().Security(ctx, hash, org, employee)
}
func (r *Repository) Employee(ctx context.Context, id string) (organization.Employee, error) {
	return r.read().Employee(ctx, id)
}
func (r *Repository) Version(ctx context.Context, org, employee, id string) (organization.Version, error) {
	return r.read().Version(ctx, org, employee, id)
}
func (r *Repository) Receipt(ctx context.Context, org, subject, op, key string) (organization.Receipt, bool, error) {
	return r.read().Receipt(ctx, org, subject, op, key)
}

func (r reader) Security(ctx context.Context, hash []byte, org, employee string) (authz.Snapshot, error) {
	var s authz.Snapshot
	var expires, idle, mfa dbTime
	q := r.sql(
		"SELECT s.subject_id,s.org_id,o.timezone,u.active,s.revoked,s.subject_epoch,u.auth_epoch,g.auth_epoch,s.expires_at,s.idle_expires_at,s.mfa_until,s.csrf_hash,s.csrf_key_id,s.csrf_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN organization o ON o.id=s.org_id JOIN authorization_guard g ON g.org_id=s.org_id WHERE s.token_hash=? AND (?='' OR s.org_id=?)",
		"SELECT s.subject_id,s.org_id,o.timezone,u.active,s.revoked,s.subject_epoch,u.auth_epoch,g.auth_epoch,s.expires_at,s.idle_expires_at,s.mfa_until,s.csrf_hash,s.csrf_key_id,s.csrf_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN organization o ON o.id=s.org_id JOIN authorization_guard g ON g.org_id=s.org_id WHERE s.token_hash=$1 AND ($2='' OR s.org_id=$3)")
	err := r.db.QueryRowContext(ctx, q, hash, org, org).Scan(&s.SubjectID, &s.OrgID, &s.Timezone, &s.Active, &s.SessionRevoked, &s.SessionEpoch, &s.SubjectEpoch, &s.AuthEpoch, &expires, &idle, &mfa, &s.CSRFHash, &s.CSRFKeyID, &s.CSRFVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return s, fault.Unauthenticated
	}
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	s.ExpiresAt = expires.Time
	s.IdleExpiresAt = idle.Time
	s.MFAUntil = mfa.Time
	rows, err := r.db.QueryContext(ctx, r.sql(
		"SELECT capability,scope_kind,scope_id FROM capability_assignment WHERE org_id=? AND subject_id=? LIMIT 1001",
		"SELECT capability,scope_kind,scope_id FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 LIMIT 1001"), s.OrgID, s.SubjectID)
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	for rows.Next() {
		var a authz.Assignment
		if err = rows.Scan(&a.Capability, &a.ScopeKind, &a.ScopeID); err != nil {
			rows.Close()
			return authz.Snapshot{}, safeError(err)
		}
		s.Assignments = append(s.Assignments, a)
		if len(s.Assignments) > 1000 {
			rows.Close()
			return authz.Snapshot{}, fault.Unavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	var grantIDs []string
	var approvalIndexes []int
	rows, err = r.db.QueryContext(ctx, r.sql(
		"SELECT id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required,relation_kind,reporting_line_id,job_assignment_id,relation_actor_employee_id,object_kind,object_ref FROM access_grant WHERE org_id=? AND subject_id=? LIMIT 1001",
		"SELECT id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required,relation_kind,reporting_line_id,job_assignment_id,relation_actor_employee_id,object_kind,object_ref FROM access_grant WHERE org_id=$1 AND subject_id=$2 LIMIT 1001"), s.OrgID, s.SubjectID)
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	for rows.Next() {
		var g authz.Grant
		var from, to dbTime
		var id string
		var kind, reporting, assignment, actor, objectKind, objectID sql.NullString
		if err = rows.Scan(&id, &g.Capability, &g.Category, &g.ScopeKind, &g.ScopeID, &g.Purpose, &from, &to, &g.Revoked, &g.RelationBound, &g.MFARequired, &kind, &reporting, &assignment, &actor, &objectKind, &objectID); err != nil {
			rows.Close()
			return authz.Snapshot{}, safeError(err)
		}
		g.ValidFrom = from.Time
		g.ExpiresAt = to.Time
		g.RelationActorEmployeeID = actor.String
		if kind.Valid {
			id := assignment.String
			if kind.String == "reporting_line" {
				id = reporting.String
			}
			g.RelationRef = &authz.RelationReference{Kind: kind.String, ID: id}
		}
		if objectKind.Valid {
			g.ObjectRef = &authz.ObjectReference{Kind: objectKind.String, ID: objectID.String}
		}
		if g.Capability == "note.publish" || g.Capability == "action.write" {
			grantIDs = append(grantIDs, id)
			approvalIndexes = append(approvalIndexes, len(s.Grants))
		}
		s.Grants = append(s.Grants, g)
		if len(s.Grants) > 1000 {
			rows.Close()
			return authz.Snapshot{}, fault.Unavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	approvals, err := r.sourceApprovals(ctx, s.OrgID, grantIDs)
	if err != nil {
		return authz.Snapshot{}, err
	}
	for i, id := range grantIDs {
		g := &s.Grants[approvalIndexes[i]]
		g.ApprovedSourceRefs = approvals[id].refs
		g.ApprovedSourceEmployees = approvals[id].employees
	}
	var actor sql.NullString
	err = r.db.QueryRowContext(ctx, r.sql(
		"SELECT employee_id FROM subject_employee WHERE org_id=? AND subject_id=?",
		"SELECT employee_id FROM subject_employee WHERE org_id=$1 AND subject_id=$2"), s.OrgID, s.SubjectID).Scan(&actor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return authz.Snapshot{}, safeError(err)
	}
	s.SubjectEmployeeID = actor.String
	s.JobAssignments, err = r.securityJobAssignments(ctx, s.OrgID, employee)
	if err != nil {
		return authz.Snapshot{}, err
	}
	s.Relations, err = r.securityRelations(ctx, s.OrgID, s.SubjectID)
	if err != nil {
		return authz.Snapshot{}, err
	}
	return s, nil
}

func (r reader) dateColumn(column string) string {
	return r.sql(column, "to_char("+column+",'YYYY-MM-DD')")
}

func (r reader) tenureColumns(kind string) string {
	if kind == "job_assignment" {
		return "m.id,m.employee_id,m.department_id,''," + r.dateColumn("m.valid_from") + "," + r.dateColumn("m.valid_to") + ",NULL," + r.sql("0", "false") + "," + r.dateColumn("e.valid_from") + "," + r.dateColumn("e.valid_to") + "," + r.dateColumn("d.valid_from") + "," + r.dateColumn("d.valid_to") + ",'',NULL"
	}
	return "m.id,m.employee_id,'',m.manager_employee_id," + r.dateColumn("m.valid_from") + "," + r.dateColumn("m.valid_to") + "," + r.dateColumn("m.effective_to") + ",m.superseded," + r.dateColumn("e.valid_from") + "," + r.dateColumn("e.valid_to") + ",'',NULL," + r.dateColumn("manager.valid_from") + "," + r.dateColumn("manager.valid_to")
}

func tenureJoin(kind string) string {
	if kind == "job_assignment" {
		return " FROM job_assignment m JOIN employee e ON e.org_id=m.org_id AND e.id=m.employee_id JOIN org_unit u ON u.org_id=m.org_id AND u.id=m.department_id AND u.kind='department' JOIN (SELECT org_id,org_unit_id,MIN(valid_from) AS valid_from,CASE WHEN COUNT(*)=COUNT(valid_to) THEN MAX(valid_to) ELSE NULL END AS valid_to FROM org_unit_version GROUP BY org_id,org_unit_id) d ON d.org_id=u.org_id AND d.org_unit_id=u.id"
	}
	return " FROM reporting_line m JOIN employee e ON e.org_id=m.org_id AND e.id=m.employee_id JOIN employee manager ON manager.org_id=m.org_id AND manager.id=m.manager_employee_id"
}

func scanTenure(row grantScanner, kind string) (authz.Tenure, error) {
	t := authz.Tenure{Kind: kind}
	var to, effective, employeeTo, departmentTo, managerTo sql.NullString
	err := row.Scan(&t.ID, &t.EmployeeID, &t.DepartmentID, &t.ManagerEmployeeID, &t.ValidFrom, &to, &effective, &t.Superseded, &t.EmployeeFrom, &employeeTo, &t.DepartmentFrom, &departmentTo, &t.ManagerFrom, &managerTo)
	t.ValidTo, t.EffectiveTo, t.EmployeeTo, t.DepartmentTo, t.ManagerTo = stringPtr(to), stringPtr(effective), stringPtr(employeeTo), stringPtr(departmentTo), stringPtr(managerTo)
	return t, err
}

func (r reader) relationTenure(ctx context.Context, org string, ref authz.RelationReference) (authz.Tenure, bool, error) {
	if ref.Kind != "job_assignment" && ref.Kind != "reporting_line" {
		return authz.Tenure{}, false, nil
	}
	q := "SELECT " + r.tenureColumns(ref.Kind) + tenureJoin(ref.Kind) + r.sql(" WHERE m.org_id=? AND m.id=? LIMIT 1", " WHERE m.org_id=$1 AND m.id=$2 LIMIT 1")
	t, err := scanTenure(r.db.QueryRowContext(ctx, q, org, ref.ID), ref.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil, safeError(err)
}

func (r reader) securityJobAssignments(ctx context.Context, org, employee string) ([]authz.Tenure, error) {
	q := "SELECT " + r.tenureColumns("job_assignment") + tenureJoin("job_assignment") + r.sql(
		" WHERE m.org_id=? AND m.employee_id=? LIMIT 1001",
		" WHERE m.org_id=$1 AND m.employee_id=$2 LIMIT 1001")
	rows, err := r.db.QueryContext(ctx, q, org, employee)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	var facts []authz.Tenure
	for rows.Next() {
		t, err := scanTenure(rows, "job_assignment")
		if err != nil {
			return nil, safeError(err)
		}
		facts = append(facts, t)
		if len(facts) > 1000 {
			return nil, fault.Unavailable
		}
	}
	return facts, safeError(rows.Err())
}

func (r reader) securityRelations(ctx context.Context, org, subject string) ([]authz.Tenure, error) {
	var facts []authz.Tenure
	for _, kind := range []string{"reporting_line", "job_assignment"} {
		column := map[string]string{"reporting_line": "reporting_line_id", "job_assignment": "job_assignment_id"}[kind]
		q := "SELECT " + r.tenureColumns(kind) + tenureJoin(kind) + r.sql(
			" WHERE m.org_id=? AND EXISTS(SELECT 1 FROM access_grant g WHERE g.org_id=m.org_id AND g.subject_id=? AND g.relation_kind='"+kind+"' AND g."+column+"=m.id) LIMIT 1001",
			" WHERE m.org_id=$1 AND EXISTS(SELECT 1 FROM access_grant g WHERE g.org_id=m.org_id AND g.subject_id=$2 AND g.relation_kind='"+kind+"' AND g."+column+"=m.id) LIMIT 1001")
		rows, err := r.db.QueryContext(ctx, q, org, subject)
		if err != nil {
			return nil, safeError(err)
		}
		for rows.Next() {
			t, err := scanTenure(rows, kind)
			if err != nil {
				rows.Close()
				return nil, safeError(err)
			}
			facts = append(facts, t)
			if len(facts) > 1000 {
				rows.Close()
				return nil, fault.Unavailable
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, safeError(err)
		}
	}
	return facts, nil
}
func (r reader) Employee(ctx context.Context, id string) (organization.Employee, error) {
	var e organization.Employee
	var to sql.NullString
	err := r.db.QueryRowContext(ctx, r.sql(
		"SELECT org_id,id,profile_head_id,profile_revision,valid_from,valid_to FROM employee WHERE id=?",
		"SELECT org_id,id,profile_head_id,profile_revision,to_char(valid_from,'YYYY-MM-DD'),to_char(valid_to,'YYYY-MM-DD') FROM employee WHERE id=$1"), id).Scan(&e.OrgID, &e.ID, &e.HeadID, &e.Revision, &e.Lifecycle.ValidFrom, &to)
	if errors.Is(err, sql.ErrNoRows) {
		return e, fault.NotFound
	}
	if err != nil {
		return organization.Employee{}, safeError(err)
	}
	if to.Valid {
		e.Lifecycle.ValidTo = &to.String
	}
	return e, nil
}
func (r reader) Version(ctx context.Context, org, employee, id string) (organization.Version, error) {
	var v organization.Version
	var supersedes sql.NullString
	var at dbTime
	q := r.sql(
		"SELECT v.org_id,v.employee_id,v.id,v.version_no,v.supersedes_id,v.recorded_at,p.org_id,p.employee_id,p.record_id,p.version_id,p.object_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM employee_profile_version v JOIN encrypted_payload p ON p.org_id=v.org_id AND p.employee_id=v.employee_id AND p.id=v.payload_id WHERE v.org_id=? AND v.employee_id=? AND v.id=?",
		"SELECT v.org_id,v.employee_id,v.id,v.version_no,v.supersedes_id,v.recorded_at,p.org_id,p.employee_id,p.record_id,p.version_id,p.object_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM employee_profile_version v JOIN encrypted_payload p ON p.org_id=v.org_id AND p.employee_id=v.employee_id AND p.id=v.payload_id WHERE v.org_id=$1 AND v.employee_id=$2 AND v.id=$3")
	e := &v.Envelope
	c := &e.Context
	err := r.db.QueryRowContext(ctx, q, org, employee, id).Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.Number, &supersedes, &at, &c.OrgID, &c.EmployeeID, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &c.SchemaVersion, &e.FormatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &e.Key.Version, &e.Key.Data, &e.SealedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return v, fault.NotFound
	}
	if err != nil {
		return organization.Version{}, safeError(err)
	}
	v.SupersedesID = supersedes.String
	v.RecordedAt = at.Time
	return v, nil
}
func (r reader) Receipt(ctx context.Context, org, subject, op, key string) (organization.Receipt, bool, error) {
	var receipt organization.Receipt
	var rev int64
	var keyVersion int
	err := r.db.QueryRowContext(ctx, r.sql("SELECT digest,digest_key_version,result_id,result_revision FROM command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?", "SELECT digest,digest_key_version,result_id,result_revision FROM command_receipt WHERE org_id=$1 AND subject_id=$2 AND operation=$3 AND key=$4"), org, subject, op, key).Scan(&receipt.Digest, &keyVersion, &receipt.Result.ID, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return organization.Receipt{}, false, safeError(err)
	}
	if keyVersion != 1 || len(receipt.Digest) != 32 || rev < 1 {
		return organization.Receipt{}, false, fault.Unavailable
	}
	receipt.Result.Revision = strconv.FormatInt(rev, 10)
	return receipt, true, nil
}
