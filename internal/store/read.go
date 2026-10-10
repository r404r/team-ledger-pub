package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/r404r/team-ledger/internal/authz"
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
		"SELECT s.subject_id,s.org_id,o.timezone,u.active,s.revoked,s.subject_epoch,u.auth_epoch,g.auth_epoch,s.expires_at,s.idle_expires_at,s.mfa_until,s.csrf_hash,s.csrf_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN organization o ON o.id=s.org_id JOIN authorization_guard g ON g.org_id=s.org_id WHERE s.token_hash=? AND (?='' OR s.org_id=?)",
		"SELECT s.subject_id,s.org_id,o.timezone,u.active,s.revoked,s.subject_epoch,u.auth_epoch,g.auth_epoch,s.expires_at,s.idle_expires_at,s.mfa_until,s.csrf_hash,s.csrf_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN organization o ON o.id=s.org_id JOIN authorization_guard g ON g.org_id=s.org_id WHERE s.token_hash=$1 AND ($2='' OR s.org_id=$3)")
	err := r.db.QueryRowContext(ctx, q, hash, org, org).Scan(&s.SubjectID, &s.OrgID, &s.Timezone, &s.Active, &s.SessionRevoked, &s.SessionEpoch, &s.SubjectEpoch, &s.AuthEpoch, &expires, &idle, &mfa, &s.CSRFHash, &s.CSRFVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return s, organization.Unauthenticated
	}
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	s.ExpiresAt = expires.Time
	s.IdleExpiresAt = idle.Time
	s.MFAUntil = mfa.Time
	rows, err := r.db.QueryContext(ctx, r.sql(
		"SELECT capability,scope_kind,scope_id FROM capability_assignment WHERE org_id=? AND subject_id=? AND ((scope_kind='org' AND scope_id=?) OR (scope_kind='employee' AND scope_id=? AND employee_id=?)) LIMIT 1001",
		"SELECT capability,scope_kind,scope_id FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 AND ((scope_kind='org' AND scope_id=$3) OR (scope_kind='employee' AND scope_id=$4 AND employee_id=$5)) LIMIT 1001"), s.OrgID, s.SubjectID, s.OrgID, employee, employee)
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
			return authz.Snapshot{}, organization.Unavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	rows, err = r.db.QueryContext(ctx, r.sql(
		"SELECT capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required FROM access_grant WHERE org_id=? AND subject_id=? AND ((scope_kind='org' AND scope_id=?) OR (scope_kind='employee' AND scope_id=? AND employee_id=?)) LIMIT 1001",
		"SELECT capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required FROM access_grant WHERE org_id=$1 AND subject_id=$2 AND ((scope_kind='org' AND scope_id=$3) OR (scope_kind='employee' AND scope_id=$4 AND employee_id=$5)) LIMIT 1001"), s.OrgID, s.SubjectID, s.OrgID, employee, employee)
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	for rows.Next() {
		var g authz.Grant
		var from, to dbTime
		if err = rows.Scan(&g.Capability, &g.Category, &g.ScopeKind, &g.ScopeID, &g.Purpose, &from, &to, &g.Revoked, &g.RelationBound, &g.MFARequired); err != nil {
			rows.Close()
			return authz.Snapshot{}, safeError(err)
		}
		g.ValidFrom = from.Time
		g.ExpiresAt = to.Time
		s.Grants = append(s.Grants, g)
		if len(s.Grants) > 1000 {
			rows.Close()
			return authz.Snapshot{}, organization.Unavailable
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return authz.Snapshot{}, safeError(err)
	}
	return s, nil
}
func (r reader) Employee(ctx context.Context, id string) (organization.Employee, error) {
	var e organization.Employee
	var to sql.NullString
	err := r.db.QueryRowContext(ctx, r.sql(
		"SELECT org_id,id,profile_head_id,profile_revision,valid_from,valid_to FROM employee WHERE id=?",
		"SELECT org_id,id,profile_head_id,profile_revision,to_char(valid_from,'YYYY-MM-DD'),to_char(valid_to,'YYYY-MM-DD') FROM employee WHERE id=$1"), id).Scan(&e.OrgID, &e.ID, &e.HeadID, &e.Revision, &e.Lifecycle.ValidFrom, &to)
	if errors.Is(err, sql.ErrNoRows) {
		return e, organization.NotFound
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
		return v, organization.NotFound
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
		return organization.Receipt{}, false, organization.Unavailable
	}
	receipt.Result.Revision = strconv.FormatInt(rev, 10)
	return receipt, true, nil
}
