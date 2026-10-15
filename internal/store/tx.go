package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func (r *Repository) WithTx(ctx context.Context, org string, fn func(organization.Tx) error) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if r.Backend == "sqlite" {
		result, e := tx.ExecContext(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch WHERE org_id=?", org)
		if e != nil {
			return safeError(e)
		}
		n, e := result.RowsAffected()
		if e != nil {
			return safeError(e)
		}
		if n != 1 {
			return fault.NotFound
		}
	} else {
		// Connection defaults also bound the guard lock; SET LOCAL cannot leak to the pool.
		if _, err = tx.ExecContext(ctx, "SET LOCAL statement_timeout='10s'"); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, "SET LOCAL lock_timeout='2s'"); err != nil {
			return safeError(err)
		}
		var epoch int64
		err = tx.QueryRowContext(ctx, "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1 FOR UPDATE", org).Scan(&epoch)
		if errors.Is(err, sql.ErrNoRows) {
			return fault.NotFound
		}
		if err != nil {
			return safeError(err)
		}
	}
	t := &transaction{reader: reader{tx, r.Backend}, tx: tx, org: org, commandMACKey: r.commandReference(), generationMACKey: r.generationReference()}
	if err = fn(t); err != nil {
		return err
	}
	return safeError(tx.Commit())
}
func exactReference(reference sensitive.KeyReference, fallback string) sensitive.KeyReference {
	if reference.KeyID == "" || reference.Version == 0 {
		return sensitive.KeyReference{KeyID: fallback, Version: 1}
	}
	return reference
}

func (r *Repository) commandReference() sensitive.KeyReference {
	return exactReference(r.CommandMACKey, "legacy-command-receipt")
}

func (r *Repository) generationReference() sensitive.KeyReference {
	return exactReference(r.GenerationMACKey, "legacy-assessment-generation")
}

func (t *transaction) bindTime(at time.Time) any {
	if t.backend == "sqlite" {
		return at.UTC().UnixMicro()
	}
	return at.UTC().Truncate(time.Microsecond)
}
func (t *transaction) Create(ctx context.Context, e organization.Employee, v organization.Version) error {
	if e.OrgID != t.org || v.OrgID != t.org || v.EmployeeID != e.ID || v.ID != e.HeadID || e.Revision != 1 || v.Number != 1 || v.SupersedesID != "" {
		return fault.Invalid
	}
	var to any
	if e.Lifecycle.ValidTo != nil {
		to = *e.Lifecycle.ValidTo
	}
	_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO employee(org_id,id,profile_head_id,profile_revision,valid_from,valid_to) VALUES(?,?,?,?,?,?)", "INSERT INTO employee(org_id,id,profile_head_id,profile_revision,valid_from,valid_to) VALUES($1,$2,$3,$4,$5,$6)"), e.OrgID, e.ID, e.HeadID, e.Revision, e.Lifecycle.ValidFrom, to)
	if err != nil {
		return safeError(err)
	}
	// Initial lifecycle facts are immutable and independent of profile history;
	// profile creation does not advance the organization graph revision.
	_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO employee_lifecycle_history(org_id,id,employee_id,valid_from,valid_to,change_id,supersedes_id) VALUES(?,?,?,?,?,NULL,NULL)", "INSERT INTO employee_lifecycle_history(org_id,id,employee_id,valid_from,valid_to,change_id,supersedes_id) VALUES($1,$2,$3,$4,$5,NULL,NULL)"), e.OrgID, value.NewID(), e.ID, e.Lifecycle.ValidFrom, to)
	if err != nil {
		return safeError(err)
	}
	return t.insertVersion(ctx, v)
}
func (t *transaction) Replace(ctx context.Context, e organization.Employee, v organization.Version, expected int64) error {
	if e.OrgID != t.org || v.OrgID != t.org || v.EmployeeID != e.ID || v.ID != e.HeadID || expected < 1 || expected == math.MaxInt64 || e.Revision != expected+1 || v.Number != e.Revision {
		return fault.Invalid
	}
	var head string
	var revision int64
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT profile_head_id,profile_revision FROM employee WHERE org_id=? AND id=?", "SELECT profile_head_id,profile_revision FROM employee WHERE org_id=$1 AND id=$2 FOR UPDATE"), e.OrgID, e.ID).Scan(&head, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.Conflict
	}
	if err != nil {
		return safeError(err)
	}
	if revision != expected || head != v.SupersedesID {
		return fault.Conflict
	}
	if err = t.insertVersion(ctx, v); err != nil {
		return err
	}
	result, err := t.tx.ExecContext(ctx, t.sql("UPDATE employee SET profile_head_id=?,profile_revision=? WHERE org_id=? AND id=? AND profile_revision=? AND profile_head_id=?", "UPDATE employee SET profile_head_id=$1,profile_revision=$2 WHERE org_id=$3 AND id=$4 AND profile_revision=$5 AND profile_head_id=$6"), v.ID, e.Revision, e.OrgID, e.ID, expected, head)
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
func (t *transaction) insertVersion(ctx context.Context, v organization.Version) error {
	e := v.Envelope
	c := e.Context
	// Persist the supplied envelope context exactly; never substitute caller routing values.
	_, err := t.tx.ExecContext(ctx, t.sql(
		"INSERT INTO encrypted_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		"INSERT INTO encrypted_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)"), c.OrgID, c.EmployeeID, v.ID, c.RecordID, c.VersionID, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, t.bindTime(v.RecordedAt))
	if err != nil {
		return safeError(err)
	}
	_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO employee_profile_version(org_id,employee_id,id,version_no,payload_id,supersedes_id,recorded_at) VALUES(?,?,?,?,?,?,?)", "INSERT INTO employee_profile_version(org_id,employee_id,id,version_no,payload_id,supersedes_id,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)"), v.OrgID, v.EmployeeID, v.ID, v.Number, v.ID, nullable(v.SupersedesID), t.bindTime(v.RecordedAt))
	return safeError(err)
}
func (t *transaction) SaveReceipt(ctx context.Context, org, subject, op, key string, r organization.Receipt) error {
	rev, err := strconv.ParseInt(r.Result.Revision, 10, 64)
	if org != t.org || err != nil || rev < 1 || strconv.FormatInt(rev, 10) != r.Result.Revision {
		return fault.Invalid
	}
	var workforceRevision, graphRevision any
	if r.Result.WorkforceRevision != "" || r.Result.GraphRevision != "" {
		workforce, workforceErr := strconv.ParseInt(r.Result.WorkforceRevision, 10, 64)
		graph, graphErr := strconv.ParseInt(r.Result.GraphRevision, 10, 64)
		if workforceErr != nil || graphErr != nil || workforce < 1 || graph < 1 ||
			strconv.FormatInt(workforce, 10) != r.Result.WorkforceRevision || strconv.FormatInt(graph, 10) != r.Result.GraphRevision {
			return fault.Invalid
		}
		workforceRevision, graphRevision = workforce, graph
	}
	_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision,result_workforce_revision,result_graph_revision,digest_key_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)", "INSERT INTO command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision,result_workforce_revision,result_graph_revision,digest_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"), org, subject, op, key, r.Digest, t.commandMACKey.Version, r.Result.ID, rev, workforceRevision, graphRevision, t.commandMACKey.KeyID)
	return safeError(err)
}
func (t *transaction) Audit(ctx context.Context, a organization.Audit) error {
	if a.OrgID != t.org {
		return fault.AuditUnavailable
	}
	return insertAudit(ctx, t.tx, t.backend, a)
}
func insertAudit(ctx context.Context, db queryer, backend string, a organization.Audit) error {
	r := reader{db, backend}
	var at any = a.At.UTC().Truncate(time.Microsecond)
	if backend == "sqlite" {
		at = a.At.UTC().UnixMicro()
	}
	if _, err := db.ExecContext(ctx, r.sql("INSERT INTO audit_event(id,org_id,subject_id,employee_id,grant_id,operation,purpose,request_id,outcome,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)", "INSERT INTO audit_event(id,org_id,subject_id,employee_id,grant_id,operation,purpose,request_id,outcome,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"), a.ID, nullable(a.OrgID), nullable(a.SubjectID), nullable(a.EmployeeID), nullable(a.GrantID), a.Operation, a.Purpose, a.RequestID, a.Outcome, at); err != nil {
		return fault.AuditUnavailable
	}
	if _, err := db.ExecContext(ctx, r.sql("INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES(?,?,?)", "INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES($1,$2,$3)"), a.ID, nullable(a.OrgID), at); err != nil {
		return fault.AuditUnavailable
	}
	return nil
}
func (r *Repository) AuditDenied(ctx context.Context, a organization.Audit) error {
	a.EmployeeID = ""
	a.GrantID = ""
	a.Outcome = "denied"
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fault.AuditUnavailable
	}
	defer tx.Rollback()
	if err = insertAudit(ctx, tx, r.Backend, a); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.AuditUnavailable
	}
	return nil
}
