package store

import (
	"context"
	"database/sql"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type StaffIndexSource struct {
	ID, OrgID, EmployeeID string
	OldDigest             []byte
	Envelope              sensitive.Envelope
}

type StaffIndexReplacement struct {
	ID, OrgID, EmployeeID string
	OldDigest, NewDigest  []byte
}

func (r *Repository) StaffIndexSources(ctx context.Context) ([]StaffIndexSource, error) {
	rows, err := r.DB.QueryContext(ctx, "SELECT i.id,i.org_id,i.employee_id,i.lookup_digest,p.record_id,p.version_id,p.owner_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM employee_business_identifier i JOIN workforce_payload p ON p.org_id=i.org_id AND p.id=i.payload_id WHERE i.kind='staff_code' ORDER BY i.org_id,i.id")
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]StaffIndexSource, 0)
	for rows.Next() {
		var item StaffIndexSource
		var schemaVersion, formatVersion, kekVersion int64
		e, c := &item.Envelope, &item.Envelope.Context
		if err = rows.Scan(&item.ID, &item.OrgID, &item.EmployeeID, &item.OldDigest, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &schemaVersion, &formatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &kekVersion, &e.Key.Data, &e.SealedBytes); err != nil {
			return nil, safeError(err)
		}
		c.OrgID, c.EmployeeID, c.SchemaVersion = item.OrgID, item.EmployeeID, uint32(schemaVersion)
		e.FormatVersion, e.Key.Version = uint16(formatVersion), uint32(kekVersion)
		out = append(out, item)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) ApplyStaffIndexReplacements(ctx context.Context, target sensitive.KeyReference, replacements []StaffIndexReplacement) error {
	if target.KeyID == "" || target.Version == 0 {
		return fault.Invalid
	}
	for _, replacement := range replacements {
		if replacement.ID == "" || replacement.OrgID == "" || replacement.EmployeeID == "" || len(replacement.OldDigest) != 32 || len(replacement.NewDigest) != 32 {
			return fault.Invalid
		}
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	var actual int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM employee_business_identifier WHERE kind='staff_code'").Scan(&actual); err != nil || actual != len(replacements) {
		return fault.Conflict
	}
	q := reader{tx, r.Backend}
	for _, replacement := range replacements {
		result, execErr := tx.ExecContext(ctx, q.structureSQL("INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) SELECT ?,'staff_code',?,?,?,?,recorded_at FROM employee_business_identifier WHERE org_id=? AND id=? ON CONFLICT(org_id,kind,key_version,digest) DO NOTHING"), replacement.OrgID, target.KeyID, target.Version, replacement.NewDigest, replacement.EmployeeID, replacement.OrgID, replacement.ID)
		if execErr != nil {
			return safeError(execErr)
		}
		if n, _ := result.RowsAffected(); n == 0 {
			var owner string
			if err = tx.QueryRowContext(ctx, q.structureSQL("SELECT employee_id FROM employee_identifier_owner WHERE org_id=? AND kind='staff_code' AND key_version=? AND digest=?"), replacement.OrgID, target.Version, replacement.NewDigest).Scan(&owner); err != nil || owner != replacement.EmployeeID {
				return fault.Conflict
			}
		}
		result, err = tx.ExecContext(ctx, q.structureSQL("UPDATE employee_business_identifier SET lookup_key_id=?,lookup_key_version=?,lookup_digest=? WHERE org_id=? AND id=? AND employee_id=? AND lookup_digest=?"), target.KeyID, target.Version, replacement.NewDigest, replacement.OrgID, replacement.ID, replacement.EmployeeID, replacement.OldDigest)
		if err != nil {
			return safeError(err)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Conflict
		}
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("DELETE FROM employee_identifier_owner WHERE kind='staff_code' AND NOT (key_id=? AND key_version=?)"), target.KeyID, target.Version); err != nil {
		return safeError(err)
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
