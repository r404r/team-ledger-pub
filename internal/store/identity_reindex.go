package store

import (
	"context"
	"database/sql"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type IdentityIndexSource struct {
	ID, OrgID, SubjectID string
	Digest               []byte
	Envelope             sensitive.Envelope
	Local                bool
}

type IdentityIndexReplacement struct {
	SourceID, OrgID, SubjectID string
	OldDigest, NewDigest       []byte
	Local                      bool
}

func (r *Repository) IdentityIndexSources(ctx context.Context) ([]IdentityIndexSource, error) {
	out := make([]IdentityIndexSource, 0)
	rows, err := r.DB.QueryContext(ctx, "SELECT mapping_id,org_id,subject_id,digest,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes FROM identity_mapping_source ORDER BY mapping_id")
	if err != nil {
		return nil, safeError(err)
	}
	for rows.Next() {
		var item IdentityIndexSource
		var schemaVersion, formatVersion, kekVersion int64
		e := &item.Envelope
		c := &e.Context
		if err = rows.Scan(&item.ID, &item.OrgID, &item.SubjectID, &item.Digest, &c.RecordID, &c.VersionID, &c.Purpose, &c.SchemaType, &schemaVersion, &formatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &kekVersion, &e.Key.Data, &e.SealedBytes); err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		c.OrgID, c.ObjectKind, c.SchemaVersion = item.OrgID, "identity_mapping", uint32(schemaVersion)
		e.FormatVersion, e.Key.Version = uint16(formatVersion), uint32(kekVersion)
		out = append(out, item)
	}
	if err = rows.Close(); err != nil {
		return nil, safeError(err)
	}
	rows, err = r.DB.QueryContext(ctx, "SELECT id,org_id,subject_id,username_digest,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes FROM local_account ORDER BY id")
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		item := IdentityIndexSource{Local: true}
		var schemaVersion, formatVersion, kekVersion int64
		e := &item.Envelope
		c := &e.Context
		if err = rows.Scan(&item.ID, &item.OrgID, &item.SubjectID, &item.Digest, &c.RecordID, &c.VersionID, &c.Purpose, &c.SchemaType, &schemaVersion, &formatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &kekVersion, &e.Key.Data, &e.SealedBytes); err != nil {
			return nil, safeError(err)
		}
		c.OrgID, c.ObjectKind, c.SchemaVersion = item.OrgID, "local_username", uint32(schemaVersion)
		e.FormatVersion, e.Key.Version = uint16(formatVersion), uint32(kekVersion)
		out = append(out, item)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) ApplyIdentityIndexReplacements(ctx context.Context, local bool, target sensitive.KeyReference, replacements []IdentityIndexReplacement) error {
	if target.KeyID == "" || target.Version == 0 {
		return fault.Invalid
	}
	for _, replacement := range replacements {
		if replacement.Local != local || len(replacement.OldDigest) != 32 || len(replacement.NewDigest) != 32 || replacement.SourceID == "" || replacement.OrgID == "" || replacement.SubjectID == "" {
			return fault.Invalid
		}
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var actual int
	table := "identity_mapping_source"
	if local {
		table = "local_account"
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&actual); err != nil || actual != len(replacements) {
		return fault.Conflict
	}
	for _, replacement := range replacements {
		var active bool
		if err = tx.QueryRowContext(ctx, q.sql(
			"SELECT active FROM subject_identity WHERE digest=? AND org_id=? AND subject_id=?",
			"SELECT active FROM subject_identity WHERE digest=$1 AND org_id=$2 AND subject_id=$3"),
			replacement.OldDigest, replacement.OrgID, replacement.SubjectID).Scan(&active); err != nil {
			if err == sql.ErrNoRows {
				return fault.Conflict
			}
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, q.sql(
			"INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES(?,?,?,?,?,?) ON CONFLICT(digest) DO NOTHING",
			"INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(digest) DO NOTHING"),
			replacement.NewDigest, target.KeyID, target.Version, replacement.OrgID, replacement.SubjectID, active); err != nil {
			return safeError(err)
		}
		var org, subject, keyID string
		var version int64
		var replacementActive bool
		if err = tx.QueryRowContext(ctx, q.sql(
			"SELECT org_id,subject_id,key_id,key_version,active FROM subject_identity WHERE digest=?",
			"SELECT org_id,subject_id,key_id,key_version,active FROM subject_identity WHERE digest=$1"),
			replacement.NewDigest).Scan(&org, &subject, &keyID, &version, &replacementActive); err != nil ||
			org != replacement.OrgID || subject != replacement.SubjectID || keyID != target.KeyID ||
			version != int64(target.Version) || replacementActive != active {
			return fault.Conflict
		}
		var result sql.Result
		if replacement.Local {
			result, err = tx.ExecContext(ctx, q.sql("UPDATE local_account SET username_digest=?,username_key_id=?,username_key_version=? WHERE id=? AND org_id=? AND subject_id=? AND username_digest=?", "UPDATE local_account SET username_digest=$1,username_key_id=$2,username_key_version=$3 WHERE id=$4 AND org_id=$5 AND subject_id=$6 AND username_digest=$7"), replacement.NewDigest, target.KeyID, target.Version, replacement.SourceID, replacement.OrgID, replacement.SubjectID, replacement.OldDigest)
			if err == nil {
				_, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_login_throttle WHERE username_digest=?", "DELETE FROM local_login_throttle WHERE username_digest=$1"), replacement.OldDigest)
			}
		} else {
			result, err = tx.ExecContext(ctx, q.sql("UPDATE identity_mapping_source SET digest=?,key_id=?,key_version=? WHERE mapping_id=? AND org_id=? AND subject_id=? AND digest=?", "UPDATE identity_mapping_source SET digest=$1,key_id=$2,key_version=$3 WHERE mapping_id=$4 AND org_id=$5 AND subject_id=$6 AND digest=$7"), replacement.NewDigest, target.KeyID, target.Version, replacement.SourceID, replacement.OrgID, replacement.SubjectID, replacement.OldDigest)
		}
		if err != nil {
			return safeError(err)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Conflict
		}
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
