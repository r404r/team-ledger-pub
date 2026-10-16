package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/backup"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func (r *Repository) SQLiteSnapshot(ctx context.Context, path string) error {
	if r.Backend != "sqlite" || !filepath.IsAbs(path) {
		return fault.Invalid
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fault.Conflict
	}
	_, err := r.DB.ExecContext(ctx, "VACUUM INTO ?", path)
	return safeError(err)
}

func (r *Repository) BeginPostgresBackup(ctx context.Context) (*sql.Tx, string, error) {
	if r.Backend != "postgres" {
		return nil, "", fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return nil, "", safeError(err)
	}
	if _, err = tx.ExecContext(ctx, "SET TRANSACTION DEFERRABLE"); err != nil {
		tx.Rollback()
		return nil, "", safeError(err)
	}
	var snapshot string
	if err = tx.QueryRowContext(ctx, "SELECT pg_export_snapshot()").Scan(&snapshot); err != nil || snapshot == "" {
		tx.Rollback()
		return nil, "", safeError(err)
	}
	return tx, snapshot, nil
}
func (r *Repository) BackupManifest(ctx context.Context, created time.Time, size int64, digest string) (backup.Manifest, error) {
	return r.backupManifest(ctx, r.DB, created, size, digest)
}

func (r *Repository) BackupManifestTx(ctx context.Context, tx *sql.Tx, created time.Time, size int64, digest string) (backup.Manifest, error) {
	if tx == nil {
		return backup.Manifest{}, fault.Invalid
	}
	return r.backupManifest(ctx, tx, created, size, digest)
}

func (r *Repository) backupManifest(ctx context.Context, q queryer, created time.Time, size int64, digest string) (backup.Manifest, error) {
	if size < 0 || len(digest) != 64 {
		return backup.Manifest{}, fault.Invalid
	}
	manifest := backup.Manifest{FormatVersion: 1, Backend: r.Backend, SchemaVersion: currentSchemaVersion, CreatedAt: created.UTC().Truncate(time.Microsecond), DatabaseSize: size, DatabaseSHA256: digest, OrganizationIDs: []string{}, KeyDependencies: []backup.KeyDependency{}}
	rows, err := q.QueryContext(ctx, "SELECT id FROM organization ORDER BY id")
	if err != nil {
		return backup.Manifest{}, safeError(err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return backup.Manifest{}, safeError(err)
		}
		manifest.OrganizationIDs = append(manifest.OrganizationIDs, id)
	}
	if err = rows.Close(); err != nil {
		return backup.Manifest{}, safeError(err)
	}
	queries := map[string]string{"pii": "SELECT DISTINCT kek_id,kek_version FROM encrypted_payload UNION SELECT DISTINCT kek_id,kek_version FROM workforce_payload", "interview": "SELECT DISTINCT kek_id,kek_version FROM interview_payload", "assessment": "SELECT DISTINCT kek_id,kek_version FROM assessment_payload", "financial": "SELECT DISTINCT kek_id,kek_version FROM compensation_payload UNION SELECT DISTINCT kek_id,kek_version FROM bonus_payload UNION SELECT DISTINCT kek_id,kek_version FROM compensation_batch_header_payload UNION SELECT DISTINCT kek_id,kek_version FROM compensation_batch_payload UNION SELECT DISTINCT kek_id,kek_version FROM compensation_batch_import_candidate UNION SELECT DISTINCT kek_id,kek_version FROM salary_range_payload", "identity_mfa": "SELECT DISTINCT kek_id,kek_version FROM local_mfa_factor UNION SELECT DISTINCT kek_id,kek_version FROM local_mfa_enrollment"}
	for _, domain := range []string{"pii", "interview", "assessment", "financial", "identity_mfa"} {
		rows, err = q.QueryContext(ctx, queries[domain])
		if err != nil {
			return backup.Manifest{}, safeError(err)
		}
		for rows.Next() {
			var dep backup.KeyDependency
			var version int64
			if err = rows.Scan(&dep.KeyID, &version); err != nil || version < 1 || uint64(version) > uint64(^uint32(0)) {
				rows.Close()
				return backup.Manifest{}, fault.Unavailable
			}
			dep.Domain, dep.Version = domain, uint32(version)
			manifest.KeyDependencies = append(manifest.KeyDependencies, dep)
		}
		if err = rows.Close(); err != nil {
			return backup.Manifest{}, safeError(err)
		}
	}
	sort.Slice(manifest.KeyDependencies, func(i, j int) bool {
		a, b := manifest.KeyDependencies[i], manifest.KeyDependencies[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.KeyID != b.KeyID {
			return a.KeyID < b.KeyID
		}
		return a.Version < b.Version
	})
	manifest.HMACState, err = r.jsonRows(ctx, q, "SELECT org_id,domain,active_version,active_key_id,state,epoch,COALESCE(snapshot_id,''),COALESCE(target_version,0),COALESCE(target_key_id,''),COALESCE(checkpoint,'') FROM hmac_index_state ORDER BY org_id,domain", 10)
	if err != nil {
		return backup.Manifest{}, err
	}
	manifest.AuditCheckpoint, err = r.singleJSON(ctx, q, "SELECT count(*),COALESCE(sum(CASE WHEN state='acked' THEN 1 ELSE 0 END),0),COALESCE(max(event_id),'') FROM audit_outbox", 3)
	if err != nil {
		return backup.Manifest{}, err
	}
	manifest.AuditReceiverCheckpoint, err = r.jsonRows(ctx, q, "SELECT c.deployment_id,c.sequence,COALESCE(c.head_hash,''),(SELECT count(*) FROM audit_receiver_ledger l WHERE l.deployment_id=c.deployment_id) FROM audit_receiver_chain c ORDER BY c.deployment_id", 4)
	if err != nil {
		return backup.Manifest{}, err
	}
	manifest.RevocationCheckpoint, err = r.singleJSON(ctx, q, "SELECT COALESCE(sum(CASE WHEN revoked THEN 1 ELSE 0 END),0),(SELECT COALESCE(sum(CASE WHEN revoked THEN 1 ELSE 0 END),0) FROM session),COALESCE(max(revision),0) FROM access_grant", 3)
	if err != nil {
		return backup.Manifest{}, err
	}
	manifest.JobFenceCheckpoint, err = r.singleJSON(ctx, q, "SELECT count(*),COALESCE(max(fence),0),COALESCE(sum(CASE WHEN state IN('queued','leased') THEN 1 ELSE 0 END),0) FROM assessment_job", 3)
	if err != nil {
		return backup.Manifest{}, err
	}
	manifest.GraphCompCheckpoint, err = r.singleJSON(ctx, q, "SELECT COALESCE(max(graph_revision),0),(SELECT COALESCE(max(revision),0) FROM compensation_aggregate),(SELECT COALESCE(max(revision),0) FROM bonus_aggregate) FROM organization", 3)
	if err != nil {
		return backup.Manifest{}, err
	}
	return manifest, nil
}
func (r *Repository) jsonRows(ctx context.Context, q queryer, query string, width int) (json.RawMessage, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := [][]any{}
	for rows.Next() {
		values := make([]any, width)
		targets := make([]any, width)
		for i := range values {
			targets[i] = &values[i]
		}
		if err = rows.Scan(targets...); err != nil {
			return nil, safeError(err)
		}
		for i, v := range values {
			if raw, ok := v.([]byte); ok {
				values[i] = string(raw)
			}
		}
		out = append(out, values)
	}
	if rows.Err() != nil {
		return nil, safeError(rows.Err())
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fault.Unavailable
	}
	return encoded, nil
}
func (r *Repository) singleJSON(ctx context.Context, q queryer, query string, width int) (json.RawMessage, error) {
	row := q.QueryRowContext(ctx, query)
	values := make([]any, width)
	targets := make([]any, width)
	for i := range values {
		targets[i] = &values[i]
	}
	if err := row.Scan(targets...); err != nil {
		return nil, safeError(err)
	}
	for i, v := range values {
		if raw, ok := v.([]byte); ok {
			values[i] = string(raw)
		}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fault.Unavailable
	}
	return encoded, nil
}

func (r *Repository) FinalizeRestore(ctx context.Context, archiveDigest, hostDigest []byte, actorUID int64, now time.Time) error {
	if len(archiveDigest) != 32 || len(hostDigest) != 32 || actorUID < 0 || uint64(actorUID) > uint64(^uint32(0)) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	for _, query := range []string{"SELECT count(*) FROM key_rewrap_job WHERE state<>'ready'", "SELECT count(*) FROM hmac_index_state WHERE state<>'ready'"} {
		var blocked int64
		if err = tx.QueryRowContext(ctx, query).Scan(&blocked); err != nil {
			return safeError(err)
		}
		if blocked != 0 {
			return fault.Conflict
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE assessment_job SET state='queued',fence=fence+1,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,error_code='restore_requeue' WHERE state='leased'"); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, r.read().sql("UPDATE oidc_transaction SET consumed=1,issued_hash=NULL WHERE consumed=0", "UPDATE oidc_transaction SET consumed=true,issued_hash=NULL WHERE consumed=false")); err != nil {
		return safeError(err)
	}
	revokeSQL := "UPDATE session SET revoked=1 WHERE revoked=0"
	if r.Backend == "postgres" {
		revokeSQL = "UPDATE session SET revoked=true WHERE revoked=false"
	}
	result, err := tx.ExecContext(ctx, revokeSQL)
	if err != nil {
		return safeError(err)
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	_, err = tx.ExecContext(ctx, r.read().sql("INSERT INTO backup_restore_audit(id,archive_digest,actor_uid,actor_host_hash,revoked_sessions,recorded_at) VALUES(?,?,?,?,?,?)", "INSERT INTO backup_restore_audit(id,archive_digest,actor_uid,actor_host_hash,revoked_sessions,recorded_at) VALUES($1,$2,$3,$4,$5,$6)"), value.NewID(), archiveDigest, actorUID, hostDigest, revoked, r.read().bindTime(now))
	if err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}

type BackupKeySample struct {
	Domain string
	Key    sensitive.WrappedKey
}

func (r *Repository) BackupKeySamples(ctx context.Context) ([]BackupKeySample, error) {
	queries := map[string]string{
		"pii":          "SELECT kek_id,kek_version,wrapped_dek FROM encrypted_payload UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM workforce_payload ORDER BY 1,2",
		"interview":    "SELECT kek_id,kek_version,wrapped_dek FROM interview_payload ORDER BY 1,2",
		"assessment":   "SELECT kek_id,kek_version,wrapped_dek FROM assessment_payload ORDER BY 1,2",
		"financial":    "SELECT kek_id,kek_version,wrapped_dek FROM compensation_payload UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM bonus_payload UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM compensation_batch_header_payload UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM compensation_batch_payload UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM compensation_batch_import_candidate UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM salary_range_payload ORDER BY 1,2",
		"identity_mfa": "SELECT kek_id,kek_version,wrapped_dek FROM local_mfa_factor UNION ALL SELECT kek_id,kek_version,wrapped_dek FROM local_mfa_enrollment ORDER BY 1,2",
	}
	out := []BackupKeySample{}
	for _, domain := range []string{"pii", "interview", "assessment", "financial", "identity_mfa"} {
		rows, err := r.DB.QueryContext(ctx, queries[domain])
		if err != nil {
			return nil, safeError(err)
		}
		lastKey := ""
		var lastVersion int64
		for rows.Next() {
			var sample BackupKeySample
			var version int64
			if err = rows.Scan(&sample.Key.KEKID, &version, &sample.Key.Data); err != nil {
				rows.Close()
				return nil, safeError(err)
			}
			if sample.Key.KEKID == lastKey && version == lastVersion {
				continue
			}
			if version < 1 || uint64(version) > uint64(^uint32(0)) {
				rows.Close()
				return nil, fault.Unavailable
			}
			sample.Domain, sample.Key.Version = domain, uint32(version)
			out = append(out, sample)
			lastKey, lastVersion = sample.Key.KEKID, version
		}
		if err = rows.Close(); err != nil {
			return nil, safeError(err)
		}
	}
	return out, nil
}
