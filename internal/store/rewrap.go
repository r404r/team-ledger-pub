package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/maintenance"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

var _ maintenance.Store = (*Repository)(nil)
var rewrapTables = map[string][]string{
	"pii": {"encrypted_payload", "workforce_payload"}, "interview": {"interview_payload"},
	"assessment": {"assessment_payload"}, "financial": {"compensation_payload", "bonus_payload", "compensation_batch_header_payload", "compensation_batch_payload", "compensation_batch_import_candidate", "salary_range_payload"},
}

func validRewrapTarget(target maintenance.Target) bool {
	tables := rewrapTables[target.Domain]
	return value.ValidID(target.OrgID) && len(tables) > 0 && target.KEKID != "" && len(target.KEKID) <= 128 && target.Version > 0 && len(target.ManifestDigest) == 32
}
func (r *Repository) recordKeyRewrapApproval(ctx context.Context, tx *sql.Tx, target maintenance.Target, kind string, now time.Time) error {
	_, err := tx.ExecContext(ctx, r.read().sql("INSERT INTO key_rewrap_approval_audit(id,org_id,domain,target_kek_id,target_kek_version,manifest_digest,kind,recorded_at) VALUES(?,?,?,?,?,?,?,?)", "INSERT INTO key_rewrap_approval_audit(id,org_id,domain,target_kek_id,target_kek_version,manifest_digest,kind,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)"), value.NewID(), target.OrgID, target.Domain, target.KEKID, int64(target.Version), target.ManifestDigest, kind, r.read().bindTime(now))
	return safeError(err)
}

func (r *Repository) BeginKeyRewrap(ctx context.Context, target maintenance.Target, now time.Time) error {
	if !validRewrapTarget(target) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if r.Backend == "postgres" {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || $2,0))", target.OrgID, target.Domain); err != nil {
			return safeError(err)
		}
	}
	var state, key string
	var version int64
	var digest []byte
	err = tx.QueryRowContext(ctx, r.read().sql("SELECT state,target_kek_id,target_kek_version,manifest_digest FROM key_rewrap_job WHERE org_id=? AND domain=?", "SELECT state,target_kek_id,target_kek_version,manifest_digest FROM key_rewrap_job WHERE org_id=$1 AND domain=$2 FOR UPDATE"), target.OrgID, target.Domain).Scan(&state, &key, &version, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		at := r.read().bindTime(now)
		statement := "INSERT INTO key_rewrap_job(org_id,domain,state,target_kek_id,target_kek_version,manifest_digest,started_at,updated_at) VALUES(?,?,'migrating',?,?,?,?,?)"
		args := []any{target.OrgID, target.Domain, target.KEKID, int64(target.Version), target.ManifestDigest, at, at}
		if r.Backend == "postgres" {
			statement = "INSERT INTO key_rewrap_job(org_id,domain,state,target_kek_id,target_kek_version,manifest_digest,started_at,updated_at) VALUES($1,$2,'migrating',$3,$4,$5,$6,$6)"
			args = args[:6]
		}
		_, err = tx.ExecContext(ctx, statement, args...)
		if err != nil {
			return safeError(err)
		}
		if err = r.recordKeyRewrapApproval(ctx, tx, target, "start", now); err != nil {
			return err
		}
	} else if err != nil {
		return safeError(err)
	} else if state == "ready" {
		if key == target.KEKID && version == int64(target.Version) && sha256Equal(digest, target.ManifestDigest) {
			return safeError(tx.Commit())
		}
		at := r.read().bindTime(now)
		statement := "UPDATE key_rewrap_job SET state='migrating',target_kek_id=?,target_kek_version=?,manifest_digest=?,completed=0,started_at=?,updated_at=? WHERE org_id=? AND domain=? AND state='ready'"
		args := []any{target.KEKID, int64(target.Version), target.ManifestDigest, at, at, target.OrgID, target.Domain}
		if r.Backend == "postgres" {
			statement = "UPDATE key_rewrap_job SET state='migrating',target_kek_id=$1,target_kek_version=$2,manifest_digest=$3,completed=0,started_at=$4,updated_at=$4 WHERE org_id=$5 AND domain=$6 AND state='ready'"
			args = []any{target.KEKID, int64(target.Version), target.ManifestDigest, at, target.OrgID, target.Domain}
		}
		result, updateErr := tx.ExecContext(ctx, statement, args...)
		if updateErr != nil {
			return safeError(updateErr)
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return fault.Conflict
		}
		if err = r.recordKeyRewrapApproval(ctx, tx, target, "start", now); err != nil {
			return err
		}
	} else if state == "migrating" && key == target.KEKID && version == int64(target.Version) && !sha256Equal(digest, target.ManifestDigest) {
		result, updateErr := tx.ExecContext(ctx, r.read().sql("UPDATE key_rewrap_job SET manifest_digest=?,updated_at=? WHERE org_id=? AND domain=? AND state='migrating' AND target_kek_id=? AND target_kek_version=?", "UPDATE key_rewrap_job SET manifest_digest=$1,updated_at=$2 WHERE org_id=$3 AND domain=$4 AND state='migrating' AND target_kek_id=$5 AND target_kek_version=$6"), target.ManifestDigest, r.read().bindTime(now), target.OrgID, target.Domain, target.KEKID, int64(target.Version))
		if updateErr != nil {
			return safeError(updateErr)
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return fault.Conflict
		}
		if err = r.recordKeyRewrapApproval(ctx, tx, target, "renew", now); err != nil {
			return err
		}
	} else if key != target.KEKID || version != int64(target.Version) || state == "blocked" {
		return fault.Conflict
	}
	return safeError(tx.Commit())
}
func (r *Repository) NextKeyRewrap(ctx context.Context, target maintenance.Target) (maintenance.Item, bool, error) {
	if !validRewrapTarget(target) {
		return maintenance.Item{}, false, fault.Invalid
	}
	var state, key string
	var version int64
	var digest []byte
	if err := r.DB.QueryRowContext(ctx, r.read().sql("SELECT state,target_kek_id,target_kek_version,manifest_digest FROM key_rewrap_job WHERE org_id=? AND domain=?", "SELECT state,target_kek_id,target_kek_version,manifest_digest FROM key_rewrap_job WHERE org_id=$1 AND domain=$2"), target.OrgID, target.Domain).Scan(&state, &key, &version, &digest); err != nil {
		return maintenance.Item{}, false, safeError(err)
	} else if state == "ready" {
		return maintenance.Item{}, false, nil
	} else if state != "migrating" || key != target.KEKID || version != int64(target.Version) || !sha256Equal(digest, target.ManifestDigest) {
		return maintenance.Item{}, false, fault.Conflict
	}
	for _, table := range rewrapTables[target.Domain] {
		query := fmt.Sprintf("SELECT id,kek_id,kek_version,wrapped_dek FROM %s WHERE org_id=? AND (kek_id<>? OR kek_version<>?) ORDER BY id LIMIT 1", table)
		if r.Backend == "postgres" {
			query = fmt.Sprintf("SELECT id,kek_id,kek_version,wrapped_dek FROM %s WHERE org_id=$1 AND (kek_id<>$2 OR kek_version<>$3) ORDER BY id COLLATE \"C\" LIMIT 1", table)
		}
		var item maintenance.Item
		var keyVersion int64
		err := r.DB.QueryRowContext(ctx, query, target.OrgID, target.KEKID, int64(target.Version)).Scan(&item.ID, &item.Key.KEKID, &keyVersion, &item.Key.Data)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return maintenance.Item{}, false, safeError(err)
		}
		item.Table, item.Key.Version = table, uint32(keyVersion)
		return item, true, nil
	}
	return maintenance.Item{}, false, nil
}
func (r *Repository) CommitKeyRewrap(ctx context.Context, target maintenance.Target, item maintenance.Item, next sensitive.WrappedKey, now time.Time) error {
	allowed := false
	for _, table := range rewrapTables[target.Domain] {
		allowed = allowed || item.Table == table
	}
	if !validRewrapTarget(target) || !allowed || !value.ValidID(item.ID) || next.KEKID != target.KEKID || next.Version != target.Version || len(next.Data) == 0 {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	query := fmt.Sprintf("UPDATE %s SET kek_id=?,kek_version=?,wrapped_dek=? WHERE org_id=? AND id=? AND kek_id=? AND kek_version=? AND wrapped_dek=?", item.Table)
	args := []any{next.KEKID, int64(next.Version), next.Data, target.OrgID, item.ID, item.Key.KEKID, int64(item.Key.Version), item.Key.Data}
	if r.Backend == "postgres" {
		query = fmt.Sprintf("UPDATE %s SET kek_id=$1,kek_version=$2,wrapped_dek=$3 WHERE org_id=$4 AND id=$5 AND kek_id=$6 AND kek_version=$7 AND wrapped_dek=$8", item.Table)
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return safeError(err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return fault.Conflict
	}
	result, err = tx.ExecContext(ctx, r.read().sql("UPDATE key_rewrap_job SET completed=completed+1,updated_at=? WHERE org_id=? AND domain=? AND state='migrating' AND target_kek_id=? AND target_kek_version=? AND manifest_digest=?", "UPDATE key_rewrap_job SET completed=completed+1,updated_at=$1 WHERE org_id=$2 AND domain=$3 AND state='migrating' AND target_kek_id=$4 AND target_kek_version=$5 AND manifest_digest=$6"), r.read().bindTime(now), target.OrgID, target.Domain, target.KEKID, int64(target.Version), target.ManifestDigest)
	if err != nil {
		return safeError(err)
	}
	changed, _ = result.RowsAffected()
	if changed != 1 {
		return fault.Conflict
	}
	return safeError(tx.Commit())
}
func (r *Repository) CompleteKeyRewrap(ctx context.Context, target maintenance.Target, actor maintenance.Actor, now time.Time) error {
	if !validRewrapTarget(target) || actor.UID < 0 || uint64(actor.UID) > uint64(^uint32(0)) || len(actor.HostDigest) != 32 {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if r.Backend == "postgres" {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || $2,0))", target.OrgID, target.Domain); err != nil {
			return safeError(err)
		}
	}
	var state string
	var completed int64
	err = tx.QueryRowContext(ctx, r.read().sql("SELECT state,completed FROM key_rewrap_job WHERE org_id=? AND domain=?", "SELECT state,completed FROM key_rewrap_job WHERE org_id=$1 AND domain=$2 FOR UPDATE"), target.OrgID, target.Domain).Scan(&state, &completed)
	if err != nil {
		return safeError(err)
	}
	if state == "ready" {
		return safeError(tx.Commit())
	}
	if state != "migrating" {
		return fault.Conflict
	}
	for _, table := range rewrapTables[target.Domain] {
		query := fmt.Sprintf("SELECT count(*) FROM %s WHERE org_id=? AND (kek_id<>? OR kek_version<>?)", table)
		if r.Backend == "postgres" {
			query = fmt.Sprintf("SELECT count(*) FROM %s WHERE org_id=$1 AND (kek_id<>$2 OR kek_version<>$3)", table)
		}
		var remaining int64
		if err = tx.QueryRowContext(ctx, query, target.OrgID, target.KEKID, int64(target.Version)).Scan(&remaining); err != nil {
			return safeError(err)
		}
		if remaining != 0 {
			return fault.Conflict
		}
	}
	result, err := tx.ExecContext(ctx, r.read().sql("UPDATE key_rewrap_job SET state='ready',updated_at=? WHERE org_id=? AND domain=? AND state='migrating' AND target_kek_id=? AND target_kek_version=? AND manifest_digest=?", "UPDATE key_rewrap_job SET state='ready',updated_at=$1 WHERE org_id=$2 AND domain=$3 AND state='migrating' AND target_kek_id=$4 AND target_kek_version=$5 AND manifest_digest=$6"), r.read().bindTime(now), target.OrgID, target.Domain, target.KEKID, int64(target.Version), target.ManifestDigest)
	if err != nil {
		return safeError(err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return fault.Conflict
	}
	_, err = tx.ExecContext(ctx, r.read().sql("INSERT INTO key_rewrap_audit(id,org_id,domain,target_kek_id,target_kek_version,manifest_digest,completed,actor_uid,actor_host_hash,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)", "INSERT INTO key_rewrap_audit(id,org_id,domain,target_kek_id,target_kek_version,manifest_digest,completed,actor_uid,actor_host_hash,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"), value.NewID(), target.OrgID, target.Domain, target.KEKID, int64(target.Version), target.ManifestDigest, completed, actor.UID, actor.HostDigest, r.read().bindTime(now))
	if err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}
