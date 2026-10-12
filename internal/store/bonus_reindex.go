package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

type bonusHMACState struct {
	activeVersion, epoch                int64
	targetVersion                       sql.NullInt64
	activeKeyID, state                  string
	snapshotID, targetKeyID, checkpoint sql.NullString
	manifest                            []byte
}

func (r *Repository) ReindexBonusPaymentHMAC(ctx context.Context, org string, targetVersion int64, targetKeyID string, interruptAfter int, approval compensation.BonusHMACMaintenanceApproval, digest func(compensation.BonusPaymentRecord) ([]byte, error)) error {
	if digest == nil || !value.ValidID(org) || targetVersion < 1 || targetKeyID == "" || interruptAfter < 0 || !value.ValidID(approval.ApprovedBySubjectID) || !value.ValidID(approval.RequestID) || len(approval.ApprovalDigest) != sha256.Size {
		return fault.Invalid
	}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return err
	}
	state, err := r.beginBonusHMACReindex(ctx, org, targetVersion, targetKeyID)
	if err != nil {
		return err
	}
	processed := 0
	for {
		batch, err := r.pendingBonusHMACPayments(ctx, org, state.snapshotID.String)
		if err != nil {
			r.blockBonusHMACReindex(ctx, org, state.snapshotID.String)
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, payment := range batch {
			computed, e := digest(payment)
			if e != nil || len(computed) != sha256.Size {
				r.blockBonusHMACReindex(ctx, org, state.snapshotID.String)
				return fault.Unavailable
			}
			if e = r.stageBonusHMACDigest(ctx, org, state.snapshotID.String, targetVersion, payment, computed); e != nil {
				r.blockBonusHMACReindex(ctx, org, state.snapshotID.String)
				return e
			}
			processed++
			if interruptAfter > 0 && processed == interruptAfter {
				r.blockBonusHMACReindex(ctx, org, state.snapshotID.String)
				return fault.Unavailable
			}
		}
	}
	err = r.finishBonusHMACReindex(ctx, org, state.snapshotID.String, targetVersion, targetKeyID, state.manifest, approval, actor)
	if err != nil {
		r.blockBonusHMACReindex(ctx, org, state.snapshotID.String)
	}
	return err
}

func (r *Repository) beginBonusHMACReindex(ctx context.Context, org string, targetVersion int64, targetKeyID string) (bonusHMACState, error) {
	var out bonusHMACState
	err := r.WithTx(ctx, org, func(raw organization.Tx) error {
		t := raw.(*transaction)
		state, err := readBonusHMACState(ctx, t, org)
		if err != nil {
			return err
		}
		if state.state == "ready" {
			if targetVersion <= state.activeVersion || targetKeyID == state.activeKeyID {
				return fault.Conflict
			}
			manifest, e := bonusPaymentManifest(ctx, t, org)
			if e != nil {
				return e
			}
			snapshot := value.NewID()
			if _, e = t.tx.ExecContext(ctx, t.structureSQL("DELETE FROM bonus_payment_business_index_staging WHERE org_id=?"), org); e != nil {
				return safeError(e)
			}
			result, e := t.tx.ExecContext(ctx, t.structureSQL("UPDATE hmac_index_state SET state='migrating',snapshot_id=?,target_version=?,target_key_id=?,checkpoint=NULL,manifest_digest=? WHERE org_id=? AND domain='bonus_payment' AND state='ready' AND epoch=?"), snapshot, targetVersion, targetKeyID, manifest, org, state.epoch)
			if e != nil {
				return safeError(e)
			}
			if n, _ := result.RowsAffected(); n != 1 {
				return fault.Conflict
			}
			state.state, state.snapshotID, state.targetVersion, state.targetKeyID, state.manifest = "migrating", sql.NullString{String: snapshot, Valid: true}, sql.NullInt64{Int64: targetVersion, Valid: true}, sql.NullString{String: targetKeyID, Valid: true}, manifest
			out = state
			return nil
		}
		if !state.snapshotID.Valid || !state.targetKeyID.Valid || !state.targetVersion.Valid || state.targetVersion.Int64 != targetVersion || state.targetKeyID.String != targetKeyID || len(state.manifest) != sha256.Size {
			return fault.Conflict
		}
		result, e := t.tx.ExecContext(ctx, t.structureSQL("UPDATE hmac_index_state SET state='migrating' WHERE org_id=? AND domain='bonus_payment' AND state IN('migrating','blocked') AND snapshot_id=?"), org, state.snapshotID.String)
		if e != nil {
			return safeError(e)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Conflict
		}
		state.state = "migrating"
		out = state
		return nil
	})
	return out, err
}

func readBonusHMACState(ctx context.Context, t *transaction, org string) (bonusHMACState, error) {
	var state bonusHMACState
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT active_version,active_key_id,state,epoch,snapshot_id,target_version,target_key_id,checkpoint,manifest_digest FROM hmac_index_state WHERE org_id=? AND domain='bonus_payment'"), org).Scan(&state.activeVersion, &state.activeKeyID, &state.state, &state.epoch, &state.snapshotID, &state.targetVersion, &state.targetKeyID, &state.checkpoint, &state.manifest)
	return state, compensationReadError(err)
}

func bonusPaymentManifest(ctx context.Context, t *transaction, org string) ([]byte, error) {
	rows, err := t.tx.QueryContext(ctx, t.structureSQL("SELECT employee_id,id,payload_id FROM bonus_payment WHERE org_id=? ORDER BY employee_id,id"), org)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	hash := sha256.New()
	hash.Write([]byte("teamledger/bonus-payment-reindex-manifest/v1"))
	var count uint64
	var size [8]byte
	for rows.Next() {
		var employee, id, payload string
		if err = rows.Scan(&employee, &id, &payload); err != nil {
			return nil, safeError(err)
		}
		count++
		for _, part := range []string{employee, id, payload} {
			binary.BigEndian.PutUint64(size[:], uint64(len(part)))
			hash.Write(size[:])
			hash.Write([]byte(part))
		}
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
	}
	binary.BigEndian.PutUint64(size[:], count)
	hash.Write(size[:])
	return hash.Sum(nil), nil
}

func (r *Repository) pendingBonusHMACPayments(ctx context.Context, org, snapshot string) ([]compensation.BonusPaymentRecord, error) {
	rows, err := r.DB.QueryContext(ctx, r.sql("SELECT p.org_id,p.employee_id,p.id,p.payload_id,p.kind,p.paid_date,p.business_source,p.award_id,p.original_payment_id,p.business_key_version,p.basis_revision,p.business_digest,p.recorded_at FROM bonus_payment p LEFT JOIN bonus_payment_business_index_staging s ON s.org_id=p.org_id AND s.snapshot_id=? AND s.payment_id=p.id WHERE p.org_id=? AND s.payment_id IS NULL ORDER BY p.employee_id,p.id LIMIT 100", "SELECT p.org_id,p.employee_id,p.id,p.payload_id,p.kind,p.paid_date::text,p.business_source,p.award_id,p.original_payment_id,p.business_key_version,p.basis_revision,p.business_digest,p.recorded_at FROM bonus_payment p LEFT JOIN bonus_payment_business_index_staging s ON s.org_id=p.org_id AND s.snapshot_id=$1 AND s.payment_id=p.id WHERE p.org_id=$2 AND s.payment_id IS NULL ORDER BY p.employee_id,p.id LIMIT 100"), snapshot, org)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.BonusPaymentRecord, 0, 100)
	for rows.Next() {
		payment, e := scanBonusPayment(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, payment)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) stageBonusHMACDigest(ctx context.Context, org, snapshot string, targetVersion int64, payment compensation.BonusPaymentRecord, digest []byte) error {
	return r.WithTx(ctx, org, func(raw organization.Tx) error {
		t := raw.(*transaction)
		var marker string
		if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT state FROM hmac_index_state WHERE org_id=? AND domain='bonus_payment' AND snapshot_id=? AND target_version=?"), org, snapshot, targetVersion).Scan(&marker); err != nil || marker != "migrating" {
			return fault.Conflict
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_payment_business_index_staging(org_id,employee_id,domain,snapshot_id,key_version,digest,payment_id) VALUES(?,?,'bonus_payment',?,?,?,?)"), org, payment.EmployeeID, snapshot, targetVersion, digest, payment.ID); err != nil {
			return safeError(err)
		}
		_, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE hmac_index_state SET checkpoint=? WHERE org_id=? AND domain='bonus_payment' AND snapshot_id=?"), payment.ID, org, snapshot)
		return safeError(err)
	})
}

func (r *Repository) blockBonusHMACReindex(ctx context.Context, org, snapshot string) {
	_ = r.WithTx(ctx, org, func(raw organization.Tx) error {
		t := raw.(*transaction)
		_, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE hmac_index_state SET state='blocked' WHERE org_id=? AND domain='bonus_payment' AND snapshot_id=? AND state='migrating'"), org, snapshot)
		return safeError(err)
	})
}

func (r *Repository) finishBonusHMACReindex(ctx context.Context, org, snapshot string, targetVersion int64, targetKeyID string, expectedManifest []byte, approval compensation.BonusHMACMaintenanceApproval, actor maintenancePrincipal) error {
	return r.WithTx(ctx, org, func(raw organization.Tx) error {
		t := raw.(*transaction)
		state, err := readBonusHMACState(ctx, t, org)
		if err != nil || state.state != "migrating" || !state.snapshotID.Valid || state.snapshotID.String != snapshot || !state.targetVersion.Valid || state.targetVersion.Int64 != targetVersion || !state.targetKeyID.Valid || state.targetKeyID.String != targetKeyID {
			return fault.Conflict
		}
		actualManifest, err := bonusPaymentManifest(ctx, t, org)
		if err != nil || !bytesEqual(actualManifest, expectedManifest) || !bytesEqual(state.manifest, expectedManifest) {
			return fault.Unavailable
		}
		var payments, staged, missing int64
		if err = t.tx.QueryRowContext(ctx, t.structureSQL("SELECT count(*) FROM bonus_payment WHERE org_id=?"), org).Scan(&payments); err != nil {
			return safeError(err)
		}
		if err = t.tx.QueryRowContext(ctx, t.structureSQL("SELECT count(*) FROM bonus_payment_business_index_staging WHERE org_id=? AND snapshot_id=?"), org, snapshot).Scan(&staged); err != nil {
			return safeError(err)
		}
		if err = t.tx.QueryRowContext(ctx, t.structureSQL("SELECT count(*) FROM bonus_payment p LEFT JOIN bonus_payment_business_index_staging s ON s.org_id=p.org_id AND s.snapshot_id=? AND s.payment_id=p.id AND s.employee_id=p.employee_id WHERE p.org_id=? AND s.payment_id IS NULL"), snapshot, org).Scan(&missing); err != nil || payments != staged || missing != 0 {
			return fault.Unavailable
		}
		var approverActive bool
		if err = t.tx.QueryRowContext(ctx, t.structureSQL("SELECT active FROM subject WHERE org_id=? AND id=?"), org, approval.ApprovedBySubjectID).Scan(&approverActive); err != nil || !approverActive {
			return fault.Forbidden
		}
		if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_hmac_maintenance_audit(id,org_id,approved_by_subject_id,request_id,target_version,target_key_id,approval_digest,actor_uid,actor_host_hash,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)"), value.NewID(), org, approval.ApprovedBySubjectID, approval.RequestID, targetVersion, targetKeyID, approval.ApprovalDigest, actor.uid, actor.hostHash[:], t.bindTime(time.Now())); err != nil {
			return fault.AuditUnavailable
		}
		if _, err = t.tx.ExecContext(ctx, t.structureSQL("DELETE FROM bonus_payment_business_index WHERE org_id=?"), org); err != nil {
			return safeError(err)
		}
		if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_payment_business_index(org_id,employee_id,domain,key_version,digest,payment_id) SELECT org_id,employee_id,domain,key_version,digest,payment_id FROM bonus_payment_business_index_staging WHERE org_id=? AND snapshot_id=?"), org, snapshot); err != nil {
			return safeError(err)
		}
		if _, err = t.tx.ExecContext(ctx, t.structureSQL("DELETE FROM bonus_payment_business_index_staging WHERE org_id=? AND snapshot_id=?"), org, snapshot); err != nil {
			return safeError(err)
		}
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE hmac_index_state SET active_version=?,active_key_id=?,state='ready',epoch=epoch+1,snapshot_id=NULL,target_version=NULL,target_key_id=NULL,checkpoint=NULL,manifest_digest=NULL WHERE org_id=? AND domain='bonus_payment' AND snapshot_id=?"), targetVersion, targetKeyID, org, snapshot)
		if err != nil {
			return safeError(err)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Conflict
		}
		return nil
	})
}

func bytesEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}
