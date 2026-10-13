package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

var _ audit.ReceiverStore = (*Repository)(nil)

func validAuditDeployment(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func (r *Repository) receiverReceipt(ctx context.Context, q queryer, deployment, event string) ([]byte, []byte, bool, error) {
	query := r.sql("SELECT payload_digest,receipt_bytes FROM audit_receiver_ledger WHERE deployment_id=? AND event_id=?", "SELECT payload_digest,receipt_bytes FROM audit_receiver_ledger WHERE deployment_id=$1 AND event_id=$2")
	var digest, receipt []byte
	err := q.QueryRowContext(ctx, query, deployment, event).Scan(&digest, &receipt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, safeError(err)
	}
	if len(digest) != 32 || len(receipt) < 2 || len(receipt) > 16<<10 {
		return nil, nil, false, fault.Unavailable
	}
	return digest, receipt, true, nil
}

func (r *Repository) CommitAuditReceipt(ctx context.Context, deployment, event string, digest []byte, build audit.ReceiptBuilder) ([]byte, error) {
	if !validAuditDeployment(deployment) || !value.ValidID(event) || len(digest) != 32 {
		return nil, fault.Invalid
	}
	if priorDigest, receipt, found, err := r.receiverReceipt(ctx, r.DB, deployment, event); err != nil {
		return nil, err
	} else if found {
		if subtle.ConstantTimeCompare(priorDigest, digest) != 1 {
			return nil, audit.ErrAuditEventConflict
		}
		return receipt, nil
	}
	if build == nil {
		return nil, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, safeError(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertHead := r.sql("INSERT OR IGNORE INTO audit_receiver_chain(deployment_id,sequence,head_hash,updated_at) VALUES(?,0,NULL,?)", "INSERT INTO audit_receiver_chain(deployment_id,sequence,head_hash,updated_at) VALUES($1,0,NULL,$2) ON CONFLICT(deployment_id) DO NOTHING")
	if _, err = tx.ExecContext(ctx, insertHead, deployment, r.BindTime(now)); err != nil {
		return nil, safeError(err)
	}
	if r.Backend == "sqlite" {
		if _, err = tx.ExecContext(ctx, "UPDATE audit_receiver_chain SET sequence=sequence WHERE deployment_id=?", deployment); err != nil {
			return nil, safeError(err)
		}
	}
	if priorDigest, receipt, found, lookupErr := r.receiverReceipt(ctx, tx, deployment, event); lookupErr != nil {
		return nil, lookupErr
	} else if found {
		if subtle.ConstantTimeCompare(priorDigest, digest) != 1 {
			return nil, audit.ErrAuditEventConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, safeError(err)
		}
		return receipt, nil
	}
	queryHead := r.sql("SELECT sequence,head_hash FROM audit_receiver_chain WHERE deployment_id=?", "SELECT sequence,head_hash FROM audit_receiver_chain WHERE deployment_id=$1 FOR UPDATE")
	var sequence int64
	var previous []byte
	if err = tx.QueryRowContext(ctx, queryHead, deployment).Scan(&sequence, &previous); err != nil {
		return nil, safeError(err)
	}
	if sequence < 0 || sequence == 0 && len(previous) != 0 || sequence > 0 && len(previous) != 32 {
		return nil, fault.Unavailable
	}
	if sequence > 0 {
		queryLedgerHead := r.sql("SELECT entry_hash FROM audit_receiver_ledger WHERE deployment_id=? AND sequence=?", "SELECT entry_hash FROM audit_receiver_ledger WHERE deployment_id=$1 AND sequence=$2")
		var ledgerHead []byte
		if err = tx.QueryRowContext(ctx, queryLedgerHead, deployment, sequence).Scan(&ledgerHead); err != nil || subtle.ConstantTimeCompare(ledgerHead, previous) != 1 {
			return nil, fault.Unavailable
		}
	}
	receipt, entryHash, err := build(sequence+1, append([]byte(nil), previous...))
	if err != nil {
		return nil, err
	}
	if len(entryHash) != 32 || len(receipt) < 2 || len(receipt) > 16<<10 {
		return nil, fault.Invalid
	}
	receiptID, keyID, receivedAt, err := audit.ValidateReceiptStorage(receipt, deployment, event, digest, sequence+1, previous, entryHash)
	if err != nil {
		return nil, fault.Invalid
	}
	insertLedger := r.sql("INSERT INTO audit_receiver_ledger(deployment_id,event_id,payload_digest,sequence,previous_hash,entry_hash,receipt_id,receipt_bytes,key_id,received_at) VALUES(?,?,?,?,?,?,?,?,?,?)", "INSERT INTO audit_receiver_ledger(deployment_id,event_id,payload_digest,sequence,previous_hash,entry_hash,receipt_id,receipt_bytes,key_id,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
	var previousValue any
	if len(previous) != 0 {
		previousValue = previous
	}
	if _, err = tx.ExecContext(ctx, insertLedger, deployment, event, digest, sequence+1, previousValue, entryHash, receiptID, receipt, keyID, r.BindTime(receivedAt)); err != nil {
		return nil, safeError(err)
	}
	updateHead := r.sql("UPDATE audit_receiver_chain SET sequence=?,head_hash=?,updated_at=? WHERE deployment_id=? AND sequence=?", "UPDATE audit_receiver_chain SET sequence=$1,head_hash=$2,updated_at=$3 WHERE deployment_id=$4 AND sequence=$5")
	result, err := tx.ExecContext(ctx, updateHead, sequence+1, entryHash, r.BindTime(receivedAt), deployment, sequence)
	if err != nil {
		return nil, safeError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, fault.Conflict
	}
	if err = tx.Commit(); err != nil {
		return nil, safeError(err)
	}
	return append([]byte(nil), receipt...), nil
}

// AuditReceiverReady checks the exact schema and proves the receiver role can
// insert its own chain state without leaving a persistent probe row.
func (r *Repository) AuditReceiverReady(ctx context.Context) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "SELECT max(version) FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		return fault.Unavailable
	}
	var invalidHeads int
	headCheck := "SELECT count(*) FROM audit_receiver_chain c WHERE c.sequence<0 OR (c.sequence=0 AND c.head_hash IS NOT NULL) OR (c.sequence>0 AND NOT EXISTS (SELECT 1 FROM audit_receiver_ledger l WHERE l.deployment_id=c.deployment_id AND l.sequence=c.sequence AND l.entry_hash=c.head_hash))"
	if err = tx.QueryRowContext(ctx, headCheck).Scan(&invalidHeads); err != nil || invalidHeads != 0 {
		return fault.Unavailable
	}
	deployment := "probe-" + value.NewID()
	query := r.sql("INSERT INTO audit_receiver_chain(deployment_id,sequence,head_hash,updated_at) VALUES(?,0,NULL,?)", "INSERT INTO audit_receiver_chain(deployment_id,sequence,head_hash,updated_at) VALUES($1,0,NULL,$2)")
	if _, err = tx.ExecContext(ctx, query, deployment, r.BindTime(time.Now().UTC().Truncate(time.Microsecond))); err != nil {
		return safeError(err)
	}
	return nil
}

func (r *Repository) RecordAuditReceiverStatus(ctx context.Context, deployment string, ready bool, checkedAt time.Time) error {
	if !validAuditDeployment(deployment) || checkedAt.IsZero() || checkedAt.Location() != time.UTC {
		return fault.Invalid
	}
	query := r.sql(
		"INSERT INTO audit_receiver_status(id,deployment_id,ready,checked_at) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET deployment_id=excluded.deployment_id,ready=excluded.ready,checked_at=excluded.checked_at",
		"INSERT INTO audit_receiver_status(id,deployment_id,ready,checked_at) VALUES(1,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET deployment_id=excluded.deployment_id,ready=excluded.ready,checked_at=excluded.checked_at")
	if _, err := r.DB.ExecContext(ctx, query, deployment, ready, r.BindTime(checkedAt)); err != nil {
		return safeError(err)
	}
	return nil
}

func (r *Repository) AuditReceiverAvailable(ctx context.Context, deployment string, now time.Time, maxAge time.Duration) error {
	if !validAuditDeployment(deployment) || now.IsZero() || now.Location() != time.UTC || maxAge <= 0 {
		return fault.Invalid
	}
	query := r.sql(
		"SELECT count(*) FROM audit_receiver_status WHERE deployment_id=? AND ready=1 AND checked_at>=?",
		"SELECT count(*) FROM audit_receiver_status WHERE deployment_id=$1 AND ready=true AND checked_at>=$2")
	var count int
	if err := r.DB.QueryRowContext(ctx, query, deployment, r.BindTime(now.Add(-maxAge))).Scan(&count); err != nil || count < 1 {
		return fault.Unavailable
	}
	return nil
}
