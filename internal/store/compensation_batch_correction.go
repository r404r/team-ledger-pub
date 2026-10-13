package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
)

func (r *Repository) AdjustmentBatchCorrection(ctx context.Context, org, id string) (compensation.BatchCorrectionRecord, error) {
	q := r.read()
	var out compensation.BatchCorrectionRecord
	var activated int64
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT org_id,id,business_code,corrects_batch_id,cycle_year,adjustment_type,manifest_digest,subject_id,activated_at FROM compensation_batch_correction WHERE org_id=? AND id=?"), org, id).Scan(&out.OrgID, &out.ID, &out.BusinessCode, &out.CorrectsBatchID, &out.CycleYear, &out.AdjustmentType, &out.ManifestDigest, &out.SubjectID, &activated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	out.ActivatedAt = time.UnixMicro(activated).UTC()
	return out, nil
}

func (t *transaction) RecordAdjustmentBatchCorrection(ctx context.Context, batch compensation.BatchRecord, id, digest, subject string, receipt compensation.BatchCommandReceipt, now time.Time) (compensation.BatchCorrectionRecord, error) {
	if batch.OrgID != t.org || batch.State != "activated" || digest == "" {
		return compensation.BatchCorrectionRecord{}, fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO compensation_batch_correction_counter(org_id,cycle_year,adjustment_type,next_sequence) VALUES(?,?,?,1) ON CONFLICT(org_id,cycle_year,adjustment_type) DO NOTHING", "INSERT INTO compensation_batch_correction_counter(org_id,cycle_year,adjustment_type,next_sequence) VALUES($1,$2,$3,1) ON CONFLICT(org_id,cycle_year,adjustment_type) DO NOTHING"), batch.OrgID, batch.CycleYear, batch.AdjustmentType)
	if err != nil {
		return compensation.BatchCorrectionRecord{}, safeError(err)
	}
	selectCounter := t.sql("SELECT next_sequence FROM compensation_batch_correction_counter WHERE org_id=? AND cycle_year=? AND adjustment_type=?", "SELECT next_sequence FROM compensation_batch_correction_counter WHERE org_id=$1 AND cycle_year=$2 AND adjustment_type=$3 FOR UPDATE")
	var sequence int64
	if err = t.tx.QueryRowContext(ctx, selectCounter, batch.OrgID, batch.CycleYear, batch.AdjustmentType).Scan(&sequence); err != nil {
		return compensation.BatchCorrectionRecord{}, safeError(err)
	}
	prefix := "NC"
	if batch.AdjustmentType == compensation.BatchSpecial {
		prefix = "SC"
	}
	code := fmt.Sprintf("%s-%04d-%04d", prefix, batch.CycleYear, sequence)
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE compensation_batch_correction_counter SET next_sequence=next_sequence+1 WHERE org_id=? AND cycle_year=? AND adjustment_type=?"), batch.OrgID, batch.CycleYear, batch.AdjustmentType); err != nil {
		return compensation.BatchCorrectionRecord{}, safeError(err)
	}
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_batch_correction(org_id,id,business_code,corrects_batch_id,cycle_year,adjustment_type,manifest_digest,subject_id,activated_at) VALUES(?,?,?,?,?,?,?,?,?)"), batch.OrgID, id, code, batch.ID, batch.CycleYear, batch.AdjustmentType, digest, subject, now.UnixMicro()); err != nil {
		return compensation.BatchCorrectionRecord{}, safeError(err)
	}
	receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt = batch.ID, batch.Revision, now
	if err = insertBatchReceipt(ctx, t.tx, reader{db: t.tx, backend: t.backend}, batch.OrgID, receipt); err != nil {
		return compensation.BatchCorrectionRecord{}, err
	}
	return compensation.BatchCorrectionRecord{OrgID: batch.OrgID, ID: id, BusinessCode: code, CorrectsBatchID: batch.ID, CycleYear: batch.CycleYear, AdjustmentType: batch.AdjustmentType, ManifestDigest: digest, SubjectID: subject, ActivatedAt: now}, nil
}
