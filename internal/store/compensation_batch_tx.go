package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
)

func (t *transaction) FinalizeAdjustmentBatch(ctx context.Context, org, batch string, expectedRevision int64, manifest, subject string, receipt compensation.BatchCommandReceipt, now time.Time) error {
	if org != t.org || manifest == "" {
		return fault.Invalid
	}
	result, err := t.tx.ExecContext(ctx, t.sql("UPDATE compensation_adjustment_batch SET state='activated',revision=revision+1,manifest_digest=?,activated_at=? WHERE org_id=? AND id=? AND revision=? AND state IN('draft','activation_blocked')", "UPDATE compensation_adjustment_batch SET state='activated',revision=revision+1,manifest_digest=$1,activated_at=$2 WHERE org_id=$3 AND id=$4 AND revision=$5 AND state IN('draft','activation_blocked')"), manifest, now.UnixMicro(), org, batch, expectedRevision)
	if err = interviewAffected(result, err, fault.Conflict); err != nil {
		return err
	}
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,?,'submitted_preparing',?,?)"), org, batch, expectedRevision, now.UnixMicro(), subject); err != nil {
		return safeError(err)
	}
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,?,'activated',?,?)"), org, batch, expectedRevision+1, now.UnixMicro(), subject); err != nil {
		return safeError(err)
	}
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_batch_activation(org_id,batch_id,activated_at,subject_id,manifest_digest) VALUES(?,?,?,?,?)"), org, batch, now.UnixMicro(), subject, manifest); err != nil {
		return safeError(err)
	}
	receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt = batch, expectedRevision+1, now
	return insertBatchReceipt(ctx, t.tx, reader{db: t.tx, backend: t.backend}, org, receipt)
}

func (t *transaction) LockSalaryRangeBasis(ctx context.Context, org, id string, revision int64, effective string) error {
	if org != t.org {
		return fault.Invalid
	}
	var current int64
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT revision FROM salary_range WHERE org_id=? AND id=? AND revision=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?)", "SELECT revision FROM salary_range WHERE org_id=$1 AND id=$2 AND revision=$3 AND valid_from<=$4 AND (valid_to IS NULL OR valid_to>$5) FOR UPDATE"), org, id, revision, effective, effective).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) || err == nil && current != revision {
		return fault.Conflict
	}
	if err != nil {
		return safeError(err)
	}
	return nil
}

func (t *transaction) LinkAdjustmentBatchEvents(ctx context.Context, org, batch, employee string, events []compensation.EventRecord, countsAsAdjustment bool) error {
	if org != t.org {
		return fault.Invalid
	}
	for _, event := range events {
		if event.OrgID != org || event.EmployeeID != employee {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_batch_event(org_id,batch_id,event_id,employee_id,effective_date,counts_as_adjustment) VALUES(?,?,?,?,?,?)"), org, batch, event.ID, employee, event.EffectiveDate, countsAsAdjustment); err != nil {
			return safeError(err)
		}
	}
	return nil
}

func (t *transaction) ValidateAdjustmentBatchCorrectionRoot(ctx context.Context, org, batch, employee string, members []compensation.CorrectionMember) error {
	if org != t.org {
		return fault.Invalid
	}
	var root string
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT event_id FROM compensation_batch_event WHERE org_id=? AND batch_id=? AND employee_id=? AND counts_as_adjustment=1", "SELECT event_id FROM compensation_batch_event WHERE org_id=$1 AND batch_id=$2 AND employee_id=$3 AND counts_as_adjustment"), org, batch, employee).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.Conflict
	}
	if err != nil {
		return safeError(err)
	}
	for _, member := range members {
		if member.OriginalEventID == root {
			return nil
		}
	}
	return fault.Conflict
}
