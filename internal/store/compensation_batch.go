package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

var _ compensation.BatchStore = (*Repository)(nil)

func scanAdjustmentBatch(row grantScanner) (compensation.BatchRecord, error) {
	var out compensation.BatchRecord
	var created, activated int64
	err := row.Scan(&out.OrgID, &out.ID, &out.BusinessCode, &out.CycleYear, &out.AdjustmentType, &out.LegalEntityID, &out.DefaultEffectiveDate, &out.State, &out.Revision, &out.ManifestDigest, &out.CreatorSubjectID, &out.ActivationSubjectID, &created, &activated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	out.CreatedAt = time.UnixMicro(created).UTC()
	if activated > 0 {
		out.ActivatedAt = time.UnixMicro(activated).UTC()
	}
	return out, nil
}

func (r reader) adjustmentBatchSelect() string {
	date := "COALESCE(default_effective_date,'')"
	if r.backend == "postgres" {
		date = "COALESCE(default_effective_date::text,'')"
	}
	return "SELECT org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id," + date + ",state,revision,COALESCE(manifest_digest,''),creator_subject_id,(SELECT subject_id FROM compensation_batch_service s WHERE s.org_id=compensation_adjustment_batch.org_id AND s.batch_id=compensation_adjustment_batch.id),created_at,COALESCE(activated_at,0) FROM compensation_adjustment_batch"
}

func (r *Repository) CreateAdjustmentBatch(ctx context.Context, org, subject, id, serviceSubject string, command compensation.CreateBatchCommand, receipt compensation.BatchCommandReceipt, now time.Time) (compensation.BatchRecord, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	_, err = tx.ExecContext(ctx, q.sql("INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,TRUE,1)"), org, serviceSubject)
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	_, err = tx.ExecContext(ctx, q.sql("INSERT INTO compensation_batch_number_counter(org_id,cycle_year,adjustment_type,next_sequence) VALUES(?,?,?,1) ON CONFLICT(org_id,cycle_year,adjustment_type) DO NOTHING", "INSERT INTO compensation_batch_number_counter(org_id,cycle_year,adjustment_type,next_sequence) VALUES($1,$2,$3,1) ON CONFLICT(org_id,cycle_year,adjustment_type) DO NOTHING"), org, command.CycleYear, command.AdjustmentType)
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	selectCounter := q.sql("SELECT next_sequence FROM compensation_batch_number_counter WHERE org_id=? AND cycle_year=? AND adjustment_type=?", "SELECT next_sequence FROM compensation_batch_number_counter WHERE org_id=$1 AND cycle_year=$2 AND adjustment_type=$3 FOR UPDATE")
	var sequence int64
	if err = tx.QueryRowContext(ctx, selectCounter, org, command.CycleYear, command.AdjustmentType).Scan(&sequence); err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	prefix := "N"
	if command.AdjustmentType == compensation.BatchSpecial {
		prefix = "S"
	}
	code := fmt.Sprintf("%s-%04d-%04d", prefix, command.CycleYear, sequence)
	_, err = tx.ExecContext(ctx, q.sql("UPDATE compensation_batch_number_counter SET next_sequence=next_sequence+1 WHERE org_id=? AND cycle_year=? AND adjustment_type=?", "UPDATE compensation_batch_number_counter SET next_sequence=next_sequence+1 WHERE org_id=$1 AND cycle_year=$2 AND adjustment_type=$3"), org, command.CycleYear, command.AdjustmentType)
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	var effective any
	if command.DefaultEffectiveDate != "" {
		effective = command.DefaultEffectiveDate
	}
	_, err = tx.ExecContext(ctx, q.sql("INSERT INTO compensation_adjustment_batch(org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id,default_effective_date,state,revision,creator_subject_id,created_at) VALUES(?,?,?,?,?,?,?,'draft',1,?,?)", "INSERT INTO compensation_adjustment_batch(org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id,default_effective_date,state,revision,creator_subject_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'draft',1,$8,$9)"), org, id, code, command.CycleYear, command.AdjustmentType, command.LegalEntityID, effective, subject, now.UnixMicro())
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,1,'draft',?,?)"), org, id, now.UnixMicro(), subject); err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	_, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_service(org_id,batch_id,subject_id) VALUES(?,?,?)"), org, id, serviceSubject)
	if err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE compensation_special_reason SET active=0 WHERE org_id=?", "UPDATE compensation_special_reason SET active=FALSE WHERE org_id=$1"), org); err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	for reasonCode, label := range command.SpecialReasons {
		_, err = tx.ExecContext(ctx, q.sql("INSERT INTO compensation_special_reason(org_id,code,label,active) VALUES(?,?,?,1) ON CONFLICT(org_id,code) DO UPDATE SET label=excluded.label,active=1", "INSERT INTO compensation_special_reason(org_id,code,label,active) VALUES($1,$2,$3,TRUE) ON CONFLICT(org_id,code) DO UPDATE SET label=EXCLUDED.label,active=TRUE"), org, reasonCode, label)
		if err != nil {
			return compensation.BatchRecord{}, safeError(err)
		}
	}
	receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt = id, 1, now
	if err = insertBatchReceipt(ctx, tx, q, org, r.commandReference(), receipt); err != nil {
		return compensation.BatchRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return compensation.BatchRecord{}, safeError(err)
	}
	return r.AdjustmentBatch(ctx, org, id)
}

func (r *Repository) AdjustmentBatch(ctx context.Context, org, id string) (compensation.BatchRecord, error) {
	q := r.read()
	return scanAdjustmentBatch(q.db.QueryRowContext(ctx, q.structureSQL(q.adjustmentBatchSelect()+" WHERE org_id=? AND id=?"), org, id))
}
func (r *Repository) AdjustmentBatchReceipt(ctx context.Context, org, subject, operation, key string) (compensation.BatchCommandReceipt, bool, error) {
	q := r.read()
	var out compensation.BatchCommandReceipt
	var recorded int64
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT subject_id,operation,key,digest,batch_id,result_revision,recorded_at FROM compensation_batch_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?"), org, subject, operation, key).Scan(&out.SubjectID, &out.Operation, &out.Key, &out.Digest, &out.BatchID, &out.ResultRevision, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, safeError(err)
	}
	out.RecordedAt = time.UnixMicro(recorded).UTC()
	return out, true, nil
}

func (r *Repository) AdjustmentBatches(ctx context.Context, org string, year int, typ string, limit int) ([]compensation.BatchRecord, error) {
	if limit < 1 || limit > 100 {
		return nil, fault.Invalid
	}
	q := r.read()
	predicate := " WHERE org_id=?"
	args := []any{org}
	if year != 0 {
		predicate += " AND cycle_year=?"
		args = append(args, year)
	}
	if typ != "" {
		predicate += " AND adjustment_type=?"
		args = append(args, typ)
	}
	args = append(args, limit)
	rows, err := q.db.QueryContext(ctx, q.structureSQL(q.adjustmentBatchSelect()+predicate+" ORDER BY cycle_year DESC,business_code DESC LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.BatchRecord, 0, limit)
	for rows.Next() {
		item, err := scanAdjustmentBatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) AdjustmentBatchLines(ctx context.Context, org, batch string, revision int64) ([]compensation.BatchLineRecord, error) {
	q := r.read()
	rows, err := q.db.QueryContext(ctx, q.structureSQL("SELECT org_id,batch_id,id,employee_id,payload_id,result,batch_revision,ordinal FROM compensation_batch_line WHERE org_id=? AND batch_id=? AND batch_revision=? ORDER BY ordinal"), org, batch, revision)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.BatchLineRecord, 0)
	for rows.Next() {
		var line compensation.BatchLineRecord
		if err = rows.Scan(&line.OrgID, &line.BatchID, &line.ID, &line.EmployeeID, &line.PayloadID, &line.Result, &line.BatchRevision, &line.Ordinal); err != nil {
			return nil, safeError(err)
		}
		out = append(out, line)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) AdjustmentBatchPayload(ctx context.Context, org, id string) (compensation.BatchPayloadRecord, error) {
	q := r.read()
	var out compensation.BatchPayloadRecord
	var format, keyVersion int64
	var created int64
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT org_id,id,batch_id,batch_revision,employee_id,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM compensation_batch_payload WHERE org_id=? AND id=?"), org, id).Scan(&out.OrgID, &out.ID, &out.BatchID, &out.BatchRevision, &out.EmployeeID, &format, &out.Envelope.Algorithm, &out.Envelope.DEKID, &out.Envelope.Key.KEKID, &keyVersion, &out.Envelope.Key.Data, &out.Envelope.SealedBytes, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	out.Envelope.FormatVersion = uint16(format)
	out.Envelope.Key.Version = uint32(keyVersion)
	out.Envelope.Context = batchEnvelopeContext(out.OrgID, out.EmployeeID, out.ID)
	out.CreatedAt = time.UnixMicro(created).UTC()
	return out, nil
}

func (r *Repository) AdjustmentBatchCounts(ctx context.Context, org, employee string, year int) (compensation.AdjustmentCounts, error) {
	q := r.read()
	var out compensation.AdjustmentCounts
	query := "SELECT COALESCE(SUM(CASE WHEN substr(d,1,4)=? THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN substr(d,1,4)=? THEN 1 ELSE 0 END),0) FROM (SELECT be.effective_date d FROM compensation_batch_event be JOIN compensation_adjustment_batch b ON b.org_id=be.org_id AND b.id=be.batch_id WHERE be.org_id=? AND be.employee_id=? AND be.counts_as_adjustment=1 AND b.state='activated' UNION ALL SELECT ce.effective_date d FROM compensation_event ce WHERE ce.org_id=? AND ce.employee_id=? AND ce.kind='adjustment' AND NOT EXISTS(SELECT 1 FROM compensation_batch_event be WHERE be.org_id=ce.org_id AND be.event_id=ce.id)) counted"
	if q.backend == "postgres" {
		query = "SELECT COALESCE(SUM(CASE WHEN substring(d::text,1,4)=$1 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN substring(d::text,1,4)=$2 THEN 1 ELSE 0 END),0) FROM (SELECT be.effective_date d FROM compensation_batch_event be JOIN compensation_adjustment_batch b ON b.org_id=be.org_id AND b.id=be.batch_id WHERE be.org_id=$3 AND be.employee_id=$4 AND be.counts_as_adjustment AND b.state='activated' UNION ALL SELECT ce.effective_date d FROM compensation_event ce WHERE ce.org_id=$5 AND ce.employee_id=$6 AND ce.kind='adjustment' AND NOT EXISTS(SELECT 1 FROM compensation_batch_event be WHERE be.org_id=ce.org_id AND be.event_id=ce.id)) counted"
	}
	err := q.db.QueryRowContext(ctx, query, strconv.Itoa(year), strconv.Itoa(year-1), org, employee, org, employee).Scan(&out.CurrentYear, &out.PreviousYear)
	if err != nil {
		return out, safeError(err)
	}
	return out, nil
}

func (r *Repository) AdjustmentBatchOriginalEvent(ctx context.Context, org, batch, employee string) (string, error) {
	q := r.read()
	var id string
	err := q.db.QueryRowContext(ctx, q.sql("SELECT event_id FROM compensation_batch_event WHERE org_id=? AND batch_id=? AND employee_id=? AND counts_as_adjustment=1", "SELECT event_id FROM compensation_batch_event WHERE org_id=$1 AND batch_id=$2 AND employee_id=$3 AND counts_as_adjustment"), org, batch, employee).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fault.NotFound
	}
	return id, safeError(err)
}

func (r *Repository) ReplaceAdjustmentBatchLines(ctx context.Context, batch compensation.BatchRecord, payloads []compensation.BatchPayloadRecord, lines []compensation.BatchLineRecord, candidateID string, receipt compensation.BatchCommandReceipt) (compensation.BatchRecord, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return batch, safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	if candidateID != "" {
		candidateResult, err := tx.ExecContext(ctx, q.structureSQL("UPDATE compensation_batch_import_candidate SET state='applied' WHERE org_id=? AND id=? AND batch_id=? AND subject_id=? AND base_revision=? AND state='valid' AND expires_at>?"), batch.OrgID, candidateID, batch.ID, receipt.SubjectID, batch.Revision, receipt.RecordedAt.UnixMicro())
		if err != nil {
			return batch, safeError(err)
		}
		if n, _ := candidateResult.RowsAffected(); n != 1 {
			return batch, fault.Conflict
		}
	}
	result, err := tx.ExecContext(ctx, q.sql("UPDATE compensation_adjustment_batch SET state='draft',revision=revision+1 WHERE org_id=? AND id=? AND revision=? AND state IN('draft','activation_conflict')", "UPDATE compensation_adjustment_batch SET state='draft',revision=revision+1 WHERE org_id=$1 AND id=$2 AND revision=$3 AND state IN('draft','activation_conflict')"), batch.OrgID, batch.ID, batch.Revision)
	if err != nil {
		return batch, safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return batch, fault.Conflict
	}
	newRevision := batch.Revision + 1
	for i := range payloads {
		p := payloads[i]
		_, err = tx.ExecContext(ctx, q.sql("INSERT INTO compensation_batch_payload(org_id,id,batch_id,batch_revision,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,'financial','compensation.batch_line.v1',1,?,?,?,?,?,?,?,?)", "INSERT INTO compensation_batch_payload(org_id,id,batch_id,batch_revision,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'financial','compensation.batch_line.v1',1,$8,$9,$10,$11,$12,$13,$14,$15)"), batch.OrgID, p.ID, batch.ID, newRevision, p.EmployeeID, p.ID, p.ID, p.Envelope.FormatVersion, p.Envelope.Algorithm, p.Envelope.DEKID, p.Envelope.Key.KEKID, p.Envelope.Key.Version, p.Envelope.Key.Data, p.Envelope.SealedBytes, p.CreatedAt.UnixMicro())
		if err != nil {
			return batch, safeError(err)
		}
	}
	for i := range lines {
		line := lines[i]
		_, err = tx.ExecContext(ctx, q.sql("INSERT INTO compensation_batch_line(org_id,batch_id,batch_revision,id,employee_id,payload_id,result,ordinal) VALUES(?,?,?,?,?,?,?,?)", "INSERT INTO compensation_batch_line(org_id,batch_id,batch_revision,id,employee_id,payload_id,result,ordinal) VALUES($1,$2,$3,$4,$5,$6,$7,$8)"), batch.OrgID, batch.ID, newRevision, line.ID, line.EmployeeID, line.PayloadID, line.Result, i)
		if err != nil {
			return batch, safeError(err)
		}
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,?,'draft',?,?) ON CONFLICT DO NOTHING"), batch.OrgID, batch.ID, newRevision, receipt.RecordedAt.UnixMicro(), receipt.SubjectID); err != nil {
		return batch, safeError(err)
	}
	receipt.BatchID, receipt.ResultRevision = batch.ID, newRevision
	if err = insertBatchReceipt(ctx, tx, q, batch.OrgID, r.commandReference(), receipt); err != nil {
		return batch, err
	}
	if err = tx.Commit(); err != nil {
		return batch, safeError(err)
	}
	return r.AdjustmentBatch(ctx, batch.OrgID, batch.ID)
}

func (r *Repository) AdjustmentWorkforceBasis(ctx context.Context, org, employee, lookupKeyID string, lookupVersion uint32, digest []byte, asOf string) (compensation.BatchWorkforceBasis, error) {
	q := r.read()
	query := "SELECT i.id,i.revision,e.id,e.revision,e.legal_entity_id,e.location_code,a.id,a.revision,a.job_family_id,a.career_level_id FROM employee_business_identifier i JOIN employment_spell e ON e.org_id=i.org_id AND e.employee_id=i.employee_id JOIN job_assignment a ON a.org_id=i.org_id AND a.employee_id=i.employee_id WHERE i.org_id=? AND i.employee_id=? AND i.kind='staff_code' AND i.lookup_key_id=? AND i.lookup_key_version=? AND i.lookup_digest=? AND i.valid_from<=? AND (i.valid_to IS NULL OR i.valid_to>?) AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?) AND a.valid_from<=? AND (a.valid_to IS NULL OR a.valid_to>?) ORDER BY i.valid_from DESC,e.valid_from DESC,a.valid_from DESC,i.id,e.id,a.id"
	rows, err := q.db.QueryContext(ctx, q.structureSQL(query), org, employee, lookupKeyID, lookupVersion, digest, asOf, asOf, asOf, asOf, asOf, asOf)
	if err != nil {
		return compensation.BatchWorkforceBasis{}, safeError(err)
	}
	defer rows.Close()
	var out compensation.BatchWorkforceBasis
	count := 0
	for rows.Next() {
		if err = rows.Scan(&out.IdentifierID, &out.IdentifierRevision, &out.EmploymentID, &out.EmploymentRevision, &out.LegalEntityID, &out.Location, &out.AssignmentID, &out.AssignmentRevision, &out.JobFamilyID, &out.CareerLevelID); err != nil {
			return compensation.BatchWorkforceBasis{}, safeError(err)
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return compensation.BatchWorkforceBasis{}, safeError(err)
	}
	if count != 1 {
		return compensation.BatchWorkforceBasis{}, fault.Conflict
	}
	return out, nil
}

func (r *Repository) MarkAdjustmentBatchActivationFailure(ctx context.Context, batch compensation.BatchRecord, state, subject, requestID string, now time.Time) error {
	if state != "activation_blocked" && state != "activation_conflict" || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	result, err := tx.ExecContext(ctx, q.structureSQL("UPDATE compensation_adjustment_batch SET state=? WHERE org_id=? AND id=? AND revision=? AND state IN('draft','activation_blocked')"), state, batch.OrgID, batch.ID, batch.Revision)
	if err = interviewAffected(result, err, fault.Conflict); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING"), batch.OrgID, batch.ID, batch.Revision, state, now.UnixMicro(), subject); err != nil {
		return safeError(err)
	}
	auditID := value.NewID()
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES(?,?,?,'OP-COMP-10','compensation_management',?,'allowed',?,'application')"), auditID, batch.OrgID, subject, requestID, q.bindTime(now)); err != nil {
		return fault.AuditUnavailable
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES(?,?,?)"), auditID, batch.OrgID, q.bindTime(now)); err != nil {
		return fault.AuditUnavailable
	}
	return safeError(tx.Commit())
}

func (r *Repository) TransitionAdjustmentBatch(ctx context.Context, batch compensation.BatchRecord, action, manifest, subject string, receipt compensation.BatchCommandReceipt, now time.Time) (compensation.BatchRecord, error) {
	state := ""
	switch action {
	case "activate":
		state = "activated"
	case "withdraw":
		state = "withdrawn"
	default:
		return batch, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return batch, safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	result, err := tx.ExecContext(ctx, q.structureSQL("UPDATE compensation_adjustment_batch SET state=?,revision=revision+1,manifest_digest=?,activated_at=? WHERE org_id=? AND id=? AND revision=? AND state='draft'"), state, manifest, nullableMicro(state == "activated", now), batch.OrgID, batch.ID, batch.Revision)
	if err != nil {
		return batch, safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return batch, fault.Conflict
	}
	if state == "activated" {
		if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_activation(org_id,batch_id,activated_at,subject_id,manifest_digest) VALUES(?,?,?,?,?)"), batch.OrgID, batch.ID, now.UnixMicro(), subject, manifest); err != nil {
			return batch, safeError(err)
		}
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_state_history(org_id,batch_id,revision,state,recorded_at,subject_id) VALUES(?,?,?,?,?,?)"), batch.OrgID, batch.ID, batch.Revision+1, state, now.UnixMicro(), subject); err != nil {
		return batch, safeError(err)
	}
	receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt = batch.ID, batch.Revision+1, now
	if err = insertBatchReceipt(ctx, tx, q, batch.OrgID, r.commandReference(), receipt); err != nil {
		return batch, err
	}
	if err = tx.Commit(); err != nil {
		return batch, safeError(err)
	}
	return r.AdjustmentBatch(ctx, batch.OrgID, batch.ID)
}
func insertBatchReceipt(ctx context.Context, tx *sql.Tx, q reader, org string, reference sensitive.KeyReference, receipt compensation.BatchCommandReceipt) error {
	if len(receipt.Digest) != sha256.Size || !value.ValidID(receipt.SubjectID) || !value.ValidID(receipt.Key) || !value.ValidID(receipt.BatchID) || !value.ValidID(receipt.RequestID) {
		return fault.Invalid
	}
	if _, err := tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_command_receipt(org_id,subject_id,operation,key,digest,batch_id,result_revision,recorded_at,digest_key_id,digest_key_version) VALUES(?,?,?,?,?,?,?,?,?,?)"), org, receipt.SubjectID, receipt.Operation, receipt.Key, receipt.Digest, receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt.UnixMicro(), reference.KeyID, reference.Version); err != nil {
		return safeError(err)
	}
	auditID := value.NewID()
	if _, err := tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES(?,?,?,?,'compensation_management',?,'allowed',?,'application')"), auditID, org, receipt.SubjectID, receipt.Operation, receipt.RequestID, q.bindTime(receipt.RecordedAt)); err != nil {
		return fault.AuditUnavailable
	}
	if _, err := tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES(?,?,?)"), auditID, org, q.bindTime(receipt.RecordedAt)); err != nil {
		return fault.AuditUnavailable
	}
	return nil
}

func nullableMicro(set bool, t time.Time) any {
	if !set {
		return nil
	}
	return t.UnixMicro()
}

func batchEnvelopeContext(org, employee, id string) sensitive.Context {
	return sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: id, VersionID: id, ObjectKind: "compensation_batch_line", Purpose: "financial", SchemaType: "compensation.batch_line.v1", SchemaVersion: 1}
}
