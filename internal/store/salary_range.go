package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

var _ compensation.SalaryRangeStore = (*Repository)(nil)

func (r *Repository) SalaryRanges(ctx context.Context, org string, query compensation.SalaryRangeQuery) ([]compensation.SalaryRangeRecord, error) {
	q := r.read()
	predicate := "org_id=?"
	args := []any{org}
	for _, filter := range []struct{ column, value string }{{"legal_entity_id", query.LegalEntityID}, {"location_code", query.Location}, {"job_family_id", query.JobFamilyID}, {"career_level_id", query.CareerLevelID}, {"currency", query.Currency}} {
		if filter.value != "" {
			predicate += " AND " + filter.column + "=?"
			args = append(args, filter.value)
		}
	}
	if query.AsOf != "" {
		predicate += " AND valid_from<=? AND (valid_to IS NULL OR valid_to>?)"
		args = append(args, query.AsOf, query.AsOf)
	}
	rows, err := q.db.QueryContext(ctx, q.structureSQL("SELECT org_id,id,legal_entity_id,location_code,job_family_id,career_level_id,currency,"+q.dateColumn("valid_from")+","+q.dateColumn("valid_to")+",payload_id,revision FROM salary_range WHERE "+predicate+" ORDER BY legal_entity_id,location_code,job_family_id,career_level_id,currency,valid_from,id"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := make([]compensation.SalaryRangeRecord, 0)
	for rows.Next() {
		var item compensation.SalaryRangeRecord
		var validTo sql.NullString
		if err = rows.Scan(&item.OrgID, &item.ID, &item.LegalEntityID, &item.Location, &item.JobFamilyID, &item.CareerLevelID, &item.Currency, &item.ValidFrom, &validTo, &item.PayloadID, &item.Revision); err != nil {
			return nil, safeError(err)
		}
		if validTo.Valid {
			item.ValidTo = &validTo.String
		}
		out = append(out, item)
	}
	return out, safeError(rows.Err())
}

func (r *Repository) SalaryRangePayload(ctx context.Context, org, id string) (compensation.SalaryRangePayload, error) {
	q := r.read()
	var out compensation.SalaryRangePayload
	var format, schema, keyVersion int64
	var created int64
	binding := &out.Envelope.Context
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT org_id,id,range_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM salary_range_payload WHERE org_id=? AND id=?"), org, id).Scan(&out.OrgID, &out.ID, &out.RangeID, &binding.RecordID, &binding.VersionID, &binding.Purpose, &binding.SchemaType, &schema, &format, &out.Envelope.Algorithm, &out.Envelope.DEKID, &out.Envelope.Key.KEKID, &keyVersion, &out.Envelope.Key.Data, &out.Envelope.SealedBytes, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	binding.OrgID, binding.ObjectKind, binding.SchemaVersion = out.OrgID, "salary_range", uint32(schema)
	out.Envelope.FormatVersion, out.Envelope.Key.Version = uint16(format), uint32(keyVersion)
	out.CreatedAt = time.UnixMicro(created).UTC()
	return out, nil
}
func (r *Repository) SalaryRangeReceipt(ctx context.Context, org, subject, key string) (compensation.SalaryRangeReceipt, bool, error) {
	q := r.read()
	var out compensation.SalaryRangeReceipt
	var recorded int64
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT subject_id,key,digest,recorded_at FROM salary_range_command_receipt WHERE org_id=? AND subject_id=? AND key=?"), org, subject, key).Scan(&out.SubjectID, &out.Key, &out.Digest, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, safeError(err)
	}
	out.RecordedAt = time.UnixMicro(recorded).UTC()
	return out, true, nil
}

func (r *Repository) ApplySalaryRangeChanges(ctx context.Context, org string, records []compensation.SalaryRangeRecord, payloads []compensation.SalaryRangePayload, changes []compensation.SalaryRangeChange, receipt compensation.SalaryRangeReceipt) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	entities := make(map[string]struct{})
	for _, record := range records {
		entities[record.LegalEntityID] = struct{}{}
	}
	entityIDs := make([]string, 0, len(entities))
	for id := range entities {
		entityIDs = append(entityIDs, id)
	}
	sort.Strings(entityIDs)
	for _, id := range entityIDs {
		var locked string
		err = tx.QueryRowContext(ctx, q.sql("SELECT id FROM legal_entity WHERE org_id=? AND id=?", "SELECT id FROM legal_entity WHERE org_id=$1 AND id=$2 FOR UPDATE"), org, id).Scan(&locked)
		if err != nil {
			return safeError(err)
		}
	}
	payloadByRange := make(map[string]compensation.SalaryRangePayload, len(payloads))
	for _, payload := range payloads {
		payloadByRange[payload.RangeID] = payload
		_, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO salary_range_payload(org_id,id,range_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,'financial','compensation.salary_range.v1',1,?,?,?,?,?,?,?,?)"), org, payload.ID, payload.RangeID, payload.RangeID, payload.ID, payload.Envelope.FormatVersion, payload.Envelope.Algorithm, payload.Envelope.DEKID, payload.Envelope.Key.KEKID, payload.Envelope.Key.Version, payload.Envelope.Key.Data, payload.Envelope.SealedBytes, payload.CreatedAt.UnixMicro())
		if err != nil {
			return safeError(err)
		}
	}
	recordByID := make(map[string]compensation.SalaryRangeRecord, len(records))
	for _, record := range records {
		recordByID[record.ID] = record
	}
	for _, change := range changes {
		switch change.Action {
		case "end", "replace":
			record := recordByID[change.ID]
			result, err := tx.ExecContext(ctx, q.structureSQL("UPDATE salary_range SET valid_to=?,revision=revision+1 WHERE org_id=? AND id=? AND revision=? AND valid_to IS NULL AND valid_from<?"), change.EffectiveTo, org, change.ID, record.Revision, change.EffectiveTo)
			if err != nil {
				return safeError(err)
			}
			if n, _ := result.RowsAffected(); n != 1 {
				return fault.Conflict
			}
		}
		if change.Action == "add" || change.Action == "replace" {
			newID := change.ID
			if change.Action == "replace" {
				newID = change.ReplacementID
			}
			record := recordByID[newID]
			var overlap int
			overlapSQL := q.sql("SELECT count(*) FROM salary_range WHERE org_id=? AND legal_entity_id=? AND location_code=? AND job_family_id=? AND career_level_id=? AND currency=? AND valid_from<COALESCE(?, '9999-12-31') AND COALESCE(valid_to,'9999-12-31')>?", "SELECT count(*) FROM salary_range WHERE org_id=$1 AND legal_entity_id=$2 AND location_code=$3 AND job_family_id=$4 AND career_level_id=$5 AND currency=$6 AND valid_from<COALESCE($7::date, DATE '9999-12-31') AND COALESCE(valid_to,DATE '9999-12-31')>$8::date")
			err := tx.QueryRowContext(ctx, overlapSQL, org, record.LegalEntityID, record.Location, record.JobFamilyID, record.CareerLevelID, record.Currency, nullableString(record.ValidTo), record.ValidFrom).Scan(&overlap)
			if err != nil {
				return safeError(err)
			}
			if overlap != 0 {
				return fault.Conflict
			}
			payload := payloadByRange[record.ID]
			_, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO salary_range(org_id,id,legal_entity_id,location_code,job_family_id,career_level_id,currency,valid_from,valid_to,payload_id,revision) VALUES(?,?,?,?,?,?,?,?,?,?,1)"), org, record.ID, record.LegalEntityID, record.Location, record.JobFamilyID, record.CareerLevelID, record.Currency, record.ValidFrom, nullableString(record.ValidTo), payload.ID)
			if err != nil {
				return safeError(err)
			}
		}
	}
	if len(receipt.Digest) != 32 {
		return fault.Invalid
	}
	reference := r.commandReference()
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO salary_range_command_receipt(org_id,subject_id,key,digest,recorded_at,digest_key_id,digest_key_version) VALUES(?,?,?,?,?,?,?)"), org, receipt.SubjectID, receipt.Key, receipt.Digest, receipt.RecordedAt.UnixMicro(), reference.KeyID, reference.Version); err != nil {
		return safeError(err)
	}
	auditID := value.NewID()
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES(?,?,?,'OP-COMP-11','compensation_management',?,'allowed',?,'application')"), auditID, org, receipt.SubjectID, receipt.RequestID, q.bindTime(receipt.RecordedAt)); err != nil {
		return fault.AuditUnavailable
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES(?,?,?)"), auditID, org, q.bindTime(receipt.RecordedAt)); err != nil {
		return fault.AuditUnavailable
	}
	return safeError(tx.Commit())
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
