package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
)

func (r *Repository) CreateAdjustmentImportCandidate(ctx context.Context, candidate compensation.ImportCandidateRecord, receipt compensation.BatchCommandReceipt) (compensation.ImportCandidateRecord, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return candidate, safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	e := candidate.Envelope
	_, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO compensation_batch_import_candidate(org_id,id,batch_id,subject_id,base_revision,state,line_count,digest,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at,expires_at) VALUES(?,?,?,?,?,?,?, ?,?,?,'financial','compensation.batch_import.v1',1,?,?,?,?,?,?,?,?,?)"), candidate.OrgID, candidate.ID, candidate.BatchID, candidate.SubjectID, candidate.BaseRevision, candidate.State, candidate.LineCount, candidate.Digest, candidate.ID, candidate.ID, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, candidate.CreatedAt.UnixMicro(), candidate.ExpiresAt.UnixMicro())
	if err != nil {
		return candidate, safeError(err)
	}
	receipt.BatchID, receipt.ResultRevision, receipt.RecordedAt = candidate.BatchID, candidate.BaseRevision, candidate.CreatedAt
	if err = insertBatchReceipt(ctx, tx, q, candidate.OrgID, receipt); err != nil {
		return candidate, err
	}
	if err = tx.Commit(); err != nil {
		return candidate, safeError(err)
	}
	return candidate, nil
}

func (r *Repository) AdjustmentImportCandidate(ctx context.Context, org, id string) (compensation.ImportCandidateRecord, error) {
	q := r.read()
	var out compensation.ImportCandidateRecord
	var format, keyVersion, created, expires int64
	e := &out.Envelope
	err := q.db.QueryRowContext(ctx, q.structureSQL("SELECT org_id,id,batch_id,subject_id,base_revision,state,line_count,digest,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at,expires_at FROM compensation_batch_import_candidate WHERE org_id=? AND id=?"), org, id).Scan(&out.OrgID, &out.ID, &out.BatchID, &out.SubjectID, &out.BaseRevision, &out.State, &out.LineCount, &out.Digest, &format, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &keyVersion, &e.Key.Data, &e.SealedBytes, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	}
	if err != nil {
		return out, safeError(err)
	}
	e.FormatVersion, e.Key.Version = uint16(format), uint32(keyVersion)
	e.Context = sensitive.Context{OrgID: org, RecordID: id, VersionID: id, ObjectKind: "compensation_batch_import", Purpose: "financial", SchemaType: "compensation.batch_import.v1", SchemaVersion: 1}
	out.CreatedAt, out.ExpiresAt = time.UnixMicro(created).UTC(), time.UnixMicro(expires).UTC()
	return out, nil
}
