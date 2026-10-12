package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

var _ organization.ExportStore = (*Repository)(nil)
var _ organization.ExportTx = (*transaction)(nil)
var _ assessment.ExportStore = (*Repository)(nil)
var _ assessment.ExportTx = (*transaction)(nil)

func (r *Repository) WithExportTx(ctx context.Context, org string, fn func(organization.ExportTx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}

func (r *Repository) WithAssessmentExportTx(ctx context.Context, org string, fn func(assessment.ExportTx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}
func (t *transaction) ExportReceipt(ctx context.Context, org, subject, purpose, key string) (organization.ExportReceipt, bool, error) {
	if org != t.org {
		return organization.ExportReceipt{}, false, fault.NotFound
	}
	var receipt organization.ExportReceipt
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT digest,export_id FROM general_export_receipt WHERE org_id=? AND subject_id=? AND purpose=? AND key=?", "SELECT digest,export_id FROM general_export_receipt WHERE org_id=$1 AND subject_id=$2 AND purpose=$3 AND key=$4"), org, subject, purpose, key).Scan(&receipt.Digest, &receipt.ExportID)
	if err == sql.ErrNoRows {
		return organization.ExportReceipt{}, false, nil
	}
	if err != nil {
		return organization.ExportReceipt{}, false, safeError(err)
	}
	return receipt, true, nil
}

func (t *transaction) SaveExportReceipt(ctx context.Context, org, subject, purpose, key string, receipt organization.ExportReceipt, at time.Time) error {
	if org != t.org || len(receipt.Digest) != 32 {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO general_export_receipt(org_id,subject_id,purpose,key,digest,export_id,created_at) VALUES(?,?,?,?,?,?,?)", "INSERT INTO general_export_receipt(org_id,subject_id,purpose,key,digest,export_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)"), org, subject, purpose, key, receipt.Digest, receipt.ExportID, t.bindTime(at))
	return safeError(err)
}
