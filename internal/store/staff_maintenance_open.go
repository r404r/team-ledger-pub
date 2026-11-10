package store

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/r404r/team-ledger/internal/fault"
)

// OpenStaffMaintenanceSQLite never creates a missing database. Preflight uses
// SQLite mode=ro and requires the already deployed WAL configuration.
func OpenStaffMaintenanceSQLite(ctx context.Context, path string, readOnly bool) (*Repository, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "?\x00") {
		return nil, fault.Invalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fault.Unavailable
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
	}
	for _, p := range []string{"foreign_keys(ON)", "synchronous(FULL)", "busy_timeout(5000)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fault.Unavailable
	}
	repo, err := openRepository(ctx, "sqlite", db)
	if err != nil {
		return nil, err
	}
	var mode string
	if err = db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		repo.Close()
		return nil, fault.Unavailable
	}
	return repo, nil
}

// CheckMaintenanceSchema validates the supported source or target catalog
// without enabling application traffic on a pending data upgrade.
func (r *Repository) CheckMaintenanceSchema(ctx context.Context) (int, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, safeError(err)
	}
	defer tx.Rollback()
	version, err := r.ledgerVersion(ctx, tx)
	if err != nil || (version != 19 && version != 20) {
		return 0, fault.Unavailable
	}
	if err = r.checkSchemaVersion(ctx, tx, version); err != nil {
		return 0, err
	}
	return version, safeError(tx.Commit())
}
