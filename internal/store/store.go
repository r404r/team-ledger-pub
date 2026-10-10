package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/r404r/team-ledger/internal/organization"
	"modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Repository struct {
	DB      *sql.DB
	Backend string
}
type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type reader struct {
	db      queryer
	backend string
}
type transaction struct {
	reader
	tx  *sql.Tx
	org string
}

var _ organization.Store = (*Repository)(nil)
var _ organization.Tx = (*transaction)(nil)

func Open(ctx context.Context, backend, dsn string) (*Repository, error) {
	var db *sql.DB
	switch backend {
	case "sqlite":
		if !filepath.IsAbs(dsn) || strings.ContainsAny(dsn, "?\x00") {
			return nil, organization.Unavailable
		}
		u := url.URL{Scheme: "file", Path: dsn}
		q := url.Values{}
		for _, p := range []string{"journal_mode(WAL)", "foreign_keys(ON)", "synchronous(FULL)", "busy_timeout(5000)"} {
			q.Add("_pragma", p)
		}
		u.RawQuery = q.Encode()
		var err error
		db, err = sql.Open("sqlite", u.String())
		if err != nil {
			return nil, safeError(err)
		}
	case "postgres":
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName == "" || cfg.TLSConfig.RootCAs == nil {
			return nil, organization.Unavailable
		}
		for _, f := range cfg.Fallbacks {
			if f.TLSConfig == nil || f.TLSConfig.InsecureSkipVerify || f.TLSConfig.ServerName == "" || f.TLSConfig.RootCAs == nil {
				return nil, organization.Unavailable
			}
		}
		cfg.ConnectTimeout = 10 * time.Second
		cfg.RuntimeParams["statement_timeout"] = "10000"
		cfg.RuntimeParams["lock_timeout"] = "2000"
		db = stdlib.OpenDB(*cfg)
	default:
		return nil, organization.Unavailable
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, safeError(err)
	}
	return &Repository{DB: db, Backend: backend}, nil
}
func (r *Repository) Close() error {
	if err := r.DB.Close(); err != nil {
		return safeError(err)
	}
	return nil
}
func (r *Repository) BindTime(t time.Time) any {
	if r.Backend == "sqlite" {
		return t.UTC().UnixMicro()
	}
	return t.UTC().Truncate(time.Microsecond)
}
func (r *Repository) sql(s, p string) string {
	if r.Backend == "sqlite" {
		return s
	}
	return p
}
func (r reader) sql(s, p string) string {
	if r.backend == "sqlite" {
		return s
	}
	return p
}
func (r *Repository) read() reader { return reader{r.DB, r.Backend} }
func (r *Repository) migration() (string, string, error) {
	if r.Backend != "sqlite" && r.Backend != "postgres" {
		return "", "", organization.Unavailable
	}
	b, e := migrations.ReadFile("migrations/" + r.Backend + "_v1.sql")
	if e != nil {
		return "", "", organization.Unavailable
	}
	return string(b), fmt.Sprintf("%x", sha256.Sum256(b)), nil
}
func (r *Repository) Migrate(ctx context.Context) error {
	ddl, checksum, err := r.migration()
	if err != nil {
		return err
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	var count int
	err = tx.QueryRowContext(ctx, r.sql("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'", "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'")).Scan(&count)
	if err != nil {
		return safeError(err)
	}
	if count != 0 {
		if err = r.checkSchema(ctx, tx); err != nil {
			return err
		}
		return safeError(tx.Commit())
	}
	// Execute the checked-in dialect's individual statements in the same transaction.
	for _, s := range strings.Split(ddl, ";") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, s); err != nil {
			return safeError(err)
		}
	}
	_, err = tx.ExecContext(ctx, r.sql("INSERT INTO schema_version(version,backend,checksum) VALUES(1,?,?)", "INSERT INTO schema_version(version,backend,checksum) VALUES(1,$1,$2)"), r.Backend, checksum)
	if err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}
func (r *Repository) CheckSchema(ctx context.Context) error { return r.checkSchema(ctx, r.DB) }
func (r *Repository) checkSchema(ctx context.Context, db queryer) error {
	_, expected, err := r.migration()
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, "SELECT version,backend,checksum FROM schema_version")
	if err != nil {
		return organization.Unavailable
	}
	var version int
	var backend, checksum string
	if !rows.Next() {
		rows.Close()
		return organization.Unavailable
	}
	err = rows.Scan(&version, &backend, &checksum)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil || extra || version != 1 || backend != r.Backend || checksum != expected {
		return organization.Unavailable
	}
	for _, q := range schemaProbes {
		rows, err = db.QueryContext(ctx, q)
		if err != nil {
			return organization.Unavailable
		}
		err = rows.Close()
		if err != nil {
			return organization.Unavailable
		}
	}
	if err = r.checkStructure(ctx, db); err != nil {
		return err
	}
	if r.Backend == "sqlite" {
		var fk int
		if err = db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			return organization.Unavailable
		}
		rows, err = db.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return organization.Unavailable
		}
		invalid := rows.Next()
		err = rows.Err()
		rows.Close()
		if invalid || err != nil {
			return organization.Unavailable
		}
	}
	return nil
}

var schemaProbes = []string{
	"SELECT id,timezone,graph_revision FROM organization WHERE 1=0",
	"SELECT org_id,auth_epoch FROM authorization_guard WHERE 1=0",
	"SELECT org_id,id,active,auth_epoch FROM subject WHERE 1=0",
	"SELECT token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version FROM session WHERE 1=0",
	"SELECT org_id,subject_id,capability,scope_kind,scope_id,employee_id FROM capability_assignment WHERE 1=0",
	"SELECT id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required FROM access_grant WHERE 1=0",
	"SELECT org_id,id,profile_head_id,profile_revision,valid_from,valid_to FROM employee WHERE 1=0",
	"SELECT org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM encrypted_payload WHERE 1=0",
	"SELECT org_id,employee_id,id,version_no,payload_id,supersedes_id,recorded_at FROM employee_profile_version WHERE 1=0",
	"SELECT org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision FROM command_receipt WHERE 1=0",
	"SELECT id,org_id,subject_id,employee_id,operation,purpose,request_id,outcome,recorded_at FROM audit_event WHERE 1=0",
}

func safeError(err error) error {
	if err == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(err, &se) && (se.Code()&255 == 5 || se.Code()&255 == 6) {
		return organization.Busy
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "55P03" || pe.Code == "57014" || pe.Code == "40001" || pe.Code == "40P01") {
		return organization.Busy
	}
	return organization.Unavailable
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// dbTime scans only the two explicit storage timestamp representations.
type dbTime struct{ time.Time }

func (t *dbTime) Scan(v any) error {
	switch x := v.(type) {
	case int64:
		t.Time = time.UnixMicro(x).UTC()
	case time.Time:
		t.Time = x.UTC()
	default:
		return organization.Unavailable
	}
	return nil
}
