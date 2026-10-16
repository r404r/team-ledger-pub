package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Repository struct {
	DB               *sql.DB
	Backend          string
	CommandMACKey    sensitive.KeyReference
	GenerationMACKey sensitive.KeyReference
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
	tx               *sql.Tx
	org              string
	commandMACKey    sensitive.KeyReference
	generationMACKey sensitive.KeyReference
}

var _ organization.Store = (*Repository)(nil)
var _ organization.Tx = (*transaction)(nil)

func Open(ctx context.Context, backend, dsn string) (*Repository, error) {
	var db *sql.DB
	switch backend {
	case "sqlite":
		if !filepath.IsAbs(dsn) || strings.ContainsAny(dsn, "?\x00") {
			return nil, fault.Unavailable
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
			return nil, fault.Unavailable
		}
		for _, f := range cfg.Fallbacks {
			if f.TLSConfig == nil || f.TLSConfig.InsecureSkipVerify || f.TLSConfig.ServerName == "" || f.TLSConfig.RootCAs == nil {
				return nil, fault.Unavailable
			}
		}
		db = postgresDB(cfg)
	default:
		return nil, fault.Unavailable
	}
	return openRepository(ctx, backend, db)
}

// OpenPostgresWithCheckedCA binds every physical connection to the trust bytes
// already read under the caller's public-file policy. sslrootcert remains a
// required declaration in the URL, but is never passed to pgx for file access.
func OpenPostgresWithCheckedCA(ctx context.Context, dsn string, caPEM []byte) (*Repository, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.Fragment != "" || os.Getenv("PGSERVICE") != "" {
		return nil, fault.Unavailable
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["sslmode"]) != 1 || q.Get("sslmode") != "verify-full" || len(q["sslrootcert"]) != 1 || q.Get("sslrootcert") == "" || q.Get("sslrootcert") == "system" {
		return nil, fault.Unavailable
	}
	// Services can override settings during ParseConfig; client credentials
	// are not part of this checked-CA connector and must not be read implicitly.
	for _, key := range []string{"service", "servicefile", "ssl", "sslcert", "sslkey", "sslpassword", "passfile"} {
		if _, present := q[key]; present {
			return nil, fault.Unavailable
		}
	}
	host := u.Hostname()
	if values, present := q["host"]; present {
		if len(values) != 1 {
			return nil, fault.Unavailable
		}
		host = values[0]
	}
	for _, h := range strings.Split(host, ",") {
		if h == "" || strings.ContainsAny(h, "/\\\x00") {
			return nil, fault.Unavailable
		}
	}
	user := q.Get("user")
	if user == "" && u.User != nil {
		user = u.User.Username()
	}
	if user == "" {
		return nil, fault.Unavailable
	}
	roots := x509.NewCertPool()
	remaining := bytes.TrimSpace(caPEM)
	if len(remaining) == 0 || len(caPEM) > 1<<20 {
		return nil, fault.Unavailable
	}
	for len(remaining) != 0 {
		// pem.Decode skips leading junk and invalid blocks; reject rather than
		// accepting only the valid subset of a malformed trust bundle.
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fault.Unavailable
		}
		const endMarker = "-----END CERTIFICATE-----"
		end := bytes.Index(remaining, []byte(endMarker))
		if end < 0 {
			return nil, fault.Unavailable
		}
		end += len(endMarker)
		if bytes.Count(remaining[:end], []byte("-----BEGIN ")) != 1 {
			return nil, fault.Unavailable
		}
		block, rest := pem.Decode(remaining[:end])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fault.Unavailable
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fault.Unavailable
		}
		roots.AddCert(cert)
		remaining = bytes.TrimSpace(remaining[end:])
	}
	// Shadow file/default/environment inputs before parsing, not afterwards:
	// pgx reads sslrootcert even when sslmode=disable.
	q.Set("sslmode", "disable")
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey", "sslpassword", "passfile"} {
		q.Set(key, "")
	}
	q.Set("user", user)
	if _, present := q["password"]; !present {
		password := ""
		if u.User != nil {
			password, _ = u.User.Password()
		}
		q.Set("password", password)
	}
	if _, present := q["database"]; !present {
		if _, present = q["dbname"]; !present {
			q.Set("database", strings.TrimPrefix(u.Path, "/"))
		}
	}
	if _, present := q["port"]; !present && u.Port() == "" {
		q.Set("port", "5432")
	}
	for key, value := range map[string]string{
		"connect_timeout": "10", "sslsni": "1", "sslnegotiation": "postgres",
		"target_session_attrs": "any", "min_protocol_version": "", "max_protocol_version": "",
		"channel_binding": "prefer", "require_auth": "",
	} {
		if _, present := q[key]; !present {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, fault.Unavailable
	}
	// Runtime environment settings must not silently augment the explicit URL.
	for _, key := range []string{"application_name", "timezone", "options"} {
		if _, present := q[key]; !present {
			delete(cfg.RuntimeParams, key)
		}
	}
	makeTLS := func(host string, port uint16) (*tls.Config, error) {
		if network, _ := pgconn.NetworkAddress(host, port); network != "tcp" || host == "" {
			return nil, fault.Unavailable
		}
		return &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}, nil
	}
	cfg.TLSConfig, err = makeTLS(cfg.Host, cfg.Port)
	if err != nil {
		return nil, err
	}
	for _, fallback := range cfg.Fallbacks {
		fallback.TLSConfig, err = makeTLS(fallback.Host, fallback.Port)
		if err != nil {
			return nil, err
		}
	}
	if cfg.SSLNegotiation == "direct" {
		cfg.TLSConfig.NextProtos = []string{"postgresql"}
		for _, fallback := range cfg.Fallbacks {
			fallback.TLSConfig.NextProtos = []string{"postgresql"}
		}
	}
	return openRepository(ctx, "postgres", postgresDB(cfg))
}

func postgresDB(cfg *pgx.ConnConfig) *sql.DB {
	cfg.ConnectTimeout = 10 * time.Second
	cfg.RuntimeParams["statement_timeout"] = "10000"
	cfg.RuntimeParams["lock_timeout"] = "2000"
	return stdlib.OpenDB(*cfg)
}

func openRepository(ctx context.Context, backend string, db *sql.DB) (*Repository, error) {
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

const currentSchemaVersion = 17

func (r *Repository) migration(version int) (string, string, error) {
	if (r.Backend != "sqlite" && r.Backend != "postgres") || version < 1 || version > currentSchemaVersion {
		return "", "", fault.Unavailable
	}
	b, err := migrations.ReadFile(fmt.Sprintf("migrations/%s_v%d.sql", r.Backend, version))
	if err != nil {
		return "", "", fault.Unavailable
	}
	return string(b), fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// Migrate is a standalone maintenance operation. Existing schemas must match
// their complete supported ledger and physical definitions before any upgrade.
// Fresh installation and every supported forward upgrade commit atomically.
func (r *Repository) Migrate(ctx context.Context) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if r.Backend == "postgres" {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),724202603))"); err != nil {
			return safeError(err)
		}
	}
	var count int
	err = tx.QueryRowContext(ctx, r.sql("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL", "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema()")).Scan(&count)
	if err != nil {
		return safeError(err)
	}
	version := 0
	if count != 0 {
		version, err = r.ledgerVersion(ctx, tx)
		if err != nil {
			return err
		}
		// v12 is the first persisted deployment baseline. Older development
		// schemas remain unsupported; exact v12 through v16 schemas are upgraded
		// or accepted without clearing operator data.
		if version < 12 || version > currentSchemaVersion {
			return fault.Unavailable
		}
		if r.Backend == "sqlite" {
			// Acquire the writer before validating the source or copying any rows.
			if _, err = tx.ExecContext(ctx, "UPDATE schema_version SET version=version"); err != nil {
				return safeError(err)
			}
		} else {
			// Stop concurrent application writes for the controlled cutover.
			if _, err = tx.ExecContext(ctx, "LOCK TABLE schema_version,organization,authorization_guard,subject,session,session_auth,employee,capability_assignment,delegation_authority,access_grant,encrypted_payload,employee_profile_version,command_receipt,audit_event,identity_mode_state,local_account,local_credential,local_login_throttle,local_bootstrap_receipt,bootstrap_admin_policy,compensation_adjustment_batch,compensation_batch_payload,compensation_batch_import_candidate IN ACCESS EXCLUSIVE MODE"); err != nil {
				return safeError(err)
			}
		}
		if err = r.checkSchemaVersion(ctx, tx, version); err != nil {
			return err
		}
		if version == currentSchemaVersion {
			return safeError(tx.Commit())
		}
	}
	for next := version + 1; next <= currentSchemaVersion; next++ {
		ddl, checksum, e := r.migration(next)
		if e != nil {
			return e
		}
		for _, statement := range migrationStatements(ddl) {
			if _, e = tx.ExecContext(ctx, statement); e != nil {
				return safeError(e)
			}
		}
		if _, e = tx.ExecContext(ctx, r.sql("INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", "INSERT INTO schema_version(version,backend,checksum) VALUES($1,$2,$3)"), next, r.Backend, checksum); e != nil {
			return safeError(e)
		}
	}
	if err = r.checkSchemaVersion(ctx, tx, currentSchemaVersion); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

// CheckSchema never upgrades the application schema. A transaction pins one
// connection for SQLite FK settings and PostgreSQL's rolled-back TEMP reference.
func (r *Repository) CheckSchema(ctx context.Context) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if err = r.checkSchemaVersion(ctx, tx, currentSchemaVersion); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func (r *Repository) ledgerVersion(ctx context.Context, db queryer) (int, error) {
	rows, err := db.QueryContext(ctx, "SELECT version,backend,checksum FROM schema_version ORDER BY version")
	if err != nil {
		return 0, fault.Unavailable
	}
	defer rows.Close()
	version := 0
	for rows.Next() {
		var found int
		var backend, checksum string
		if err = rows.Scan(&found, &backend, &checksum); err != nil || found != version+1 || found > currentSchemaVersion || backend != r.Backend {
			return 0, fault.Unavailable
		}
		_, expected, e := r.migration(found)
		if e != nil || checksum != expected {
			return 0, fault.Unavailable
		}
		version = found
	}
	if rows.Err() != nil || version == 0 {
		return 0, fault.Unavailable
	}
	return version, nil
}

func (r *Repository) checkSchemaVersion(ctx context.Context, db queryer, expected int) error {
	version, err := r.ledgerVersion(ctx, db)
	if err != nil || version != expected {
		return fault.Unavailable
	}
	if err = r.checkStructure(ctx, db, version); err != nil {
		return err
	}
	if r.Backend == "sqlite" {
		var enabled int
		if err = db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil || enabled != 1 {
			return fault.Unavailable
		}
		rows, e := db.QueryContext(ctx, "PRAGMA foreign_key_check")
		if e != nil {
			return fault.Unavailable
		}
		invalid := rows.Next()
		e = rows.Err()
		rows.Close()
		if invalid || e != nil {
			return fault.Unavailable
		}
	}
	return nil
}

func conflictError(err error) error {
	if err == nil {
		return nil
	}
	var sqliteError *sqlite.Error
	if errors.As(err, &sqliteError) && (sqliteError.Code() == 1555 || sqliteError.Code() == 2067) {
		return fault.Conflict
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return fault.Conflict
	}
	return safeError(err)
}

func safeError(err error) error {
	if err == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(err, &se) && (se.Code()&255 == 5 || se.Code()&255 == 6) {
		return fault.Busy
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "55P03" || pe.Code == "57014" || pe.Code == "40001" || pe.Code == "40P01") {
		return fault.Busy
	}
	return fault.Unavailable
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
		return fault.Unavailable
	}
	return nil
}
