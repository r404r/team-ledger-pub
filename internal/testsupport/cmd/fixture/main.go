// Command fixture is an explicit test-only companion to the production API.
// It seeds synthetic credentials and controls external KMS I/O, not business handlers.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fixture startup or control failed")
		os.Exit(1)
	}
}

func run() error {
	backend := flag.String("backend", "", "sqlite or postgres")
	directory := flag.String("directory", "", "absolute existing private output directory")
	port := flag.String("port", "", "numeric API port or literal loopback IP:port")
	web := flag.String("web-dir", "", "absolute production web dist directory")
	flag.Parse()
	if flag.NArg() != 0 || (*backend != "sqlite" && *backend != "postgres") || !filepath.IsAbs(*directory) || !filepath.IsAbs(*web) {
		return errors.New("invalid flags")
	}
	info, err := os.Lstat(*directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid output directory")
	}
	if err = os.Chmod(*directory, 0700); err != nil {
		return err
	}
	info, err = os.Stat(*web)
	if err != nil || !info.IsDir() {
		return errors.New("invalid web directory")
	}
	listen := *port
	if !strings.Contains(listen, ":") {
		listen = net.JoinHostPort("127.0.0.1", listen)
	}
	host, p, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("invalid port")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() {
		return errors.New("invalid port")
	}
	listen = net.JoinHostPort(host, strconv.Itoa(n))
	origin := "https://" + listen
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dsn := filepath.Join(*directory, "fixture.db")
	if *backend == "sqlite" {
		file, err := os.OpenFile(dsn, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
	} else {
		original := os.Getenv("TEAMLEDGER_TEST_POSTGRES_DSN")
		u, err := url.Parse(original)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
			return errors.New("PostgreSQL URL required")
		}
		base, err := store.Open(startup, "postgres", original)
		if err != nil {
			return err
		}
		defer base.Close()
		var super, bypass, tls bool
		if err = base.DB.QueryRowContext(startup, "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").Scan(&super, &bypass); err != nil || super || bypass {
			return errors.New("unsafe PostgreSQL role")
		}
		if err = base.DB.QueryRowContext(startup, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&tls); err != nil || !tls {
			return errors.New("PostgreSQL TLS required")
		}
		schema := "dev002_" + strings.ReplaceAll(value.NewID(), "-", "")
		if _, err = base.DB.ExecContext(startup, "CREATE SCHEMA "+schema); err != nil {
			return err
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			if _, err := base.DB.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
				fmt.Fprintln(os.Stderr, "fixture schema cleanup failed")
			}
		}()
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	f, err := testsupport.NewFixture(startup, *backend, dsn)
	if err != nil {
		return err
	}
	defer f.Close()
	cert := f.KMS.Server.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname(host) != nil {
		return errors.New("fixture certificate does not match API IP")
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	defer clear(key)
	var ca []byte
	for _, der := range cert.Certificate {
		ca = append(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"csrf.key", f.CSRFKey}, {"digest.key", f.DigestKey}, {"cursor.key", f.CursorKey}, {"kms.token", []byte(f.KMS.Token)},
		{"kms-ca.pem", ca}, {"api-cert.pem", ca}, {"api-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})},
	}
	for _, file := range files {
		if err = privateFile(filepath.Join(*directory, file.name), file.data); err != nil {
			return err
		}
	}
	config := []struct{ name, value string }{
		{"BACKEND", *backend}, {"DSN", dsn}, {"LISTEN", listen}, {"PUBLIC_ORIGIN", origin},
		{"TLS_CERT_FILE", filepath.Join(*directory, "api-cert.pem")}, {"TLS_KEY_FILE", filepath.Join(*directory, "api-key.pem")},
		{"KMS_URL", f.KMS.Server.URL}, {"KMS_KEY", "dev002-pii"}, {"KMS_TOKEN_FILE", filepath.Join(*directory, "kms.token")},
		{"KMS_CA_FILE", filepath.Join(*directory, "kms-ca.pem")}, {"CSRF_KEY_FILE", filepath.Join(*directory, "csrf.key")},
		{"DIGEST_KEY_FILE", filepath.Join(*directory, "digest.key")}, {"CURSOR_KEY_FILE", filepath.Join(*directory, "cursor.key")}, {"WEB_DIR", *web},
	}
	var env strings.Builder
	for _, entry := range config {
		fmt.Fprintf(&env, "export TEAMLEDGER_%s=%s\n", entry.name, shellQuote(entry.value))
	}
	if err = privateFile(filepath.Join(*directory, "api.env"), []byte(env.String())); err != nil {
		return err
	}
	descriptor, err := json.Marshal(map[string]any{"backend": *backend, "origin": origin, "org_id": f.OrgID, "owner_token": f.Owner.Token, "observer_token": f.Observer.Token, "stranger_token": f.Stranger.Token, "manager_subject_id": f.Manager.SubjectID, "reader_subject_id": f.Reader.SubjectID, "approved_by": f.Approver.SubjectID, "authority_ids": f.AuthorityIDs, "manager_token": f.Manager.Token, "manager_csrf": f.Manager.CSRF, "reader_token": f.Reader.Token, "reader_csrf": f.Reader.CSRF})
	if err != nil {
		return err
	}
	if err = privateFile(filepath.Join(*directory, "descriptor.json"), append(descriptor, '\n')); err != nil {
		return err
	}
	if err = f.Repo.CheckSchema(startup); err != nil {
		return err
	}
	fmt.Printf("fixture_ready backend=%s\n", *backend)
	lines := make(chan []byte)
	readDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), 16<<10)
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		readDone <- scanner.Err()
	}()
	encoder := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readDone:
			return err
		case line := <-lines:
			var command struct {
				Action string `json:"action"`
			}
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&command)
			var extra any
			if err == nil && decoder.Decode(&extra) != io.EOF {
				err = errors.New("trailing input")
			}
			response := map[string]any{"ok": false}
			if err == nil {
				control, done := context.WithTimeout(ctx, 15*time.Second)
				switch command.Action {
				case "kms_down":
					f.KMS.Fail.Store(true)
				case "kms_up":
					f.KMS.Fail.Store(false)
				case "revoke_owner_pii":
					err = revoke(control, f)
				case "status":
					response, err = counts(control, f)
				default:
					err = errors.New("unknown action")
				}
				done()
			}
			if response == nil {
				response = map[string]any{}
			}
			response["ok"] = err == nil
			if err != nil {
				response = map[string]any{"ok": false, "error": "control failed"}
			}
			if err := encoder.Encode(response); err != nil {
				return err
			}
		}
	}
}

func privateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// This direct SQL control is test-only; it does not implement OP-SEC-03.
func revoke(ctx context.Context, f *testsupport.Fixture) error {
	tx, err := f.Repo.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if f.Backend == "postgres" {
		var epoch int64
		if err = tx.QueryRowContext(ctx, "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1 FOR UPDATE", f.OrgID).Scan(&epoch); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1", f.OrgID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND category='pii'", f.OrgID, f.Owner.SubjectID)
	} else {
		// The first write obtains SQLite's writer/organization guard before grants.
		result, e := tx.ExecContext(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", f.OrgID)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return errors.New("missing guard")
		}
		_, err = tx.ExecContext(ctx, "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND category='pii'", f.OrgID, f.Owner.SubjectID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func counts(ctx context.Context, f *testsupport.Fixture) (map[string]any, error) {
	response := map[string]any{"kms_calls": f.KMS.Calls.Load()}
	tx, err := f.Repo.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, table := range []string{"employee", "employee_profile_version", "encrypted_payload", "command_receipt", "audit_event"} {
		var count int64
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			return nil, err
		}
		response[table+"_count"] = count
	}
	var revisions int64
	if err = tx.QueryRowContext(ctx, "SELECT coalesce(sum(profile_revision),0) FROM employee").Scan(&revisions); err != nil {
		return nil, err
	}
	response["current_profile_revision_sum"] = revisions
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}
