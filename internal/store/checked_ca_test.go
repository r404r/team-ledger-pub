package store_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func unrelatedPostgresCertificate(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic unrelated PostgreSQL certificate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func checkedPostgresCA(t *testing.T, dsn string) (string, string, []byte) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("test DSN must be a PostgreSQL URL")
	}
	ca, err := configfile.Read(u.Query().Get("sslrootcert"), 1<<20, false)
	if err != nil {
		t.Fatal("test PostgreSQL CA must satisfy checked public trust policy")
	}
	path := filepath.Join(t.TempDir(), "postgres-ca.pem")
	if err = os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	checked, err := configfile.Read(path, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("sslrootcert", path)
	u.RawQuery = q.Encode()
	return u.String(), path, checked
}

func assertPostgresTLSConnection(t *testing.T, ctx context.Context, repo *store.Repository) {
	t.Helper()
	var tlsUsed bool
	if err := repo.DB.QueryRowContext(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&tlsUsed); err != nil || !tlsUsed {
		t.Fatal("checked CA connection must reach the actual PostgreSQL server over TLS:", err)
	}
}

func TestPostgresCheckedCATrustSurvivesPathRemovalAndReplacement(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	for _, change := range []string{"remove", "replace"} {
		t.Run(change, func(t *testing.T) {
			dsn, path, checked := checkedPostgresCA(t, f.DSN)
			if change == "remove" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, unrelatedPostgresCertificate(t, true), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			repo, err := store.OpenPostgresWithCheckedCA(ctx, dsn, checked)
			if err != nil {
				t.Fatal("removing/replacing the path must not change already checked connection trust:", err)
			}
			defer repo.Close()
			assertPostgresTLSConnection(t, ctx, repo)
			// A subsequent physical connection must retain the same checked roots.
			repo.DB.SetMaxIdleConns(0)
			assertPostgresTLSConnection(t, ctx, repo)
			assertPostgresTLSConnection(t, ctx, repo)
		})
	}
}

func TestPostgresCheckedCARejectsWrongBytesDespiteValidPath(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, path, _ := checkedPostgresCA(t, f.DSN)
	wrongPath := filepath.Join(t.TempDir(), "wrong-ca.pem")
	if err := os.WriteFile(wrongPath, unrelatedPostgresCertificate(t, true), 0600); err != nil {
		t.Fatal(err)
	}
	wrong, err := configfile.Read(wrongPath, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := configfile.Read(path, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	positive, err := store.OpenPostgresWithCheckedCA(ctx, dsn, valid)
	if err != nil {
		t.Fatal("valid path/control connection must succeed:", err)
	}
	assertPostgresTLSConnection(t, ctx, positive)
	positive.Close()
	repo, err := store.OpenPostgresWithCheckedCA(ctx, dsn, wrong)
	if repo != nil {
		repo.Close()
	}
	if !errors.Is(err, fault.Unavailable) {
		t.Fatal("wrong checked roots must fail live TLS even when sslrootcert has valid roots")
	}
}

func TestPostgresCheckedCAStillVerifiesActualServerHostname(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, _, checked := checkedPostgresCA(t, f.DSN)
	cfg, err := pgx.ParseConfig(f.DSN)
	if err != nil {
		t.Fatal("fixture DSN must parse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := f.Repo.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var leaf *x509.Certificate
	err = conn.Raw(func(raw any) error {
		tlsConn, ok := raw.(*stdlib.Conn).Conn().PgConn().Conn().(*tls.Conn)
		if !ok {
			return errors.New("fixture requires native TLS PostgreSQL connection")
		}
		leaf = tlsConn.ConnectionState().PeerCertificates[0]
		return nil
	})
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Forward the actual PostgreSQL wire protocol through a local TCP endpoint
	// whose address is deliberately absent from the real server certificate.
	var host string
	for n := 2; n < 255; n++ {
		candidate := fmt.Sprintf("127.0.0.%d", n)
		if leaf.VerifyHostname(candidate) != nil {
			host = candidate
			break
		}
	}
	if host == "" {
		t.Fatal("fixture certificate must leave a loopback address unapproved")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	forwarded := make(chan error, 1)
	go func() {
		client, err := listener.Accept()
		if err != nil {
			forwarded <- err
			return
		}
		defer client.Close()
		server, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
		if err != nil {
			forwarded <- err
			return
		}
		defer server.Close()
		client.SetDeadline(time.Now().Add(10 * time.Second))
		server.SetDeadline(time.Now().Add(10 * time.Second))
		copied := make(chan struct{})
		go func() {
			io.Copy(server, client)
			server.(*net.TCPConn).CloseWrite()
			close(copied)
		}()
		io.Copy(client, server)
		client.(*net.TCPConn).CloseWrite()
		<-copied
		forwarded <- nil
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = listener.Addr().String()
	q := u.Query()
	q.Del("host")
	q.Del("port")
	u.RawQuery = q.Encode()
	repo, err := store.OpenPostgresWithCheckedCA(ctx, u.String(), checked)
	if repo != nil {
		repo.Close()
	}
	if !errors.Is(err, fault.Unavailable) {
		t.Fatal("trusted CA alone must not authorize an unapproved server hostname")
	}
	select {
	case err := <-forwarded:
		if err != nil {
			t.Fatal("hostname rejection must exercise a real forwarded PostgreSQL TLS handshake:", err)
		}
	case <-ctx.Done():
		t.Fatal("live hostname-validation forwarding did not complete")
	}
}

func TestPostgresCheckedCARejectsMalformedTrustBundles(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, _, valid := checkedPostgresCA(t, f.DSN)
	for _, tc := range []struct {
		name string
		ca   []byte
	}{
		{"empty", nil},
		{"not_pem", []byte("not a certificate")},
		{"not_a_ca", unrelatedPostgresCertificate(t, false)},
		{"nested_begin", append([]byte("-----BEGIN CERTIFICATE-----\n"), valid...)},
		{"leading_junk", append([]byte("unapproved prefix\n"), valid...)},
		{"trailing_junk", append(append([]byte(nil), valid...), []byte("unapproved suffix")...)},
		{"invalid_first_block", append([]byte("-----BEGIN CERTIFICATE-----\nnot-base64!\n-----END CERTIFICATE-----\n"), valid...)},
		{"invalid_last_block", append(append([]byte(nil), valid...), []byte("-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")...)},
		{"unexpected_pem_block", append(append([]byte(nil), valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic-not-a-key")})...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			repo, err := store.OpenPostgresWithCheckedCA(ctx, dsn, tc.ca)
			if repo != nil {
				repo.Close()
			}
			if !errors.Is(err, fault.Unavailable) {
				t.Fatal("malformed trust must not be accepted as a valid subset or use roots from the valid path")
			}
		})
	}
}

func TestPostgresCheckedCARequiresExplicitVerifiedURLAndRejectsTrustBypasses(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, _, valid := checkedPostgresCA(t, f.DSN)
	for _, tc := range []struct {
		name, key, value string
	}{
		{"plaintext", "sslmode", "disable"},
		{"opportunistic", "sslmode", "prefer"},
		{"no_hostname", "sslmode", "verify-ca"},
		{"no_declared_ca", "sslrootcert", ""},
		{"system_roots", "sslrootcert", "system"},
		{"ssl_alias", "ssl", "true"},
		{"service", "service", "synthetic-service"},
		{"service_file", "servicefile", "/nonexistent/synthetic-service"},
		{"client_cert", "sslcert", "/nonexistent/synthetic-cert"},
		{"client_key", "sslkey", "/nonexistent/synthetic-key"},
		{"pass_file", "passfile", "/nonexistent/synthetic-pass"},
		{"socket", "host", "/tmp"},
		{"empty_host", "host", ""},
		{"empty_fallback", "host", "localhost,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			q.Set(tc.key, tc.value)
			u.RawQuery = q.Encode()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			repo, err := store.OpenPostgresWithCheckedCA(ctx, u.String(), valid)
			if repo != nil {
				repo.Close()
			}
			if !errors.Is(err, fault.Unavailable) {
				t.Fatal("checked-CA entry must reject an unsafe or implicit connection trust configuration")
			}
		})
	}
}

func TestPostgresCheckedCAIgnoresAmbientCredentialsAndSSLFiles(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, path, valid := checkedPostgresCA(t, f.DSN)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"PGHOST": "synthetic-unreachable.invalid", "PGPORT": "1", "PGUSER": "synthetic-wrong-user",
		"PGPASSWORD": "synthetic-wrong-password", "PGDATABASE": "synthetic-wrong-db",
		"PGSSLMODE": "disable", "PGSSLROOTCERT": "/nonexistent/synthetic-root",
		"PGSSLCERT": "/nonexistent/synthetic-cert", "PGSSLKEY": "/nonexistent/synthetic-key",
		"PGPASSFILE": "/nonexistent/synthetic-pass", "PGSERVICEFILE": "/nonexistent/synthetic-service",
		"PGOPTIONS": "synthetic-invalid-options", "PGTZ": "synthetic-invalid-timezone",
	} {
		t.Setenv(key, value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo, err := store.OpenPostgresWithCheckedCA(ctx, dsn, valid)
	if err != nil {
		t.Fatal("explicit URL and checked CA must not reopen or fall back to ambient files/credentials:", err)
	}
	defer repo.Close()
	assertPostgresTLSConnection(t, ctx, repo)
}

func TestPostgresCheckedCATrustAppliesToEveryTCPFallback(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	dsn, path, valid := checkedPostgresCA(t, f.DSN)
	cfg, err := pgx.ParseConfig(f.DSN)
	if err != nil {
		t.Fatal("fixture DSN must parse")
	}
	// Keep the first endpoint reserved but close every incoming connection, so
	// the live successful connection must use pgx's second host configuration.
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := refused.Addr().(*net.TCPAddr).Port
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := refused.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer func() {
		refused.Close()
		<-stopped
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = ""
	q := u.Query()
	q.Set("host", "127.0.0.1,"+cfg.Host)
	q.Set("port", fmt.Sprintf("%d,%d", refusedPort, cfg.Port))
	u.RawQuery = q.Encode()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo, err := store.OpenPostgresWithCheckedCA(ctx, u.String(), valid)
	if err != nil {
		t.Fatal("TCP fallback must connect with the same checked roots without reopening the removed path:", err)
	}
	assertPostgresTLSConnection(t, ctx, repo)
	repo.Close()
	repo, err = store.OpenPostgresWithCheckedCA(ctx, u.String(), unrelatedPostgresCertificate(t, true))
	if repo != nil {
		repo.Close()
	}
	if !errors.Is(err, fault.Unavailable) {
		t.Fatal("TCP fallback must not weaken checked-root verification")
	}
}
