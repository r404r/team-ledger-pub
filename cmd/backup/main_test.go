package main

import (
	"context"
	"fmt"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
)

func TestSQLiteBackupRestoreRequiresLocalKeydAndRecordsRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	repo, err := store.Open(ctx, "sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	archive, target := filepath.Join(dir, "snapshot.tlb"), filepath.Join(dir, "restored.db")
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(home, ".teamledger-backup-keyd-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	keyDir, socket := filepath.Join(parent, "keys"), filepath.Join(parent, "keyd.sock")
	if err = sensitive.InitKeyDirectory(keyDir); err != nil {
		t.Fatal(err)
	}
	keyContext, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- sensitive.ServeKeyd(keyContext, sensitive.KeydServerConfig{KeyDirectory: keyDir, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}, MaintenanceUIDs: []uint32{uint32(os.Geteuid())}})
	}()
	client := &sensitive.KeydClient{Socket: socket, Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = client.Ready(ctx); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		stop()
		<-done
		t.Fatal(err)
	}
	if err = createSQLite(ctx, source, archive, client, now); err != nil {
		stop()
		<-done
		t.Fatal(err)
	}
	if err = restore(ctx, archive, target, client, now); err != nil {
		stop()
		<-done
		t.Fatal(err)
	}
	restored, err := store.Open(ctx, "sqlite", target)
	if err != nil {
		stop()
		<-done
		t.Fatal(err)
	}
	var audits int
	if err = restored.DB.QueryRow("SELECT count(*) FROM backup_restore_audit").Scan(&audits); err != nil || audits != 1 {
		restored.Close()
		stop()
		<-done
		t.Fatal("restore audit missing", audits, err)
	}
	_ = restored.Close()
	stop()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = restore(ctx, archive, filepath.Join(dir, "must-not-activate.db"), client, now); err == nil {
		t.Fatal("restore activated without local key service")
	}
}

func TestPostgresRestoreInventoryExcludesCredentialState(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "pg_restore")
	script := "#!/bin/sh\ncat <<'EOF'\n;\n4; 2615 2200 SCHEMA - public owner\n1; 0 1 TABLE DATA public organization owner\n2; 0 2 TABLE DATA public session owner\n3; 0 3 TABLE DATA public oidc_transaction owner\n5; 0 4 TABLE DATA public session_auth owner\nEOF\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := pgRestoreBinary
	pgRestoreBinary = binary
	t.Cleanup(func() { pgRestoreBinary = previous })
	dump := filepath.Join(dir, "database.dump")
	if err := os.WriteFile(dump, nil, 0600); err != nil {
		t.Fatal(err)
	}
	list, err := postgresRestoreList(context.Background(), dump, dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "\n;4; 2615 2200 SCHEMA - public owner") ||
		!strings.Contains(text, "\n;2; 0 2 TABLE DATA public session owner") ||
		!strings.Contains(text, "\n;3; 0 3 TABLE DATA public oidc_transaction owner") ||
		!strings.Contains(text, "\n;5; 0 4 TABLE DATA public session_auth owner") ||
		!strings.Contains(text, "\n1; 0 1 TABLE DATA public organization owner") {
		t.Fatal("restore inventory did not isolate credential-bearing rows", text)
	}
}

func TestEncryptedV19BackupRestoresBothBackendsBeforeStaffUpgrade(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			f := testsupport.NewHarness(t, backend)
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			parent, err := os.MkdirTemp(home, ".tl-backup-upgrade-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(parent) })
			keyDir, socket := filepath.Join(parent, "keys"), filepath.Join(parent, "keyd.sock")
			if err = sensitive.InitKeyDirectory(keyDir); err != nil {
				t.Fatal(err)
			}
			keyContext, stop := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				done <- sensitive.ServeKeyd(keyContext, sensitive.KeydServerConfig{KeyDirectory: keyDir, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}, MaintenanceUIDs: []uint32{uint32(os.Geteuid())}})
			}()
			t.Cleanup(func() {
				stop()
				if e := <-done; e != nil {
					t.Error(e)
				}
			})
			keys := &sensitive.KeydClient{Socket: socket, Timeout: time.Second}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err = keys.Ready(ctx); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("keyd not ready")
			}
			wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainPIIPayload)
			if err != nil {
				t.Fatal(err)
			}
			f.Service.Cipher = sensitive.Cipher{Wrapper: wrapper}
			f.Service.StaffCodeMAC = func(ctx context.Context, b []byte) (sensitive.MACValue, error) {
				return keys.MAC(ctx, sensitive.DomainStaffCodeLookup, b)
			}
			employee := testsupport.SeedLegacyStaffIdentifier(t, f, "", "2213", "2020-01-01", nil)
			state, err := keys.Ready(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.VerifyOrInitializeCryptoState(ctx, state, f.Now); err != nil {
				t.Fatal(err)
			}
			testsupport.BuildSyntheticV19Fixture(t, f, "../../internal/store/migrations")
			archive := filepath.Join(parent, "database.tlb")
			var restored *store.Repository
			if backend == "sqlite" {
				if err = createSQLite(ctx, f.DSN, archive, keys, f.Now); err != nil {
					t.Fatal("encrypted v19 create", err)
				}
				target := filepath.Join(parent, "restored.db")
				if err = restore(ctx, archive, target, keys, f.Now); err != nil {
					t.Fatal("encrypted v19 restore", err)
				}
				restored, err = store.Open(ctx, "sqlite", target)
			} else {
				container := os.Getenv("TEAMLEDGER_TEST_POSTGRES_CONTAINER")
				if container == "" {
					t.Fatal("disposable PostgreSQL container required")
				}
				u, e := url.Parse(f.DSN)
				if e != nil {
					t.Fatal(e)
				}
				caPath := u.Query().Get("sslrootcert")
				installPostgresClientProxies(t, parent, caPath)
				if err = createPostgres(ctx, f.DSN, caPath, archive, keys, f.Now); err != nil {
					t.Fatal("encrypted PostgreSQL v19 create", err)
				}
				database := "backup_" + strings.ReplaceAll(value.NewID(), "-", "")
				if err = exec.Command("docker", "exec", container, "createdb", "-U", "postgres", "-O", u.User.Username(), database).Run(); err != nil {
					t.Fatal("isolated restore database", err)
				}
				t.Cleanup(func() {
					_ = exec.Command("docker", "exec", container, "dropdb", "-U", "postgres", "--force", database).Run()
				})
				u.Path = "/" + database
				restored, err = store.Open(ctx, "postgres", u.String())
				if err != nil {
					t.Fatal(err)
				}
				if err = restorePostgres(ctx, archive, u.String(), caPath, keys, f.Now); err != nil {
					restored.Close()
					t.Fatal("encrypted PostgreSQL v19 restore", err)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			before, err := restored.NormalizeStaffCodes(ctx, f.Service.Cipher, testsupport.LegacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil || before.SchemaVersion != 19 || before.ShortNumeric != 1 {
				t.Fatal("restored old baseline invalid", err)
			}
			if _, err = restored.NormalizeStaffCodes(ctx, f.Service.Cipher, testsupport.LegacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: before.Snapshot}); err != nil {
				t.Fatal("restored baseline upgrade failed", err)
			}
			mac, err := keys.MAC(ctx, sensitive.DomainStaffCodeLookup, []byte("staff-code\x00"+f.OrgID+"\x00"+"002213"))
			if err != nil {
				t.Fatal(err)
			}
			found, err := restored.StaffCodeEmployeeID(ctx, f.OrgID, mac.KeyID, mac.Version, mac.Digest, "2026-01-01")
			if err != nil || found != employee {
				t.Fatal("restored upgraded owner lookup failed", err)
			}
		})
	}
}

// The clients run real pg_dump/pg_restore in the disposable service image.
// Only protected service/pass files and the public CA are mounted; SQL is never mocked.
func installPostgresClientProxies(t *testing.T, parent, caPath string) {
	t.Helper()
	oldDump, oldRestore := pgDumpBinary, pgRestoreBinary
	t.Cleanup(func() { pgDumpBinary, pgRestoreBinary = oldDump, oldRestore })
	caMount := "'" + strings.ReplaceAll(filepath.Dir(caPath)+":"+filepath.Dir(caPath)+":ro", "'", "'\\''") + "'"
	for _, name := range []string{"pg_dump", "pg_restore"} {
		script := fmt.Sprintf(`#!/bin/sh
set -eu
if [ "${1:-}" = --list ]; then
  work=$(dirname "$2")
  PGSERVICEFILE=$work/unused
else
  work=$(dirname "$PGSERVICEFILE")
fi
exec /usr/bin/docker run --rm --network host --user %s:%s -e PGSERVICEFILE="$PGSERVICEFILE" -e PGSYSCONFDIR=/nonexistent -v "$work:$work" -v %s --entrypoint %s postgres:17-bookworm "$@"
`, strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid()), caMount, name)
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		if name == "pg_dump" {
			pgDumpBinary = path
		} else {
			pgRestoreBinary = path
		}
	}
}
