package main

import (
	"context"
	"os"
	"path/filepath"
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
