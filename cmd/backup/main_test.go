package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteBackupRestoreChecksIndependentKeysAndRevokesSessions(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	if _, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "BACKUP_KEY_PROBE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archive, target := filepath.Join(dir, "snapshot.tlb"), filepath.Join(dir, "restored.db")
	key := bytes.Repeat([]byte{23}, 32)
	if err := createSQLite(context.Background(), f.DSN, archive, key, f.Now); err != nil {
		t.Fatal(err)
	}
	configs := []wrapperConfig{}
	for _, entry := range []struct {
		domain string
		vault  *testsupport.VaultFixture
	}{{"pii", f.KMS}, {"interview", f.InterviewKMS}, {"financial", f.FinancialKMS}} {
		tokenPath := filepath.Join(dir, entry.domain+".token")
		if err := os.WriteFile(tokenPath, []byte(entry.vault.Token), 0600); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, wrapperConfig{entry.domain, entry.vault.KeyName, entry.vault.Server.URL, tokenPath})
	}
	raw, _ := json.Marshal(keyConfig{Wrappers: configs})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if err := restore(context.Background(), archive, target, key, raw, client, f.Now); err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(context.Background(), "sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	var active int
	if err = repo.DB.QueryRow("SELECT count(*) FROM session WHERE revoked=0").Scan(&active); err != nil || active != 0 {
		t.Fatal("restored sessions remained active", active, err)
	}
	var audits int
	if err = repo.DB.QueryRow("SELECT count(*) FROM backup_restore_audit").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("restore audit missing", audits, err)
	}
	missing, _ := json.Marshal(keyConfig{Wrappers: configs[1:]})
	if err = restore(context.Background(), archive, filepath.Join(dir, "must-not-activate.db"), key, missing, client, f.Now); err == nil {
		t.Fatal("restore activated without every independent key")
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
