package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetireSignerRequiresBackupAndLiveDatabaseDependencyChecks(t *testing.T) {
	args := []string{"retire-signer", "-dir", "/unreachable", "-receiver-uid", "1", "-forwarder-uid", "2", "-gid", "3", "-key-id", "receipt-20261014-test"}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "backup dependency confirmation") {
		t.Fatal("retirement did not require backup dependency confirmation", err)
	}
	t.Setenv("TEAMLEDGER_DB_BACKEND", "")
	args = append(args, "-confirm-no-backup-dependencies")
	if err := run(args); err == nil || !strings.Contains(err.Error(), "database configuration") {
		t.Fatal("retirement reached material without checking live database dependencies", err)
	}
}

func TestDatabaseDSNAcceptsOnlyOneProtectedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte("postgres://local.example/teamledger"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEAMLEDGER_DB_DSN", "")
	t.Setenv("TEAMLEDGER_DB_DSN_FILE", path)
	if dsn, err := databaseDSN(); err != nil || dsn != "postgres://local.example/teamledger" {
		t.Fatal("protected DSN file was not accepted", err)
	}
	t.Setenv("TEAMLEDGER_DB_DSN", "postgres://environment.example/teamledger")
	if _, err := databaseDSN(); err == nil {
		t.Fatal("ambiguous DSN sources were accepted")
	}
	t.Setenv("TEAMLEDGER_DB_DSN", "")
	if err := os.WriteFile(path, []byte("postgres://local.example/teamledger\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseDSN(); err == nil {
		t.Fatal("newline-terminated DSN secret was accepted")
	}
}
