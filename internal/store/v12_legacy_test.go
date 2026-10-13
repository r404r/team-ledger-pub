package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
)

func TestV12RefusesV11WithoutWriting(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "legacy-v11.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 11; version++ {
		ddl, checksum, loadErr := repo.migration(version)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("build v11 statement: %v", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before := legacySchemaSnapshot(t, repo)
	if err = repo.Migrate(ctx); !errors.Is(err, fault.Unavailable) {
		t.Fatalf("v11 migration = %v, want unavailable", err)
	}
	after := legacySchemaSnapshot(t, repo)
	if before != after {
		t.Fatal("v11 refusal modified schema or migration ledger")
	}
}

func legacySchemaSnapshot(t *testing.T, repo *Repository) string {
	t.Helper()
	var schema, ledger string
	if err := repo.DB.QueryRow("SELECT group_concat(type||':'||name||':'||sql,'\n') FROM (SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY type,name)").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if err := repo.DB.QueryRow("SELECT group_concat(version||':'||backend||':'||checksum,'\n') FROM (SELECT version,backend,checksum FROM schema_version ORDER BY version)").Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	return schema + "\n--ledger--\n" + ledger
}
