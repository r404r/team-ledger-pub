package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
)

func TestV13MigratesPersistedV12BatchWithoutClearingData(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "persisted-v12.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 12; version++ {
		ddl, checksum, loadErr := repo.migration(version)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("build v12 statement: %v", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	org := "10000000-0000-4000-8000-000000000001"
	creator := "10000000-0000-4000-8000-000000000002"
	service := "10000000-0000-4000-8000-000000000003"
	entity := "10000000-0000-4000-8000-000000000004"
	batch := "10000000-0000-4000-8000-000000000005"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization(id,timezone,graph_revision) VALUES(?,'UTC',1)", []any{org}},
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{org, creator}},
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{org, service}},
		{"INSERT INTO legal_entity(org_id,id,code,kind) VALUES(?,?,?,'branch_company')", []any{org, entity, "SH"}},
		{"INSERT INTO compensation_adjustment_batch(org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id,default_effective_date,state,revision,creator_subject_id,created_at) VALUES(?,?,'N-2026-0001',2026,'normal',?,'2026-10-01','draft',1,?,1)", []any{org, batch, entity, creator}},
		{"INSERT INTO compensation_batch_service(org_id,batch_id,subject_id) VALUES(?,?,?)", []any{org, batch, service}},
	} {
		if _, err = tx.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var version, rows int
	if err = repo.DB.QueryRowContext(ctx, "SELECT max(version),count(*) FROM schema_version").Scan(&version, &rows); err != nil || version != 13 || rows != 13 {
		t.Fatalf("ledger version=%d rows=%d err=%v", version, rows, err)
	}
	var code, state string
	var header any
	if err = repo.DB.QueryRowContext(ctx, "SELECT business_code,state,header_payload_id FROM compensation_adjustment_batch WHERE org_id=? AND id=?", org, batch).Scan(&code, &state, &header); err != nil {
		t.Fatal(err)
	}
	if code != "N-2026-0001" || state != "draft" || header != nil {
		t.Fatalf("migrated batch code=%q state=%q header=%v", code, state, header)
	}
	if err = repo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestV13RefusesV11WithoutWriting(t *testing.T) {
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
