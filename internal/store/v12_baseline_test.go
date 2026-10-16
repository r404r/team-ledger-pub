package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestV14FreshInstallPreservesCleanWorkforceBaseline(t *testing.T) {
	ctx := context.Background()
	repo, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "v14.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}

	var versionRows, version int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*),max(version) FROM schema_version").Scan(&versionRows, &version); err != nil {
		t.Fatal(err)
	}
	if versionRows != 14 || version != 14 {
		t.Fatalf("fresh baseline ledger = %d rows/max %d, want complete v1..v14 checksums", versionRows, version)
	}

	for _, name := range []string{"team", "team_parent_history", "team_membership", "position_assignment"} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("legacy table %s exists in v14 clean baseline", name)
		}
	}
	for _, name := range []string{
		"legal_entity", "legal_entity_version", "work_location", "org_unit", "org_unit_version", "org_unit_parent_history",
		"workforce_payload", "employee_business_identifier", "employee_identifier_owner", "employment_spell",
		"education_level", "education_record", "job_family", "job_family_version", "career_level", "career_level_version",
		"job_assignment", "reporting_line", "structure_change", "structure_change_item", "compensation_batch_header_payload",
		"local_mfa_account", "local_mfa_factor", "local_mfa_enrollment", "local_mfa_recovery_code", "local_mfa_recovery_receipt", "local_mfa_reset_receipt", "key_domain_expansion_receipt",
	} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("required v14 table %s count = %d", name, count)
		}
	}
	for _, column := range []struct{ table, name string }{
		{"legal_entity", "name"}, {"org_unit", "name"}, {"employee_business_identifier", "staff_code"}, {"job_assignment", "title"},
	} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info(?) WHERE name=?", column.table, column.name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("plaintext workforce column %s.%s exists", column.table, column.name)
		}
	}
	var locations, education, educationRanks string
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code,',') FROM (SELECT code FROM work_location ORDER BY code)").Scan(&locations); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code,',') FROM (SELECT code FROM education_level ORDER BY code)").Scan(&education); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code||':'||rank,',') FROM (SELECT code,rank FROM education_level ORDER BY rank DESC)").Scan(&educationRanks); err != nil {
		t.Fatal(err)
	}
	if locations != "Shanghai,Tokyo,Wuxi" || education != "Bachelor,Diploma,Master" || educationRanks != "Master:3,Bachelor:2,Diploma:1" {
		t.Fatalf("fixed catalogs = locations %q education %q ranks %q", locations, education, educationRanks)
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO audit_event(id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES(?,'OP-ORG-02','',?,'allowed',?,'application')", value.NewID(), value.NewID(), repo.BindTime(time.Now())); err == nil {
		t.Fatal("retired OP-ORG-02 accepted by SQLite v14 audit schema")
	}
}

func TestV14PostgresInstallHasNoTeamEraTables(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	ctx := context.Background()
	var versionRows, version int
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*),max(version) FROM schema_version").Scan(&versionRows, &version); err != nil {
		t.Fatal(err)
	}
	if versionRows != 14 || version != 14 {
		t.Fatalf("fresh PostgreSQL baseline ledger = %d rows/max %d", versionRows, version)
	}
	for _, name := range []string{"team", "team_parent_history", "team_membership", "position_assignment"} {
		var count int
		if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=$1", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("legacy PostgreSQL table %s exists in v14 clean baseline", name)
		}
	}
	for _, column := range []struct{ table, name string }{
		{"legal_entity", "name"}, {"org_unit", "name"}, {"employee_business_identifier", "staff_code"}, {"job_assignment", "title"},
	} {
		var count int
		if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2", column.table, column.name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("plaintext PostgreSQL workforce column %s.%s exists", column.table, column.name)
		}
	}
	var locations, education, educationRanks string
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT string_agg(code,',' ORDER BY code) FROM work_location").Scan(&locations); err != nil {
		t.Fatal(err)
	}
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT string_agg(code,',' ORDER BY code) FROM education_level").Scan(&education); err != nil {
		t.Fatal(err)
	}
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT string_agg(code||':'||rank,',' ORDER BY rank DESC) FROM education_level").Scan(&educationRanks); err != nil {
		t.Fatal(err)
	}
	if locations != "Shanghai,Tokyo,Wuxi" || education != "Bachelor,Diploma,Master" || educationRanks != "Master:3,Bachelor:2,Diploma:1" {
		t.Fatalf("fixed PostgreSQL catalogs = locations %q education %q ranks %q", locations, education, educationRanks)
	}
	if _, err := f.Repo.DB.ExecContext(ctx, "INSERT INTO audit_event(id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES($1,'OP-ORG-02','',$2,'allowed',$3,'application')", value.NewID(), value.NewID(), f.Repo.BindTime(time.Now())); err == nil {
		t.Fatal("retired OP-ORG-02 accepted by PostgreSQL v14 audit schema")
	}
}
