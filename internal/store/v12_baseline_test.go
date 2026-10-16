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

func TestV19FreshInstallPreservesCleanWorkforceBaseline(t *testing.T) {
	ctx := context.Background()
	repo, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "v15.sqlite"))
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
	if versionRows != 19 || version != 19 {
		t.Fatalf("fresh baseline ledger = %d rows/max %d, want complete v1..v19 checksums", versionRows, version)
	}

	for _, name := range []string{"team", "team_parent_history", "team_membership", "position_assignment"} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("legacy table %s exists in v19 clean baseline", name)
		}
	}
	for _, name := range []string{
		"organization", "subject", "authorization_guard", "employee", "employee_profile_version", "encrypted_payload",
		"job_assignment", "reporting_line", "structure_change", "structure_change_item", "compensation_batch_header_payload",
		"local_mfa_account", "local_mfa_factor", "local_mfa_enrollment", "local_mfa_recovery_code", "local_mfa_recovery_receipt", "local_mfa_reset_receipt", "key_domain_expansion_receipt", "bootstrap_admin_policy", "local_user_command_receipt", "staff_account_access",
	} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("required v18 table %s count = %d", name, count)
		}
	}
	var passwordChangeColumn int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('local_account') WHERE name='password_change_required'").Scan(&passwordChangeColumn); err != nil || passwordChangeColumn != 1 {
		t.Fatal("v16 local account password-change state missing", err)
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
	orgID := value.NewID()
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO organization(id,timezone) VALUES(?,'Asia/Shanghai')", orgID); err != nil {
		t.Fatal(err)
	}
	var locations, education, educationRanks string
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code,',') FROM (SELECT code FROM work_location ORDER BY code)").Scan(&locations); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code,',') FROM (SELECT code FROM education_level WHERE org_id=? ORDER BY code)", orgID).Scan(&education); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT group_concat(code||':'||rank,',') FROM (SELECT code,rank FROM education_level WHERE org_id=? ORDER BY rank DESC)", orgID).Scan(&educationRanks); err != nil {
		t.Fatal(err)
	}
	if locations != "Shanghai,Tokyo,Wuxi" || education != "Bachelor,Diploma,Master" || educationRanks != "Master:3,Bachelor:2,Diploma:1" {
		t.Fatalf("fixed catalogs = locations %q education %q ranks %q", locations, education, educationRanks)
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO audit_event(id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES(?,'OP-ORG-02','',?,'allowed',?,'application')", value.NewID(), value.NewID(), repo.BindTime(time.Now())); err == nil {
		t.Fatal("retired OP-ORG-02 accepted by SQLite v18 audit schema")
	}
}

func TestV19PostgresInstallHasNoTeamEraTables(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	ctx := context.Background()
	var versionRows, version int
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*),max(version) FROM schema_version").Scan(&versionRows, &version); err != nil {
		t.Fatal(err)
	}
	if versionRows != 19 || version != 19 {
		t.Fatalf("fresh PostgreSQL baseline ledger = %d rows/max %d", versionRows, version)
	}
	for _, name := range []string{"team", "team_parent_history", "team_membership", "position_assignment"} {
		var count int
		if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=$1", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("legacy PostgreSQL table %s exists in v19 clean baseline", name)
		}
	}
	for _, name := range []string{"bootstrap_admin_policy", "local_user_command_receipt", "staff_account_access"} {
		var count int
		if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=$1", name).Scan(&count); err != nil || count != 1 {
			t.Fatalf("required PostgreSQL v15 table %s count = %d: %v", name, count, err)
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
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT string_agg(code,',' ORDER BY code) FROM education_level WHERE org_id=$1", f.OrgID).Scan(&education); err != nil {
		t.Fatal(err)
	}
	if err := f.Repo.DB.QueryRowContext(ctx, "SELECT string_agg(code||':'||rank,',' ORDER BY rank DESC) FROM education_level WHERE org_id=$1", f.OrgID).Scan(&educationRanks); err != nil {
		t.Fatal(err)
	}
	if locations != "Shanghai,Tokyo,Wuxi" || education != "Bachelor,Diploma,Master" || educationRanks != "Master:3,Bachelor:2,Diploma:1" {
		t.Fatalf("fixed PostgreSQL catalogs = locations %q education %q ranks %q", locations, education, educationRanks)
	}
	if _, err := f.Repo.DB.ExecContext(ctx, "INSERT INTO audit_event(id,operation,purpose,request_id,outcome,recorded_at,actor_kind) VALUES($1,'OP-ORG-02','',$2,'allowed',$3,'application')", value.NewID(), value.NewID(), f.Repo.BindTime(time.Now())); err == nil {
		t.Fatal("retired OP-ORG-02 accepted by PostgreSQL v15 audit schema")
	}
}
