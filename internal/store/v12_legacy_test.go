package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
)

func TestV18MigratesEducationCatalogPerOrganization(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "education-v17.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 17; version++ {
		ddl, checksum, loadErr := repo.migration(version)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("build v17 statement: %v", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	orgA := "10000000-0000-4000-8000-000000000081"
	orgB := "10000000-0000-4000-8000-000000000082"
	if _, err = tx.ExecContext(ctx, "INSERT INTO organization(id,timezone) VALUES(?,'UTC'),(?,'UTC')", orgA, orgB); err != nil {
		t.Fatal(err)
	}
	subject := "10000000-0000-4000-8000-000000000084"
	employee := "10000000-0000-4000-8000-000000000085"
	profile := "10000000-0000-4000-8000-000000000086"
	change := "10000000-0000-4000-8000-000000000087"
	education := "10000000-0000-4000-8000-000000000088"
	educationPayload := "10000000-0000-4000-8000-000000000089"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{orgA, subject}},
		{"INSERT INTO employee(org_id,id,profile_head_id,profile_revision,valid_from) VALUES(?,?,?,1,'2020-01-01')", []any{orgA, employee, profile}},
		{"INSERT INTO encrypted_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,'employee_profile','pii','pii.profile.v2',1,1,'A256GCM-RANDOMNONCE','profile-dek','pii-key',1,?,?,1)", []any{orgA, employee, profile, employee, profile, []byte{1}, make([]byte, 28)}},
		{"INSERT INTO employee_profile_version(org_id,employee_id,id,version_no,payload_id,recorded_at) VALUES(?,?,?,1,?,1)", []any{orgA, employee, profile, profile}},
		{"INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after) VALUES(?,?,?,1,1,1,1,1)", []any{orgA, change, subject}},
		{"INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,'education_record',?,?,?,?, 'pii','pii.education.v1',1,1,'A256GCM-RANDOMNONCE','education-dek','pii-key',1,?,?,1)", []any{orgA, educationPayload, education, employee, education, educationPayload, []byte{1}, make([]byte, 28)}},
		{"INSERT INTO education_record(org_id,id,employee_id,level_code,payload_id,valid_from,recorded_at,change_id,revision) VALUES(?,?,?,'Master',?,'2020-01-01',1,?,1)", []any{orgA, education, employee, educationPayload, change}},
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
	var count int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM education_level WHERE org_id IN(?,?)", orgA, orgB).Scan(&count); err != nil || count != 6 {
		t.Fatalf("migrated education levels=%d err=%v", count, err)
	}
	var migratedLevel, migratedPayload string
	if err = repo.DB.QueryRowContext(ctx, "SELECT level_code,payload_id FROM education_record WHERE org_id=? AND id=?", orgA, education).Scan(&migratedLevel, &migratedPayload); err != nil || migratedLevel != "Master" || migratedPayload != educationPayload {
		t.Fatalf("migrated education record level=%q payload=%q err=%v", migratedLevel, migratedPayload, err)
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO education_level(org_id,code,rank) VALUES(?,'Doctor',4)", orgA); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM education_level WHERE org_id=? AND code='Doctor'", orgB).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cross-org education level count=%d err=%v", count, err)
	}
	orgC := "10000000-0000-4000-8000-000000000083"
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO organization(id,timezone) VALUES(?,'UTC')", orgC); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM education_level WHERE org_id=?", orgC).Scan(&count); err != nil || count != 3 {
		t.Fatalf("new organization education levels=%d err=%v", count, err)
	}
}

func TestV19MigratesPersistedV12BatchWithoutClearingData(t *testing.T) {
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
	if err = repo.DB.QueryRowContext(ctx, "SELECT max(version),count(*) FROM schema_version").Scan(&version, &rows); err != nil || version != 19 || rows != 19 {
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
	baseline := "10000000-0000-4000-8000-000000000006"
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO compensation_adjustment_batch(org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id,default_effective_date,state,revision,creator_subject_id,created_at) VALUES(?,?,'B-2026-0001',2026,'normal',?,'2026-10-01','draft',1,?,2)", org, baseline, entity, creator); err != nil {
		t.Fatal("v19 baseline storage row:", err)
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO compensation_salary_baseline_batch(org_id,batch_id) VALUES(?,?)", org, baseline); err != nil {
		t.Fatal("v19 baseline subtype:", err)
	}
	var baselineMarkers int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM compensation_salary_baseline_batch WHERE org_id=? AND batch_id=?", org, baseline).Scan(&baselineMarkers); err != nil || baselineMarkers != 1 {
		t.Fatalf("v19 baseline marker count=%d err=%v", baselineMarkers, err)
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO compensation_adjustment_batch(org_id,id,business_code,cycle_year,adjustment_type,legal_entity_id,default_effective_date,state,revision,creator_subject_id,created_at) VALUES(?,?,'B-2026-0002',2026,'baseline',?,'2026-10-01','draft',1,?,3)", org, "10000000-0000-4000-8000-000000000007", entity, creator); err == nil {
		t.Fatal("v19 must retain the normal/special parent constraint and represent baseline through the subtype table")
	}
	if err = repo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestV16MigrationRequiresLocalMFAEnrollmentAndPreservesOIDCSession(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "persisted-v13.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 13; version++ {
		ddl, checksum, loadErr := repo.migration(version)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("build v13 statement: %v", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	org := "10000000-0000-4000-8000-000000000011"
	localSubject := "10000000-0000-4000-8000-000000000012"
	oidcSubject := "10000000-0000-4000-8000-000000000013"
	account := "10000000-0000-4000-8000-000000000014"
	localToken := make([]byte, 32)
	oidcToken := make([]byte, 32)
	localToken[0], oidcToken[0] = 1, 2
	username := make([]byte, 32)
	csrf := make([]byte, 32)
	now := repo.BindTime(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC))
	expires := repo.BindTime(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC))
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization(id,timezone,graph_revision) VALUES(?,'UTC',1)", []any{org}},
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{org, localSubject}},
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{org, oidcSubject}},
		{"INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,1,1,?,?, 'identity','identity.local_username.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,?,?,?)", []any{account, org, localSubject, username, "username-v1", account, account, []byte{1}, []byte{2}, now}},
		{"INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES(?,'pepper-v1',1,?,1,?)", []any{account, "$argon2id$v=19$m=65536,t=3,p=1$MTIzNDU2Nzg5MDEyMzQ1Ng$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI", now}},
		{"INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version) VALUES(?,?,?,1,?,?,?,0,?,'csrf-v1',1)", []any{localToken, org, localSubject, expires, expires, now, csrf}},
		{"INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version) VALUES(?,?,?,1,?,?,?,0,?,'csrf-v1',1)", []any{oidcToken, org, oidcSubject, expires, expires, now, csrf}},
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
	var status string
	var generation, localRevoked, oidcRevoked int64
	if err = repo.DB.QueryRowContext(ctx, "SELECT status,generation FROM local_mfa_account WHERE account_id=?", account).Scan(&status, &generation); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT revoked FROM session WHERE token_hash=?", localToken).Scan(&localRevoked); err != nil {
		t.Fatal(err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT revoked FROM session WHERE token_hash=?", oidcToken).Scan(&oidcRevoked); err != nil {
		t.Fatal(err)
	}
	if status != "enrollment_required" || generation != 1 || localRevoked != 1 || oidcRevoked != 0 {
		t.Fatalf("migration state status=%q generation=%d local_revoked=%d oidc_revoked=%d", status, generation, localRevoked, oidcRevoked)
	}
	if err = repo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestV16RefusesV11WithoutWriting(t *testing.T) {
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

func TestV16MigratesPersistedV14AuditOutboxWithoutClearingData(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "persisted-v14.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 14; version++ {
		ddl, checksum, loadErr := repo.migration(version)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("build v14 statement: %v", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	org := "10000000-0000-4000-8000-000000000021"
	subject := "10000000-0000-4000-8000-000000000022"
	event := "10000000-0000-4000-8000-000000000023"
	request := "10000000-0000-4000-8000-000000000024"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organization(id,timezone,graph_revision) VALUES(?,'UTC',1)", []any{org}},
		{"INSERT INTO authorization_guard(org_id,auth_epoch) VALUES(?,1)", []any{org}},
		{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", []any{org, subject}},
		{"INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at) VALUES(?,?,?,'OP-ORG-04','organization_management',?,'allowed',1)", []any{event, org, subject, request}},
		{"INSERT INTO audit_outbox(event_id,org_id,available_at) VALUES(?,?,1)", []any{event, org}},
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
	var events, outbox, versions int
	if err = repo.DB.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM audit_event WHERE id=?),(SELECT count(*) FROM audit_outbox WHERE event_id=?),(SELECT max(version) FROM schema_version)", event, event).Scan(&events, &outbox, &versions); err != nil {
		t.Fatal(err)
	}
	if events != 1 || outbox != 1 || versions != 19 {
		t.Fatalf("migrated audit event=%d outbox=%d schema=%d", events, outbox, versions)
	}
	if err = repo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
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
