package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"modernc.org/sqlite"
)

var originalMigrationChecksums = map[string]string{
	"sqlite":   "9f4b41ea7c30e984c55999e87ffb8dc8f4a434a88b3c20f63c17a262e9b772d8",
	"postgres": "373bb9b84f64a867704687c921af7cdd096c420349862846997a890585d51bf3",
}

func TestMigrationActualV1PreservesEveryLegacyFact(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			ctx := context.Background()
			created := migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V1_ENCRYPTED_ORIGINAL"}, "")
			profile := organization.Profile{DisplayName: "SYNTHETIC_V1_ENCRYPTED_CURRENT", ProfileSummary: "SYNTHETIC_V1_SUMMARY"}
			migrationV1Profile(t, f, profile, created.ID)
			var err error
			if err = f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked) VALUES(?,?,?,'pii.read','pii','org',?,'organization_management',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked) VALUES($1,$2,$3,'pii.read','pii','org',$4,'organization_management',$5,$6,true)", value.NewID(), f.OrgID, f.Owner.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
				t.Fatal("legacy revoked grant must exist before upgrade:", err)
			}
			before := migrationLegacyFacts(t, f.Repo)
			runtimeUnavailable(t, f.Repo.CheckSchema(ctx))
			runtimeUnchanged(t, before, migrationLegacyFacts(t, f.Repo))
			if err = f.Repo.Migrate(ctx); err != nil {
				t.Fatal("genuine v1 must upgrade transactionally:", err)
			}
			runtimeUnchanged(t, before, migrationLegacyFacts(t, f.Repo))
			migrationLedger(t, f.Repo)
			var unexpected int
			if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM access_grant WHERE revision<>1 OR authority_id IS NOT NULL OR issued_by IS NOT NULL OR issued_at IS NOT NULL OR revoked_by IS NOT NULL OR revoked_at IS NOT NULL OR revoke_reason IS NOT NULL").Scan(&unexpected); err != nil || unexpected != 0 {
				t.Fatal("v1 grants must retain unknown approval/issue/revocation facts as NULL")
			}
			if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE grant_id IS NOT NULL").Scan(&unexpected); err != nil || unexpected != 0 {
				t.Fatal("legacy audit facts must not acquire invented grant objects")
			}
			for _, table := range []string{"delegation_authority", "grant_command_receipt"} {
				if f.Count(t, table) != 0 {
					t.Fatal("migration must not invent approval or command facts")
				}
			}
			for range 2 {
				if err = f.Repo.Migrate(ctx); err != nil {
					t.Fatal("repeat migration must preserve all facts:", err)
				}
			}
			if err = f.Repo.CheckSchema(ctx); err != nil {
				t.Fatal("upgraded schema must pass startup:", err)
			}
			runtimeUnchanged(t, before, migrationLegacyFacts(t, f.Repo))
			migrationLedger(t, f.Repo)
			reopened := runtimeOpen(t, ctx, f)
			service := *f.Service
			service.Store = reopened
			view, err := service.Read(ctx, f.Request(f.Owner), created.ID, "2026-01-01", true)
			if err != nil || view.Revision != "2" || view.Profile == nil || !reflect.DeepEqual(*view.Profile, profile) {
				t.Fatal("upgraded and reopened service must decrypt the exact current v1 profile:", err)
			}
		})
	}
}

func TestMigrationInterruptedUpgradeRollsBack(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_INTERRUPTED_V1"}, "")
			before := migrationLegacyFacts(t, f.Repo)
			ctx, cancel := context.WithCancel(context.Background())
			tx, err := f.Repo.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			// Execute the real forward SQL through all four table rebuilds, then
			// interrupt before its new receipt/index/trigger definitions and ledger.
			for _, statement := range migrationSQL(t, backend, 2) {
				if strings.HasPrefix(statement, "CREATE TABLE grant_command_receipt") {
					break
				}
				if _, err = tx.ExecContext(ctx, statement); err != nil {
					t.Fatal("real upgrade prefix must execute before interruption:", err)
				}
			}
			cancel()
			if err = tx.Commit(); err == nil {
				t.Fatal("an interrupted transaction must never report upgrade success")
			}
			_ = tx.Rollback()
			runtimeUnchanged(t, before, migrationLegacyFacts(t, f.Repo))
			var versions int
			if err = f.Repo.DB.QueryRowContext(context.Background(), "SELECT count(*) FROM schema_version WHERE version=1").Scan(&versions); err != nil || versions != 1 {
				t.Fatal("interruption must restore the original v1 ledger:", err)
			}
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("rollback must leave genuine v1 recoverable by the real migrator:", err)
			}
			runtimeUnchanged(t, before, migrationLegacyFacts(t, f.Repo))
			migrationLedger(t, f.Repo)
		})
	}
}

func TestMigrationRejectsReplacedDefinitionsAndLedgerDrift(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		for _, version := range []int{1, 2} {
			for _, drift := range []string{"missing_index", "replaced_index", "replaced_enum", "replaced_owner", "missing_column", "altered_ledger", "missing_ledger_record"} {
				t.Run(fmt.Sprintf("%s/v%d/%s", backend, version, drift), func(t *testing.T) {
					f := migrationV1Fixture(t, backend)
					if version == 2 {
						migrationInstallVersion(t, f.Repo, 2)
					}
					migrationDrift(t, f.Repo, version, drift)
					before := migrationLegacyFacts(t, f.Repo)
					for range 2 {
						runtimeUnavailable(t, f.Repo.Migrate(context.Background()))
						runtimeUnavailable(t, f.Repo.CheckSchema(context.Background()))
					}
					if !reflect.DeepEqual(before, migrationLegacyFacts(t, f.Repo)) {
						t.Fatal("refused migration/startup must not repair physical or ledger drift")
					}
				})
			}
		}
	}
}

func migrationSQL(t *testing.T, backend string, version int) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("migrations", fmt.Sprintf("%s_v%d.sql", backend, version)))
	if err != nil {
		t.Fatal("checked-in migration must be readable:", err)
	}
	if version == 1 && fmt.Sprintf("%x", sha256.Sum256(b)) != originalMigrationChecksums[backend] {
		t.Fatal("deployed v1 migration bytes must never change")
	}
	var statements []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "--") {
			statements = append(statements, line)
		}
	}
	return statements
}

func migrationV1Fixture(t *testing.T, backend string) *testsupport.Fixture {
	t.Helper()
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "actual-v1.db")
	if backend == "postgres" {
		original := os.Getenv("TEAMLEDGER_TEST_POSTGRES_DSN")
		if original == "" {
			t.Fatal("real PostgreSQL DSN is required; no skip/fallback")
		}
		base, err := store.Open(ctx, backend, original)
		if err != nil {
			t.Fatal("isolated real PostgreSQL connection must open")
		}
		schema := "dev003_migration_" + strings.ReplaceAll(value.NewID(), "-", "")
		if _, err = base.DB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
			base.Close()
			t.Fatal("isolated schema creation failed")
		}
		u, err := url.Parse(original)
		if err != nil {
			t.Fatal("test DSN must be a PostgreSQL URL")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
		t.Cleanup(func() {
			_, _ = base.DB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			_ = base.Close()
		})
	}
	repo, err := store.Open(ctx, backend, dsn)
	if err != nil {
		t.Fatal("actual v1 repository must open")
	}
	f := &testsupport.Fixture{Repo: repo, Backend: backend, DSN: dsn, OrgID: value.NewID(), OtherOrgID: value.NewID(), Now: time.Now().UTC().Truncate(time.Microsecond)}
	t.Cleanup(f.Close)
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range migrationSQL(t, backend, 1) {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			t.Fatal("actual immutable v1 DDL must install:", err)
		}
	}
	query := "INSERT INTO schema_version(version,backend,checksum) VALUES(1,?,?)"
	if backend == "postgres" {
		query = "INSERT INTO schema_version(version,backend,checksum) VALUES(1,$1,$2)"
	}
	if _, err = tx.ExecContext(ctx, query, backend, originalMigrationChecksums[backend]); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		org        string
		credential *testsupport.Credential
	}{{f.OrgID, &f.Owner}, {f.OtherOrgID, &f.OtherOwner}} {
		entry.credential.SubjectID = value.NewID()
		hash := sha256.Sum256([]byte("SYNTHETIC_MIGRATION_SESSION:" + entry.credential.SubjectID))
		entry.credential.Hash = bytes.Clone(hash[:])
		for _, statement := range []struct {
			sq, pg string
			args   []any
		}{
			{"INSERT INTO organization(id,timezone) VALUES(?,'UTC')", "INSERT INTO organization(id,timezone) VALUES($1,'UTC')", []any{entry.org}},
			{"INSERT INTO authorization_guard(org_id) VALUES(?)", "INSERT INTO authorization_guard(org_id) VALUES($1)", []any{entry.org}},
			{"INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)", []any{entry.org, entry.credential.SubjectID}},
			{"INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,csrf_hash,csrf_version) VALUES(?,?,?,1,?,?,?,?,1)", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,csrf_hash,csrf_version) VALUES($1,$2,$3,1,$4,$5,$6,$7,1)", []any{hash[:], entry.org, entry.credential.SubjectID, repo.BindTime(f.Now.Add(time.Hour)), repo.BindTime(f.Now.Add(time.Hour)), repo.BindTime(f.Now.Add(time.Hour)), bytes.Repeat([]byte{1}, 32)}},
		} {
			if err = f.Exec(ctx, statement.sq, statement.pg, statement.args...); err != nil {
				t.Fatal("synthetic v1 identity seed failed:", err)
			}
		}
		for _, capability := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
			if err = f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,?,'org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,$3,'org',$4)", entry.org, entry.credential.SubjectID, capability, entry.org); err != nil {
				t.Fatal(err)
			}
			category := "metadata"
			if strings.HasPrefix(capability, "pii.") {
				category = "pii"
			}
			if err = f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at) VALUES(?,?,?,?,?,'org',?,'organization_management',?,?)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at) VALUES($1,$2,$3,$4,$5,'org',$6,'organization_management',$7,$8)", value.NewID(), entry.org, entry.credential.SubjectID, capability, category, entry.org, repo.BindTime(f.Now.Add(-time.Hour)), repo.BindTime(f.Now.Add(time.Hour))); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.KMS, err = testsupport.NewVaultFixture("dev002-pii")
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := f.KMS.Wrapper()
	if err != nil {
		t.Fatal(err)
	}
	f.DigestKey = bytes.Repeat([]byte{2}, 32)
	f.CursorKey = bytes.Repeat([]byte{3}, 32)
	f.Service = &organization.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, DigestKey: f.DigestKey, CursorKey: f.CursorKey, Now: func() time.Time { return f.Now }}
	return f
}

// Seed the genuine deployed schema using its original guarded SQL and actual
// cipher, not today's store writes (which append new lifecycle facts in v5).
func migrationV1Profile(t *testing.T, f *testsupport.Fixture, profile organization.Profile, id string) organization.Result {
	t.Helper()
	ctx := context.Background()
	employee := organization.Employee{ID: id, OrgID: f.OrgID, Revision: 1, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}
	operation, supersedes := "OP-ORG-05", ""
	if id == "" {
		employee.ID = value.NewID()
	} else {
		query := "SELECT profile_head_id,profile_revision FROM employee WHERE org_id=? AND id=?"
		if f.Backend == "postgres" {
			query = "SELECT profile_head_id,profile_revision FROM employee WHERE org_id=$1 AND id=$2"
		}
		if err := f.Repo.DB.QueryRowContext(ctx, query, f.OrgID, id).Scan(&employee.HeadID, &employee.Revision); err != nil {
			t.Fatal(err)
		}
		supersedes = employee.HeadID
		employee.Revision++
		operation = "OP-ORG-08"
	}
	version := organization.Version{ID: value.NewID(), OrgID: f.OrgID, EmployeeID: employee.ID, Number: employee.Revision, SupersedesID: supersedes, RecordedAt: f.Now}
	payload, err := json.Marshal(organization.ProfilePayload{Profile: profile, EditReason: "SYNTHETIC_V1_APPROVED_EDIT"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	binding := sensitive.Context{OrgID: f.OrgID, EmployeeID: employee.ID, RecordID: employee.ID, VersionID: version.ID, ObjectKind: "employee_profile", Purpose: "pii", SchemaType: "pii.profile.v1", SchemaVersion: 1}
	version.Envelope, err = f.Service.Cipher.Seal(ctx, binding, payload)
	if err != nil {
		t.Fatal("real v1 synthetic encryption must succeed:", err)
	}
	employee.HeadID = version.ID
	result := organization.Result{ID: employee.ID, Revision: fmt.Sprint(employee.Revision)}
	tx, err := f.Repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	exec := func(sq, pg string, args ...any) sql.Result {
		query := sq
		if f.Backend == "postgres" {
			query = pg
		}
		res, e := tx.ExecContext(ctx, query, args...)
		if e != nil {
			t.Fatal("genuine historical SQL must persist:", e)
		}
		return res
	}
	if f.Backend == "sqlite" {
		exec("UPDATE authorization_guard SET auth_epoch=auth_epoch WHERE org_id=?", "", f.OrgID)
	} else {
		var epoch int64
		if err = tx.QueryRowContext(ctx, "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1 FOR UPDATE", f.OrgID).Scan(&epoch); err != nil {
			t.Fatal(err)
		}
	}
	if supersedes == "" {
		exec("INSERT INTO employee(org_id,id,profile_head_id,profile_revision,valid_from) VALUES(?,?,?,?,?)", "INSERT INTO employee(org_id,id,profile_head_id,profile_revision,valid_from) VALUES($1,$2,$3,$4,$5)", f.OrgID, employee.ID, version.ID, employee.Revision, employee.Lifecycle.ValidFrom)
	}
	e, c := version.Envelope, version.Envelope.Context
	exec("INSERT INTO encrypted_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", "INSERT INTO encrypted_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)", c.OrgID, c.EmployeeID, version.ID, c.RecordID, c.VersionID, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, f.Repo.BindTime(f.Now))
	var old any
	if supersedes != "" {
		old = supersedes
	}
	exec("INSERT INTO employee_profile_version(org_id,employee_id,id,version_no,payload_id,supersedes_id,recorded_at) VALUES(?,?,?,?,?,?,?)", "INSERT INTO employee_profile_version(org_id,employee_id,id,version_no,payload_id,supersedes_id,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)", f.OrgID, employee.ID, version.ID, employee.Revision, version.ID, old, f.Repo.BindTime(f.Now))
	if supersedes != "" {
		res := exec("UPDATE employee SET profile_head_id=?,profile_revision=? WHERE org_id=? AND id=? AND profile_revision=? AND profile_head_id=?", "UPDATE employee SET profile_head_id=$1,profile_revision=$2 WHERE org_id=$3 AND id=$4 AND profile_revision=$5 AND profile_head_id=$6", version.ID, employee.Revision, f.OrgID, employee.ID, employee.Revision-1, supersedes)
		if n, e := res.RowsAffected(); e != nil || n != 1 {
			t.Fatal("historical profile CAS must update exactly its original head")
		}
	}
	exec("INSERT INTO command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision) VALUES(?,?,?,?,?,1,?,?)", "INSERT INTO command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_id,result_revision) VALUES($1,$2,$3,$4,$5,1,$6,$7)", f.OrgID, f.Owner.SubjectID, operation, value.NewID(), bytes.Repeat([]byte{4}, 32), employee.ID, employee.Revision)
	exec("INSERT INTO audit_event(id,org_id,subject_id,employee_id,operation,purpose,request_id,outcome,recorded_at) VALUES(?,?,?,?,?,'organization_management',?,'allowed',?)", "INSERT INTO audit_event(id,org_id,subject_id,employee_id,operation,purpose,request_id,outcome,recorded_at) VALUES($1,$2,$3,$4,$5,'organization_management',$6,'allowed',$7)", value.NewID(), f.OrgID, f.Owner.SubjectID, employee.ID, operation, value.NewID(), f.Repo.BindTime(f.Now))
	if err = tx.Commit(); err != nil {
		t.Fatal("historical encrypted history/receipt/audit must commit atomically:", err)
	}
	return result
}

func migrationLegacyFacts(t *testing.T, repo *store.Repository) map[string][][]any {
	t.Helper()
	facts := map[string][][]any{}
	for _, statement := range migrationSQL(t, repo.Backend, 1) {
		if !strings.HasPrefix(statement, "CREATE TABLE ") {
			continue
		}
		name := strings.Split(strings.Fields(statement)[2], "(")[0]
		columns := "*"
		if name == "access_grant" {
			columns = "id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required"
		}
		if name == "audit_event" {
			columns = "id,org_id,subject_id,employee_id,operation,purpose,request_id,outcome,recorded_at"
		}
		if name == "capability_assignment" {
			columns = "org_id,subject_id,capability,scope_kind,scope_id,employee_id"
		}
		order := "1,2,3"
		if name == "authorization_guard" {
			order = "1"
		}
		rows, err := repo.DB.QueryContext(context.Background(), "SELECT "+columns+" FROM "+name+" ORDER BY "+order)
		if err != nil {
			t.Fatal("legacy fact snapshot failed:", name, err)
		}
		facts[name] = runtimeRows(t, rows)
	}
	// The original ledger row is preserved; forward upgrades append records.
	rows, err := repo.DB.QueryContext(context.Background(), "SELECT version,backend,checksum FROM schema_version WHERE version=1")
	if err != nil {
		t.Fatal(err)
	}
	facts["schema_version"] = runtimeRows(t, rows)
	return facts
}

// Compare only columns present in the genuine source schema. New v5 owner
// columns are independently constrained/tested, never invented legacy facts.
func migrationOriginalUnchanged(t *testing.T, before, after map[string][][]any) {
	t.Helper()
	projected := make(map[string][][]any, len(before))
	for table, original := range before {
		rows := after[table]
		if len(rows) != len(original) {
			t.Fatalf("upgrade must preserve every original row in %s", table)
		}
		for i, row := range rows {
			if len(row) < len(original[i]) {
				t.Fatalf("upgrade must preserve every original column in %s", table)
			}
			projected[table] = append(projected[table], row[:len(original[i])])
		}
	}
	runtimeUnchanged(t, before, projected)
}

func migrationLedger(t *testing.T, repo *store.Repository) {
	t.Helper()
	rows, err := repo.DB.QueryContext(context.Background(), "SELECT version,backend,checksum FROM schema_version ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for _, version := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		var found int
		var backend, checksum string
		if !rows.Next() || rows.Scan(&found, &backend, &checksum) != nil {
			t.Fatal("every supported checksum ledger record must exist")
		}
		b, err := os.ReadFile(filepath.Join("migrations", fmt.Sprintf("%s_v%d.sql", repo.Backend, version)))
		if err != nil || found != version || backend != repo.Backend || checksum != fmt.Sprintf("%x", sha256.Sum256(b)) {
			t.Fatal("migration ledger must preserve exact dialect provenance")
		}
	}
	if rows.Next() || rows.Err() != nil {
		t.Fatal("ledger must contain exactly the supported versions")
	}
}

func migrationDrift(t *testing.T, repo *store.Repository, version int, drift string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) {
		if _, err := repo.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatal("isolated drift injection failed:", err)
		}
	}
	switch drift {
	case "missing_index":
		exec("DROP INDEX grant_subject_scope")
	case "replaced_index":
		exec("DROP INDEX grant_subject_scope")
		exec("CREATE INDEX grant_subject_scope ON access_grant(subject_id,org_id)")
	case "missing_column":
		exec("ALTER TABLE organization RENAME COLUMN timezone TO drifted_timezone")
	case "altered_ledger":
		exec("UPDATE schema_version SET checksum='SYNTHETIC_DRIFT' WHERE version=1")
	case "missing_ledger_record":
		exec("DELETE FROM schema_version WHERE version=1")
	case "replaced_enum", "replaced_owner":
		if repo.Backend == "postgres" {
			definition := "capability IN('organization.read','organization.write','pii.read','pii.write','SYNTHETIC.extra')"
			selector := "contype='c' AND pg_get_constraintdef(oid) LIKE '%organization.read%'"
			if drift == "replaced_owner" {
				definition = "FOREIGN KEY(employee_id) REFERENCES employee(id)"
				selector = "contype='f' AND confrelid='employee'::regclass"
			} else if version == 2 {
				definition = "capability IN('organization.read','organization.write','pii.read','pii.write','access_grant.manage','SYNTHETIC.extra')"
			}
			var name string
			if err := repo.DB.QueryRowContext(ctx, "SELECT conname FROM pg_constraint WHERE conrelid='capability_assignment'::regclass AND "+selector).Scan(&name); err != nil {
				t.Fatal(err)
			}
			exec("ALTER TABLE capability_assignment DROP CONSTRAINT " + name)
			if drift == "replaced_enum" {
				definition = "CHECK(" + definition + ")"
			}
			exec("ALTER TABLE capability_assignment ADD CONSTRAINT " + name + " " + definition)
			return
		}
		var ddl string
		if err := repo.DB.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE name='capability_assignment'").Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		if drift == "replaced_enum" {
			needle := "'pii.write'"
			if version == 2 {
				needle = "'access_grant.manage'"
			}
			ddl = strings.Replace(ddl, needle+")", needle+",'SYNTHETIC.extra')", 1)
		} else {
			ddl = strings.Replace(ddl, "FOREIGN KEY(org_id,employee_id) REFERENCES employee(org_id,id)", "FOREIGN KEY(employee_id) REFERENCES employee(id)", 1)
		}
		ddl = strings.Replace(ddl, "capability_assignment", "drift_assignment", 1)
		tx, err := repo.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, statement := range []string{ddl, "INSERT INTO drift_assignment SELECT * FROM capability_assignment", "DROP TABLE capability_assignment", "ALTER TABLE drift_assignment RENAME TO capability_assignment", "CREATE INDEX assignment_employee ON capability_assignment(org_id,employee_id)"} {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatal("isolated replaced constraint injection failed:", err)
			}
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func migrationConstraint(t *testing.T, backend string, err error) {
	t.Helper()
	if backend == "sqlite" {
		var e *sqlite.Error
		if !errors.As(err, &e) || e.Code() != 275 {
			t.Fatalf("SQLite must enforce the actual CHECK: %v", err)
		}
		return
	}
	var e *pgconn.PgError
	if !errors.As(err, &e) || e.Code != "23514" {
		t.Fatalf("PostgreSQL must enforce the actual CHECK: %v", err)
	}
}
