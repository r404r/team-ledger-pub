package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"modernc.org/sqlite"
)

func TestRuntimeCurrentEncryptedProfileSurvivesReopen(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			created := runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_RUNTIME_ORIGINAL")
			profile := organization.Profile{
				DisplayName:    "SYNTHETIC_RUNTIME_CURRENT",
				WorkContact:    new(organization.Contact{Email: "synthetic-runtime@example.invalid", Phone: "SYNTHETIC_PHONE"}),
				ProfileSummary: "SYNTHETIC_RUNTIME_FULL_CORRECTION",
			}
			updated, err := f.Service.Update(ctx, f.Request(f.Owner), created.ID, organization.UpdateCommand{
				ExpectedRevision: "1", Profile: profile, EditReason: "SYNTHETIC_RUNTIME_CORRECTION_REASON",
			})
			if err != nil || updated.ID != created.ID || updated.Revision != "2" {
				t.Fatalf("authorized full correction must commit revision 2: result=%+v err=%v", updated, err)
			}
			employee, err := f.Repo.Employee(ctx, created.ID)
			if err != nil {
				t.Fatal("current employee must be persisted:", err)
			}
			version, err := f.Repo.Version(ctx, f.OrgID, created.ID, employee.HeadID)
			if err != nil || version.Number != 2 || version.SupersedesID == "" {
				t.Fatalf("current immutable version must supersede the first: %v", err)
			}
			for _, marker := range []string{profile.DisplayName, profile.WorkContact.Email, profile.ProfileSummary, "SYNTHETIC_RUNTIME_CORRECTION_REASON"} {
				if bytes.Contains(version.Envelope.SealedBytes, []byte(marker)) {
					t.Fatal("encrypted current payload must not persist a plaintext synthetic marker")
				}
			}
			before := runtimeFacts(t, ctx, f.Repo)
			if err := f.Repo.Close(); err != nil {
				t.Fatal("original repository must close:", err)
			}
			reopened := runtimeOpen(t, ctx, f)
			if reopened == f.Repo || reopened.DB == f.Repo.DB {
				t.Fatal("reopen must use a separate repository and pool")
			}
			if err := reopened.CheckSchema(ctx); err != nil {
				t.Fatal("persisted schema must satisfy startup:", err)
			}
			for range 2 {
				if err := reopened.Migrate(ctx); err != nil {
					t.Fatal("repeat migration must accept the existing schema:", err)
				}
			}
			if err := reopened.CheckSchema(ctx); err != nil {
				t.Fatal("repeat migration must preserve schema validity:", err)
			}
			runtimeUnchanged(t, before, runtimeFacts(t, ctx, reopened))
			persisted, err := reopened.Version(ctx, f.OrgID, created.ID, employee.HeadID)
			if err != nil || !reflect.DeepEqual(persisted, version) {
				t.Fatal("reopen and repeat migration must preserve the complete encrypted envelope and version")
			}
			service := *f.Service
			service.Store = reopened
			view, err := service.Read(ctx, f.Request(f.Owner), created.ID, "2026-01-01", true)
			if err != nil || view.ID != created.ID || view.OrgID != f.OrgID || view.Revision != "2" ||
				view.Profile == nil || !reflect.DeepEqual(*view.Profile, profile) || !reflect.DeepEqual(view.Lifecycle, employee.Lifecycle) {
				t.Fatalf("authenticated consumer must decrypt the full current profile after reopen: %v", err)
			}
		})
	}
}

func TestRuntimeSchemaDriftFailsStartupWithoutRepairingFacts(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, drift := range []string{"missing_index", "altered_ledger"} {
				t.Run(drift, func(t *testing.T) {
					f := testsupport.NewHarness(t, backend)
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_RUNTIME_SCHEMA_FACT")
					if err := f.Repo.CheckSchema(ctx); err != nil {
						t.Fatal("fixture schema must initially be valid:", err)
					}
					if drift == "missing_index" {
						if _, err := f.Repo.DB.ExecContext(ctx, "DROP INDEX version_payload"); err != nil {
							t.Fatal("isolated index removal failed:", err)
						}
					} else {
						if _, err := f.Repo.DB.ExecContext(ctx, "UPDATE schema_version SET checksum='SYNTHETIC_RUNTIME_ALTERED_LEDGER'"); err != nil {
							t.Fatal("isolated ledger alteration failed:", err)
						}
					}
					before := runtimeFacts(t, ctx, f.Repo)
					runtimeUnavailable(t, f.Repo.CheckSchema(ctx))
					// Production startup opens a fresh repository and requires CheckSchema
					// before constructing the service/listener; Open alone is not migration.
					startup := runtimeOpen(t, ctx, f)
					runtimeUnavailable(t, startup.CheckSchema(ctx))
					for range 2 {
						runtimeUnavailable(t, startup.Migrate(ctx))
					}
					runtimeUnavailable(t, startup.CheckSchema(ctx))
					runtimeUnchanged(t, before, runtimeFacts(t, ctx, startup))
					if drift == "missing_index" {
						query := "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='version_payload'"
						if backend == "postgres" {
							query = "SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='version_payload'"
						}
						var count int
						if err := startup.DB.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
							t.Fatal("failed startup/migration must not recreate the missing index")
						}
					} else {
						var checksum string
						if err := startup.DB.QueryRowContext(ctx, "SELECT checksum FROM schema_version").Scan(&checksum); err != nil || checksum != "SYNTHETIC_RUNTIME_ALTERED_LEDGER" {
							t.Fatal("failed startup/migration must not overwrite the altered ledger")
						}
					}
				})
			}
		})
	}
}

func TestRuntimeCompositeOwnerForeignKeysRejectForeignOrganization(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			local := runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_RUNTIME_LOCAL_OWNER")
			foreign := runtimeCreate(t, ctx, f, f.OtherOwner, f.OtherOrgID, "SYNTHETIC_RUNTIME_FOREIGN_OWNER")
			foreignEmployee, err := f.Repo.Employee(ctx, foreign.ID)
			if err != nil {
				t.Fatal("foreign fixture employee must exist:", err)
			}
			// A positive employee-scoped grant establishes that the same valid shape
			// is accepted when both subject and employee have the declared owner.
			if err := runtimeInsertGrant(ctx, f, f.OrgID, f.Owner.SubjectID, local.ID); err != nil {
				t.Fatal("same-owner employee grant must be accepted:", err)
			}
			before := runtimeFacts(t, ctx, f.Repo)
			t.Run("profile_head", func(t *testing.T) {
				conn, err := f.Repo.DB.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
					t.Fatal("owned FK transaction must begin:", err)
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = conn.ExecContext(cleanup, "ROLLBACK")
				}()
				query := "UPDATE employee SET profile_head_id=? WHERE org_id=? AND id=?"
				if backend == "postgres" {
					query = "UPDATE employee SET profile_head_id=$1 WHERE org_id=$2 AND id=$3"
				}
				result, err := conn.ExecContext(ctx, query, foreignEmployee.HeadID, f.OrgID, local.ID)
				if err != nil {
					t.Fatal("initially-deferred head FK must allow the statement before commit:", err)
				}
				if n, err := result.RowsAffected(); err != nil || n != 1 {
					t.Fatal("head mutation must target the existing local employee")
				}
				_, err = conn.ExecContext(ctx, "COMMIT")
				runtimeForeignKey(t, backend, err)
				// Own the connection explicitly: SQLite's failed deferred COMMIT
				// leaves its transaction active, unlike PostgreSQL's failed COMMIT.
				if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
					t.Fatal("failed FK transaction must be released:", err)
				}
				runtimeUnchanged(t, before, runtimeFacts(t, ctx, f.Repo))
			})
			t.Run("grant_employee", func(t *testing.T) {
				runtimeForeignKey(t, backend, runtimeInsertGrant(ctx, f, f.OrgID, f.Owner.SubjectID, foreign.ID))
				runtimeUnchanged(t, before, runtimeFacts(t, ctx, f.Repo))
			})
			t.Run("grant_subject", func(t *testing.T) {
				runtimeForeignKey(t, backend, runtimeInsertGrant(ctx, f, f.OrgID, f.OtherOwner.SubjectID, local.ID))
				runtimeUnchanged(t, before, runtimeFacts(t, ctx, f.Repo))
			})
			if err := f.Repo.CheckSchema(ctx); err != nil {
				t.Fatal("rejected foreign-owner writes must preserve valid schema and facts:", err)
			}
			for _, entry := range []struct {
				credential testsupport.Credential
				result     organization.Result
				marker     string
			}{
				{f.Owner, local, "SYNTHETIC_RUNTIME_LOCAL_OWNER"},
				{f.OtherOwner, foreign, "SYNTHETIC_RUNTIME_FOREIGN_OWNER"},
			} {
				view, err := f.Service.Read(ctx, f.Request(entry.credential), entry.result.ID, "2026-01-01", true)
				if err != nil || view.Revision != "1" || view.Profile == nil || view.Profile.DisplayName != entry.marker {
					t.Fatalf("each authorized owner must still decrypt their original profile: %v", err)
				}
			}
		})
	}
}

func TestRuntimeHeldAuthorizationWriterReturnsSafeBusyBeforeCallback(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			created := runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_RUNTIME_BEFORE_BUSY")
			before := runtimeFacts(t, ctx, f.Repo)
			locker := runtimeOpen(t, ctx, f)
			held, err := locker.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal("second-connection lock transaction failed:", err)
			}
			defer held.Rollback()
			query := "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?"
			if backend == "postgres" {
				query = "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1"
			}
			result, err := held.ExecContext(ctx, query, f.OrgID)
			if err != nil {
				t.Fatal("held authorization writer must acquire the actual database lock:", err)
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				t.Fatal("held writer must lock the fixture organization guard")
			}
			// The completed UPDATE above is the synchronization barrier: no sleeps,
			// goroutine scheduling assumptions, or context-induced lock failures.
			blocked, stop := context.WithTimeout(ctx, 15*time.Second)
			defer stop()
			called := false
			err = f.Repo.WithTx(blocked, f.OrgID, func(tx organization.Tx) error {
				called = true
				return tx.Audit(blocked, organization.Audit{
					ID: value.NewID(), OrgID: f.OrgID, SubjectID: f.Owner.SubjectID, EmployeeID: created.ID,
					Operation: "OP-ORG-08", Purpose: "organization_management", RequestID: value.NewID(), Outcome: "allowed", At: f.Now,
				})
			})
			if !errors.Is(err, organization.Busy) || err.Error() != "UNAVAILABLE" || organization.Busy.Status != 503 || organization.Busy.Reason != "WRITE_BUSY" {
				t.Fatalf("held guard must return the safe write-busy fault, not driver details: %v", err)
			}
			if blocked.Err() != nil {
				t.Fatal("database busy/lock timeout must win before the generous context deadline")
			}
			if called {
				t.Fatal("authorization guard contention must prevent callback execution")
			}
			if err := held.Rollback(); err != nil {
				t.Fatal("held writer rollback failed:", err)
			}
			runtimeUnchanged(t, before, runtimeFacts(t, ctx, f.Repo))
			profile := organization.Profile{DisplayName: "SYNTHETIC_RUNTIME_AFTER_BUSY"}
			updated, err := f.Service.Update(ctx, f.Request(f.Owner), created.ID, organization.UpdateCommand{
				ExpectedRevision: "1", Profile: profile, EditReason: "SYNTHETIC_RUNTIME_LOCK_RELEASED",
			})
			if err != nil || updated.Revision != "2" {
				t.Fatalf("authorized encrypted correction must work after the lock is released: %v", err)
			}
			view, err := f.Service.Read(ctx, f.Request(f.Owner), created.ID, "2026-01-01", true)
			if err != nil || view.Revision != "2" || view.Profile == nil || !reflect.DeepEqual(*view.Profile, profile) {
				t.Fatalf("busy rollback must leave the pool usable for real authenticated writes and decryption: %v", err)
			}
		})
	}
}

func runtimeCreate(t *testing.T, ctx context.Context, f *testsupport.Fixture, credential testsupport.Credential, org, marker string) organization.Result {
	t.Helper()
	result, err := f.Service.Create(ctx, f.Request(credential), org, organization.CreateCommand{
		Profile: organization.Profile{DisplayName: marker}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"},
	})
	if err != nil || !value.ValidID(result.ID) || result.Revision != "1" {
		t.Fatalf("real authorized synthetic employee creation failed: %v", err)
	}
	return result
}

func runtimeOpen(t *testing.T, ctx context.Context, f *testsupport.Fixture) *store.Repository {
	t.Helper()
	repo, err := store.Open(ctx, f.Backend, f.DSN)
	if err != nil {
		t.Fatal("separate repository open failed:", err)
	}
	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Error("separate repository cleanup failed:", err)
		}
	})
	return repo
}

func runtimeInsertGrant(ctx context.Context, f *testsupport.Fixture, org, subject, employee string) error {
	return f.Exec(ctx,
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,'pii.read','pii','employee',?,?,'organization_management',?,?,0,0,0)",
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,'pii.read','pii','employee',$4,$5,'organization_management',$6,$7,false,false,false)",
		value.NewID(), org, subject, employee, employee, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)),
	)
}

func runtimeForeignKey(t *testing.T, backend string, err error) {
	t.Helper()
	if backend == "sqlite" {
		var constraint *sqlite.Error
		if !errors.As(err, &constraint) || constraint.Code() != 787 {
			t.Fatalf("SQLite must reject the actual foreign-owner FK (SQLITE_CONSTRAINT_FOREIGNKEY): %v", err)
		}
		return
	}
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatalf("PostgreSQL must reject the actual foreign-owner FK (foreign_key_violation): %v", err)
	}
}

func runtimeUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, organization.Unavailable) || err.Error() != "UNAVAILABLE" {
		t.Fatalf("schema drift must fail closed with a safe unavailable fault: %v", err)
	}
}

// Snapshot every persisted fact, including ciphertext, authentication state,
// receipts, audit events and the ledger. This compares preservation, not defaults.
func runtimeFacts(t *testing.T, ctx context.Context, repo *store.Repository) map[string][][]any {
	t.Helper()
	facts := make(map[string][][]any)
	for _, table := range []struct{ name, order string }{
		{"schema_version", "version"}, {"organization", "id"}, {"authorization_guard", "org_id"},
		{"subject", "org_id,id"}, {"session", "token_hash"}, {"employee", "org_id,id"},
		{"capability_assignment", "org_id,subject_id,capability,scope_kind,scope_id"}, {"access_grant", "id"},
		{"encrypted_payload", "org_id,employee_id,id"}, {"employee_profile_version", "org_id,employee_id,id"},
		{"command_receipt", "org_id,subject_id,operation,key"}, {"audit_event", "id"},
	} {
		rows, err := repo.DB.QueryContext(ctx, "SELECT * FROM "+table.name+" ORDER BY "+table.order)
		if err != nil {
			t.Fatal("persisted fact query failed:", table.name, err)
		}
		facts[table.name] = runtimeRows(t, rows)
	}
	return facts
}

func runtimeRows(t *testing.T, rows *sql.Rows) [][]any {
	t.Helper()
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal("persisted fact columns failed:", err)
	}
	var result [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal("persisted fact scan failed:", err)
		}
		for i, item := range values {
			switch item := item.(type) {
			case []byte:
				values[i] = bytes.Clone(item)
			case time.Time:
				values[i] = item.UTC()
			}
		}
		result = append(result, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal("persisted fact iteration failed:", err)
	}
	return result
}

func runtimeUnchanged(t *testing.T, before, after map[string][][]any) {
	t.Helper()
	for table, expected := range before {
		if !reflect.DeepEqual(expected, after[table]) {
			t.Fatalf("operation must preserve every persisted fact in %s", table)
		}
	}
}
