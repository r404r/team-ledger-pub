package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"testing"

	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestIdentityMaintenanceAuditDoesNotImpersonateTarget(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, operation := range []string{"AUTH-BIND", "AUTH-UNBIND"} {
				t.Run(operation, func(t *testing.T) {
					f := testsupport.NewHarness(t, backend)
					ctx := context.Background()
					digest := sha256.Sum256([]byte("synthetic-maintenance-identity"))
					mapping := identity.Identity{Digest: digest[:], KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Reader.SubjectID}
					requestID := value.NewID()
					bindID := requestID
					if operation == "AUTH-UNBIND" {
						bindID = value.NewID()
					}
					if err := f.Repo.BindIdentity(ctx, mapping, bindID, f.Now); err != nil {
						t.Fatal(err)
					}
					if operation == "AUTH-UNBIND" {
						if err := f.Repo.UnbindIdentity(ctx, mapping, requestID, f.Now); err != nil {
							t.Fatal(err)
						}
					}
					var subject sql.NullString
					query := "SELECT subject_id FROM audit_event WHERE request_id=? AND operation=?"
					if backend == "postgres" {
						query = "SELECT subject_id FROM audit_event WHERE request_id=$1 AND operation=$2"
					}
					if err := f.Repo.DB.QueryRowContext(ctx, query, requestID, operation).Scan(&subject); err != nil {
						t.Fatal(err)
					}
					if subject.Valid {
						t.Fatal("maintenance audit must not impersonate the mapped target as authenticated actor")
					}
					query = "SELECT actor_kind,actor_uid,actor_host_hash,target_subject_id,identity_digest FROM audit_event WHERE request_id=? AND operation=?"
					if backend == "postgres" {
						query = "SELECT actor_kind,actor_uid,actor_host_hash,target_subject_id,identity_digest FROM audit_event WHERE request_id=$1 AND operation=$2"
					}
					var kind, target string
					var uid int64
					var host, recordedDigest []byte
					if err := f.Repo.DB.QueryRowContext(ctx, query, requestID, operation).Scan(&kind, &uid, &host, &target, &recordedDigest); err != nil {
						t.Fatal(err)
					}
					hostname, err := os.Hostname()
					if err != nil {
						t.Fatal(err)
					}
					expectedHost := sha256.Sum256([]byte("TEAMLEDGER-MAINTENANCE-HOST\x00\x01" + hostname))
					if kind != "local_maintenance" || uid != int64(os.Geteuid()) || string(host) != string(expectedHost[:]) || target != mapping.SubjectID || string(recordedDigest) != string(mapping.Digest) {
						t.Fatal("maintenance audit must retain actual kernel process principal separately from exact approved identity target")
					}
				})
			}
		})
	}
}

func TestMaintenanceAuditV4PreservesV3HistoryWithoutInventingOperator(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			ctx := context.Background()
			employee := migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V3_AUDIT_HISTORY"}, "")
			migrationInstallVersion(t, f.Repo, 2)
			migrationInstallVersion(t, f.Repo, 3)
			digest := sha256.Sum256([]byte("synthetic-pre-v4-mapping"))
			mapping := map[string]any{"digest": digest[:], "key_version": 1, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "active": true}
			if err := grantSchemaInsert(f.Repo, "subject_identity", mapping); err != nil {
				t.Fatal(err)
			}
			legacyID := value.NewID()
			legacy := map[string]any{"id": legacyID, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "employee_id": nil, "grant_id": nil, "operation": "AUTH-BIND", "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": f.Repo.BindTime(f.Now)}
			if err := grantSchemaInsert(f.Repo, "audit_event", legacy); err != nil {
				t.Fatal(err)
			}
			before := runtimeFacts(t, ctx, f.Repo)
			delete(before, "schema_version")
			identityRows, err := f.Repo.DB.QueryContext(ctx, "SELECT * FROM subject_identity ORDER BY digest")
			if err != nil {
				t.Fatal(err)
			}
			beforeIdentity := runtimeRows(t, identityRows)
			tx, err := f.Repo.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range migrationSQL(t, backend, 4) {
				if _, err = tx.ExecContext(ctx, statement); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
				if statement == "DROP TABLE audit_event;" {
					break
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, before, runtimeFacts(t, ctx, f.Repo))
			if err = f.Repo.Migrate(ctx); err != nil {
				t.Fatal("v3 audit cutover must preserve data and remain recoverable:", err)
			}
			after := runtimeFacts(t, ctx, f.Repo)
			for i, row := range after["audit_event"] {
				after["audit_event"][i] = row[:10]
			}
			migrationOriginalUnchanged(t, before, after)
			migrationLedger(t, f.Repo)
			identityRows, err = f.Repo.DB.QueryContext(ctx, "SELECT * FROM subject_identity ORDER BY digest")
			if err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, map[string][][]any{"subject_identity": beforeIdentity}, map[string][][]any{"subject_identity": runtimeRows(t, identityRows)})
			query := "SELECT actor_kind,subject_id,target_subject_id,actor_uid,actor_host_hash,identity_digest FROM audit_event WHERE id=?"
			if backend == "postgres" {
				query = "SELECT actor_kind,subject_id,target_subject_id,actor_uid,actor_host_hash,identity_digest FROM audit_event WHERE id=$1"
			}
			var kind, original, target string
			var uid sql.NullInt64
			var host, auditDigest []byte
			if err = f.Repo.DB.QueryRowContext(ctx, query, legacyID).Scan(&kind, &original, &target, &uid, &host, &auditDigest); err != nil {
				t.Fatal(err)
			}
			if kind != "legacy_unattributed" || original != f.Owner.SubjectID || target != f.Owner.SubjectID || uid.Valid || host != nil || auditDigest != nil {
				t.Fatal("historical ambiguous subject must be preserved but never promoted to a verified operator or guessed identity")
			}
			view, err := f.Service.Read(ctx, f.Request(f.Owner), employee.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.LocalName != "SYNTHETIC_V3_AUDIT_HISTORY" {
				t.Fatal("audit cutover must preserve authorized decryptable business facts:", err)
			}
		})
	}
}

func TestMaintenanceAuditRejectsActorTargetAndIdentityConfusion(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			digest := sha256.Sum256([]byte("synthetic-typed-maintenance-mapping"))
			m := identity.Identity{Digest: digest[:], KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Reader.SubjectID}
			if err := f.Repo.BindIdentity(context.Background(), m, value.NewID(), f.Now); err != nil {
				t.Fatal(err)
			}
			base := map[string]any{"org_id": f.OrgID, "subject_id": nil, "employee_id": nil, "grant_id": nil, "operation": "AUTH-BIND", "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": f.Repo.BindTime(f.Now), "actor_kind": "local_maintenance", "actor_uid": int64(os.Geteuid()), "actor_host_hash": bytes.Repeat([]byte{11}, 32), "target_subject_id": m.SubjectID, "identity_digest": m.Digest}
			for _, test := range []struct {
				name    string
				change  func(map[string]any)
				foreign bool
			}{
				{"target pretending actor", func(row map[string]any) { row["subject_id"] = m.SubjectID }, false},
				{"application pretending maintenance", func(row map[string]any) { row["actor_kind"] = "application" }, false},
				{"legacy pretending known operator", func(row map[string]any) { row["actor_kind"] = "legacy_unattributed" }, false},
				{"missing kernel principal", func(row map[string]any) { row["actor_uid"] = nil }, false},
				{"negative kernel principal", func(row map[string]any) { row["actor_uid"] = int64(-1) }, false},
				{"oversized kernel principal", func(row map[string]any) { row["actor_uid"] = int64(1 << 32) }, false},
				{"truncated execution node", func(row map[string]any) { row["actor_host_hash"] = bytes.Repeat([]byte{11}, 31) }, false},
				{"wrong organization target", func(row map[string]any) { row["target_subject_id"] = f.OtherOwner.SubjectID }, true},
				{"unmapped identity target", func(row map[string]any) { row["identity_digest"] = bytes.Repeat([]byte{12}, 32) }, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.change(row)
					err := grantSchemaInsert(f.Repo, "audit_event", row)
					if test.foreign {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
		})
	}
}
