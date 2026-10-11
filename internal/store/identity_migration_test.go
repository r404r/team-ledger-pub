package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func migrationInstallVersion(t *testing.T, repo *store.Repository, version int) {
	t.Helper()
	ctx := context.Background()
	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range migrationSQL(t, repo.Backend, version) {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			t.Fatal("genuine historical migration must install:", err)
		}
	}
	b, err := os.ReadFile(filepath.Join("migrations", fmt.Sprintf("%s_v%d.sql", repo.Backend, version)))
	if err != nil {
		t.Fatal(err)
	}
	query := "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)"
	if repo.Backend == "postgres" {
		query = "INSERT INTO schema_version(version,backend,checksum) VALUES($1,$2,$3)"
	}
	if _, err = tx.ExecContext(ctx, query, version, repo.Backend, fmt.Sprintf("%x", sha256.Sum256(b))); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func TestIdentityV3ActualV2UpgradePreservesEncryptedHistoryApprovalsReceiptsAndAudit(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			ctx := context.Background()
			first := migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V2_ORIGINAL"}, "")
			migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V2_CURRENT"}, first.ID)
			migrationInstallVersion(t, f.Repo, 2)
			approver, target := grantSchemaSubject(t, f, f.OrgID), grantSchemaSubject(t, f, f.OrgID)
			authority := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
			if err := grantSchemaInsert(f.Repo, "delegation_authority", authority); err != nil {
				t.Fatal(err)
			}
			grant := grantSchemaGrant(f, target)
			grant["authority_id"], grant["issued_by"], grant["issued_at"] = authority["id"], f.Owner.SubjectID, f.Repo.BindTime(f.Now)
			grant["revoked"], grant["revision"], grant["revoked_by"], grant["revoked_at"], grant["revoke_reason"] = true, int64(2), approver, f.Repo.BindTime(f.Now), "policy_change"
			if err := grantSchemaInsert(f.Repo, "access_grant", grant); err != nil {
				t.Fatal(err)
			}
			receipt := map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "operation": "OP-SEC-03", "key": value.NewID(), "digest": bytes.Repeat([]byte{41}, 32), "digest_key_version": 1, "result_id": grant["id"], "result_revision": 2, "result_status": "revoked", "result_auth_epoch": 1}
			if err := grantSchemaInsert(f.Repo, "grant_command_receipt", receipt); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"OP-SEC-02", "OP-SEC-03", "OP-SEC-06"} {
				audit := map[string]any{"id": value.NewID(), "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "employee_id": nil, "grant_id": grant["id"], "operation": operation, "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": f.Repo.BindTime(f.Now)}
				if err := grantSchemaInsert(f.Repo, "audit_event", audit); err != nil {
					t.Fatal(err)
				}
			}
			before := runtimeFacts(t, ctx, f.Repo)
			delete(before, "schema_version")
			runtimeUnavailable(t, f.Repo.CheckSchema(ctx))
			if err := f.Repo.Migrate(ctx); err != nil {
				t.Fatal("genuine v2 must upgrade to identity schema:", err)
			}
			after := runtimeFacts(t, ctx, f.Repo)
			for i, row := range after["audit_event"] {
				after["audit_event"][i] = row[:10]
			}
			runtimeUnchanged(t, before, after)
			migrationLedger(t, f.Repo)
			view, err := f.Service.Read(ctx, f.Request(f.Owner), first.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.DisplayName != "SYNTHETIC_V2_CURRENT" {
				t.Fatal("v3 must retain decryptable current historical projection:", err)
			}
			for _, table := range []string{"subject_identity", "session_auth", "oidc_transaction"} {
				if f.Count(t, table) != 0 {
					t.Fatal("upgrade cannot invent identity/session facts")
				}
			}
		})
	}
}
func TestIdentityV3InterruptedUpgradePreservesExactV2(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_IDENTITY_INTERRUPTION"}, "")
			migrationInstallVersion(t, f.Repo, 2)
			before := runtimeFacts(t, context.Background(), f.Repo)
			ctx, cancel := context.WithCancel(context.Background())
			tx, err := f.Repo.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, statement := range migrationSQL(t, backend, 3) {
				if strings.HasPrefix(statement, "CREATE TABLE subject_identity") {
					break
				}
				if _, err = tx.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			if err = tx.Commit(); err == nil {
				t.Fatal("interrupted v3 cannot report successful cutover")
			}
			_ = tx.Rollback()
			runtimeUnchanged(t, before, runtimeFacts(t, context.Background(), f.Repo))
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("rollback must leave v2 recoverable:", err)
			}
		})
	}
}
func TestIdentityV3OwnersProofOnceAndFiniteAuditRemainEnforced(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			digest := bytes.Repeat([]byte{83}, 32)
			mapping := identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID}
			if err := f.Repo.BindIdentity(ctx, mapping, value.NewID(), f.Now); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name         string
				org, subject string
				hash         []byte
			}{
				{"foreign_mapping_owner", f.OtherOrgID, f.OtherOwner.SubjectID, f.OtherOwner.Hash},
				{"foreign_session_owner", f.OrgID, f.Owner.SubjectID, f.OtherOwner.Hash},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := map[string]any{"token_hash": test.hash, "org_id": test.org, "subject_id": test.subject, "identity_digest": digest, "key_version": 1, "created_at": f.Repo.BindTime(f.Now), "auth_time": nil, "acr": "", "amr_json": "[]"}
					runtimeForeignKey(t, backend, grantSchemaInsert(f.Repo, "session_auth", row))
				})
			}
			base := map[string]any{"state_hash": bytes.Repeat([]byte{84}, 32), "binding_hash": bytes.Repeat([]byte{85}, 32), "sealed_bytes": bytes.Repeat([]byte{86}, 28), "key_version": 1, "created_at": f.Repo.BindTime(f.Now), "expires_at": f.Repo.BindTime(f.Now.Add(10 * time.Minute)), "mode": "step_up", "action": "pii.write", "return_route": "/", "previous_hash": f.Owner.Hash, "expected_org": f.OrgID, "expected_subject": f.Owner.SubjectID, "expected_epoch": 1, "expected_identity": digest}
			for _, test := range []struct {
				name    string
				change  func(map[string]any)
				foreign bool
			}{
				{"wrong_previous_owner", func(row map[string]any) { row["previous_hash"] = f.OtherOwner.Hash }, true},
				{"missing_epoch", func(row map[string]any) { row["expected_epoch"] = nil }, false},
				{"unsupported_action", func(row map[string]any) { row["action"] = "financial.export" }, false},
				{"overlong_proof", func(row map[string]any) {
					row["expires_at"] = f.Repo.BindTime(f.Now.Add(10*time.Minute + time.Microsecond))
				}, false},
				{"issued_without_consume", func(row map[string]any) { row["issued_hash"] = f.Owner.Hash }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					test.change(row)
					err := grantSchemaInsert(f.Repo, "oidc_transaction", row)
					if test.foreign {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			if err := grantSchemaInsert(f.Repo, "oidc_transaction", base); err != nil {
				t.Fatal(err)
			}
			_, err := f.Repo.ConsumeOIDCTransaction(ctx, base["state_hash"].([]byte), base["binding_hash"].([]byte), f.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Repo.ConsumeOIDCTransaction(ctx, base["state_hash"].([]byte), base["binding_hash"].([]byte), f.Now); err == nil {
				t.Fatal("persisted proof must consume exactly once")
			}
			row := map[string]any{"id": value.NewID(), "org_id": nil, "subject_id": nil, "employee_id": nil, "grant_id": nil, "operation": "AUTH-UNKNOWN", "purpose": "", "request_id": value.NewID(), "outcome": "denied", "recorded_at": f.Repo.BindTime(f.Now)}
			migrationConstraint(t, backend, grantSchemaInsert(f.Repo, "audit_event", row))
			if _, err = f.Repo.DB.Exec("DROP INDEX session_auth_identity"); err != nil {
				t.Fatal(err)
			}
			runtimeUnavailable(t, f.Repo.CheckSchema(ctx))
			runtimeUnavailable(t, f.Repo.Migrate(ctx))
		})
	}
}
