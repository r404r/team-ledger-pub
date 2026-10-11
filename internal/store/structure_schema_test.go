package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"modernc.org/sqlite"
)

func structureImmutableConstraint(t *testing.T, backend string, err error) {
	t.Helper()
	if backend != "sqlite" {
		migrationConstraint(t, backend, err)
		return
	}
	var failure *sqlite.Error
	if !errors.As(err, &failure) || failure.Code() != 1811 {
		t.Fatalf("SQLite must enforce the actual immutable trigger: %v", err)
	}
}

func structureTxInsert(tx *sql.Tx, backend, table string, row map[string]any) error {
	columns, placeholders, args := []string{}, []string{}, []any{}
	for name, v := range row {
		columns = append(columns, name)
		args = append(args, v)
		p := "?"
		if backend == "postgres" {
			p = fmt.Sprintf("$%d", len(args))
		}
		placeholders = append(placeholders, p)
	}
	_, err := tx.Exec("INSERT INTO "+table+"("+strings.Join(columns, ",")+") VALUES("+strings.Join(placeholders, ",")+")", args...)
	return err
}

func TestStructureV5DeferredTypedEncryptedOwnersAndFiniteContexts(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := structureSchemaSeed(t, backend)
			for _, kind := range []string{"team_label", "position_assignment", "structure_change"} {
				t.Run(kind, func(t *testing.T) {
					owner, id := value.NewID(), value.NewID()
					binding := sensitive.Context{OrgID: x.f.OrgID, RecordID: owner, VersionID: id, ObjectKind: kind, Purpose: "pii", SchemaVersion: 1}
					target := map[string]any{"org_id": x.f.OrgID, "id": owner}
					table := "team"
					payload := map[string]any{"org_id": x.f.OrgID, "id": id, "employee_id": nil, "team_id": nil, "position_id": nil, "change_id": nil, "record_id": owner, "version_id": id, "object_kind": kind, "purpose": "pii", "schema_version": 1, "format_version": 1, "algorithm": "A256GCM-RANDOMNONCE", "created_at": x.f.Repo.BindTime(x.f.Now)}
					switch kind {
					case "team_label":
						binding.SchemaType = "org.team.label.v1"
						payload["team_id"] = owner
						target["code"], target["valid_from"], target["label_payload_id"] = "SYNTHETIC_"+owner, "2026-01-01", id
					case "position_assignment":
						table = "position_assignment"
						binding.SchemaType = "org.position.v1"
						binding.EmployeeID = x.employee
						payload["employee_id"], payload["position_id"] = x.employee, owner
						target["employee_id"], target["is_primary"], target["valid_from"], target["change_id"], target["payload_id"] = x.employee, true, "2026-01-01", x.change, id
					case "structure_change":
						table = "structure_change"
						binding.SchemaType = "org.structure.reason.v1"
						payload["change_id"] = owner
						target = x.changeRow(owner)
						target["reason_payload_id"] = id
					}
					envelope, err := x.f.Service.Cipher.Seal(context.Background(), binding, []byte("SYNTHETIC_ENCRYPTED_"+kind))
					if err != nil {
						t.Fatal("real envelope must seal typed owner", err)
					}
					payload["schema_type"], payload["dek_id"], payload["kek_id"], payload["kek_version"], payload["wrapped_dek"], payload["sealed_bytes"] = binding.SchemaType, envelope.DEKID, envelope.Key.KEKID, envelope.Key.Version, envelope.Key.Data, envelope.SealedBytes
					tx, err := x.f.Repo.DB.BeginTx(context.Background(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if err = structureTxInsert(tx, backend, table, target); err != nil {
						t.Fatal("owner first must accept deferred payload reference", err)
					}
					if err = structureTxInsert(tx, backend, "organizational_payload", payload); err != nil {
						t.Fatal(err)
					}
					if err = tx.Commit(); err != nil {
						t.Fatal("actual cyclic same-org ownership must commit", err)
					}
					for _, test := range []struct {
						name   string
						mutate func(map[string]any)
					}{
						{"wrong_record", func(v map[string]any) { v["record_id"] = value.NewID() }},
						{"wrong_version", func(v map[string]any) { v["version_id"] = value.NewID() }},
						{"unsupported_schema", func(v map[string]any) { v["schema_type"] = "pii.profile.v1" }},
						{"mixed_owner", func(v map[string]any) {
							v["employee_id"], v["team_id"], v["position_id"], v["change_id"] = x.employee, x.team, value.NewID(), x.change
						}},
						{"wrong_purpose", func(v map[string]any) { v["purpose"] = "financial" }},
					} {
						t.Run(test.name, func(t *testing.T) {
							row := grantSchemaClone(payload)
							row["id"] = value.NewID()
							row["version_id"] = row["id"]
							test.mutate(row)
							migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "organizational_payload", row))
						})
					}
					row := grantSchemaClone(payload)
					row["id"] = value.NewID()
					row["version_id"] = row["id"]
					missing := value.NewID()
					row["record_id"] = missing
					switch kind {
					case "team_label":
						row["team_id"] = missing
					case "position_assignment":
						row["position_id"] = missing
					case "structure_change":
						row["change_id"] = missing
					}
					if err := grantSchemaInsert(x.f.Repo, "organizational_payload", row); err == nil {
						t.Fatal("a well-formed context with nonexistent typed owner must fail its deferred FK")
					}
				})
			}
		})
	}
}

func TestStructureV5ExactRelationActorAndTeamScopeConstraints(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := structureSchemaSeed(t, backend)
			member := x.membership()
			if err := grantSchemaInsert(x.f.Repo, "team_membership", member); err != nil {
				t.Fatal(err)
			}
			if err := grantSchemaInsert(x.f.Repo, "subject_employee", map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "employee_id": x.employee}); err != nil {
				t.Fatal(err)
			}
			base := grantSchemaGrant(x.f, x.f.Owner.SubjectID)
			base["scope_kind"], base["scope_id"], base["team_id"], base["relation_bound"], base["relation_kind"], base["membership_id"], base["relation_actor_employee_id"] = "team", x.team, x.team, true, "team_membership", member["id"], x.employee
			if err := grantSchemaInsert(x.f.Repo, "access_grant", base); err != nil {
				t.Fatal("exact approved subject+member+team binding must persist", err)
			}
			for _, test := range []struct {
				name    string
				mutate  func(map[string]any)
				foreign bool
			}{
				{"wrong_team", func(v map[string]any) { v["team_id"], v["scope_id"] = x.secondTeam, x.secondTeam }, true},
				{"unapproved_actor", func(v map[string]any) { v["relation_actor_employee_id"] = x.manager }, true},
				{"missing_relation", func(v map[string]any) { v["membership_id"] = value.NewID() }, true},
				{"foreign_scope", func(v map[string]any) { id := value.NewID(); v["team_id"], v["scope_id"] = id, id }, true},
				{"unbound_columns", func(v map[string]any) { v["relation_bound"] = false }, false},
				{"missing_kind", func(v map[string]any) { v["relation_kind"] = nil }, false},
				{"irrelevant_reporting_ref", func(v map[string]any) { v["reporting_line_id"] = value.NewID() }, false},
				{"mixed_scope_owner", func(v map[string]any) { v["employee_id"] = x.employee }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.mutate(row)
					err := grantSchemaInsert(x.f.Repo, "access_grant", row)
					if test.foreign {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "capability_assignment", map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "capability": "organization.read", "scope_kind": "team", "scope_id": x.team, "team_id": nil}))
			runtimeForeignKey(t, backend, grantSchemaInsert(x.f.Repo, "subject_employee", map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.OtherOwner.SubjectID, "employee_id": x.manager}))
		})
	}
}

func TestStructureV5TypedReceiptsRetainOriginalResultAndRejectPhysicalDrift(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := structureSchemaSeed(t, backend)
			for _, op := range []string{"OP-ORG-02", "OP-ORG-03"} {
				row := map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "operation": op, "key": value.NewID(), "digest": bytes.Repeat([]byte{92}, 32), "digest_key_version": 1, "result_json": `{"id":"` + x.team + `","graph_revision":"2","auth_epoch":"3"}`, "graph_revision": 2, "auth_epoch": 3, "result_team_id": nil, "result_change_id": nil}
				row["authority_targets_json"] = `[{"capability":"organization.write","category":"metadata","kind":"org","id":"` + x.f.OrgID + `"}]`
				if op == "OP-ORG-02" {
					row["result_team_id"] = x.team
				} else {
					row["result_change_id"] = x.change
					row["result_json"] = `{"id":"` + x.change + `","graph_revision":"2","auth_epoch":"3"}`
				}
				if err := grantSchemaInsert(x.f.Repo, "structure_command_receipt", row); err != nil {
					t.Fatal(err)
				}
				invalidTargets := grantSchemaClone(row)
				invalidTargets["key"], invalidTargets["authority_targets_json"] = value.NewID(), `{}`
				migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "structure_command_receipt", invalidTargets))
				bad := grantSchemaClone(row)
				bad["key"] = value.NewID()
				if op == "OP-ORG-02" {
					bad["result_change_id"] = x.change
				} else {
					bad["result_team_id"] = x.team
				}
				migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "structure_command_receipt", bad))
				bad = grantSchemaClone(row)
				bad["key"] = value.NewID()
				if op == "OP-ORG-02" {
					bad["result_team_id"] = value.NewID()
				} else {
					bad["result_change_id"] = value.NewID()
				}
				runtimeForeignKey(t, backend, grantSchemaInsert(x.f.Repo, "structure_command_receipt", bad))
			}
			if err := x.f.Exec(context.Background(), "UPDATE organization SET graph_revision=8 WHERE id=?", "UPDATE organization SET graph_revision=8 WHERE id=$1", x.f.OrgID); err != nil {
				t.Fatal(err)
			}
			if err := x.f.Exec(context.Background(), "UPDATE authorization_guard SET auth_epoch=9 WHERE org_id=?", "UPDATE authorization_guard SET auth_epoch=9 WHERE org_id=$1", x.f.OrgID); err != nil {
				t.Fatal(err)
			}
			var originals int
			if err := x.f.Repo.DB.QueryRow("SELECT count(*) FROM structure_command_receipt WHERE graph_revision=2 AND auth_epoch=3").Scan(&originals); err != nil || originals != 2 {
				t.Fatal("receipt must retain committed result, never recompute current epochs", err)
			}
			_, err := x.f.Repo.DB.Exec("UPDATE structure_command_receipt SET graph_revision=8")
			structureImmutableConstraint(t, backend, err)
			if err = x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal("new schema reflection must match full immutable/typed DDL", err)
			}
			if _, err = x.f.Repo.DB.Exec("DROP INDEX grant_membership"); err != nil {
				t.Fatal(err)
			}
			runtimeUnavailable(t, x.f.Repo.CheckSchema(context.Background()))
			runtimeUnavailable(t, x.f.Repo.Migrate(context.Background()))
		})
	}
}

func TestStructureV5NativeAuditApprovedEmployeeAndLifecycleFactOwnership(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := structureSchemaSeed(t, backend)
			digest := bytes.Repeat([]byte{103}, 32)
			if err := grantSchemaInsert(x.f.Repo, "subject_employee", map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "employee_id": x.employee}); err != nil {
				t.Fatal(err)
			}
			if err := grantSchemaInsert(x.f.Repo, "subject_identity", map[string]any{"digest": digest, "key_version": 1, "org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "active": true}); err != nil {
				t.Fatal(err)
			}
			native := map[string]any{"id": value.NewID(), "org_id": x.f.OrgID, "operation": "AUTH-BIND", "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": x.f.Repo.BindTime(x.f.Now), "actor_kind": "local_maintenance", "actor_uid": int64(1234), "actor_host_hash": bytes.Repeat([]byte{104}, 32), "target_subject_id": x.f.Owner.SubjectID, "identity_digest": digest, "target_employee_id": x.employee}
			if err := grantSchemaInsert(x.f.Repo, "audit_event", native); err != nil {
				t.Fatal("native actor and exact approved employee target are distinct real references", err)
			}
			for _, employee := range []string{x.manager, x.foreign} {
				row := grantSchemaClone(native)
				row["id"], row["request_id"], row["target_employee_id"] = value.NewID(), value.NewID(), employee
				runtimeForeignKey(t, backend, grantSchemaInsert(x.f.Repo, "audit_event", row))
			}
			row := grantSchemaClone(native)
			row["id"], row["actor_kind"], row["operation"] = "invalid-"+value.NewID(), "application", "OP-ORG-04"
			migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "audit_event", row))
			for _, operation := range []string{"OP-ORG-01", "OP-ORG-02", "OP-ORG-03", "OP-ORG-04", "OP-ORG-07"} {
				allowed := map[string]any{"id": value.NewID(), "org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "operation": operation, "purpose": "organization_management", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": x.f.Repo.BindTime(x.f.Now)}
				if err := grantSchemaInsert(x.f.Repo, "audit_event", allowed); err != nil {
					t.Fatal("real structure operations require application audit allowlist", err)
				}
			}
			parent := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "child_team_id": x.team, "parent_team_id": x.team, "valid_from": "2026-01-01", "change_id": x.change}
			migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "team_parent_history", parent))
			report := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "manager_employee_id": x.employee, "kind": "administrative", "valid_from": "2026-01-01", "change_id": x.change}
			migrationConstraint(t, backend, grantSchemaInsert(x.f.Repo, "reporting_line", report))
			report["id"], report["manager_employee_id"] = value.NewID(), x.foreign
			runtimeForeignKey(t, backend, grantSchemaInsert(x.f.Repo, "reporting_line", report))
			fact := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "valid_from": "2027-01-01", "change_id": x.change, "supersedes_id": x.employee}
			if err := grantSchemaInsert(x.f.Repo, "employee_lifecycle_history", fact); err != nil {
				t.Fatal("same-owner lifecycle correction must preserve original chain", err)
			}
			wrong := grantSchemaClone(fact)
			wrong["id"], wrong["employee_id"] = value.NewID(), x.manager
			runtimeForeignKey(t, backend, grantSchemaInsert(x.f.Repo, "employee_lifecycle_history", wrong))
			_, err := x.f.Repo.DB.Exec("UPDATE employee_lifecycle_history SET valid_from='2028-01-01'")
			structureImmutableConstraint(t, backend, err)
		})
	}
}
