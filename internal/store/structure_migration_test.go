package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func structureOriginalFacts(t *testing.T, repo *store.Repository) map[string][][]any {
	t.Helper()
	facts := runtimeFacts(t, context.Background(), repo)
	for _, table := range []string{"subject_identity", "session_auth", "oidc_transaction"} {
		columns := runtimeTableProjection(t, context.Background(), repo, table)
		rows, err := repo.DB.QueryContext(context.Background(), "SELECT "+columns+" FROM "+table+" ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		facts[table] = runtimeRows(t, rows)
	}
	return facts
}

func TestStructureV5ActualV4PreservesEncryptedHistoryApprovalReceiptSessionAndNativeAudit(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			ctx := context.Background()
			employee := migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V4_ORIGINAL"}, "")
			migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V4_CURRENT"}, employee.ID)
			for _, v := range []int{2, 3, 4} {
				migrationInstallVersion(t, f.Repo, v)
			}
			approver := grantSchemaSubject(t, f, f.OrgID)
			authority := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
			if err := grantSchemaInsert(f.Repo, "delegation_authority", authority); err != nil {
				t.Fatal(err)
			}
			grant := grantSchemaGrant(f, approver)
			grant["authority_id"], grant["issued_by"], grant["issued_at"] = authority["id"], f.Owner.SubjectID, f.Repo.BindTime(f.Now)
			if err := grantSchemaInsert(f.Repo, "access_grant", grant); err != nil {
				t.Fatal(err)
			}
			receipt := map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "operation": "OP-SEC-02", "key": value.NewID(), "digest": bytes.Repeat([]byte{55}, 32), "digest_key_version": 1, "result_id": grant["id"], "result_revision": 1, "result_status": "current", "result_auth_epoch": 1}
			if err := grantSchemaInsert(f.Repo, "grant_command_receipt", receipt); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("SYNTHETIC_V4_APPROVED_IDENTITY"))
			if err := grantSchemaInsert(f.Repo, "subject_identity", map[string]any{"digest": digest[:], "key_version": 1, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "active": true}); err != nil {
				t.Fatal(err)
			}
			if err := grantSchemaInsert(f.Repo, "session_auth", map[string]any{"token_hash": f.Owner.Hash, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "identity_digest": digest[:], "key_version": 1, "created_at": f.Repo.BindTime(f.Now), "auth_time": nil, "acr": "", "amr_json": "[]"}); err != nil {
				t.Fatal(err)
			}
			maintenance := map[string]any{"id": value.NewID(), "org_id": f.OrgID, "subject_id": nil, "employee_id": nil, "grant_id": nil, "operation": "AUTH-BIND", "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": f.Repo.BindTime(f.Now), "actor_kind": "local_maintenance", "actor_uid": int64(1234), "actor_host_hash": bytes.Repeat([]byte{71}, 32), "target_subject_id": f.Owner.SubjectID, "identity_digest": digest[:]}
			if err := grantSchemaInsert(f.Repo, "audit_event", maintenance); err != nil {
				t.Fatal(err)
			}
			before := structureOriginalFacts(t, f.Repo)
			delete(before, "schema_version")
			if err := f.Repo.Migrate(ctx); err != nil {
				t.Fatal("genuine populated v4 must upgrade:", err)
			}
			migrationOriginalUnchanged(t, before, structureOriginalFacts(t, f.Repo))
			migrationLedger(t, f.Repo)
			var count int
			if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM employee_lifecycle_history h JOIN employee e ON e.org_id=h.org_id AND e.id=h.employee_id WHERE h.id=e.id AND h.valid_from=e.valid_from AND (h.valid_to=e.valid_to OR (h.valid_to IS NULL AND e.valid_to IS NULL)) AND h.change_id IS NULL AND h.supersedes_id IS NULL").Scan(&count); err != nil || count != len(before["employee"]) {
				t.Fatal("v4 employees require exact immutable baseline dates without invented change/profile identity", err)
			}
			for _, table := range []string{"team", "structure_change", "structure_change_item", "subject_employee", "organizational_payload", "structure_command_receipt"} {
				if f.Count(t, table) != 0 {
					t.Fatal("upgrade must not invent new organization/approval/encrypted facts", table)
				}
			}
			view, err := f.Service.Read(ctx, f.Request(f.Owner), employee.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.LocalName != "SYNTHETIC_V4_CURRENT" || view.Revision != "2" {
				t.Fatal("old envelope AAD, head and current approved release must survive", err)
			}
			afterRelease := structureOriginalFacts(t, f.Repo)
			for range 2 {
				if err := f.Repo.Migrate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Repo.CheckSchema(ctx); err != nil {
				t.Fatal("complete v5 physical reflection must pass", err)
			}
			migrationOriginalUnchanged(t, afterRelease, structureOriginalFacts(t, f.Repo))
		})
	}
}

func TestStructureV5InterruptedAuthorizationCutoverRestoresExactV4(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V4_ROLLBACK"}, "")
			for _, v := range []int{2, 3, 4} {
				migrationInstallVersion(t, f.Repo, v)
			}
			before := structureOriginalFacts(t, f.Repo)
			tx, err := f.Repo.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, statement := range migrationSQL(t, backend, 5) {
				if _, err = tx.ExecContext(context.Background(), statement); err != nil {
					t.Fatal("real v5 cutover prefix must execute", err)
				}
				if statement == "DROP TABLE access_grant;" {
					break
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, before, structureOriginalFacts(t, f.Repo))
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("interrupted real cutover must remain recoverable", err)
			}
		})
	}
}

type structureSchemaFixture struct {
	f                                                    *testsupport.Fixture
	employee, manager, foreign, team, secondTeam, change string
}

func structureSchemaSeed(t *testing.T, backend string) structureSchemaFixture {
	t.Helper()
	f := migrationV1Fixture(t, backend)
	employee := migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_SCHEMA_EMPLOYEE"}, "").ID
	manager := migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_SCHEMA_MANAGER"}, "").ID
	if err := f.Repo.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreignResult, err := f.Service.Create(context.Background(), f.Request(f.OtherOwner), f.OtherOrgID, organization.CreateCommand{Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}, Profile: organization.Profile{LocalName: "SYNTHETIC_FOREIGN_EMPLOYEE"}})
	if err != nil {
		t.Fatal(err)
	}
	x := structureSchemaFixture{f: f, employee: employee, manager: manager, foreign: foreignResult.ID, team: value.NewID(), secondTeam: value.NewID(), change: value.NewID()}
	for i, id := range []string{x.team, x.secondTeam} {
		if err := grantSchemaInsert(f.Repo, "team", map[string]any{"org_id": f.OrgID, "id": id, "code": fmt.Sprintf("SYNTHETIC_%d", i), "valid_from": "2026-01-01", "valid_to": nil}); err != nil {
			t.Fatal(err)
		}
	}
	if err := grantSchemaInsert(f.Repo, "structure_change", x.changeRow(x.change)); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x structureSchemaFixture) changeRow(id string) map[string]any {
	return map[string]any{"org_id": x.f.OrgID, "id": id, "subject_id": x.f.Owner.SubjectID, "recorded_at": x.f.Repo.BindTime(x.f.Now), "graph_before": 1, "graph_after": 2}
}
func (x structureSchemaFixture) membership() map[string]any {
	return map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "team_id": x.team, "is_primary": true, "valid_from": "2026-01-01", "valid_to": "2028-01-01", "effective_to": nil, "superseded": false, "change_id": x.change, "end_change_id": nil, "supersedes_id": nil}
}

func TestStructureV5TypedDatesEndpointsAndImmutableTenure(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := structureSchemaSeed(t, backend)
			base := x.membership()
			for _, test := range []struct {
				name    string
				mutate  func(map[string]any)
				foreign bool
			}{
				{"foreign_employee", func(v map[string]any) { v["employee_id"] = x.foreign }, true},
				{"missing_team", func(v map[string]any) { v["team_id"] = value.NewID() }, true},
				{"reverse_dates", func(v map[string]any) { v["valid_to"] = "2025-12-31" }, false},
				{"invalid_calendar_day", func(v map[string]any) { v["valid_from"] = "2026-02-30" }, false},
				{"secondary_unapproved", func(v map[string]any) { v["is_primary"] = false }, false},
				{"projection_without_change", func(v map[string]any) { v["effective_to"] = "2027-01-01" }, false},
				{"projection_at_start", func(v map[string]any) { v["effective_to"], v["end_change_id"] = "2026-01-01", x.change }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.mutate(row)
					err := grantSchemaInsert(x.f.Repo, "team_membership", row)
					if test.foreign {
						runtimeForeignKey(t, backend, err)
					} else if err == nil {
						t.Fatal("invalid typed/date/state fact must fail")
					}
				})
			}
			if err := grantSchemaInsert(x.f.Repo, "team_membership", base); err != nil {
				t.Fatal(err)
			}
			later := x.membership()
			later["effective_to"], later["end_change_id"] = "2029-01-01", x.change
			if err := grantSchemaInsert(x.f.Repo, "team_membership", later); err != nil {
				t.Fatal("end projection may be after nominal end; actual end remains the minimum", err)
			}
			id := base["id"].(string)
			for _, field := range []string{"valid_from", "valid_to", "team_id", "change_id"} {
				query := "UPDATE team_membership SET " + field + "=? WHERE org_id=? AND id=?"
				if backend == "postgres" {
					query = "UPDATE team_membership SET " + field + "=$1 WHERE org_id=$2 AND id=$3"
				}
				v := "2027-01-01"
				if strings.HasSuffix(field, "_id") {
					v = x.secondTeam
				}
				_, err := x.f.Repo.DB.ExecContext(context.Background(), query, v, x.f.OrgID, id)
				structureImmutableConstraint(t, backend, err)
			}
			end := value.NewID()
			if err := grantSchemaInsert(x.f.Repo, "structure_change", x.changeRow(end)); err != nil {
				t.Fatal(err)
			}
			if err := x.f.Exec(context.Background(), "UPDATE team_membership SET effective_to=?,end_change_id=? WHERE org_id=? AND id=?", "UPDATE team_membership SET effective_to=$1,end_change_id=$2 WHERE org_id=$3 AND id=$4", "2027-01-01", end, x.f.OrgID, id); err != nil {
				t.Fatal("ending must update only projection", err)
			}
			item := map[string]any{"org_id": x.f.OrgID, "change_id": end, "ordinal": 0, "action": "end", "kind": "membership", "relation_id": id, "employee_id": x.employee, "team_id": x.team, "end_date": "2027-01-01"}
			if err := grantSchemaInsert(x.f.Repo, "structure_change_item", item); err != nil {
				t.Fatal(err)
			}
			var from, to, effective string
			query := "SELECT CAST(valid_from AS TEXT),CAST(valid_to AS TEXT),CAST(effective_to AS TEXT) FROM team_membership WHERE org_id=? AND id=?"
			if backend == "postgres" {
				query = "SELECT valid_from::text,valid_to::text,effective_to::text FROM team_membership WHERE org_id=$1 AND id=$2"
			}
			if err := x.f.Repo.DB.QueryRow(query, x.f.OrgID, id).Scan(&from, &to, &effective); err != nil || from != "2026-01-01" || to != "2028-01-01" || effective != "2027-01-01" {
				t.Fatal("nominal original dates must remain exact", err)
			}
			for _, table := range []string{"team_membership", "structure_change", "structure_change_item", "employee_lifecycle_history"} {
				_, err := x.f.Repo.DB.Exec("DELETE FROM " + table)
				structureImmutableConstraint(t, backend, err)
			}
		})
	}
}
