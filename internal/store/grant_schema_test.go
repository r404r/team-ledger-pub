package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"modernc.org/sqlite"
)

func TestGrantSchemaFullConstraintIdentityRejectsMissingProfileOwner(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	ctx := context.Background()
	var name string
	err := f.Repo.DB.QueryRowContext(ctx, "SELECT conname::text FROM pg_constraint WHERE conrelid='employee_profile_version'::regclass AND contype='f' AND conkey=ARRAY[1,2]::smallint[] AND confrelid='employee'::regclass").Scan(&name)
	if err != nil {
		t.Fatal("expected canonical profile ownership constraint unavailable:", err)
	}
	if _, err = f.Repo.DB.ExecContext(ctx, `ALTER TABLE employee_profile_version DROP CONSTRAINT "`+strings.ReplaceAll(name, `"`, `""`)+`"`); err != nil {
		t.Fatal("isolated missing ownership constraint setup failed:", err)
	}
	if err = f.Repo.CheckSchema(ctx); !errors.Is(err, fault.Unavailable) {
		t.Fatal("missing profile owner FK must refuse startup even when long constraint names share a prefix:", err)
	}
}

func TestGrantSchemaAuthorityOwnersFiniteValuesAndImmutability(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			local := runtimeCreate(t, context.Background(), f, f.Owner, f.OrgID, "SYNTHETIC_AUTHORITY_LOCAL")
			foreign := runtimeCreate(t, context.Background(), f, f.OtherOwner, f.OtherOrgID, "SYNTHETIC_AUTHORITY_FOREIGN")
			approver := grantSchemaSubject(t, f, f.OrgID)
			base := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
			base["scope_kind"], base["scope_id"], base["employee_id"] = "employee", local.ID, local.ID
			if err := grantSchemaInsert(f.Repo, "delegation_authority", base); err != nil {
				t.Fatal("same-owner approved employee authority must persist:", err)
			}
			before := runtimeFacts(t, context.Background(), f.Repo)
			for _, test := range []struct {
				name   string
				change func(map[string]any)
				owner  bool
			}{
				{"foreign_manager", func(v map[string]any) { v["manager_subject_id"] = f.OtherOwner.SubjectID }, true},
				{"foreign_approver", func(v map[string]any) { v["approved_by"] = f.OtherOwner.SubjectID }, true},
				{"foreign_employee", func(v map[string]any) { v["scope_id"], v["employee_id"] = foreign.ID, foreign.ID }, true},
				{"self_approval", func(v map[string]any) { v["approved_by"] = f.Owner.SubjectID }, false},
				{"management_capability", func(v map[string]any) { v["capability"] = "access_grant.manage" }, false},
				{"unknown_capability", func(v map[string]any) { v["capability"] = "SYNTHETIC.extra" }, false},
				{"wrong_category", func(v map[string]any) { v["category"] = "metadata" }, false},
				{"wrong_purpose", func(v map[string]any) { v["purpose"] = "security_administration" }, false},
				{"unsupported_scope", func(v map[string]any) { v["scope_kind"] = "team" }, false},
				{"foreign_org_scope", func(v map[string]any) { v["scope_kind"], v["scope_id"], v["employee_id"] = "org", f.OtherOrgID, nil }, false},
				{"scope_employee_mismatch", func(v map[string]any) { v["scope_id"] = value.NewID() }, false},
				{"empty_interval", func(v map[string]any) { v["expires_at"] = v["valid_from"] }, false},
				{"approval_after_validity", func(v map[string]any) { v["approved_at"] = f.Repo.BindTime(f.Now) }, false},
				{"empty_policy", func(v map[string]any) { v["policy_version"] = "" }, false},
				{"oversized_policy", func(v map[string]any) { v["policy_version"] = strings.Repeat("x", 129) }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.change(row)
					err := grantSchemaInsert(f.Repo, "delegation_authority", row)
					if test.owner {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			for _, query := range []string{"UPDATE delegation_authority SET policy_version='SYNTHETIC_CHANGED'", "DELETE FROM delegation_authority"} {
				_, err := f.Repo.DB.ExecContext(context.Background(), query)
				if backend == "sqlite" {
					var e *sqlite.Error
					if !errors.As(err, &e) || e.Code() != 1811 {
						t.Fatal("SQLite must reject immutable approved authority changes:", err)
					}
				} else {
					migrationConstraint(t, backend, err)
				}
			}
			runtimeUnchanged(t, before, runtimeFacts(t, context.Background(), f.Repo))
			if err := f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal("rejected authority writes must preserve the exact schema:", err)
			}
		})
	}
}

func TestDepartmentAuthorizationScopesRejectNonDepartmentUnits(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			unit, approver, target := value.NewID(), grantSchemaSubject(t, f, f.OrgID), grantSchemaSubject(t, f, f.OrgID)
			if err := f.Exec(ctx,
				"INSERT INTO org_unit(org_id,id,code,kind) VALUES(?,?,?,'division')",
				"INSERT INTO org_unit(org_id,id,code,kind) VALUES($1,$2,$3,'division')",
				f.OrgID, unit, "SYNTHETIC-NON-DEPARTMENT"); err != nil {
				t.Fatal(err)
			}
			authority := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
			authority["scope_kind"], authority["scope_id"], authority["employee_id"], authority["department_id"] = "department", unit, nil, unit
			migrationConstraint(t, backend, grantSchemaInsert(f.Repo, "delegation_authority", authority))

			assignment := map[string]any{"org_id": f.OrgID, "subject_id": target, "capability": "pii.read", "scope_kind": "department", "scope_id": unit, "department_id": unit}
			migrationConstraint(t, backend, grantSchemaInsert(f.Repo, "capability_assignment", assignment))

			grant := grantSchemaGrant(f, target)
			grant["scope_kind"], grant["scope_id"], grant["employee_id"], grant["department_id"] = "department", unit, nil, unit
			migrationConstraint(t, backend, grantSchemaInsert(f.Repo, "access_grant", grant))
			var err error
			if backend == "sqlite" {
				_, err = f.Repo.DB.ExecContext(ctx, "UPDATE capability_assignment SET scope_kind='department',scope_id=?,employee_id=NULL,department_id=? WHERE org_id=? AND subject_id=? AND capability='organization.read'", unit, unit, f.OrgID, f.Owner.SubjectID)
			} else {
				_, err = f.Repo.DB.ExecContext(ctx, "UPDATE capability_assignment SET scope_kind='department',scope_id=$1,employee_id=NULL,department_id=$2 WHERE org_id=$3 AND subject_id=$4 AND capability='organization.read'", unit, unit, f.OrgID, f.Owner.SubjectID)
			}
			migrationConstraint(t, backend, err)
		})
	}
}

func TestGrantSchemaSourceActorsRevisionRevocationAndManagement(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			approver, target := grantSchemaSubject(t, f, f.OrgID), grantSchemaSubject(t, f, f.OrgID)
			authority := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
			foreignAuthority := grantSchemaAuthority(f, f.OtherOrgID, f.OtherOwner.SubjectID, grantSchemaSubject(t, f, f.OtherOrgID))
			for _, row := range []map[string]any{authority, foreignAuthority} {
				if err := grantSchemaInsert(f.Repo, "delegation_authority", row); err != nil {
					t.Fatal(err)
				}
			}
			base := grantSchemaGrant(f, target)
			base["authority_id"], base["issued_by"], base["issued_at"] = authority["id"], f.Owner.SubjectID, f.Repo.BindTime(f.Now)
			if err := grantSchemaInsert(f.Repo, "access_grant", base); err != nil {
				t.Fatal("complete same-owner source grant must persist:", err)
			}
			before := runtimeFacts(t, context.Background(), f.Repo)
			for _, test := range []struct {
				name   string
				change func(map[string]any)
				owner  bool
			}{
				{"foreign_source", func(v map[string]any) { v["authority_id"] = foreignAuthority["id"] }, true},
				{"foreign_issuer", func(v map[string]any) { v["issued_by"] = f.OtherOwner.SubjectID }, true},
				{"wrong_authority_manager", func(v map[string]any) { v["issued_by"] = approver }, true},
				{"wrong_authority_capability", func(v map[string]any) { v["capability"] = "pii.write" }, true},
				{"wrong_authority_category", func(v map[string]any) { v["capability"], v["category"] = "organization.read", "metadata" }, true},
				{"foreign_revoker", func(v map[string]any) {
					v["revoked"], v["revoked_by"], v["revoked_at"], v["revoke_reason"] = true, f.OtherOwner.SubjectID, f.Repo.BindTime(f.Now), "policy_change"
				}, true},
				{"known_revoked_without_facts", func(v map[string]any) { v["revoked"] = true }, false},
				{"missing_source", func(v map[string]any) { v["authority_id"] = nil }, false},
				{"missing_issuer", func(v map[string]any) { v["issued_by"] = nil }, false},
				{"missing_issue_time", func(v map[string]any) { v["issued_at"] = nil }, false},
				{"self_issue", func(v map[string]any) { v["issued_by"] = target }, false},
				{"zero_revision", func(v map[string]any) { v["revision"] = int64(0) }, false},
				{"negative_revision", func(v map[string]any) { v["revision"] = int64(-1) }, false},
				{"partial_revocation", func(v map[string]any) { v["revoked"], v["revoked_by"] = true, f.Owner.SubjectID }, false},
				{"unknown_reason", func(v map[string]any) {
					v["revoked"], v["revoked_by"], v["revoked_at"], v["revoke_reason"] = true, f.Owner.SubjectID, f.Repo.BindTime(f.Now), "SYNTHETIC.free_text"
				}, false},
				{"facts_without_revoked", func(v map[string]any) {
					v["revoked_by"], v["revoked_at"], v["revoke_reason"] = f.Owner.SubjectID, f.Repo.BindTime(f.Now), "policy_change"
				}, false},
				{"revoke_before_issue", func(v map[string]any) {
					v["revoked"], v["revoked_by"], v["revoked_at"], v["revoke_reason"] = true, f.Owner.SubjectID, f.Repo.BindTime(f.Now.Add(-time.Second)), "policy_change"
				}, false},
				{"wrong_capability_category", func(v map[string]any) { v["category"] = "metadata" }, false},
				{"business_security_purpose", func(v map[string]any) { v["purpose"] = "security_administration" }, false},
				{"management_wrong_category", func(v map[string]any) {
					v["capability"], v["category"], v["purpose"] = "access_grant.manage", "metadata", "security_administration"
				}, false},
				{"management_business_purpose", func(v map[string]any) { v["capability"], v["category"] = "access_grant.manage", "audit" }, false},
				{"management_delegation", func(v map[string]any) {
					v["capability"], v["category"], v["purpose"] = "access_grant.manage", "audit", "security_administration"
				}, false},
				{"relation_binding", func(v map[string]any) { v["relation_bound"] = true }, false},
				{"empty_interval", func(v map[string]any) { v["expires_at"] = v["valid_from"] }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.change(row)
					err := grantSchemaInsert(f.Repo, "access_grant", row)
					if test.owner {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			runtimeUnchanged(t, before, runtimeFacts(t, context.Background(), f.Repo))
			for _, reason := range []string{"access_no_longer_required", "policy_change", "incorrect_grant"} {
				row := grantSchemaClone(base)
				row["id"], row["revoked"], row["revoked_by"], row["revoked_at"], row["revoke_reason"] = value.NewID(), true, f.Owner.SubjectID, f.Repo.BindTime(f.Now), reason
				if err := grantSchemaInsert(f.Repo, "access_grant", row); err != nil {
					t.Fatal("complete finite revocation facts must persist:", err)
				}
			}
			management := grantSchemaGrant(f, f.Owner.SubjectID)
			management["capability"], management["category"], management["purpose"] = "access_grant.manage", "audit", "security_administration"
			if err := grantSchemaInsert(f.Repo, "access_grant", management); err != nil {
				t.Fatal("controlled independent manager bootstrap must be representable:", err)
			}
			if err := grantSchemaInsert(f.Repo, "capability_assignment", map[string]any{"org_id": f.OrgID, "subject_id": target, "capability": "access_grant.manage", "scope_kind": "org", "scope_id": f.OrgID}); err != nil {
				t.Fatal("management assignment enum must be supported:", err)
			}
			local := runtimeCreate(t, context.Background(), f, f.Owner, f.OrgID, "SYNTHETIC_MANAGEMENT_EMPLOYEE")
			employeeManagement := grantSchemaClone(management)
			employeeManagement["id"], employeeManagement["scope_kind"], employeeManagement["scope_id"], employeeManagement["employee_id"] = value.NewID(), "employee", local.ID, local.ID
			if err := grantSchemaInsert(f.Repo, "access_grant", employeeManagement); err != nil {
				t.Fatal("independent employee management grant must be representable:", err)
			}
			if err := grantSchemaInsert(f.Repo, "capability_assignment", map[string]any{"org_id": f.OrgID, "subject_id": target, "capability": "access_grant.manage", "scope_kind": "employee", "scope_id": local.ID, "employee_id": local.ID}); err != nil {
				t.Fatal("employee management assignment must retain ownership constraints:", err)
			}
			legacy := grantSchemaGrant(f, target)
			legacy["revoked"] = true
			if err := grantSchemaInsert(f.Repo, "access_grant", legacy); err != nil {
				t.Fatal("legacy revoked grants with unknown facts must remain valid:", err)
			}
		})
	}
}

func TestGrantSchemaCommandReceiptOwnersAndFiniteResults(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			localGrant, foreignGrant := grantSchemaGrant(f, f.Owner.SubjectID), grantSchemaGrant(f, f.OtherOwner.SubjectID)
			foreignGrant["org_id"], foreignGrant["scope_id"] = f.OtherOrgID, f.OtherOrgID
			for _, row := range []map[string]any{localGrant, foreignGrant} {
				if err := grantSchemaInsert(f.Repo, "access_grant", row); err != nil {
					t.Fatal(err)
				}
			}
			base := map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "operation": "OP-SEC-02", "key": value.NewID(), "digest": bytes.Repeat([]byte{3}, 32), "digest_key_version": 1, "result_id": localGrant["id"], "result_revision": int64(1), "result_status": "current", "result_auth_epoch": int64(1)}
			if err := grantSchemaInsert(f.Repo, "grant_command_receipt", base); err != nil {
				t.Fatal("same-owner typed grant receipt must persist:", err)
			}
			before := runtimeFacts(t, context.Background(), f.Repo)
			for _, test := range []struct {
				name   string
				change func(map[string]any)
				owner  bool
			}{
				{"foreign_actor", func(v map[string]any) { v["subject_id"] = f.OtherOwner.SubjectID }, true},
				{"foreign_result", func(v map[string]any) { v["result_id"] = foreignGrant["id"] }, true},
				{"employee_as_grant", func(v map[string]any) { v["result_id"] = value.NewID() }, true},
				{"profile_operation", func(v map[string]any) { v["operation"] = "OP-ORG-05" }, false},
				{"short_digest", func(v map[string]any) { v["digest"] = []byte{1} }, false},
				{"unsupported_digest_key", func(v map[string]any) { v["digest_key_version"] = 2 }, false},
				{"zero_revision", func(v map[string]any) { v["result_revision"] = int64(0) }, false},
				{"zero_epoch", func(v map[string]any) { v["result_auth_epoch"] = int64(0) }, false},
				{"unknown_status", func(v map[string]any) { v["result_status"] = "SYNTHETIC.unknown" }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["key"] = value.NewID()
					test.change(row)
					err := grantSchemaInsert(f.Repo, "grant_command_receipt", row)
					if test.owner {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			runtimeUnchanged(t, before, runtimeFacts(t, context.Background(), f.Repo))
			for _, status := range []string{"current", "future", "expired", "revoked"} {
				row := grantSchemaClone(base)
				row["operation"], row["key"], row["result_status"] = "OP-SEC-03", value.NewID(), status
				if err := grantSchemaInsert(f.Repo, "grant_command_receipt", row); err != nil {
					t.Fatal("each supported typed result must persist:", err)
				}
			}
		})
	}
}

func TestGrantSchemaSecurityAuditTypedOwnerAndFiniteValues(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			localGrant, foreignGrant := grantSchemaGrant(f, f.Owner.SubjectID), grantSchemaGrant(f, f.OtherOwner.SubjectID)
			foreignGrant["org_id"], foreignGrant["scope_id"] = f.OtherOrgID, f.OtherOrgID
			for _, row := range []map[string]any{localGrant, foreignGrant} {
				if err := grantSchemaInsert(f.Repo, "access_grant", row); err != nil {
					t.Fatal(err)
				}
			}
			base := map[string]any{"id": value.NewID(), "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "employee_id": nil, "grant_id": localGrant["id"], "operation": "OP-SEC-02", "purpose": "security_administration", "request_id": value.NewID(), "outcome": "allowed", "recorded_at": f.Repo.BindTime(f.Now)}
			for _, operation := range []string{"OP-SEC-02", "OP-SEC-03", "OP-SEC-06"} {
				row := grantSchemaClone(base)
				row["id"], row["operation"] = value.NewID(), operation
				if err := grantSchemaInsert(f.Repo, "audit_event", row); err != nil {
					t.Fatal("allowed management audit must retain the typed grant object:", err)
				}
			}
			before := runtimeFacts(t, context.Background(), f.Repo)
			for _, test := range []struct {
				name   string
				change func(map[string]any)
				owner  bool
			}{
				{"foreign_grant", func(v map[string]any) { v["grant_id"] = foreignGrant["id"] }, true},
				{"missing_grant", func(v map[string]any) { v["grant_id"] = value.NewID() }, true},
				{"unowned_grant", func(v map[string]any) { v["org_id"], v["subject_id"] = nil, nil }, false},
				{"denied_disclosure", func(v map[string]any) { v["outcome"] = "denied" }, false},
				{"unknown_operation", func(v map[string]any) { v["operation"] = "SYNTHETIC.extra" }, false},
				{"unknown_purpose", func(v map[string]any) { v["purpose"] = "SYNTHETIC.extra" }, false},
				{"unknown_outcome", func(v map[string]any) { v["outcome"] = "SYNTHETIC.extra" }, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					row := grantSchemaClone(base)
					row["id"] = value.NewID()
					test.change(row)
					err := grantSchemaInsert(f.Repo, "audit_event", row)
					if test.owner {
						runtimeForeignKey(t, backend, err)
					} else {
						migrationConstraint(t, backend, err)
					}
				})
			}
			runtimeUnchanged(t, before, runtimeFacts(t, context.Background(), f.Repo))
			denied := grantSchemaClone(base)
			denied["id"], denied["grant_id"], denied["outcome"] = value.NewID(), nil, "denied"
			if err := grantSchemaInsert(f.Repo, "audit_event", denied); err != nil {
				t.Fatal("denied management audits must remain object-neutral:", err)
			}
		})
	}
}

func grantSchemaSubject(t *testing.T, f *testsupport.Fixture, org string) string {
	t.Helper()
	id := value.NewID()
	if err := f.Exec(context.Background(), "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)", org, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func grantSchemaAuthority(f *testsupport.Fixture, org, manager, approver string) map[string]any {
	return map[string]any{"id": value.NewID(), "org_id": org, "manager_subject_id": manager, "capability": "pii.read", "category": "pii", "scope_kind": "org", "scope_id": org, "employee_id": nil, "purpose": "organization_management", "valid_from": f.Repo.BindTime(f.Now.Add(-time.Hour)), "expires_at": f.Repo.BindTime(f.Now.Add(time.Hour)), "mfa_required": true, "approved_by": approver, "approved_at": f.Repo.BindTime(f.Now.Add(-2 * time.Hour)), "policy_version": "synthetic-policy-1"}
}

func grantSchemaGrant(f *testsupport.Fixture, subject string) map[string]any {
	return map[string]any{"id": value.NewID(), "org_id": f.OrgID, "subject_id": subject, "capability": "pii.read", "category": "pii", "scope_kind": "org", "scope_id": f.OrgID, "employee_id": nil, "purpose": "organization_management", "valid_from": f.Repo.BindTime(f.Now.Add(-time.Hour)), "expires_at": f.Repo.BindTime(f.Now.Add(time.Hour)), "mfa_required": false, "relation_bound": false, "revoked": false, "revision": int64(1), "authority_id": nil, "issued_by": nil, "issued_at": nil, "revoked_by": nil, "revoked_at": nil, "revoke_reason": nil}
}

func grantSchemaClone(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func grantSchemaInsert(repo *store.Repository, table string, values map[string]any) error {
	columns, placeholders, arguments := make([]string, 0, len(values)), make([]string, 0, len(values)), make([]any, 0, len(values))
	for key, value := range values {
		columns = append(columns, key)
		placeholder := "?"
		if repo.Backend == "postgres" {
			placeholder = fmt.Sprintf("$%d", len(arguments)+1)
		}
		placeholders = append(placeholders, placeholder)
		arguments = append(arguments, value)
	}
	_, err := repo.DB.ExecContext(context.Background(), "INSERT INTO "+table+"("+strings.Join(columns, ",")+") VALUES("+strings.Join(placeholders, ",")+")", arguments...)
	return err
}

func migrationConstraint(t *testing.T, backend string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted a row that violates the v12 schema", backend)
	}
}
