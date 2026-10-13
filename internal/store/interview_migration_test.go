package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

// Snapshot actual relations, not a hard-coded old table list: every v5 column,
// encrypted envelope, native approval, receipt and historical fact must survive.
func interviewMigrationFacts(t *testing.T, repo *store.Repository) map[string][][]any {
	t.Helper()
	query := "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
	if repo.Backend == "postgres" {
		query = "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind='r' ORDER BY c.relname"
	}
	rows, err := repo.DB.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	facts := make(map[string][][]any, len(tables))
	for _, table := range tables {
		columns := runtimeTableProjection(t, context.Background(), repo, table)
		rows, err = repo.DB.QueryContext(context.Background(), "SELECT "+columns+" FROM "+table+" ORDER BY "+columns)
		if err != nil {
			t.Fatal(err)
		}
		facts[table] = runtimeRows(t, rows)
	}
	return facts
}

func TestInterviewV6PopulatedV5PreservesAllOriginalColumnsAndDecryptableHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			employee := migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V5_ORIGINAL"}, "")
			migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V5_CURRENT"}, employee.ID)
			for _, version := range []int{2, 3, 4, 5} {
				migrationInstallVersion(t, f.Repo, version)
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
			if err := grantSchemaInsert(f.Repo, "grant_command_receipt", map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "operation": "OP-SEC-02", "key": value.NewID(), "digest": bytes.Repeat([]byte{17}, 32), "digest_key_version": 1, "result_id": grant["id"], "result_revision": 1, "result_status": "current", "result_auth_epoch": 1}); err != nil {
				t.Fatal(err)
			}
			before := interviewMigrationFacts(t, f.Repo)
			ledger := before["schema_version"]
			delete(before, "schema_version")
			migrationInstallVersion(t, f.Repo, 6)
			after := interviewMigrationFacts(t, f.Repo)
			migrationOriginalUnchanged(t, before, after)
			if len(after["schema_version"]) != len(ledger)+1 {
				t.Fatal("one new migration ledger entry required")
			}
			runtimeUnchanged(t, map[string][][]any{"schema_version": ledger}, map[string][][]any{"schema_version": after["schema_version"][:len(ledger)]})
			for _, table := range []string{"interview", "interview_event", "interview_participant", "note_head", "note_version", "action_item", "action_item_event", "interview_payload", "source_reference", "interview_receipt", "access_grant_source_approval"} {
				if f.Count(t, table) != 0 {
					t.Fatal("migration must not invent interview facts", table)
				}
			}
			// Verify the historical v6 cutover above, then advance to the current
			// reader schema before exercising today's service and startup checks.
			if err := f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("preserved historical v6 must advance to current schema", err)
			}
			view, err := f.Service.Read(context.Background(), f.Request(f.Owner), employee.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.LocalName != "SYNTHETIC_V5_CURRENT" || view.Revision != "2" {
				t.Fatal("original AAD and history must remain readable", err)
			}
			if err = f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
			stable := interviewMigrationFacts(t, f.Repo)
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, stable, interviewMigrationFacts(t, f.Repo))
		})
	}
}

func TestInterviewV6InterruptedCutoverRestoresPopulatedV5(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			migrationV1Profile(t, f, organization.Profile{LocalName: "SYNTHETIC_V5_ROLLBACK"}, "")
			for _, version := range []int{2, 3, 4, 5} {
				migrationInstallVersion(t, f.Repo, version)
			}
			before := interviewMigrationFacts(t, f.Repo)
			tx, err := f.Repo.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, statement := range migrationSQL(t, backend, 6) {
				if _, err = tx.ExecContext(context.Background(), statement); err != nil {
					t.Fatal("real cutover prefix must execute", err)
				}
				if statement == "DROP TABLE access_grant;" || strings.HasPrefix(statement, "ALTER TABLE access_grant ADD COLUMN object_kind") {
					break
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, f.Repo))
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("rolled-back migration remains recoverable", err)
			}
		})
	}
}

// Native schema fixtures use bounded synthetic envelope bytes solely to exercise
// SQL ownership/shape constraints. Actual cipher behavior is tested by the domain.
type interviewSchemaFixture struct {
	f                                                                   *testsupport.Fixture
	employee, otherEmployee, foreignEmployee, interview, otherInterview string
	head, version, privateHead, privateVersion, draftHead, draftVersion string
	action, event, actionPayload                                        string
}

func interviewSchemaInsertTx(tx *sql.Tx, backend, table string, row map[string]any) error {
	columns, placeholders, args := make([]string, 0, len(row)), make([]string, 0, len(row)), make([]any, 0, len(row))
	for col, v := range row {
		columns = append(columns, col)
		placeholder := "?"
		if backend == "postgres" {
			placeholder = fmt.Sprintf("$%d", len(args)+1)
		}
		placeholders, args = append(placeholders, placeholder), append(args, v)
	}
	_, err := tx.ExecContext(context.Background(), "INSERT INTO "+table+"("+strings.Join(columns, ",")+") VALUES("+strings.Join(placeholders, ",")+")", args...)
	return err
}

func (x interviewSchemaFixture) payload(id, kind, record, version string) map[string]any {
	schema := "interview.note.v1"
	if kind == "interview_action" {
		schema = "interview.action.v1"
	}
	if kind == "interview_reason" {
		schema = "interview.reason.v1"
	}
	return map[string]any{"org_id": x.f.OrgID, "id": id, "employee_id": x.employee, "record_id": record, "version_id": version, "object_kind": kind, "purpose": "interview", "schema_type": schema, "schema_version": 1, "format_version": 1, "algorithm": "A256GCM-RANDOMNONCE", "dek_id": value.NewID(), "kek_id": "synthetic-interview-key", "kek_version": 1, "wrapped_dek": []byte{1}, "sealed_bytes": bytes.Repeat([]byte{7}, 28), "created_at": x.f.Repo.BindTime(x.f.Now)}
}

func (x interviewSchemaFixture) noteRows(head, version, category, status string, number int) (map[string]any, map[string]any) {
	v := map[string]any{"org_id": x.f.OrgID, "id": version, "employee_id": x.employee, "head_id": head, "interview_id": x.interview, "category": category, "version_no": number, "status": status, "payload_id": version, "author_subject_id": x.f.Owner.SubjectID, "recorded_at": x.f.Repo.BindTime(x.f.Now), "content_digest": bytes.Repeat([]byte{11}, 32), "source_epoch": 1}
	p := x.payload(version, "interview_note_"+category, head, version)
	p["head_id"], p["note_version_id"], p["category"] = head, version, category
	return v, p
}

func interviewSchemaSeed(t *testing.T, backend string) interviewSchemaFixture {
	t.Helper()
	f := testsupport.NewHarness(t, backend)
	x := interviewSchemaFixture{f: f, employee: runtimeCreate(t, context.Background(), f, f.Owner, f.OrgID, "SYNTHETIC_INTERVIEW_EMPLOYEE").ID, otherEmployee: runtimeCreate(t, context.Background(), f, f.Owner, f.OrgID, "SYNTHETIC_SECOND_EMPLOYEE").ID, foreignEmployee: runtimeCreate(t, context.Background(), f, f.OtherOwner, f.OtherOrgID, "SYNTHETIC_FOREIGN_EMPLOYEE").ID, interview: value.NewID(), otherInterview: value.NewID(), head: value.NewID(), version: value.NewID(), privateHead: value.NewID(), privateVersion: value.NewID(), draftHead: value.NewID(), draftVersion: value.NewID(), action: value.NewID(), event: value.NewID(), actionPayload: value.NewID()}
	tx, err := f.Repo.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	insert := func(table string, row map[string]any) {
		if err := interviewSchemaInsertTx(tx, backend, table, row); err != nil {
			t.Fatal(table, err)
		}
	}
	for _, id := range []string{x.interview, x.otherInterview} {
		insert("interview", map[string]any{"org_id": f.OrgID, "id": id, "employee_id": x.employee, "status": "scheduled", "revision": 1, "scheduled_at": f.Repo.BindTime(f.Now), "backfilled": false, "author_subject_id": f.Owner.SubjectID, "recorded_at": f.Repo.BindTime(f.Now)})
	}
	for _, n := range []struct{ head, version, category, status string }{{x.head, x.version, "shared", "published"}, {x.privateHead, x.privateVersion, "manager_private", "published"}, {x.draftHead, x.draftVersion, "hr_confidential", "draft"}} {
		head := map[string]any{"org_id": f.OrgID, "id": n.head, "employee_id": x.employee, "interview_id": x.interview, "category": n.category, "revision": 1, "acl_epoch": 1, n.status + "_version_id": n.version}
		insert("note_head", head)
		v, p := x.noteRows(n.head, n.version, n.category, n.status, 1)
		insert("note_version", v)
		insert("interview_payload", p)
	}
	insert("action_item", map[string]any{"org_id": f.OrgID, "id": x.action, "employee_id": x.employee, "interview_id": x.interview, "owner_kind": "subject", "owner_subject_id": f.Owner.SubjectID, "due_date": "2026-01-01", "status": "todo", "revision": 1, "payload_id": x.actionPayload, "author_subject_id": f.Owner.SubjectID, "recorded_at": f.Repo.BindTime(f.Now)})
	insert("action_item_event", map[string]any{"org_id": f.OrgID, "id": x.event, "employee_id": x.employee, "interview_id": x.interview, "action_item_id": x.action, "status": "todo", "revision": 1, "payload_id": x.actionPayload, "author_subject_id": f.Owner.SubjectID, "recorded_at": f.Repo.BindTime(f.Now)})
	p := x.payload(x.actionPayload, "interview_action", x.action, x.actionPayload)
	p["action_item_id"], p["action_event_id"] = x.action, x.event
	insert("interview_payload", p)
	if err = tx.Commit(); err != nil {
		t.Fatal("complete deferred typed note/action ownership must commit", err)
	}
	return x
}

func (x interviewSchemaFixture) source() map[string]any {
	return map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "owner_note_version_id": x.version, "source_note_version_id": x.privateVersion, "category": "manager_private", "expected_version": 1, "source_epoch": 1}
}

func (x interviewSchemaFixture) grant(capability, category, kind, id string) map[string]any {
	g := grantSchemaGrant(x.f, x.f.Owner.SubjectID)
	g["capability"], g["category"], g["purpose"] = capability, category, "interview_followup"
	g["scope_kind"], g["scope_id"], g["employee_id"] = "employee", x.employee, x.employee
	if kind != "" {
		g["object_kind"], g["object_ref"], g["object_employee_id"], g[kind+"_id"] = kind, id, x.employee, id
	}
	return g
}

func TestInterviewV6TypedObjectsFinitePairsAndImmutableObjectGrant(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			for _, g := range []map[string]any{x.grant("interview.read", "metadata", "interview", x.interview), x.grant("note.read", "manager_private", "note_version", x.privateVersion), x.grant("note.publish", "shared", "note_head", x.head), x.grant("action.write", "shared", "action_item", x.action), x.grant("sensitive.export", "shared", "action_item", x.action)} {
				if err := grantSchemaInsert(x.f.Repo, "access_grant", g); err != nil {
					t.Fatal("valid finite typed grant must persist", err)
				}
			}
			broad := x.grant("note.read", "shared", "note_version", x.version)
			broad["scope_kind"], broad["scope_id"], broad["employee_id"] = "org", x.f.OrgID, nil
			if err := grantSchemaInsert(x.f.Repo, "access_grant", broad); err != nil {
				t.Fatal("typed object may narrow an approved org scope", err)
			}
			base := x.grant("note.read", "shared", "note_version", x.version)
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"canonical_mismatch", func(g map[string]any) { g["object_ref"] = value.NewID() }},
				{"two_typed_objects", func(g map[string]any) { g["interview_id"] = x.interview }},
				{"untyped_string", func(g map[string]any) { g["object_kind"] = nil }},
				{"different_employee", func(g map[string]any) {
					g["employee_id"], g["scope_id"], g["object_employee_id"] = x.otherEmployee, x.otherEmployee, x.otherEmployee
				}},
				{"foreign_employee", func(g map[string]any) { g["object_employee_id"] = x.foreignEmployee }},
				{"wrong_category", func(g map[string]any) { g["category"] = "manager_private" }},
				{"immutable_version_write", func(g map[string]any) { g["capability"] = "note.write" }},
				{"wrong_family", func(g map[string]any) { g["capability"], g["category"] = "interview.read", "metadata" }},
				{"unknown_purpose", func(g map[string]any) { g["purpose"] = "SYNTHETIC.unapproved" }},
				{"unknown_capability", func(g map[string]any) { g["capability"] = "SYNTHETIC.extra" }},
			} {
				t.Run(test.name, func(t *testing.T) {
					g := grantSchemaClone(base)
					g["id"] = value.NewID()
					test.mutate(g)
					if err := grantSchemaInsert(x.f.Repo, "access_grant", g); err == nil {
						t.Fatal("typed/category/family violation accepted")
					}
				})
			}
			if err := grantSchemaInsert(x.f.Repo, "access_grant", base); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE access_grant SET object_ref=?,note_version_id=? WHERE id=?"
			if backend == "postgres" {
				query = "UPDATE access_grant SET object_ref=$1,note_version_id=$2 WHERE id=$3"
			}
			_, err := x.f.Repo.DB.ExecContext(context.Background(), query, x.privateVersion, x.privateVersion, base["id"])
			structureImmutableConstraint(t, backend, err)
			if err = x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6PinnedPublishedSourcesAndImmutableHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"both_owners", func(r map[string]any) { r["owner_action_event_id"] = x.event }},
				{"neither_owner", func(r map[string]any) { r["owner_note_version_id"] = nil }},
				{"wrong_owner_family", func(r map[string]any) { r["owner_note_version_id"] = x.event }},
				{"wrong_employee", func(r map[string]any) { r["employee_id"] = x.otherEmployee }},
				{"wrong_version", func(r map[string]any) { r["expected_version"] = 2 }},
				{"wrong_epoch", func(r map[string]any) { r["source_epoch"] = 2 }},
				{"wrong_category", func(r map[string]any) { r["category"] = "shared" }},
				{"draft_source", func(r map[string]any) { r["source_note_version_id"], r["category"] = x.draftVersion, "hr_confidential" }},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := x.source()
					test.mutate(r)
					if err := grantSchemaInsert(x.f.Repo, "source_reference", r); err == nil {
						t.Fatal("invalid source tuple accepted")
					}
				})
			}
			r := x.source()
			if err := grantSchemaInsert(x.f.Repo, "source_reference", r); err != nil {
				t.Fatal("exact published immutable source must persist", err)
			}
			actionSource := x.source()
			actionSource["owner_note_version_id"], actionSource["owner_action_event_id"] = nil, x.event
			if err := grantSchemaInsert(x.f.Repo, "source_reference", actionSource); err != nil {
				t.Fatal("typed action-event source must persist", err)
			}
			before := interviewMigrationFacts(t, x.f.Repo)
			for _, table := range []string{"note_version", "action_item_event", "interview_payload", "source_reference"} {
				_, err := x.f.Repo.DB.ExecContext(context.Background(), "UPDATE "+table+" SET id=id")
				structureImmutableConstraint(t, backend, err)
				_, err = x.f.Repo.DB.ExecContext(context.Background(), "DELETE FROM "+table)
				structureImmutableConstraint(t, backend, err)
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, x.f.Repo))
			// A same-category version from a different head cannot be substituted
			// into the current head through a deferred FK at COMMIT.
			tx, err := x.f.Repo.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			query := "UPDATE note_head SET published_version_id=? WHERE org_id=? AND id=?"
			if backend == "postgres" {
				query = "UPDATE note_head SET published_version_id=$1 WHERE org_id=$2 AND id=$3"
			}
			_, err = tx.ExecContext(context.Background(), query, x.privateVersion, x.f.OrgID, x.head)
			if err == nil {
				err = tx.Commit()
			}
			if err == nil {
				t.Fatal("head pointer cannot cross category or head")
			}
			tx.Rollback()
			if err = x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6SourceApprovalOwnerScopeCapabilityPublishedAndBound(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			g := x.grant("note.publish", "shared", "note_head", x.head)
			if err := grantSchemaInsert(x.f.Repo, "access_grant", g); err != nil {
				t.Fatal(err)
			}
			approval := map[string]any{"org_id": x.f.OrgID, "grant_id": g["id"], "source_note_version_id": x.privateVersion, "employee_id": x.employee, "source_category": "manager_private"}
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"wrong_employee", func(r map[string]any) { r["employee_id"] = x.otherEmployee }},
				{"wrong_category", func(r map[string]any) { r["source_category"] = "shared" }},
				{"draft", func(r map[string]any) {
					r["source_note_version_id"], r["source_category"] = x.draftVersion, "hr_confidential"
				}},
				{"missing_grant", func(r map[string]any) { r["grant_id"] = value.NewID() }},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := grantSchemaClone(approval)
					test.mutate(r)
					if err := grantSchemaInsert(x.f.Repo, "access_grant_source_approval", r); err == nil {
						t.Fatal("invalid source approval accepted")
					}
				})
			}
			broadGrant := x.grant("note.publish", "shared", "note_head", x.head)
			broadGrant["scope_kind"], broadGrant["scope_id"], broadGrant["employee_id"] = "org", x.f.OrgID, nil
			if err := grantSchemaInsert(x.f.Repo, "access_grant", broadGrant); err != nil {
				t.Fatal("ordinary object restriction permits org scope", err)
			}
			broadApproval := grantSchemaClone(approval)
			broadApproval["grant_id"] = broadGrant["id"]
			if err := grantSchemaInsert(x.f.Repo, "access_grant_source_approval", broadApproval); err == nil {
				t.Fatal("approved source minimization must have explicit one-employee target scope")
			}
			readGrant := x.grant("note.read", "shared", "note_head", x.head)
			if err := grantSchemaInsert(x.f.Repo, "access_grant", readGrant); err != nil {
				t.Fatal(err)
			}
			readApproval := grantSchemaClone(approval)
			readApproval["grant_id"] = readGrant["id"]
			if err := grantSchemaInsert(x.f.Repo, "access_grant_source_approval", readApproval); err == nil {
				t.Fatal("read grant cannot authorize publication minimization")
			}
			if err := grantSchemaInsert(x.f.Repo, "access_grant_source_approval", approval); err != nil {
				t.Fatal("explicit target publication approval must persist", err)
			}
			for number := 2; number <= 11; number++ {
				version := value.NewID()
				v, p := x.noteRows(x.privateHead, version, "manager_private", "published", number)
				tx, err := x.f.Repo.DB.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if err = interviewSchemaInsertTx(tx, backend, "note_version", v); err == nil {
					err = interviewSchemaInsertTx(tx, backend, "interview_payload", p)
				}
				if err == nil {
					err = tx.Commit()
				}
				tx.Rollback()
				if err != nil {
					t.Fatal(err)
				}
				r := grantSchemaClone(approval)
				r["source_note_version_id"] = version
				err = grantSchemaInsert(x.f.Repo, "access_grant_source_approval", r)
				if number <= 10 && err != nil {
					t.Fatal("first ten distinct source approvals permitted", err)
				}
				if number == 11 && err == nil {
					t.Fatal("eleventh source approval must fail")
				}
			}
			for _, query := range []string{"UPDATE access_grant_source_approval SET source_category=source_category", "DELETE FROM access_grant_source_approval"} {
				_, err := x.f.Repo.DB.ExecContext(context.Background(), query)
				structureImmutableConstraint(t, backend, err)
			}
			if err := x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6NativeReceiptAndAuditFiniteOperations(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			for _, op := range []string{"OP-INT-01", "OP-INT-02", "OP-INT-03", "OP-INT-04", "OP-INT-05", "OP-INT-06", "OP-INT-07", "OP-INT-08", "OP-SEC-05"} {
				for _, outcome := range []string{"allowed", "denied", "partial"} {
					r := map[string]any{"id": value.NewID(), "org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "operation": op, "purpose": "interview_followup", "request_id": value.NewID(), "outcome": outcome, "recorded_at": x.f.Repo.BindTime(x.f.Now)}
					if err := grantSchemaInsert(x.f.Repo, "audit_event", r); err != nil {
						t.Fatal("finite interview audit operation/outcome required", err)
					}
				}
			}
			receipt := map[string]any{"org_id": x.f.OrgID, "subject_id": x.f.Owner.SubjectID, "operation": "OP-INT-05", "key": value.NewID(), "digest": bytes.Repeat([]byte{17}, 32), "digest_key_version": 1, "result_json": `{"id":"` + x.version + `","revision":"1","status":"published"}`, "recorded_at": x.f.Repo.BindTime(x.f.Now)}
			if err := grantSchemaInsert(x.f.Repo, "interview_receipt", receipt); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"unknown_operation", func(r map[string]any) { r["operation"] = "OP-INT-99" }},
				{"read_receipt", func(r map[string]any) { r["operation"] = "OP-INT-04" }},
				{"short_digest", func(r map[string]any) { r["digest"] = []byte{1} }},
				{"unknown_digest_version", func(r map[string]any) { r["digest_key_version"] = 2 }},
				{"unstructured_result", func(r map[string]any) { r["result_json"] = `[]` }},
				{"foreign_subject", func(r map[string]any) { r["subject_id"] = x.f.OtherOwner.SubjectID }},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := grantSchemaClone(receipt)
					r["key"] = value.NewID()
					test.mutate(r)
					if err := grantSchemaInsert(x.f.Repo, "interview_receipt", r); err == nil {
						t.Fatal("invalid receipt accepted")
					}
				})
			}
			for _, query := range []string{"UPDATE interview_receipt SET key=key", "DELETE FROM interview_receipt"} {
				_, err := x.f.Repo.DB.ExecContext(context.Background(), query)
				structureImmutableConstraint(t, backend, err)
			}
		})
	}
}

func interviewSchemaUpdate(x interviewSchemaFixture, table, id string, fields map[string]any) error {
	assignments, args := make([]string, 0, len(fields)), make([]any, 0, len(fields)+2)
	for col, v := range fields {
		placeholder := "?"
		if x.f.Backend == "postgres" {
			placeholder = fmt.Sprintf("$%d", len(args)+1)
		}
		assignments, args = append(assignments, col+"="+placeholder), append(args, v)
	}
	orgPlaceholder, idPlaceholder := "?", "?"
	if x.f.Backend == "postgres" {
		orgPlaceholder, idPlaceholder = fmt.Sprintf("$%d", len(args)+1), fmt.Sprintf("$%d", len(args)+2)
	}
	args = append(args, x.f.OrgID, id)
	_, err := x.f.Repo.DB.ExecContext(context.Background(), "UPDATE "+table+" SET "+strings.Join(assignments, ",")+" WHERE org_id="+orgPlaceholder+" AND id="+idPlaceholder, args...)
	return err
}

func TestInterviewV6NativeTransitionRevisionActualFactsAndTerminalGuards(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			start := x.f.Now.Add(time.Hour)
			end := start.Add(time.Hour)
			before := interviewMigrationFacts(t, x.f.Repo)
			for _, fields := range []map[string]any{
				{"revision": 1},
				{"revision": 3},
				{"revision": 2, "status": "completed", "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end)},
				{"revision": 2, "status": "in_progress"},
				{"revision": 2, "status": "SYNTHETIC.unknown"},
			} {
				if err := interviewSchemaUpdate(x, "interview", x.interview, fields); err == nil {
					t.Fatal("native interview order/revision/time violation accepted", fields)
				}
			}
			for _, fields := range []map[string]any{
				{"revision": 1, "status": "in_progress"},
				{"revision": 3, "status": "done"},
				{"revision": 2},
				{"revision": 2, "status": "SYNTHETIC.unknown"},
			} {
				if err := interviewSchemaUpdate(x, "action_item", x.action, fields); err == nil {
					t.Fatal("native action order/revision violation accepted", fields)
				}
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, x.f.Repo))
			if err := interviewSchemaUpdate(x, "interview", x.interview, map[string]any{"revision": 2}); err != nil {
				t.Fatal("nonterminal CreateAction aggregate revision bump must be legal", err)
			}
			if err := interviewSchemaUpdate(x, "interview", x.interview, map[string]any{"revision": 3, "status": "in_progress", "actual_started_at": x.f.Repo.BindTime(start)}); err != nil {
				t.Fatal("actual may occur after original creation recorded_at", err)
			}
			event := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "interview_id": x.interview, "revision": 3, "status": "in_progress", "backfilled": false, "actual_started_at": x.f.Repo.BindTime(start), "author_subject_id": x.f.Owner.SubjectID, "recorded_at": x.f.Repo.BindTime(x.f.Now)}
			if err := grantSchemaInsert(x.f.Repo, "interview_event", event); err == nil {
				t.Fatal("immutable event cannot claim future actual relative to its server recording")
			}
			event["recorded_at"] = x.f.Repo.BindTime(end)
			if err := grantSchemaInsert(x.f.Repo, "interview_event", event); err != nil {
				t.Fatal("valid historical transition event must persist", err)
			}
			for _, fields := range []map[string]any{
				{"revision": 4, "actual_started_at": nil},
				{"revision": 4, "actual_started_at": x.f.Repo.BindTime(end)},
				{"revision": 4, "status": "scheduled", "actual_started_at": nil},
			} {
				if err := interviewSchemaUpdate(x, "interview", x.interview, fields); err == nil {
					t.Fatal("recorded actual start cannot be rewritten")
				}
			}
			if err := interviewSchemaUpdate(x, "interview", x.interview, map[string]any{"revision": 4, "status": "completed", "actual_ended_at": x.f.Repo.BindTime(end)}); err != nil {
				t.Fatal(err)
			}
			for _, status := range []string{"completed", "in_progress", "cancelled"} {
				if err := interviewSchemaUpdate(x, "interview", x.interview, map[string]any{"revision": 5, "status": status}); err == nil {
					t.Fatal("terminal interview cannot update or reopen")
				}
			}
			// Completing the interview leaves its existing action open.
			var status string
			query := "SELECT status FROM action_item WHERE org_id=? AND id=?"
			if backend == "postgres" {
				query = "SELECT status FROM action_item WHERE org_id=$1 AND id=$2"
			}
			if err := x.f.Repo.DB.QueryRowContext(context.Background(), query, x.f.OrgID, x.action).Scan(&status); err != nil || status != "todo" {
				t.Fatal("interview completion cannot close action", err)
			}
			if err := interviewSchemaUpdate(x, "action_item", x.action, map[string]any{"revision": 2, "status": "in_progress"}); err != nil {
				t.Fatal(err)
			}
			if err := interviewSchemaUpdate(x, "action_item", x.action, map[string]any{"revision": 3, "status": "todo"}); err == nil {
				t.Fatal("action cannot restart")
			}
			if err := interviewSchemaUpdate(x, "action_item", x.action, map[string]any{"revision": 3, "status": "done"}); err != nil {
				t.Fatal(err)
			}
			for _, status := range []string{"done", "todo", "cancelled"} {
				if err := interviewSchemaUpdate(x, "action_item", x.action, map[string]any{"revision": 4, "status": status}); err == nil {
					t.Fatal("terminal action cannot update or reopen")
				}
			}
			for _, table := range []string{"interview_event", "note_head"} {
				query := "UPDATE " + table + " SET employee_id=employee_id"
				if table == "note_head" {
					query = "UPDATE note_head SET category='shared' WHERE category='manager_private'"
				}
				if _, err := x.f.Repo.DB.ExecContext(context.Background(), query); err == nil {
					t.Fatal("immutable history/owner change must fail", table)
				}
			}
			if err := x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6NativePayloadAADOwnersAndTypedParticipants(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"wrong_record", func(p map[string]any) { p["record_id"] = x.privateHead }},
				{"wrong_version", func(p map[string]any) { p["version_id"] = x.privateVersion }},
				{"wrong_head", func(p map[string]any) { p["head_id"], p["record_id"] = x.privateHead, x.privateHead }},
				{"wrong_employee", func(p map[string]any) { p["employee_id"] = x.otherEmployee }},
				{"category_swap", func(p map[string]any) {
					p["object_kind"], p["category"] = "interview_note_manager_private", "manager_private"
				}},
				{"wrong_schema", func(p map[string]any) { p["schema_type"] = "interview.action.v1" }},
				{"wrong_purpose", func(p map[string]any) { p["purpose"] = "pii" }},
				{"two_owner_families", func(p map[string]any) { p["action_item_id"], p["action_event_id"] = x.action, x.event }},
				{"missing_category", func(p map[string]any) { p["category"] = nil }},
				{"short_ciphertext", func(p map[string]any) { p["sealed_bytes"] = []byte{1} }},
			} {
				t.Run(test.name, func(t *testing.T) {
					p := x.payload(value.NewID(), "interview_note_shared", x.head, x.version)
					p["head_id"], p["note_version_id"], p["category"] = x.head, x.version, "shared"
					test.mutate(p)
					if err := grantSchemaInsert(x.f.Repo, "interview_payload", p); err == nil {
						t.Fatal("payload owner/schema/envelope mismatch accepted")
					}
				})
			}
			participant := map[string]any{"org_id": x.f.OrgID, "interview_id": x.interview, "ordinal": 0, "kind": "subject", "subject_id": x.f.Owner.SubjectID}
			for _, test := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"crossorg_subject", func(p map[string]any) { p["subject_id"] = x.f.OtherOwner.SubjectID }},
				{"untyped_employee", func(p map[string]any) { p["kind"], p["subject_id"] = "employee", nil }},
				{"two_parties", func(p map[string]any) { p["employee_id"] = x.employee }},
				{"unknown_kind", func(p map[string]any) { p["kind"] = "manager" }},
				{"too_many_participants", func(p map[string]any) { p["ordinal"] = 20 }},
			} {
				t.Run(test.name, func(t *testing.T) {
					p := grantSchemaClone(participant)
					test.mutate(p)
					if err := grantSchemaInsert(x.f.Repo, "interview_participant", p); err == nil {
						t.Fatal("untyped or crossorg participant accepted")
					}
				})
			}
			if err := grantSchemaInsert(x.f.Repo, "interview_participant", participant); err != nil {
				t.Fatal(err)
			}
			duplicate := grantSchemaClone(participant)
			duplicate["ordinal"] = 1
			if err := grantSchemaInsert(x.f.Repo, "interview_participant", duplicate); err == nil {
				t.Fatal("duplicate participant cannot bypass unique party rule")
			}
			if err := x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6FiniteCapabilityAssignmentsAndDelegatedCategoryPurpose(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			subject := grantSchemaSubject(t, x.f, x.f.OrgID)
			for _, capability := range []string{"interview.read", "interview.write", "note.read", "note.write", "note.publish", "action.read", "action.write", "sensitive.export"} {
				if err := grantSchemaInsert(x.f.Repo, "capability_assignment", map[string]any{"org_id": x.f.OrgID, "subject_id": subject, "capability": capability, "scope_kind": "employee", "scope_id": x.employee, "employee_id": x.employee}); err != nil {
					t.Fatal("finite interview capability must be assignable", capability, err)
				}
			}
			if err := grantSchemaInsert(x.f.Repo, "capability_assignment", map[string]any{"org_id": x.f.OrgID, "subject_id": subject, "capability": "SYNTHETIC.arbitrary", "scope_kind": "org", "scope_id": x.f.OrgID}); err == nil {
				t.Fatal("unknown capability assignment accepted")
			}
			approver := grantSchemaSubject(t, x.f, x.f.OrgID)
			authority := grantSchemaAuthority(x.f, x.f.OrgID, subject, approver)
			authority["capability"], authority["category"], authority["purpose"] = "note.publish", "manager_private", "interview_followup"
			if err := grantSchemaInsert(x.f.Repo, "delegation_authority", authority); err != nil {
				t.Fatal("approved finite note publication authority must persist", err)
			}
			for _, change := range []map[string]any{
				{"category": "metadata"},
				{"purpose": "organization_management"},
				{"capability": "interview.write"},
				{"capability": "action.write", "category": "hr_confidential"},
				{"capability": "access_grant.manage", "category": "audit", "purpose": "security_administration"},
			} {
				row := grantSchemaClone(authority)
				row["id"] = value.NewID()
				for k, v := range change {
					row[k] = v
				}
				if err := grantSchemaInsert(x.f.Repo, "delegation_authority", row); err == nil {
					t.Fatal("invalid delegated capability/category/purpose tuple accepted", change)
				}
			}
			if err := x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterviewV6CheckSchemaRejectsNativeOwnerAndHistoryDrift(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		for _, drift := range []string{"missing_source_index", "missing_history_trigger", "missing_typed_owner"} {
			t.Run(backend+"/"+drift, func(t *testing.T) {
				x := interviewSchemaSeed(t, backend)
				var query string
				switch drift {
				case "missing_source_index":
					query = "DROP INDEX source_version"
				case "missing_history_trigger":
					query = "DROP TRIGGER note_version_no_update"
					if backend == "postgres" {
						query = "DROP TRIGGER note_version_immutable ON note_version"
					}
				case "missing_typed_owner":
					if backend == "postgres" {
						query = "ALTER TABLE source_reference DROP CONSTRAINT source_reference_owner_2"
					} else {
						query = "DROP TRIGGER interview_transition_guard"
					}
				}
				if _, err := x.f.Repo.DB.ExecContext(context.Background(), query); err != nil {
					t.Fatal("controlled native schema drift setup", err)
				}
				before := interviewMigrationFacts(t, x.f.Repo)
				runtimeUnavailable(t, x.f.Repo.CheckSchema(context.Background()))
				runtimeUnavailable(t, x.f.Repo.Migrate(context.Background()))
				runtimeUnchanged(t, before, interviewMigrationFacts(t, x.f.Repo))
			})
		}
	}
}

func TestInterviewV6ExplicitScheduledBackfillPreservesOriginalPlanAndImmutableEvents(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			x := interviewSchemaSeed(t, backend)
			start, end := x.f.Now.Add(-2*time.Hour), x.f.Now.Add(-time.Hour)
			scheduledEvent := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "interview_id": x.interview, "status": "scheduled", "revision": 1, "backfilled": false, "author_subject_id": x.f.Owner.SubjectID, "recorded_at": x.f.Repo.BindTime(x.f.Now)}
			if err := grantSchemaInsert(x.f.Repo, "interview_event", scheduledEvent); err != nil {
				t.Fatal("original planned event must persist", err)
			}
			before := interviewMigrationFacts(t, x.f.Repo)
			for _, fields := range []map[string]any{
				{"revision": 2, "status": "completed", "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end)},
				{"revision": 2, "status": "completed", "backfilled": true},
				{"revision": 2, "status": "completed", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start)},
				{"revision": 2, "status": "completed", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(end), "actual_ended_at": x.f.Repo.BindTime(start)},
				{"revision": 2, "status": "in_progress", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start)},
				{"revision": 2, "status": "cancelled", "backfilled": true},
				{"revision": 2, "status": "completed", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end), "scheduled_at": x.f.Repo.BindTime(start)},
				{"revision": 2, "status": "completed", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end), "recorded_at": x.f.Repo.BindTime(start)},
				{"revision": 2, "status": "completed", "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end), "author_subject_id": x.f.Manager.SubjectID},
			} {
				if err := interviewSchemaUpdate(x, "interview", x.interview, fields); err == nil {
					t.Fatal("illegal or nonexplicit backfill accepted", fields)
				}
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, x.f.Repo))
			completedEvent := map[string]any{"org_id": x.f.OrgID, "id": value.NewID(), "employee_id": x.employee, "interview_id": x.interview, "status": "completed", "revision": 2, "backfilled": true, "actual_started_at": x.f.Repo.BindTime(start), "actual_ended_at": x.f.Repo.BindTime(end), "author_subject_id": x.f.Owner.SubjectID, "recorded_at": x.f.Repo.BindTime(x.f.Now)}
			future := grantSchemaClone(completedEvent)
			future["actual_ended_at"] = x.f.Repo.BindTime(x.f.Now.Add(time.Hour))
			if err := grantSchemaInsert(x.f.Repo, "interview_event", future); err == nil {
				t.Fatal("backfill event cannot claim future actual end")
			}
			tx, err := x.f.Repo.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = interviewSchemaInsertTx(tx, backend, "interview_event", completedEvent); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE interview SET status='completed',revision=2,backfilled=?,actual_started_at=?,actual_ended_at=? WHERE org_id=? AND id=? AND revision=1"
			if backend == "postgres" {
				query = "UPDATE interview SET status='completed',revision=2,backfilled=$1,actual_started_at=$2,actual_ended_at=$3 WHERE org_id=$4 AND id=$5 AND revision=1"
			}
			result, err := tx.ExecContext(context.Background(), query, true, x.f.Repo.BindTime(start), x.f.Repo.BindTime(end), x.f.OrgID, x.interview)
			if err != nil {
				t.Fatal("explicit scheduled completion with actuals must persist", err)
			}
			if count, err := result.RowsAffected(); err != nil || count != 1 {
				t.Fatal("backfill must CAS exactly original aggregate", err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal("backfill and immutable completion event must commit together", err)
			}
			var status string
			var revision int64
			var backfilled bool
			query = "SELECT status,revision,backfilled FROM interview WHERE org_id=? AND id=? AND scheduled_at=? AND recorded_at=? AND author_subject_id=?"
			if backend == "postgres" {
				query = "SELECT status,revision,backfilled FROM interview WHERE org_id=$1 AND id=$2 AND scheduled_at=$3 AND recorded_at=$4 AND author_subject_id=$5"
			}
			if err = x.f.Repo.DB.QueryRowContext(context.Background(), query, x.f.OrgID, x.interview, x.f.Repo.BindTime(x.f.Now), x.f.Repo.BindTime(x.f.Now), x.f.Owner.SubjectID).Scan(&status, &revision, &backfilled); err != nil || status != "completed" || revision != 2 || !backfilled {
				t.Fatal("backfill preserves original schedule/recording/author while adding explicit actual facts", err)
			}
			for _, fields := range []map[string]any{{"revision": 3, "backfilled": false}, {"revision": 3, "actual_started_at": x.f.Repo.BindTime(end)}, {"revision": 3, "status": "in_progress"}} {
				if err := interviewSchemaUpdate(x, "interview", x.interview, fields); err == nil {
					t.Fatal("terminal backfill cannot lose flag, rewrite actuals or reopen")
				}
			}
			for _, original := range []map[string]any{scheduledEvent, completedEvent} {
				duplicate := grantSchemaClone(original)
				duplicate["id"], duplicate["revision"] = value.NewID(), 9
				if err := grantSchemaInsert(x.f.Repo, "interview_event", duplicate); err == nil {
					t.Fatal("immutable interview state phase cannot be repeated")
				}
			}
			cancel := grantSchemaClone(completedEvent)
			cancel["id"], cancel["revision"], cancel["status"], cancel["backfilled"] = value.NewID(), 10, "cancelled", false
			if err := grantSchemaInsert(x.f.Repo, "interview_event", cancel); err == nil {
				t.Fatal("completed and cancelled terminal histories cannot coexist")
			}
			var count int
			query = "SELECT count(*) FROM interview_event WHERE org_id=? AND interview_id=?"
			if backend == "postgres" {
				query = "SELECT count(*) FROM interview_event WHERE org_id=$1 AND interview_id=$2"
			}
			if err = x.f.Repo.DB.QueryRowContext(context.Background(), query, x.f.OrgID, x.interview).Scan(&count); err != nil || count != 2 {
				t.Fatal("original planned and explicit completed backfill events both retained", err)
			}
			for _, query := range []string{"UPDATE interview_event SET backfilled=backfilled", "DELETE FROM interview_event"} {
				_, err := x.f.Repo.DB.ExecContext(context.Background(), query)
				structureImmutableConstraint(t, backend, err)
			}
			if err := x.f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
