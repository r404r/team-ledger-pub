package store_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

// Native SQL fixtures exercise the database boundary independently of domain
// validation. Envelope bytes are synthetic; no test pretends these are ciphertext
// produced by the financial KMS.
type compensationSchemaRow struct {
	table  string
	values map[string]any
}
type compensationSchemaGraph struct {
	org, employee, proposal, submitted, approved, approval, event, term string
	rows                                                                []compensationSchemaRow
}

func compensationNativeGraph(f *testsupport.Fixture, org, employee, author, approver string, basis, sequence int64) compensationSchemaGraph {
	g := compensationSchemaGraph{org: org, employee: employee, proposal: value.NewID(), submitted: value.NewID(), approved: value.NewID(), approval: value.NewID(), event: value.NewID(), term: value.NewID()}
	now := f.Repo.BindTime(f.Now)
	add := func(table string, row map[string]any) { g.rows = append(g.rows, compensationSchemaRow{table, row}) }
	payload := func(id, kind, record, version, schema string) map[string]any {
		return map[string]any{"org_id": org, "id": id, "employee_id": employee, "record_id": record, "version_id": version, "object_kind": kind, "purpose": "financial", "schema_type": schema, "schema_version": 1, "format_version": 1, "algorithm": "A256GCM-RANDOMNONCE", "dek_id": value.NewID(), "kek_id": "synthetic-financial-key", "kek_version": 1, "wrapped_dek": []byte{1}, "sealed_bytes": bytes.Repeat([]byte{7}, 28), "created_at": now}
	}
	add("compensation_proposal", map[string]any{"org_id": org, "id": g.proposal, "employee_id": employee, "kind": "initial", "status": "approved", "author_subject_id": author, "revision_id": g.approved, "payload_id": g.approved, "effective_date": "2026-01-01", "revision": 3, "basis_revision": basis, "recorded_at": now, "approval_id": g.approval})
	for _, r := range []struct {
		id, status string
		revision   int
	}{{g.submitted, "submitted", 2}, {g.approved, "approved", 3}} {
		add("compensation_proposal_revision", map[string]any{"org_id": org, "id": r.id, "employee_id": employee, "proposal_id": g.proposal, "payload_id": r.id, "kind": "initial", "status": r.status, "effective_date": "2026-01-01", "actor_subject_id": author, "revision": r.revision, "basis_revision": basis, "recorded_at": now})
		p := payload(r.id, "compensation_proposal", g.proposal, r.id, "compensation.proposal.v1")
		p["proposal_id"], p["proposal_revision_id"] = g.proposal, r.id
		add("compensation_payload", p)
	}
	add("compensation_approval", map[string]any{"org_id": org, "id": g.approval, "employee_id": employee, "proposal_id": g.proposal, "proposal_revision_id": g.submitted, "approver_subject_id": approver, "author_subject_id": author, "payload_id": g.approval, "proposal_revision": 2, "basis_revision": basis, "comp_revision": basis + 1, "recorded_at": now})
	p := payload(g.approval, "compensation_decision", g.approval, g.approval, "compensation.decision.v1")
	p["approval_id"] = g.approval
	add("compensation_payload", p)
	add("compensation_event", map[string]any{"org_id": org, "id": g.event, "employee_id": employee, "approval_id": g.approval, "kind": "initial", "effective_date": "2026-01-01", "member_key": "", "after_term_id": g.term, "sequence": sequence})
	add("compensation_terms_version", map[string]any{"org_id": org, "id": g.term, "employee_id": employee, "event_id": g.event, "approval_id": g.approval, "payload_id": g.term, "effective_date": "2026-01-01", "version_no": sequence})
	p = payload(g.term, "compensation_terms", g.term, g.term, "compensation.terms.v1")
	p["term_id"] = g.term
	add("compensation_payload", p)
	return g
}

func compensationNativeCommit(repoBackend string, db *sql.DB, rows []compensationSchemaRow) error {
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, row := range rows {
		if err = interviewSchemaInsertTx(tx, repoBackend, row.table, row.values); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func compensationNativeClone(g compensationSchemaGraph) compensationSchemaGraph {
	out := g
	out.rows = make([]compensationSchemaRow, len(g.rows))
	for i, r := range g.rows {
		out.rows[i] = compensationSchemaRow{r.table, grantSchemaClone(r.values)}
	}
	return out
}

func compensationNativeCorrection(f *testsupport.Fixture, original compensationSchemaGraph, author, approver string) compensationSchemaGraph {
	g := compensationNativeGraph(f, original.org, original.employee, author, approver, 2, 2)
	for _, r := range g.rows {
		if r.table == "compensation_proposal" || r.table == "compensation_proposal_revision" {
			r.values["kind"] = "correction"
		}
		if r.table == "compensation_event" {
			r.values["kind"], r.values["member_key"], r.values["corrects_event_id"], r.values["correction_group_id"] = "correction_replacement", "replace_initial", original.event, g.approval
		}
	}
	g.rows = append(g.rows,
		compensationSchemaRow{"compensation_correction_group", map[string]any{"org_id": g.org, "id": g.approval, "employee_id": g.employee, "proposal_id": g.proposal, "proposal_revision_id": g.submitted, "approval_id": g.approval, "basis_revision": 2}},
		compensationSchemaRow{"compensation_correction_member", map[string]any{"org_id": g.org, "group_id": g.approval, "employee_id": g.employee, "member_key": "replace_initial", "action": "replace", "original_event_id": original.event, "event_id": g.event, "after_term_id": g.term, "effective_date": "2026-01-01"}})
	return g
}

func compensationNativeSeed(t *testing.T, backend string) (*testsupport.Fixture, compensationSchemaGraph, compensationSchemaGraph, compensationSchemaGraph, string) {
	t.Helper()
	f := testsupport.NewHarness(t, backend)
	ctx := context.Background()
	employee := runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_FINANCIAL_LOCAL").ID
	other := runtimeCreate(t, ctx, f, f.Owner, f.OrgID, "SYNTHETIC_FINANCIAL_OTHER").ID
	foreign := runtimeCreate(t, ctx, f, f.OtherOwner, f.OtherOrgID, "SYNTHETIC_FINANCIAL_FOREIGN").ID
	approver := grantSchemaSubject(t, f, f.OrgID)
	foreignApprover := grantSchemaSubject(t, f, f.OtherOrgID)
	a := compensationNativeGraph(f, f.OrgID, employee, f.Owner.SubjectID, approver, 1, 1)
	b := compensationNativeGraph(f, f.OrgID, other, f.Owner.SubjectID, approver, 1, 1)
	c := compensationNativeGraph(f, f.OtherOrgID, foreign, f.OtherOwner.SubjectID, foreignApprover, 1, 1)
	for _, g := range []compensationSchemaGraph{a, b, c} {
		rows := append([]compensationSchemaRow{{"compensation_aggregate", map[string]any{"org_id": g.org, "employee_id": g.employee, "revision": 2}}}, g.rows...)
		rows = append(rows, compensationSchemaRow{"compensation_schedule_projection", map[string]any{"org_id": g.org, "employee_id": g.employee, "effective_date": "2026-01-01", "term_id": g.term, "event_id": g.event, "revision": 2}})
		if err := compensationNativeCommit(backend, f.Repo.DB, rows); err != nil {
			t.Fatal("complete deferred native graph must commit", err)
		}
	}
	return f, a, b, c, approver
}

func TestCompensationV7DeferredOwnersFrozenApprovalAndCorrectionFacts(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f, a, b, c, approver := compensationNativeSeed(t, backend)
			correction := compensationNativeCorrection(f, a, f.Owner.SubjectID, approver)
			for _, test := range []struct {
				name, table string
				change      func(map[string]any)
			}{
				{"foreign_revision_employee", "compensation_proposal_revision", func(r map[string]any) { r["employee_id"] = c.employee }},
				{"other_employee_revision", "compensation_proposal_revision", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"foreign_author", "compensation_proposal", func(r map[string]any) { r["author_subject_id"] = f.OtherOwner.SubjectID }},
				{"foreign_approver", "compensation_approval", func(r map[string]any) { r["approver_subject_id"] = f.OtherOwner.SubjectID }},
				{"other_employee_approval", "compensation_approval", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"approved_not_frozen_submitted", "compensation_approval", func(r map[string]any) { r["proposal_revision_id"], r["proposal_revision"] = correction.approved, 3 }},
				{"other_employee_event", "compensation_event", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"other_employee_before", "compensation_event", func(r map[string]any) { r["before_term_id"] = b.term }},
				{"foreign_corrected_event", "compensation_event", func(r map[string]any) { r["corrects_event_id"] = c.event }},
				{"other_employee_term", "compensation_terms_version", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"wrong_term_approval", "compensation_terms_version", func(r map[string]any) { r["approval_id"] = a.approval }},
				{"wrong_term_date", "compensation_terms_version", func(r map[string]any) { r["effective_date"] = "2026-01-02" }},
				{"wrong_payload_owner", "compensation_payload", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"other_employee_correction_group", "compensation_correction_group", func(r map[string]any) { r["employee_id"] = b.employee }},
				{"wrong_correction_original", "compensation_correction_member", func(r map[string]any) { r["original_event_id"] = b.event }},
				{"wrong_correction_action", "compensation_correction_member", func(r map[string]any) { r["action"], r["after_term_id"] = "reverse", nil }},
			} {
				t.Run(test.name, func(t *testing.T) {
					g := compensationNativeClone(correction)
					for _, r := range g.rows {
						if r.table == test.table {
							test.change(r.values)
							break
						}
					}
					runtimeForeignKey(t, backend, compensationNativeCommit(backend, f.Repo.DB, g.rows))
				})
			}
			if err := compensationNativeCommit(backend, f.Repo.DB, correction.rows); err != nil {
				t.Fatal("valid complete correction member facts must commit", err)
			}
			before := interviewMigrationFacts(t, f.Repo)
			for _, table := range []string{"compensation_proposal_revision", "compensation_approval", "compensation_event", "compensation_terms_version", "compensation_payload", "compensation_correction_group", "compensation_correction_member"} {
				for _, query := range []string{"UPDATE " + table + " SET employee_id=employee_id", "DELETE FROM " + table} {
					if _, err := f.Repo.DB.ExecContext(context.Background(), query); err == nil {
						t.Fatal("immutable financial history changed", table)
					}
				}
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, f.Repo))
		})
	}
}

func TestCompensationV7FiniteShapesAndEncryptedReceiptBoundary(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f, a, _, _, approver := compensationNativeSeed(t, backend)
			correction := compensationNativeCorrection(f, a, f.Owner.SubjectID, approver)
			for _, test := range []struct {
				name, table string
				change      func(map[string]any)
			}{
				{"unknown_proposal_kind", "compensation_proposal", func(r map[string]any) { r["kind"] = "bonus" }},
				{"unknown_state", "compensation_proposal_revision", func(r map[string]any) { r["status"] = "effective" }},
				{"zero_revision", "compensation_proposal_revision", func(r map[string]any) { r["revision"] = 0 }},
				{"invalid_gregorian_date", "compensation_proposal", func(r map[string]any) { r["effective_date"] = "2026-02-30" }},
				{"self_approval", "compensation_approval", func(r map[string]any) { r["approver_subject_id"] = f.Owner.SubjectID }},
				{"wrong_aggregate_successor", "compensation_approval", func(r map[string]any) { r["comp_revision"] = 2 }},
				{"unknown_event_kind", "compensation_event", func(r map[string]any) { r["kind"] = "reversal" }},
				{"zero_event_sequence", "compensation_event", func(r map[string]any) { r["sequence"] = 0 }},
				{"invalid_member_key", "compensation_event", func(r map[string]any) { r["member_key"] = "Upper" }},
				{"reverse_with_terms", "compensation_event", func(r map[string]any) { r["kind"] = "correction_reversal" }},
				{"zero_term_version", "compensation_terms_version", func(r map[string]any) { r["version_no"] = 0 }},
				{"unknown_payload_kind", "compensation_payload", func(r map[string]any) { r["object_kind"] = "bonus" }},
				{"wrong_payload_purpose", "compensation_payload", func(r map[string]any) { r["purpose"] = "interview" }},
				{"wrong_payload_schema", "compensation_payload", func(r map[string]any) { r["schema_type"] = "compensation.terms.v1" }},
				{"wrong_payload_context", "compensation_payload", func(r map[string]any) { r["record_id"] = value.NewID() }},
			} {
				t.Run(test.name, func(t *testing.T) {
					g := compensationNativeClone(correction)
					for _, r := range g.rows {
						if r.table == test.table {
							test.change(r.values)
							break
						}
					}
					if err := compensationNativeCommit(backend, f.Repo.DB, g.rows); err == nil {
						t.Fatal("native finite CHECK accepted", test.name)
					}
				})
			}
			receipt := map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "operation": "OP-COMP-05", "key": value.NewID(), "digest": bytes.Repeat([]byte{9}, 32), "digest_key_version": 1, "result_json": fmt.Sprintf(`{"id":%q,"revision":"3","comp_revision":"2","status":"approved","proposal":null,"members":[]}`, a.proposal), "recorded_at": f.Repo.BindTime(f.Now)}
			if err := grantSchemaInsert(f.Repo, "compensation_command_receipt", receipt); err != nil {
				t.Fatal("safe replay metadata must persist", err)
			}
			unsafe := grantSchemaClone(receipt)
			unsafe["key"] = value.NewID()
			unsafe["result_json"] = `{"proposal":{"reason":"SYNTHETIC_SECRET"}}`
			if err := grantSchemaInsert(f.Repo, "compensation_command_receipt", unsafe); err == nil {
				t.Fatal("decrypted Proposal cannot enter receipt")
			}
			for _, query := range []string{"UPDATE compensation_command_receipt SET result_json='{}'", "DELETE FROM compensation_command_receipt", "UPDATE compensation_proposal SET revision=revision+1", "DELETE FROM compensation_proposal", "UPDATE compensation_aggregate SET revision=revision+2", "DELETE FROM compensation_aggregate"} {
				if _, err := f.Repo.DB.ExecContext(context.Background(), query); err == nil {
					t.Fatal("native immutable/terminal/CAS guard accepted", query)
				}
			}
		})
	}
}

func TestCompensationV7ZeroBaselineApprovalAndReplaceableProjection(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			employee := runtimeCreate(t, context.Background(), f, f.Owner, f.OrgID, "SYNTHETIC_ZERO_COMPENSATION").ID
			approver := grantSchemaSubject(t, f, f.OrgID)
			if err := grantSchemaInsert(f.Repo, "compensation_aggregate", map[string]any{"org_id": f.OrgID, "employee_id": employee, "revision": 0}); err != nil {
				t.Fatal("unestablished aggregate B0 must persist", err)
			}
			g := compensationNativeGraph(f, f.OrgID, employee, f.Owner.SubjectID, approver, 0, 1)
			if err := compensationNativeCommit(backend, f.Repo.DB, g.rows); err != nil {
				t.Fatal("first approved facts must reference frozen basis B0 and approved B1", err)
			}
			query := "UPDATE compensation_aggregate SET revision=1 WHERE org_id=? AND employee_id=? AND revision=0"
			if backend == "postgres" {
				query = "UPDATE compensation_aggregate SET revision=1 WHERE org_id=$1 AND employee_id=$2 AND revision=0"
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), query, f.OrgID, employee); err != nil {
				t.Fatal("aggregate CAS zero-to-one", err)
			}
			projection := map[string]any{"org_id": f.OrgID, "employee_id": employee, "effective_date": "2026-01-01", "term_id": g.term, "event_id": g.event, "revision": 1}
			if err := grantSchemaInsert(f.Repo, "compensation_schedule_projection", projection); err != nil {
				t.Fatal("B1 projection must persist", err)
			}
			for _, test := range []struct {
				name   string
				change func(map[string]any)
			}{
				{"unknown_event", func(r map[string]any) { r["event_id"] = value.NewID() }},
				{"unknown_term", func(r map[string]any) { r["term_id"] = value.NewID() }},
				{"wrong_projection_revision", func(r map[string]any) { r["revision"] = 2 }},
				{"zero_projection_revision", func(r map[string]any) { r["revision"] = 0 }},
				{"invalid_end_date", func(r map[string]any) { r["valid_to"] = "2026-02-30" }},
				{"empty_projection_interval", func(r map[string]any) { r["valid_to"] = "2026-01-02" }},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := grantSchemaClone(projection)
					r["effective_date"] = "2026-01-02"
					test.change(r)
					if err := grantSchemaInsert(f.Repo, "compensation_schedule_projection", r); err == nil {
						t.Fatal("invalid financial schedule projection persisted")
					}
				})
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), "UPDATE compensation_schedule_projection SET valid_to='2027-01-01'"); err != nil {
				t.Fatal("projection endpoints remain replaceable", err)
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), "DELETE FROM compensation_schedule_projection"); err != nil {
				t.Fatal("projection remains rebuildable", err)
			}
			if err := grantSchemaInsert(f.Repo, "compensation_schedule_projection", projection); err != nil {
				t.Fatal("complete projection rebuild", err)
			}
			if err := f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal("native projection changes preserve physical schema", err)
			}
		})
	}
}

func TestCompensationV7FinancialGrantsTypedObjectsAndAuthorityPairs(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f, a, b, c, approver := compensationNativeSeed(t, backend)
			grant := func(capability, kind, id string) map[string]any {
				g := grantSchemaGrant(f, f.Owner.SubjectID)
				g["capability"], g["category"], g["purpose"] = capability, "financial", "compensation_management"
				g["scope_kind"], g["scope_id"], g["employee_id"] = "employee", a.employee, a.employee
				if kind != "" {
					g["object_kind"], g["object_ref"], g["object_employee_id"], g[kind+"_id"] = kind, id, a.employee, id
				}
				return g
			}
			for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
				for _, object := range []struct{ kind, id string }{{"", ""}, {"compensation_proposal", a.proposal}, {"compensation_event", a.event}, {"compensation_term", a.term}} {
					if (capability == "compensation.propose" || capability == "compensation.approve") && (object.kind == "compensation_event" || object.kind == "compensation_term") {
						continue
					}
					if err := grantSchemaInsert(f.Repo, "access_grant", grant(capability, object.kind, object.id)); err != nil {
						t.Fatal("valid finite financial grant", err)
					}
				}
			}
			for _, test := range []struct {
				name   string
				row    map[string]any
				change func(map[string]any)
			}{
				{"wrong_category", grant("compensation.read", "", ""), func(g map[string]any) { g["category"] = "metadata" }},
				{"wrong_purpose", grant("compensation.read", "", ""), func(g map[string]any) { g["purpose"] = "interview_followup" }},
				{"other_employee_event", grant("compensation.read", "compensation_event", b.event), func(g map[string]any) {}},
				{"foreign_term", grant("compensation.read", "compensation_term", c.term), func(g map[string]any) {}},
				{"mixed_typed_objects", grant("compensation.read", "compensation_proposal", a.proposal), func(g map[string]any) { g["compensation_event_id"] = a.event }},
				{"proposal_capability_on_event", grant("compensation.propose", "compensation_event", a.event), func(g map[string]any) {}},
				{"approve_capability_on_term", grant("compensation.approve", "compensation_term", a.term), func(g map[string]any) {}},
				{"relation_bound_finance", grant("compensation.read", "", ""), func(g map[string]any) { g["relation_bound"] = true }},
			} {
				t.Run(test.name, func(t *testing.T) {
					test.change(test.row)
					if err := grantSchemaInsert(f.Repo, "access_grant", test.row); err == nil {
						t.Fatal("invalid typed financial grant persisted")
					}
				})
			}
			exact := grant("compensation.read", "compensation_term", a.term)
			if err := grantSchemaInsert(f.Repo, "access_grant", exact); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE access_grant SET compensation_term_id=?,object_ref=? WHERE id=?"
			if backend == "postgres" {
				query = "UPDATE access_grant SET compensation_term_id=$1,object_ref=$2 WHERE id=$3"
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), query, b.term, b.term, exact["id"]); err == nil {
				t.Fatal("exact financial object grant was rebound")
			}
			for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
				authority := grantSchemaAuthority(f, f.OrgID, f.Owner.SubjectID, approver)
				authority["capability"], authority["category"], authority["purpose"] = capability, "financial", "compensation_management"
				if err := grantSchemaInsert(f.Repo, "delegation_authority", authority); err != nil {
					t.Fatal("approved finite financial authority", err)
				}
				bad := grantSchemaClone(authority)
				bad["id"] = value.NewID()
				bad["category"] = "pii"
				if err := grantSchemaInsert(f.Repo, "delegation_authority", bad); err == nil {
					t.Fatal("invalid financial authority pair")
				}
			}
			for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve"} {
				if err := grantSchemaInsert(f.Repo, "capability_assignment", map[string]any{"org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "capability": capability, "scope_kind": "employee", "scope_id": a.employee, "employee_id": a.employee}); err != nil {
					t.Fatal("financial responsibility assignment", err)
				}
			}
		})
	}
}

func compensationNativeProof(f *testsupport.Fixture, digest []byte, action string) map[string]any {
	return map[string]any{"state_hash": []byte(strings.ReplaceAll(value.NewID(), "-", "")), "binding_hash": bytes.Repeat([]byte{23}, 32), "sealed_bytes": bytes.Repeat([]byte{27}, 28), "key_version": 1, "created_at": f.Repo.BindTime(f.Now), "expires_at": f.Repo.BindTime(f.Now.Add(5 * time.Minute)), "mode": "step_up", "action": action, "return_route": "/employees", "previous_hash": f.Owner.Hash, "expected_org": f.OrgID, "expected_subject": f.Owner.SubjectID, "expected_epoch": 1, "expected_identity": digest, "consumed": false}
}

func TestAssessmentV9OIDCProofActionAllowlist(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			digest := []byte(strings.ReplaceAll(value.NewID(), "-", ""))
			if err := grantSchemaInsert(f.Repo, "subject_identity", map[string]any{"digest": digest, "key_version": 1, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "active": true}); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{"pii.write", "access_grant.manage", "note.publish", "sensitive.export", "compensation.read", "compensation.propose", "compensation.approve", "bonus.target.manage", "bonus.propose", "bonus.approve", "bonus.payment.record", "compensation.extension.manage", "interview_policy.manage"} {
				if err := grantSchemaInsert(f.Repo, "oidc_transaction", compensationNativeProof(f, digest, action)); err != nil {
					t.Fatal("finite step-up intent must persist", action, err)
				}
			}
			for _, action := range []string{"compensation.write", "bonus.write", "compensation.export"} {
				if err := grantSchemaInsert(f.Repo, "oidc_transaction", compensationNativeProof(f, digest, action)); err == nil {
					t.Fatal("unimplemented proof intent persisted", action)
				}
			}
		})
	}
}

func compensationNativeV6History(t *testing.T, f *testsupport.Fixture, employee string) {
	t.Helper()
	x := interviewSchemaFixture{f: f, employee: employee, interview: value.NewID(), head: value.NewID(), version: value.NewID()}
	version, payload := x.noteRows(x.head, x.version, "shared", "published", 1)
	rows := []compensationSchemaRow{
		{"interview", map[string]any{"org_id": f.OrgID, "id": x.interview, "employee_id": employee, "status": "scheduled", "revision": 1, "scheduled_at": f.Repo.BindTime(f.Now), "backfilled": false, "author_subject_id": f.Owner.SubjectID, "recorded_at": f.Repo.BindTime(f.Now)}},
		{"note_head", map[string]any{"org_id": f.OrgID, "id": x.head, "employee_id": employee, "interview_id": x.interview, "category": "shared", "revision": 1, "acl_epoch": 1, "published_version_id": x.version}},
		{"note_version", version}, {"interview_payload", payload},
	}
	if err := compensationNativeCommit(f.Backend, f.Repo.DB, rows); err != nil {
		t.Fatal("native deployed v6 history", err)
	}
	grant := x.grant("note.publish", "shared", "note_head", x.head)
	if err := grantSchemaInsert(f.Repo, "access_grant", grant); err != nil {
		t.Fatal(err)
	}
	if err := grantSchemaInsert(f.Repo, "access_grant_source_approval", map[string]any{"org_id": f.OrgID, "grant_id": grant["id"], "source_note_version_id": x.version, "employee_id": employee, "source_category": "shared"}); err != nil {
		t.Fatal("v6 immutable source approval", err)
	}
	digest := []byte(strings.ReplaceAll(value.NewID(), "-", ""))
	if err := grantSchemaInsert(f.Repo, "subject_identity", map[string]any{"digest": digest, "key_version": 1, "org_id": f.OrgID, "subject_id": f.Owner.SubjectID, "active": true}); err != nil {
		t.Fatal(err)
	}
	if err := grantSchemaInsert(f.Repo, "oidc_transaction", compensationNativeProof(f, digest, "note.publish")); err != nil {
		t.Fatal("pending old step-up proof", err)
	}
}

func TestCompensationV7PopulatedV6UpgradePreservesAllOriginalColumnsAndHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			employee := migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V6_ORIGINAL"}, "")
			migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V6_CURRENT"}, employee.ID)
			for version := 2; version <= 6; version++ {
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
			compensationNativeV6History(t, f, employee.ID)
			before := interviewMigrationFacts(t, f.Repo)
			ledger := before["schema_version"]
			delete(before, "schema_version")
			if err := f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("genuine populated v6 must migrate", err)
			}
			after := interviewMigrationFacts(t, f.Repo)
			migrationOriginalUnchanged(t, before, after)
			if len(after["schema_version"]) != 10 {
				t.Fatal("exact v10 migration ledger required")
			}
			runtimeUnchanged(t, map[string][][]any{"schema_version": ledger}, map[string][][]any{"schema_version": after["schema_version"][:6]})
			for table := range after {
				if strings.HasPrefix(table, "compensation_") && f.Count(t, table) != 0 {
					t.Fatal("upgrade invented financial facts", table)
				}
			}
			view, err := f.Service.Read(context.Background(), f.Request(f.Owner), employee.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.DisplayName != "SYNTHETIC_V6_CURRENT" {
				t.Fatal("old encrypted payload/AAD must remain readable", err)
			}
			if err = f.Repo.CheckSchema(context.Background()); err != nil {
				t.Fatal("v8 physical schema must pass exact reference", err)
			}
			stable := interviewMigrationFacts(t, f.Repo)
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, stable, interviewMigrationFacts(t, f.Repo))
		})
	}
}

func TestCompensationV7InterruptedCutoverRestoresV6AndPhysicalDriftRefusesStartup(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := migrationV1Fixture(t, backend)
			migrationV1Profile(t, f, organization.Profile{DisplayName: "SYNTHETIC_V6_ROLLBACK"}, "")
			for version := 2; version <= 6; version++ {
				migrationInstallVersion(t, f.Repo, version)
			}
			before := interviewMigrationFacts(t, f.Repo)
			tx, err := f.Repo.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, statement := range migrationSQL(t, backend, 7) {
				if _, err = tx.ExecContext(context.Background(), statement); err != nil {
					t.Fatal("real v7 cutover prefix", err)
				}
				if statement == "DROP TABLE access_grant;" || strings.HasPrefix(statement, "ALTER TABLE access_grant ADD COLUMN compensation_event_id") {
					break
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			runtimeUnchanged(t, before, interviewMigrationFacts(t, f.Repo))
			if err = f.Repo.Migrate(context.Background()); err != nil {
				t.Fatal("rollback left migration unrecoverable", err)
			}
			query := "DROP TRIGGER compensation_event_no_update"
			if backend == "postgres" {
				query = "DROP TRIGGER compensation_event_immutable ON compensation_event"
			}
			if _, err = f.Repo.DB.ExecContext(context.Background(), query); err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.CheckSchema(context.Background()); !errors.Is(err, fault.Unavailable) {
				t.Fatal("missing native immutability must refuse startup", err)
			}
		})
	}
}
