package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func financeHTTPRequest(t *testing.T, f *testsupport.Fixture, c testsupport.Credential, method, path, body, key string) *http.Request {
	t.Helper()
	r := apiRequest(t, f, c, method, path, body, key)
	r.Header.Set("X-Access-Purpose", "compensation_management")
	return r
}

func TestFinanceHTTPIndependentApprovalExactMoneyAndStrictNestedInput(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), 201, &employee)
			base := "/api/v1/employees/" + employee.ID + "/compensation"
			var session struct {
				ScopeKind   string                    `json:"scope_kind"`
				ScopeID     string                    `json:"scope_id"`
				Permissions []compensation.Permission `json:"compensation_permissions"`
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", "/api/v1/session?employee_id="+employee.ID, "", ""), 200, &session)
			if session.ScopeKind != "employee" || session.ScopeID != employee.ID || len(session.Permissions) != 1 || session.Permissions[0].Capability != "compensation.read" {
				t.Fatal("independent scoped FinR session must expose only its actual financial read capability without directory authority")
			}
			apiSend(t, f, apiRequest(t, f, f.FinR, "GET", "/api/v1/session?employee_id="+employee.ID, "", ""), 404, nil)
			var current compensation.CurrentView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", base+"?as_of=2026-01-01", "", ""), 200, &current)
			if current.CurrentTerm != nil {
				t.Fatal("unestablished compensation must not be zero salary")
			}
			amount := "9007199254740993"
			command := compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: current.CompRevision, After: &compensation.Terms{Currency: "CNY", Scale: 0, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}, Reason: "SYNTHETIC_FINANCE_HTTP_REASON", Members: []compensation.CorrectionMember{}}
			body := structureJSON(t, command)
			for _, bad := range []string{
				strings.Replace(body, `"currency":"CNY"`, `"currency":"CNY","currency":"CNY"`, 1),
				strings.Replace(body, `"currency":"CNY"`, `"currency":"CNY","unknown":true`, 1),
				strings.Replace(body, `"components":[]`, `"components":null`, 1),
				strings.Replace(body, `"amount_minor":"9007199254740993"`, `"amount_minor":9007199254740993`, 1),
				strings.Replace(body, `"scale":0`, `"scale":null`, 1),
			} {
				apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "POST", base+"/proposals", bad, value.NewID()), 422, nil)
			}
			for _, query := range []string{"?as_of=2026-01-01&as_of=2026-01-02", "?as_of=2026-01-01&unknown=x", "?as_of=2026-01-01&future_limit=101"} {
				apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", base+query, "", ""), 422, nil)
			}
			var draft compensation.Result
			key := value.NewID()
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "POST", base+"/proposals", body, key), 201, &draft)
			var replay compensation.Result
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "POST", base+"/proposals", body, key), 201, &replay)
			if replay.ID != draft.ID {
				t.Fatal("explicit original request confirmation must not create a second proposal")
			}
			patch := "/api/v1/compensation/proposals/" + draft.ID
			edit := compensation.DraftCommand{Kind: command.Kind, EffectiveDate: command.EffectiveDate, CompRevision: draft.CompRevision, After: command.After, Reason: "SYNTHETIC_EDITED_REASON", Members: command.Members, Revision: draft.Revision}
			var edited compensation.Result
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "PATCH", patch, structureJSON(t, edit), value.NewID()), 200, &edited)
			if edited.ID != draft.ID || edited.Revision == draft.Revision {
				t.Fatal("draft edit must append a proposal revision without replacing identity")
			}
			draft = edited
			var proposals compensation.ChangesView
			history := base + "/changes?from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z&record_kind=proposals"
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", history, "", ""), 200, &proposals)
			if len(proposals.Proposals) != 1 || proposals.Proposals[0].Revision != draft.Revision || proposals.Proposals[0].Reason != edit.Reason {
				t.Fatal("proposal history must reload current draft fields and revision independently from salary")
			}
			revisionPath := base + "/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID
			for _, query := range []string{
				"/changes?record_kind=proposal_revisions",
				"/changes?record_kind=proposal_revisions&proposal_id=invalid",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&proposal_id=" + draft.ID,
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&from=2026-01-01T00:00:00Z",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&to=2027-01-01T00:00:00Z",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&status=draft",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&limit=0",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&limit=101",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&limit=01",
				"/changes?record_kind=proposal_revisions&proposal_id=" + draft.ID + "&unknown=x",
				"/changes?record_kind=proposals&proposal_id=" + draft.ID,
				"/changes?record_kind=approvals&from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z&status=approved",
			} {
				apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", base+query, "", ""), 422, nil)
			}
			var revisions compensation.ChangesView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", revisionPath, "", ""), 200, &revisions)
			if revisions.RecordKind != "proposal_revisions" || len(revisions.Proposals) != 1 || revisions.Proposals[0].Revision != draft.Revision || len(revisions.Approvals) != 0 || len(revisions.Revisions) != 2 || revisions.Revisions[0].Command.Reason != edit.Reason || revisions.Revisions[1].Command.Reason != command.Reason || revisions.NextCursor != "" || len(proposals.Revisions) != 0 {
				t.Fatal("independent revisions must preserve original commands in descending order while ordinary proposal reads remain head-only")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", revisionPath+"&limit=1", "", ""), 200, &revisions)
			if len(revisions.Revisions) != 1 || revisions.Revisions[0].Revision != draft.Revision || revisions.NextCursor == "" {
				t.Fatal("latest revision page must expose a bounded page and an older-page cursor")
			}
			oldCursor := revisions.NextCursor
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", revisionPath+"&limit=1&cursor="+url.QueryEscape(oldCursor), "", ""), 200, &revisions)
			if len(revisions.Revisions) != 1 || revisions.Revisions[0].Revision != "1" || revisions.Revisions[0].Command.Reason != command.Reason || revisions.Proposals[0].Revision != draft.Revision || revisions.NextCursor != "" {
				t.Fatal("older revision page must retain the current head and release only the original revision")
			}
			var submitted compensation.Result
			path := "/api/v1/compensation/proposals/" + draft.ID + "/transitions"
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "POST", path, structureJSON(t, compensation.TransitionCommand{Action: "submit", Revision: draft.Revision, CompRevision: draft.CompRevision}), value.NewID()), 200, &submitted)
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", revisionPath+"&limit=1&cursor="+url.QueryEscape(oldCursor), "", ""), 422, nil)
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "POST", path, structureJSON(t, compensation.TransitionCommand{Action: "approve", Revision: submitted.Revision, CompRevision: submitted.CompRevision, DecisionReason: "SYNTHETIC_APPROVAL"}), value.NewID()), 403, nil)
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", base+"?as_of=2026-01-01", "", ""), 200, &current)
			if current.CurrentTerm != nil {
				t.Fatal("submitted proposal must not affect current compensation")
			}
			var approved compensation.Result
			apiSend(t, f, financeHTTPRequest(t, f, f.CompApprover, "POST", path, structureJSON(t, compensation.TransitionCommand{Action: "approve", Revision: submitted.Revision, CompRevision: submitted.CompRevision, DecisionReason: "SYNTHETIC_APPROVAL"}), value.NewID()), 200, &approved)
			edit.Revision = approved.Revision
			edit.CompRevision = approved.CompRevision
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, "PATCH", patch, structureJSON(t, edit), value.NewID()), 409, nil)
			var approvals compensation.ChangesView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", strings.Replace(history, "record_kind=proposals", "record_kind=approvals", 1), "", ""), 200, &approvals)
			if len(approvals.Approvals) != 1 || approvals.Approvals[0].ApproverSubjectID != f.CompApprover.SubjectID || len(approvals.Approvals[0].Events) != 1 {
				t.Fatal("approved history must preserve independent approval and immutable event facts")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "GET", base+"?as_of=2026-01-01", "", ""), 200, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != amount {
				t.Fatal("finance API must preserve money above JavaScript safe integer exactly")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.Owner, "GET", base+"?as_of=2026-01-01", "", ""), 404, nil)
			export := compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: "compensation_proposal", ID: approved.ID, ExpectedRevision: approved.Revision}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, "POST", "/api/v1/sensitive-exports", structureJSON(t, export), value.NewID()), 403, nil)
		})
	}
}
