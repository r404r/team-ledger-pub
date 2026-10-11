package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestR2TeamCreationPersistsAndHonorsHalfOpenTreeProjection(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID
			command := `{"code":"SYNTHETIC_TEAM_A","lifecycle":{"valid_from":"2026-01-01","valid_to":"2027-01-01"}}`
			key := value.NewID()
			var made, replay struct {
				ID string `json:"id"`
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", path+"/teams", command, key), 201, &made)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", path+"/teams", command, key), 201, &replay)
			if !value.ValidID(made.ID) || made.ID != replay.ID {
				t.Fatal("same authorized creation must confirm the committed stable team identity")
			}
			for _, at := range []struct {
				date    string
				visible bool
			}{{"2026-12-31", true}, {"2027-01-01", false}} {
				var tree struct {
					Nodes []struct {
						ID   string `json:"id"`
						Code string `json:"code"`
					} `json:"nodes"`
				}
				apiSend(t, f, apiRequest(t, f, f.Owner, "GET", path+"/tree?as_of="+at.date, "", ""), 200, &tree)
				found := false
				for _, node := range tree.Nodes {
					if node.ID == made.ID {
						found = true
						if node.Code != "SYNTHETIC_TEAM_A" {
							t.Fatal("tree must project the persisted team, not a fixture-only label")
						}
					}
				}
				if found != at.visible {
					t.Fatalf("team visibility at %s=%t;want%t", at.date, found, at.visible)
				}
			}
		})
	}
}

func structureJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestR2AtomicTransferProjectsDirectoryDetailAndHistoryWithoutMetadataPII(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			base := "/api/v1/orgs/" + f.OrgID
			var teams [2]organization.StructureResult
			for i, code := range []string{"SYNTHETIC_TEAM_A", "SYNTHETIC_TEAM_B"} {
				body := structureJSON(t, map[string]any{"code": code, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}, "label": "SYNTHETIC_PRIVATE_TEAM_LABEL"})
				apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/teams", body, value.NewID()), 201, &teams[i])
			}
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/employees", createJSON, value.NewID()), 201, &employee)
			var tree organization.TreeView
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", base+"/tree?as_of=2026-10-11", "", ""), 200, &tree)
			first := map[string]any{
				"expected_graph_revision": tree.GraphRevision,
				"changes": []map[string]any{
					{"action": "add", "kind": "membership", "employee_id": employee.ID, "team_id": teams[1].ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}},
					{"action": "add", "kind": "position", "employee_id": employee.ID, "team_id": teams[1].ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}, "position": map[string]any{"title": "SYNTHETIC_PRIVATE_POSITION_X", "position_code": strings.Repeat("X", 64)}},
					{"action": "add", "kind": "team_parent", "team_id": teams[1].ID, "parent_team_id": teams[0].ID, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}},
				},
			}
			for _, code := range []any{strings.Repeat("X", 65), " ", nil, 17} {
				invalid := map[string]any{
					"expected_graph_revision": tree.GraphRevision,
					"changes": []map[string]any{
						{"action": "add", "kind": "position", "employee_id": employee.ID, "team_id": teams[1].ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}, "position": map[string]any{"title": "SYNTHETIC_PRIVATE_POSITION_X", "position_code": code}},
					},
				}
				apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", structureJSON(t, invalid), value.NewID()), 422, nil)
			}
			var initial organization.StructureResult
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", structureJSON(t, first), value.NewID()), 201, &initial)
			refs := make(map[string]string)
			for _, item := range initial.Items {
				refs[item.Kind] = item.ID
			}
			if !value.ValidID(refs["membership"]) || !value.ValidID(refs["position"]) {
				t.Fatal("committed relationship identities must support precise future termination")
			}
			transfer := map[string]any{
				"expected_graph_revision": initial.GraphRevision,
				"reason":                  "SYNTHETIC_PRIVATE_TRANSFER_REASON",
				"changes": []map[string]any{
					{"action": "end", "kind": "membership", "ref": refs["membership"], "end_date": "2027-01-01"},
					{"action": "end", "kind": "position", "ref": refs["position"], "end_date": "2027-01-01"},
					{"action": "add", "kind": "membership", "employee_id": employee.ID, "team_id": teams[0].ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2027-01-01", "valid_to": nil}},
					{"action": "add", "kind": "position", "employee_id": employee.ID, "team_id": teams[0].ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2027-01-01", "valid_to": nil}, "position": map[string]any{"title": "SYNTHETIC_PRIVATE_POSITION_Y", "position_code": "ROLE_Y"}},
				},
			}
			var moved, replay organization.StructureResult
			key, body := value.NewID(), structureJSON(t, transfer)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", body, key), 201, &moved)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", body, key), 201, &replay)
			if moved.ID != replay.ID || moved.GraphRevision != replay.GraphRevision {
				t.Fatal("original committed transfer must confirm despite its now-stale input revision")
			}
			for _, at := range []struct{ date, team, title, code string }{{"2026-12-31", teams[1].ID, "SYNTHETIC_PRIVATE_POSITION_X", strings.Repeat("X", 64)}, {"2027-01-01", teams[0].ID, "SYNTHETIC_PRIVATE_POSITION_Y", "ROLE_Y"}} {
				path := "/api/v1/employees/" + employee.ID + "?as_of=" + at.date
				var detail organization.View
				apiSend(t, f, apiRequest(t, f, f.Owner, "GET", path+"&include_profile=true", "", ""), 200, &detail)
				if len(detail.Memberships) != 1 || detail.Memberships[0].TeamID != at.team || len(detail.Positions) != 1 || detail.Positions[0].Position == nil || detail.Positions[0].Position.Title != at.title || detail.Positions[0].Position.PositionCode == nil || *detail.Positions[0].Position.PositionCode != at.code {
					t.Fatal("employee as_of projection must switch both primary assignments at the exact half-open boundary")
				}
				var page organization.DirectoryPage
				query := structureJSON(t, map[string]any{"as_of": at.date, "team_id": at.team, "q": "SYNTHETIC_API_PROFILE", "include_profile": true, "limit": 1})
				apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/employees/query", query, ""), 200, &page)
				if len(page.Items) != 1 || page.Items[0].ID != employee.ID || page.Items[0].Profile == nil || page.Items[0].Profile.DisplayName != "SYNTHETIC_API_PROFILE" {
					t.Fatal("body-only authorized directory must project the persisted profile and dated membership without requiring a mutation key")
				}
				var metadata organization.View
				apiSend(t, f, apiRequest(t, f, f.Observer, "GET", path+"&include_profile=false", "", ""), 200, &metadata)
				if metadata.Profile != nil || metadata.Revision != "" || len(metadata.Positions) != 1 || metadata.Positions[0].Position != nil {
					t.Fatal("metadata-only organization view cannot disclose profile revision or sensitive position title")
				}
			}
			var history organization.HistoryPage
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/employees/"+employee.ID+"/organization-history", "", ""), 200, &history)
			old, newer, reason := false, false, false
			for _, change := range history.Items {
				if change.ID == moved.ID && change.Reason != nil && *change.Reason == "SYNTHETIC_PRIVATE_TRANSFER_REASON" {
					reason = true
				}
				for _, item := range change.Items {
					old = old || item.ID == refs["membership"] && item.TeamID == teams[1].ID
					newer = newer || item.Kind == "membership" && item.TeamID == teams[0].ID && item.ValidFrom == "2027-01-01"
				}
			}
			if !old || !newer || !reason {
				t.Fatal("history must retain original stable tenure, new transfer fact and independently approved encrypted reason")
			}
			var safe organization.HistoryPage
			apiSend(t, f, apiRequest(t, f, f.Observer, "GET", "/api/v1/employees/"+employee.ID+"/organization-history", "", ""), 200, &safe)
			for _, change := range safe.Items {
				if change.Reason != nil {
					t.Fatal("metadata history cannot disclose encrypted reason")
				}
				for _, item := range change.Items {
					if item.Position != nil {
						t.Fatal("metadata history cannot disclose historical sensitive title")
					}
				}
			}
			search := `{"as_of":"2026-10-11","q":"SYNTHETIC_API_PROFILE","include_profile":true}`
			apiSend(t, f, apiRequest(t, f, f.Observer, "POST", base+"/employees/query", search, ""), 403, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/employees/query?q=private", search, ""), 403, nil)
		})
	}
}

func TestR2HistoryRecordedDateWindowExcludesStopDayDespiteFutureEffectiveDate(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			base := "/api/v1/orgs/" + f.OrgID
			var team organization.StructureResult
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/teams", `{"code":"FUTURE_RECORDED","lifecycle":{"valid_from":"2026-01-01","valid_to":null}}`, value.NewID()), 201, &team)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/employees", createJSON, value.NewID()), 201, &employee)
			command := map[string]any{"expected_graph_revision": team.GraphRevision, "changes": []map[string]any{{"action": "add", "kind": "membership", "employee_id": employee.ID, "team_id": team.ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2027-01-01", "valid_to": nil}}}}
			var made organization.StructureResult
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", structureJSON(t, command), value.NewID()), 201, &made)
			day, before, next := f.Now.Format("2006-01-02"), f.Now.AddDate(0, 0, -1).Format("2006-01-02"), f.Now.AddDate(0, 0, 1).Format("2006-01-02")
			var excluded, included organization.HistoryPage
			history := "/api/v1/employees/" + employee.ID + "/organization-history"
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", history+"?from="+before+"&to="+day, "", ""), 200, &excluded)
			if len(excluded.Items) != 0 {
				t.Fatal("UTC recorded stop day must be excluded, not extended by one day in SQL")
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", history+"?from="+day+"&to="+next, "", ""), 200, &included)
			if len(included.Items) != 1 || included.Items[0].ID != made.ID || len(included.Items[0].Items) != 1 || included.Items[0].Items[0].ValidFrom != "2027-01-01" {
				t.Fatal("history recorded-date window must include the exact future-effective immutable fact recorded today")
			}
		})
	}
}

func TestR2StructureReceiptDeniesCurrentScopeLossBeforeDigestDisclosure(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			base := "/api/v1/orgs/" + f.OrgID
			var team organization.StructureResult
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/teams", `{"code":"RECEIPT_SCOPE","lifecycle":{"valid_from":"2026-01-01","valid_to":null}}`, value.NewID()), 201, &team)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/employees", createJSON, value.NewID()), 201, &employee)
			key := value.NewID()
			command := map[string]any{"expected_graph_revision": team.GraphRevision, "changes": []map[string]any{{"action": "add", "kind": "membership", "employee_id": employee.ID, "team_id": team.ID, "is_primary": true, "lifecycle": map[string]any{"valid_from": "2026-01-01", "valid_to": nil}}}}
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", structureJSON(t, command), key), 201, nil)
			var page struct {
				Items []authz.GrantDTO `json:"items"`
				Epoch string           `json:"auth_epoch"`
			}
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", "/api/v1/access-grants?subject_id="+f.Owner.SubjectID+"&category=metadata", "", ""), 200, &page)
			var writer authz.GrantDTO
			for _, item := range page.Items {
				if item.Capability == "organization.write" {
					writer = item
				}
			}
			if !value.ValidID(writer.ID) {
				t.Fatal("actual original write grant must be found for scope-loss consumer scenario")
			}
			revoke := structureJSON(t, map[string]any{"expected_revision": writer.Revision, "expected_auth_epoch": page.Epoch, "reason": "policy_change"})
			apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants/"+writer.ID+"/revoke", revoke, value.NewID()), 200, nil)
			command["expected_graph_revision"] = "999"
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", base+"/structure-changes", structureJSON(t, command), key), 403, nil)
		})
	}
}
