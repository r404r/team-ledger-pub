package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func apiRequest(t *testing.T, f *testsupport.Fixture, c testsupport.Credential, method, path, body, key string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, f.Server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: c.Token})
	r.Header.Set("X-Access-Purpose", "organization_management")
	r.Header.Set("X-CSRF-Token", c.CSRF)
	r.Header.Set("Origin", f.Server.URL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	return r
}
func apiSend(t *testing.T, f *testsupport.Fixture, r *http.Request, status int, out any) {
	t.Helper()
	res, err := f.Server.Client().Do(r)
	if err != nil {
		t.Fatal("real TLS API request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		t.Fatalf("real API HTTP status=%d;want%d body=%s", res.StatusCode, status, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive response must not be cached")
	}
	if out != nil {
		if json.NewDecoder(res.Body).Decode(out) != nil {
			t.Fatal("safe JSON response decoding failed")
		}
	} else {
		_, _ = io.Copy(io.Discard, res.Body)
	}
}

const createJSON = `{"profile":{"local_name":"SYNTHETIC_API_PROFILE","english_name":"Synthetic API Profile"},"lifecycle":{"valid_from":"2026-01-01","valid_to":null}}`

func structureJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestAPIProfileCreateReloadCorrectionAndSafeRejection(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID + "/employees"
			key := value.NewID()
			var made, again organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", path, createJSON, key), 201, &made)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", path, createJSON, key), 201, &again)
			if made != again || f.Count(t, "employee") != 1 {
				t.Fatal("actual HTTP replay duplicated creation")
			}
			get := "/api/v1/employees/" + made.ID + "?as_of=2026-10-11&include_profile=true"
			var first organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", get, "", ""), 200, &first)
			if first.Profile == nil || first.Profile.LocalName != "SYNTHETIC_API_PROFILE" || first.Revision != "1" {
				t.Fatal("HTTP reload must expose actual authorized saved profile")
			}
			var updated organization.Result
			patch := "/api/v1/employees/" + made.ID + "/profile"
			body := `{"expected_profile_revision":"1","profile":{"local_name":"SYNTHETIC_API_REPLACEMENT","english_name":"Synthetic API Replacement"},"edit_reason":"SYNTHETIC_API_PRIVATE_REASON"}`
			apiSend(t, f, apiRequest(t, f, f.Owner, "PATCH", patch, body, value.NewID()), 200, &updated)
			if updated.Revision != "2" {
				t.Fatal("HTTP correction must confirm revision2")
			}
			var after organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", get, "", ""), 200, &after)
			if after.Profile == nil || after.Profile.LocalName != "SYNTHETIC_API_REPLACEMENT" {
				t.Fatal("HTTP reload did not reflect committed correction")
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "PATCH", patch, body, value.NewID()), 409, nil)
			var metadata map[string]json.RawMessage
			apiSend(t, f, apiRequest(t, f, f.Observer, "GET", get, "", ""), 200, &metadata)
			if _, ok := metadata["profile"]; ok {
				t.Fatal("metadata-only API reader received PII")
			}
			if _, ok := metadata["profile_revision"]; ok {
				t.Fatal("metadata-only reader received hidden PII aggregate revision")
			}
			before := f.KMS.Calls.Load()
			f.KMS.Fail.Store(true)
			var forbidden map[string]any
			apiSend(t, f, apiRequest(t, f, f.Stranger, "GET", get, "", ""), 404, &forbidden)
			if f.KMS.Calls.Load() != before || forbidden["code"] != "NOT_FOUND" {
				t.Fatal("unreadable HTTP object contacted unavailable KMS or leaked wrong error")
			}
		})
	}
}

func TestAPIEmployeeCreateAtomicallyAddsStaffCodeAndDirectManager(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID + "/employees"
			var manager organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, createJSON, value.NewID()), http.StatusCreated, &manager)

			body := `{"profile":{"local_name":"SYNTHETIC_ATOMIC_EMPLOYEE"},"lifecycle":{"valid_from":"2026-10-11","valid_to":"2026-12-01"},"staff_code":"ATOMIC-0007","manager_employee_id":"` + manager.ID + `","expected_catalog_revision":"1","expected_graph_revision":"1"}`
			key := value.NewID()
			var made, replay map[string]string
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &made)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &replay)
			if made["id"] == "" || made["profile_revision"] != "1" || made["workforce_revision"] != "2" || made["graph_revision"] != "2" || !reflect.DeepEqual(made, replay) {
				t.Fatalf("atomic employee create receipt = %#v replay=%#v", made, replay)
			}
			if f.Count(t, "employee") != 2 || f.Count(t, "employee_business_identifier") != 1 || f.Count(t, "reporting_line") != 1 || f.Count(t, "structure_change") != 1 {
				t.Fatal("employee, identifier, and manager relation were not one committed unit")
			}

			var view organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/employees/"+made["id"]+"?as_of=2026-10-11&include_profile=true", "", ""), http.StatusOK, &view)
			if len(view.Identifiers) != 1 || view.Identifiers[0].StaffCode != "ATOMIC-0007" || view.Identifiers[0].ValidTo == nil || *view.Identifiers[0].ValidTo != "2026-12-01" ||
				view.DirectManager == nil || view.DirectManager.ManagerEmployeeID != manager.ID || view.DirectManager.ValidTo == nil || *view.DirectManager.ValidTo != "2026-12-01" {
				t.Fatalf("bounded atomic employee facts were not readable: %#v", view)
			}

			conflict := `{"profile":{"local_name":"SYNTHETIC_CONFLICT"},"lifecycle":{"valid_from":"2026-10-11","valid_to":null},"staff_code":"ATOMIC-0007","expected_catalog_revision":"1","expected_graph_revision":"2"}`
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, conflict, value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "employee") != 2 || f.Count(t, "employee_profile_version") != 2 {
				t.Fatal("staff-code conflict left a partial employee")
			}

			invalidManager := `{"profile":{"local_name":"SYNTHETIC_INVALID_MANAGER"},"lifecycle":{"valid_from":"2026-10-11","valid_to":null},"staff_code":"ATOMIC-0008","manager_employee_id":"10000000-0000-4000-8000-000000000099","expected_catalog_revision":"1","expected_graph_revision":"2"}`
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, invalidManager, value.NewID()), http.StatusNotFound, nil)
			if f.Count(t, "employee") != 2 || f.Count(t, "employee_business_identifier") != 1 {
				t.Fatal("invalid manager left partial employee or identifier")
			}
		})
	}
}

func TestAPIEmployeeCreateAtomicallyAddsCompleteMasterData(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			catalogs := seedCompleteEmployeeCatalogs(t, f)
			body := `{"profile":{"local_name":"SYNTHETIC_COMPLETE_EMPLOYEE","english_name":"Synthetic Complete Employee"},"lifecycle":{"valid_from":"2026-10-11","valid_to":null},"staff_code":"COMPLETE-0007","employment":{"legal_entity_id":"` + catalogs.Items[0].ID + `","location_code":"Shanghai"},"education":{"level":"Master"},"job_assignment":{"department_id":"` + catalogs.Items[3].ID + `","job_family_id":"` + catalogs.Items[4].ID + `","career_level_id":"` + catalogs.Items[5].ID + `","position":{"title":"Consultant"}},"expected_catalog_revision":"3","expected_graph_revision":"3"}`
			var made map[string]string
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", body, value.NewID()), http.StatusCreated, &made)
			if made["profile_revision"] != "1" || made["workforce_revision"] != "2" || made["graph_revision"] != "3" {
				t.Fatalf("complete employee receipt = %#v", made)
			}
			if f.Count(t, "employee") != 1 || f.Count(t, "employee_business_identifier") != 1 || f.Count(t, "employment_spell") != 1 || f.Count(t, "education_record") != 1 || f.Count(t, "job_assignment") != 1 || f.Count(t, "structure_change") != 3 {
				t.Fatal("complete employee facts were not one committed unit")
			}
			var view organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/employees/"+made["id"]+"?as_of=2026-10-11&include_profile=true", "", ""), http.StatusOK, &view)
			if len(view.Identifiers) != 1 || len(view.Employment) != 1 || len(view.Education) != 1 || len(view.JobAssignments) != 1 ||
				view.Employment[0].LegalEntityID != catalogs.Items[0].ID || view.Employment[0].LocationCode != "Shanghai" ||
				view.Education[0].Level != "Master" || view.JobAssignments[0].DepartmentID != catalogs.Items[3].ID ||
				view.JobAssignments[0].JobFamilyID == nil || *view.JobAssignments[0].JobFamilyID != catalogs.Items[4].ID ||
				view.JobAssignments[0].CareerLevelID == nil || *view.JobAssignments[0].CareerLevelID != catalogs.Items[5].ID ||
				view.JobAssignments[0].Position == nil || view.JobAssignments[0].Position.Title != "Consultant" {
				t.Fatalf("complete employee projection = %#v", view)
			}
		})
	}
}

func TestAPIRejectsFramingAndAmbiguousJSONWithoutWrite(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID + "/employees"
			for _, tc := range []struct {
				name, body string
				status     int
				alter      func(*http.Request)
			}{
				{"unknown field", `{"profile":{"local_name":"synthetic","private_extra":"SYNTHETIC_UNKNOWN"},"lifecycle":{"valid_from":"2026-01-01"}}`, 422, nil},
				{"duplicate field", `{"profile":{"local_name":"synthetic","local_name":"SYNTHETIC_DUPLICATE"},"lifecycle":{"valid_from":"2026-01-01"}}`, 422, nil},
				{"noncanonical case", `{"Profile":{"local_name":"synthetic"},"lifecycle":{"valid_from":"2026-01-01"}}`, 422, nil},
				{"case collision", `{"profile":{"local_name":"synthetic","Local_Name":"SYNTHETIC_CASE_OVERRIDE"},"lifecycle":{"valid_from":"2026-01-01"}}`, 422, nil},
				{"invalid UTF8", "{\"profile\":{\"local_name\":\"" + string([]byte{0xff}) + "\"},\"lifecycle\":{\"valid_from\":\"2026-01-01\"}}", 422, nil},
				{"unsupported media", createJSON, 415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
				{"oversized body", `{"profile":{"local_name":"synthetic","profile_summary":"` + strings.Repeat("x", 257<<10) + `"},"lifecycle":{"valid_from":"2026-01-01"}}`, 413, nil},
				{"profile payload bound", `{"profile":{"local_name":"synthetic","profile_summary":"` + strings.Repeat("x", 17<<10) + `"},"lifecycle":{"valid_from":"2026-01-01"}}`, 422, nil},
				{"missing CSRF", createJSON, 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
				{"cross Origin", createJSON, 403, func(r *http.Request) { r.Header.Set("Origin", "https://untrusted.invalid") }},
				{"cross site", createJSON, 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
				{"duplicate cookie", createJSON, 401, func(r *http.Request) {
					r.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: f.Owner.Token})
				}},
				{"missing cookie", createJSON, 401, func(r *http.Request) { r.Header.Del("Cookie") }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req := apiRequest(t, f, f.Owner, "POST", path, tc.body, value.NewID())
					if tc.alter != nil {
						tc.alter(req)
					}
					apiSend(t, f, req, tc.status, nil)
				})
			}
			if f.Count(t, "employee") != 0 || f.Count(t, "employee_profile_version") != 0 || f.Count(t, "command_receipt") != 0 || f.KMS.Calls.Load() != 0 {
				t.Fatal("rejected HTTP commands wrote state or contacted KMS")
			}
		})
	}
}

func TestAPIWrongOwnerNeverUsesClientSuppliedOrganization(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OtherOrgID + "/employees"
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", path, createJSON, value.NewID()), 404, nil)
			if f.Count(t, "employee") != 0 || f.KMS.Calls.Load() != 0 {
				t.Fatal("cross-org creation must not encrypt or persist")
			}
			if _, err := f.Service.Session(context.Background(), f.Request(f.Owner), ""); err != nil {
				t.Fatal("safe rejection must not silently revoke valid independent session")
			}
		})
	}
}

func TestEmployeeScopedSessionCanReadAndCorrectOnlyGrantedEmployee(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			createPath := "/api/v1/orgs/" + f.OrgID + "/employees"
			var first, second organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", createPath, createJSON, value.NewID()), 201, &first)
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", createPath, createJSON, value.NewID()), 201, &second)
			ctx := context.Background()
			if err := f.Exec(ctx, "DELETE FROM capability_assignment WHERE subject_id=?", "DELETE FROM capability_assignment WHERE subject_id=$1", f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			if err := f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE subject_id=?", "UPDATE access_grant SET revoked=true WHERE subject_id=$1", f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			for _, cap := range []string{"organization.read", "pii.read", "pii.write"} {
				category := "pii"
				if cap == "organization.read" {
					category = "metadata"
				}
				if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES(?,?,?,'employee',?,?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES($1,$2,$3,'employee',$4,$5)", f.OrgID, f.Owner.SubjectID, cap, first.ID, first.ID); err != nil {
					t.Fatal(err)
				}
				if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,?,?,'employee',?,?,'organization_management',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,$4,$5,'employee',$6,$7,'organization_management',$8,$9,true)", value.NewID(), f.OrgID, f.Owner.SubjectID, cap, category, first.ID, first.ID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Exec(ctx, "UPDATE organization SET timezone=? WHERE id=?", "UPDATE organization SET timezone=$1 WHERE id=$2", "Asia/Tokyo", f.OrgID); err != nil {
				t.Fatal(err)
			}
			zone, err := time.LoadLocation("Asia/Tokyo")
			if err != nil {
				t.Fatal(err)
			}
			var root, scoped struct {
				Capabilities []string `json:"capabilities"`
				BusinessDate string   `json:"business_date"`
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/session", "", ""), 200, &root)
			if len(root.Capabilities) != 0 || root.BusinessDate != f.Now.In(zone).Format("2006-01-02") {
				t.Fatal("employee-only root session returned wrong authority or organization business date", root)
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/session?employee_id="+first.ID, "", ""), 200, &scoped)
			for _, capability := range scoped.Capabilities {
				if capability == "organization.write" {
					t.Fatal("profile-only employee scope cannot advertise an unapproved organization-write action")
				}
			}
			get := "/api/v1/employees/" + first.ID + "?as_of=2026-10-11&include_profile=true"
			var view organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", get, "", ""), 200, &view)
			if view.Profile == nil || view.Profile.LocalName != "SYNTHETIC_API_PROFILE" {
				t.Fatal("employee scope cannot read approved profile")
			}
			var history organization.HistoryPage
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/employees/"+first.ID+"/organization-history?from=2026-10-01&to=2026-11-01&limit=10", "", ""), 200, &history)
			if len(history.Items) != 0 {
				t.Fatalf("employee-scoped empty organization history = %#v", history)
			}
			body := `{"expected_profile_revision":"1","profile":{"local_name":"SYNTHETIC_SCOPED_CORRECTION"},"edit_reason":"synthetic scoped correction"}`
			apiSend(t, f, apiRequest(t, f, f.Owner, "PATCH", "/api/v1/employees/"+first.ID+"/profile", body, value.NewID()), 200, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", get, "", ""), 200, &view)
			if view.Revision != "2" || view.Profile.LocalName != "SYNTHETIC_SCOPED_CORRECTION" {
				t.Fatal("employee-scoped correction did not persist")
			}
			before := f.KMS.Calls.Load()
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/session?employee_id="+second.ID, "", ""), 404, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/employees/"+second.ID+"?as_of=2026-10-11&include_profile=true", "", ""), 404, nil)
			if f.KMS.Calls.Load() != before {
				t.Fatal("ungranted employee summary/read reached KMS")
			}
		})
	}
}

func TestDeniedAuditFailurePreservesRefusalAndReportsSafeCorrelation(t *testing.T) {
	// Package cases are serial; restore the standard operational stream before exit.
	var operational bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&operational)
	defer log.SetOutput(previous)
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			createPath := "/api/v1/orgs/" + f.OrgID + "/employees"
			var made organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", createPath, createJSON, value.NewID()), 201, &made)
			calls := f.KMS.Calls.Load()
			if err := f.DisableAudit(ctx); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ name, method, path, body string }{
				{"create", "POST", createPath, createJSON},
				{"read", "GET", "/api/v1/employees/" + made.ID + "?as_of=2026-10-11&include_profile=true", ""},
				{"correct", "PATCH", "/api/v1/employees/" + made.ID + "/profile", `{"expected_profile_revision":"1","profile":{"local_name":"SYNTHETIC_DENIED_CHANGE"},"edit_reason":"synthetic denied"}`},
				{"context_summary", "GET", "/api/v1/session?employee_id=" + made.ID, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					operational.Reset()
					var fault map[string]json.RawMessage
					apiSend(t, f, apiRequest(t, f, f.Stranger, tc.method, tc.path, tc.body, value.NewID()), 404, &fault)
					var code, requestID string
					if json.Unmarshal(fault["code"], &code) != nil || code != "NOT_FOUND" ||
						json.Unmarshal(fault["request_id"], &requestID) != nil || !value.ValidID(requestID) {
						t.Fatal("audit outage must preserve safe refusal and request correlation")
					}
					alert := operational.String()
					if !strings.Contains(alert, requestID) {
						t.Fatal("lost denied audit must reach operational stream with same request ID")
					}
					for field := range fault {
						if field != "code" && field != "reason" && field != "request_id" {
							t.Fatal("refusal exposed hidden data")
						}
					}
					for _, private := range []string{made.ID, f.Stranger.Token, f.DSN, "SYNTHETIC_", "synthetic denied"} {
						if strings.Contains(alert, private) {
							t.Fatal("operational alert leaked private context")
						}
						for _, field := range fault {
							if strings.Contains(string(field), private) {
								t.Fatal("refusal leaked private context")
							}
						}
					}
				})
			}
			current, err := f.Repo.Employee(ctx, made.ID)
			if err != nil || current.Revision != 1 || f.Count(t, "employee") != 1 || f.Count(t, "employee_profile_version") != 1 ||
				f.Count(t, "encrypted_payload") != 1 || f.Count(t, "command_receipt") != 1 || f.KMS.Calls.Load() != calls {
				t.Fatal("audit-failed denial reached KMS or mutated protected facts")
			}
		})
	}
}
