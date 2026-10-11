package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func grantRequest(t *testing.T, f *testsupport.Fixture, c testsupport.Credential, method, path, body, key string) *http.Request {
	r := apiRequest(t, f, c, method, path, body, key)
	r.Header.Set("X-Access-Purpose", authz.ManagementPurpose)
	return r
}
func issueBody(t *testing.T, f *testsupport.Fixture, cap, epoch string) string {
	t.Helper()
	category := "metadata"
	if strings.HasPrefix(cap, "pii.") {
		category = "pii"
	}
	b, e := json.Marshal(authz.IssueCommand{SubjectID: f.Reader.SubjectID, Capability: cap, Category: category, Scope: authz.Scope{Kind: "org", ID: f.OrgID}, Purpose: "organization_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: true, AuthorityID: f.AuthorityIDs[cap], ExpectedRevision: epoch})
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestAPIGrantAuthorityHintsAreCurrentManagementIntersection(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), 201, &employee)
			if err := f.Exec(ctx, "UPDATE capability_assignment SET scope_kind='employee',scope_id=?,employee_id=? WHERE org_id=? AND subject_id=? AND capability='access_grant.manage'", "UPDATE capability_assignment SET scope_kind='employee',scope_id=$1,employee_id=$2 WHERE org_id=$3 AND subject_id=$4 AND capability='access_grant.manage'", employee.ID, employee.ID, f.OrgID, f.Manager.SubjectID); err != nil {
				t.Fatal(err)
			}
			if err := f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND capability='access_grant.manage'", "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND capability='access_grant.manage'", f.OrgID, f.Manager.SubjectID); err != nil {
				t.Fatal(err)
			}
			if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,'access_grant.manage','audit','employee',?,?,'security_administration',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,'access_grant.manage','audit','employee',$4,$5,'security_administration',$6,$7,true)", value.NewID(), f.OrgID, f.Manager.SubjectID, employee.ID, employee.ID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
				t.Fatal(err)
			}
			type hint struct {
				ID              string        `json:"id"`
				Scope           authz.Scope   `json:"scope"`
				DelegableScopes []authz.Scope `json:"delegable_scopes"`
			}
			var session struct {
				Authorities []hint `json:"grant_authorities"`
			}
			var page struct {
				Authorities []hint `json:"authorities"`
			}
			apiSend(t, f, apiRequest(t, f, f.Manager, "GET", "/api/v1/session", "", ""), 200, &session)
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", "/api/v1/access-grants", "", ""), 200, &page)
			for _, hints := range [][]hint{session.Authorities, page.Authorities} {
				seenPII := false
				for _, a := range hints {
					if a.Scope != (authz.Scope{Kind: "org", ID: f.OrgID}) || len(a.DelegableScopes) != 1 || a.DelegableScopes[0] != (authz.Scope{Kind: "employee", ID: employee.ID}) {
						t.Fatal("original approval must remain org but current delegable scope must only be managed employee", a)
					}
					if a.ID == f.AuthorityIDs["pii.read"] {
						seenPII = true
					}
				}
				if !seenPII {
					t.Fatal("current narrow intersection lost the existing approved PII read action")
				}
			}
		})
	}
}
func TestAPIGrantIssueReadRevokeConsumer(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), 201, &employee)
			path := "/api/v1/employees/" + employee.ID + "?as_of=" + f.Now.Format("2006-01-02") + "&include_profile=true"
			apiSend(t, f, apiRequest(t, f, f.Reader, "GET", path, "", ""), 404, nil)
			grants := make([]authz.Result, 0, 2)
			epoch := "1"
			for _, cap := range []string{"organization.read", "pii.read"} {
				body := issueBody(t, f, cap, epoch)
				key := value.NewID()
				var made, replay authz.Result
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", body, key), 201, &made)
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", body, key), 201, &replay)
				if made != replay || made.Revision != "1" || made.Status != "current" {
					t.Fatal("real HTTP issue/replay must preserve result")
				}
				epoch = made.AuthEpoch
				grants = append(grants, made)
			}
			var page authz.Page
			before := f.KMS.Calls.Load()
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", "/api/v1/access-grants?subject_id="+f.Reader.SubjectID, "", ""), 200, &page)
			if len(page.Items) != 2 || f.KMS.Calls.Load() != before {
				t.Fatal("filtered metadata must expose only target grants without KMS")
			}
			for _, g := range page.Items {
				if g.AuthorityID == nil || g.ApprovedBy == nil || *g.ApprovedBy != f.Approver.SubjectID || g.RelationRef != nil || g.ObjectRef != nil || g.RelationBound {
					t.Fatal("grant provenance and null references must be safe")
				}
			}
			safeJSON, e := json.Marshal(page)
			if e != nil {
				t.Fatal(e)
			}
			for _, private := range []string{"SYNTHETIC_API_PROFILE", f.Reader.Token, f.Manager.Token, f.DSN, "csrf_token", "total_count", "display_name"} {
				if strings.Contains(string(safeJSON), private) {
					t.Fatal("grant metadata disclosed private content or hidden count")
				}
			}
			var view organization.View
			apiSend(t, f, apiRequest(t, f, f.Reader, "GET", path, "", ""), 200, &view)
			if view.Profile == nil || view.Profile.DisplayName != "SYNTHETIC_API_PROFILE" {
				t.Fatal("issued business grants must authorize real encrypted profile")
			}
			apiSend(t, f, apiRequest(t, f, f.Manager, "GET", path, "", ""), 404, nil)
			for i, g := range []authz.Result{grants[1], grants[0]} {
				body := `{"expected_revision":"` + g.Revision + `","expected_auth_epoch":"` + epoch + `","reason":"access_no_longer_required"}`
				var revoked, replay authz.Result
				key := value.NewID()
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants/"+g.ID+"/revoke", body, key), 200, &revoked)
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants/"+g.ID+"/revoke", body, key), 200, &replay)
				if replay != revoked {
					t.Fatal("revoke replay must return original committed result")
				}
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants/"+g.ID+"/revoke", body, value.NewID()), 409, nil)
				if revoked.Status != "revoked" || revoked.Revision != "2" {
					t.Fatal("revoke must advance real revision")
				}
				epoch = revoked.AuthEpoch
				if i == 0 {
					calls := f.KMS.Calls.Load()
					f.KMS.Fail.Store(true)
					var metadata organization.View
					apiSend(t, f, apiRequest(t, f, f.Reader, "GET", path, "", ""), 200, &metadata)
					if metadata.Profile != nil || metadata.Revision != "" || f.KMS.Calls.Load() != calls {
						t.Fatal("PII revoke must retain authorized metadata without PII/revision/KMS")
					}
				}
			}
			before = f.KMS.Calls.Load()
			f.KMS.Fail.Store(true)
			apiSend(t, f, apiRequest(t, f, f.Reader, "GET", path, "", ""), 404, nil)
			if f.KMS.Calls.Load() != before {
				t.Fatal("revoked reader must refuse before unavailable KMS")
			}
		})
	}
}
func TestAPIGrantStrictInputsAndAuthorization(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			for _, query := range []string{"limit=1&limit=2", "unknown=x", "scope_kind=org", "limit=0", "limit=101", "limit=01", "subject_id=bad", "state=unknown"} {
				apiSend(t, f, grantRequest(t, f, f.Manager, "GET", "/api/v1/access-grants?"+query, "", ""), 422, nil)
			}
			body := issueBody(t, f, "organization.read", "1")
			invalid := []string{strings.Replace(body, `"relation_ref":null`, `"relation_ref":true`, 1), strings.Replace(body, `"object_ref":null`, `"object_ref":{}`, 1), strings.Replace(body, `"mfa_required":true,`, "", 1), strings.Replace(body, `"relation_bound":false`, `"relation_bound":null`, 1), strings.Replace(body, `"subject_id":`, `"unknown":1,"subject_id":`, 1), strings.Replace(body, `"subject_id":`, `"subject_id":null,"subject_id":`, 1), strings.Replace(body, `"valid_from":"`, `"valid_from":null,"discard":"`, 1)}
			for _, b := range invalid {
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", b, value.NewID()), 422, nil)
			}
			for _, c := range []testsupport.Credential{f.Owner, f.Reader, f.Observer, f.Stranger} {
				apiSend(t, f, grantRequest(t, f, c, "GET", "/api/v1/access-grants", "", ""), 403, nil)
			}
			for _, header := range []string{"Origin", "Sec-Fetch-Site", "X-CSRF-Token"} {
				r := grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", body, value.NewID())
				r.Header.Del(header)
				apiSend(t, f, r, 403, nil)
			}
			if f.Count(t, "grant_command_receipt") != 0 {
				t.Fatal("rejected HTTP commands wrote receipts")
			}
		})
	}
}

func TestAPIGrantCursorAndAuditFailure(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			prefix := "/api/v1/access-grants?limit=1"
			var page authz.Page
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix, "", ""), 200, &page)
			if page.NextCursor == nil || len(page.Items) != 1 {
				t.Fatal("bounded real list must return authenticated next cursor")
			}
			cursor := url.QueryEscape(*page.NextCursor)
			var next authz.Page
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix+"&cursor="+cursor, "", ""), 200, &next)
			if len(next.Items) != 1 || next.Items[0].ID <= page.Items[0].ID {
				t.Fatal("keyset continuation must advance without duplication")
			}
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix+"&cursor="+cursor+"x", "", ""), 422, nil)
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix+"&category=pii&cursor="+cursor, "", ""), 409, nil)
			if err := f.Exec(context.Background(), "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now.Add(time.Hour)), f.Manager.Hash); err != nil {
				t.Fatal(err)
			}
			originalNow := f.Now
			f.Now = f.Now.Add(15 * time.Minute)
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix+"&cursor="+cursor, "", ""), 409, nil)
			f.Now = originalNow
			body := issueBody(t, f, "organization.read", "1")
			key := value.NewID()
			var made authz.Result
			apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", body, key), 201, &made)
			apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", issueBody(t, f, "pii.read", made.AuthEpoch), key), 409, nil)
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", prefix+"&cursor="+cursor, "", ""), 409, nil)
			receipts := f.Count(t, "grant_command_receipt")
			grants := f.Count(t, "access_grant")
			if err := f.Exec(context.Background(), "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
				t.Fatal(err)
			}
			apiSend(t, f, grantRequest(t, f, f.Manager, "GET", "/api/v1/access-grants", "", ""), 503, nil)
			apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", issueBody(t, f, "pii.read", made.AuthEpoch), value.NewID()), 503, nil)
			apiSend(t, f, grantRequest(t, f, f.Reader, "GET", "/api/v1/access-grants", "", ""), 403, nil)
			if f.Count(t, "access_grant") != grants || f.Count(t, "grant_command_receipt") != receipts {
				t.Fatal("audit outage must rollback grant and receipt atomically")
			}
		})
	}
}

func TestAPIGrantRefusesUnqualifiedAndUnsupportedDelegation(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			body := issueBody(t, f, "organization.read", "1")
			for _, tc := range []struct {
				body   string
				status int
			}{
				{strings.Replace(body, f.Reader.SubjectID, f.Manager.SubjectID, 1), 403},
				{strings.Replace(body, f.Reader.SubjectID, f.Approver.SubjectID, 1), 403},
				{strings.Replace(body, `"capability":"organization.read"`, `"capability":"access_grant.manage"`, 1), 422},
				{strings.Replace(body, `"relation_bound":false`, `"relation_bound":true`, 1), 422},
				{strings.Replace(body, `"mfa_required":true`, `"mfa_required":false`, 1), 403},
				{strings.Replace(body, f.Now.Add(time.Hour).Format(time.RFC3339Nano), f.Now.Add(48*time.Hour).Format(time.RFC3339Nano), 1), 403},
				{strings.Replace(body, f.Now.Add(-time.Minute).Format(time.RFC3339Nano), f.Now.Add(-time.Minute).Format("2006-01-02T15:04:05")+".1234567Z", 1), 422},
				{strings.Replace(body, f.OrgID, f.OtherOrgID, 1), 403},
			} {
				apiSend(t, f, grantRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", tc.body, value.NewID()), tc.status, nil)
			}
			if f.Count(t, "grant_command_receipt") != 0 {
				t.Fatal("refused delegation persisted command")
			}
		})
	}
}

func TestAPIGrantDeniedAuditFailurePreservesSafeCorrelation(t *testing.T) {
	var operational bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&operational)
	defer log.SetOutput(previous)
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			if err := f.Exec(context.Background(), "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/v1/access-grants", "/api/v1/access-grants?grant_id=" + value.NewID()} {
				operational.Reset()
				var denied map[string]json.RawMessage
				apiSend(t, f, grantRequest(t, f, f.Reader, "GET", path, "", ""), 403, &denied)
				var code, requestID string
				if json.Unmarshal(denied["code"], &code) != nil || code != "FORBIDDEN" || json.Unmarshal(denied["request_id"], &requestID) != nil || !value.ValidID(requestID) || !strings.Contains(operational.String(), requestID) {
					t.Fatal("lost denied audit must preserve original403 and canonical correlation")
				}
				for field := range denied {
					if field != "code" && field != "reason" && field != "request_id" {
						t.Fatal("refusal exposed hidden metadata")
					}
				}
				for _, private := range []string{f.Reader.Token, f.Manager.Token, f.DSN, f.Reader.SubjectID, "SYNTHETIC_"} {
					if strings.Contains(operational.String(), private) {
						t.Fatal("operational alert disclosed private context")
					}
				}
			}
		})
	}
}
