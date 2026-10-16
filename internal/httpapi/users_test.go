package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestLocalUserAdministrationRequiresPermissionAndInitialPasswordChange(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := f.Repo.DB.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,?)", f.Repo.BindTime(f.Now))
	exec("INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'identity.manage','org',?)", f.OrgID, f.Owner.SubjectID, f.OrgID)
	exec("INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,'identity.manage','audit','org',?,'security_administration',?,?,0,0,1)", value.NewID(), f.OrgID, f.Owner.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)))
	keys := testsupport.MACKeys{Key: f.CSRFKey}
	f.Service.StaffCodeMAC = func(ctx context.Context, frame []byte) (sensitive.MACValue, error) {
		return keys.MAC(ctx, sensitive.DomainStaffCodeLookup, frame)
	}
	identities, err := identity.NewLocal(ctx, f.Repo, f.Repo, keys, sensitive.Cipher{Wrapper: unavailableUserTestWrapper{}}, sensitive.Cipher{Wrapper: httpLocalWrapper{}})
	if err != nil {
		t.Fatal(err)
	}
	identities.Now = func() time.Time { return f.Now }
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><main></main>"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := httpapi.New(f.Service, f.Interviews, f.Assessment, f.Compensation, f.Authz, identities, keys, origin, dir, "synthetic-deployment")
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()

	type response struct {
		Status  int
		Headers http.Header
		Body    []byte
		Cookies []*http.Cookie
	}
	send := func(credential testsupport.Credential, method, path, body, purpose, key string, extraCookie *http.Cookie, csrf string) response {
		t.Helper()
		req, requestErr := http.NewRequest(method, server.URL+path, bytes.NewBufferString(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if credential.Token != "" {
			req.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: credential.Token})
		} else if extraCookie != nil {
			req.AddCookie(extraCookie)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
		}
		if purpose != "" {
			req.Header.Set("X-Access-Purpose", purpose)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if csrf == "" {
			csrf = credential.CSRF
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, requestErr := server.Client().Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
		return response{Status: res.StatusCode, Headers: res.Header, Body: raw, Cookies: res.Cookies()}
	}

	if denied := send(f.Reader, http.MethodGet, "/api/v1/security/users", "", "security_administration", "", nil, ""); denied.Status != http.StatusForbidden {
		t.Fatal("user without identity.manage listed local users", denied.Status, string(denied.Body))
	}
	key := value.NewID()
	created := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"temporary horse battery staple","account_type":"standalone"}`, "security_administration", key, nil, "")
	if created.Status != http.StatusCreated {
		t.Fatal("local user create failed", created.Status, string(created.Body))
	}
	var first identity.LocalUserResult
	if json.Unmarshal(created.Body, &first) != nil || !value.ValidID(first.AccountID) || !value.ValidID(first.SubjectID) || first.AccountType != "standalone" || first.EmployeeID != "" {
		t.Fatal("local user create result invalid", string(created.Body))
	}
	replayed := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"temporary horse battery staple","account_type":"standalone"}`, "security_administration", key, nil, "")
	var replayResult identity.LocalUserResult
	if replayed.Status != http.StatusCreated || json.Unmarshal(replayed.Body, &replayResult) != nil || replayResult != first {
		t.Fatal("local user idempotent replay changed result", replayed.Status, string(replayed.Body))
	}
	duplicate := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"another temporary password","account_type":"standalone"}`, "security_administration", value.NewID(), nil, "")
	if duplicate.Status != http.StatusConflict {
		t.Fatal("duplicate username was not rejected", duplicate.Status, string(duplicate.Body))
	}
	second := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"second.operator","initial_password":"second temporary password","account_type":"standalone"}`, "security_administration", value.NewID(), nil, "")
	if second.Status != http.StatusCreated {
		t.Fatal("second local user create failed", second.Status, string(second.Body))
	}
	listed := send(f.Owner, http.MethodGet, "/api/v1/security/users?limit=1", "", "security_administration", "", nil, "")
	var page identity.LocalUserPage
	if listed.Status != http.StatusOK || json.Unmarshal(listed.Body, &page) != nil || len(page.Items) != 1 || page.NextCursor == nil || !page.Items[0].PasswordChangeRequired || page.Items[0].AccountType != "standalone" || page.Items[0].EmployeeID != "" {
		t.Fatal("first local user page invalid", listed.Status, string(listed.Body))
	}
	nextPageResponse := send(f.Owner, http.MethodGet, "/api/v1/security/users?limit=1&cursor="+url.QueryEscape(*page.NextCursor), "", "security_administration", "", nil, "")
	var nextPage identity.LocalUserPage
	if nextPageResponse.Status != http.StatusOK || json.Unmarshal(nextPageResponse.Body, &nextPage) != nil || len(nextPage.Items) != 1 || nextPage.NextCursor != nil || !nextPage.Items[0].PasswordChangeRequired || nextPage.Items[0].AccountType != "standalone" || nextPage.Items[0].EmployeeID != "" || nextPage.Items[0].Username == page.Items[0].Username {
		t.Fatal("second local user page invalid", nextPageResponse.Status, string(nextPageResponse.Body))
	}
	names := map[string]bool{page.Items[0].Username: true, nextPage.Items[0].Username: true}
	if !names["first.operator"] || !names["second.operator"] {
		t.Fatal("paginated local user list lost an account", names)
	}
	staffCode, catalogRevision, graphRevision := "STAFF-ACCOUNT-001", "1", "1"
	employee, createErr := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{
		Profile:   organization.Profile{LocalName: "合成员工账号"},
		Lifecycle: organization.Lifecycle{ValidFrom: f.Now.Format("2006-01-02")},
		StaffCode: &staffCode, ExpectedCatalogRevision: &catalogRevision, ExpectedGraphRevision: &graphRevision,
	})
	if createErr != nil {
		t.Fatal("create staff candidate:", createErr)
	}
	staffBody := `{"username":"staff.operator","initial_password":"staff temporary password","account_type":"staff","staff_code":"STAFF-ACCOUNT-001"}`
	staffResponse := send(f.Owner, http.MethodPost, "/api/v1/security/users", staffBody, "security_administration", value.NewID(), nil, "")
	var staffUser identity.LocalUserResult
	if staffResponse.Status != http.StatusCreated || json.Unmarshal(staffResponse.Body, &staffUser) != nil || staffUser.AccountType != "staff" || staffUser.EmployeeID != employee.ID {
		t.Fatal("staff-linked account create failed", staffResponse.Status, string(staffResponse.Body))
	}
	if f.Count(t, "staff_account_access") != 1 || f.Count(t, "subject_employee") != 1 {
		t.Fatal("staff account binding and default policy were not committed")
	}
	graphRevision = employee.GraphRevision
	report, createErr := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{
		Profile:                 organization.Profile{LocalName: "直属员工"},
		Lifecycle:               organization.Lifecycle{ValidFrom: f.Now.Format("2006-01-02")},
		ManagerEmployeeID:       &employee.ID,
		ExpectedCatalogRevision: &catalogRevision,
		ExpectedGraphRevision:   &graphRevision,
	})
	if createErr != nil {
		t.Fatal("create direct report:", createErr)
	}
	peer, createErr := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{
		Profile: organization.Profile{LocalName: "同级员工"}, Lifecycle: organization.Lifecycle{ValidFrom: f.Now.Format("2006-01-02")},
	})
	if createErr != nil {
		t.Fatal("create peer:", createErr)
	}
	tokenHash, csrfHash := sha256.Sum256([]byte("staff-default-business-session")), sha256.Sum256([]byte("staff-default-csrf"))
	exec("INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES(?,?,?,?,?,?,?,0,?,1)", tokenHash[:], f.OrgID, staffUser.SubjectID, int64(1), f.Repo.BindTime(f.Now.Add(8*time.Hour)), f.Repo.BindTime(f.Now.Add(30*time.Minute)), f.Repo.BindTime(f.Now.Add(10*time.Minute)), csrfHash[:])
	staffRequest := organization.Request{TokenHash: tokenHash[:], Purpose: "organization_management", RequestID: value.NewID()}
	staffSnapshot, securityErr := f.Repo.Security(ctx, tokenHash[:], f.OrgID, report.ID)
	if securityErr != nil || staffSnapshot.StaffDefaultEmployeeID != employee.ID || len(staffSnapshot.StaffDefaultReports) != 1 || !staffSnapshot.Allows("organization.read", "metadata", report.ID, staffRequest.Purpose, f.Now) || !staffSnapshot.Allows("pii.read", "pii", report.ID, staffRequest.Purpose, f.Now) {
		t.Fatal("staff default policy was not loaded for current direct report", securityErr, staffSnapshot)
	}
	for _, target := range []string{employee.ID, report.ID} {
		view, readErr := f.Service.Read(ctx, staffRequest, target, f.Now.Format("2006-01-02"), true)
		if readErr != nil || view.ID != target || view.Profile == nil {
			t.Fatal("staff default employee read failed", target, readErr)
		}
	}
	if _, readErr := f.Service.Read(ctx, staffRequest, peer.ID, f.Now.Format("2006-01-02"), true); !errors.Is(readErr, fault.NotFound) {
		t.Fatal("staff default policy exposed a peer", readErr)
	}
	directory, directoryErr := f.Service.Directory(ctx, staffRequest, f.OrgID, organization.DirectoryQuery{AsOf: f.Now.Format("2006-01-02"), IncludeProfile: true, Lifecycle: "active", Limit: 50})
	if directoryErr != nil || len(directory.Items) != 2 {
		t.Fatal("staff default directory did not contain self and direct report", directoryErr, len(directory.Items))
	}
	staffInterviewRequest := interview.Request{TokenHash: tokenHash[:], Purpose: "interview_followup", Key: value.NewID(), RequestID: value.NewID()}
	staffInterviewCommand := interview.CreateCommand{ScheduledAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano)}
	staffInterview, interviewErr := f.Interviews.Create(ctx, staffInterviewRequest, report.ID, staffInterviewCommand)
	if interviewErr != nil || staffInterview.Status != "scheduled" {
		t.Fatal("staff default interview creation failed", staffInterview, interviewErr)
	}
	replayedInterview, replayErr := f.Interviews.Create(ctx, staffInterviewRequest, report.ID, staffInterviewCommand)
	if replayErr != nil || replayedInterview != staffInterview {
		t.Fatal("staff default interview replay failed", replayedInterview, replayErr)
	}
	staffInterviews, listErr := f.Interviews.List(ctx, interview.Request{TokenHash: tokenHash[:], Purpose: "interview_followup", RequestID: value.NewID()}, report.ID, interview.ListQuery{Limit: 20})
	if listErr != nil || len(staffInterviews.Items) != 1 || staffInterviews.Items[0].ID != staffInterview.ID || len(staffInterviews.Permissions) != 2 || staffInterviews.Permissions[1].Capability != "interview.create" {
		t.Fatal("staff default interview list or create hint failed", staffInterviews, listErr)
	}
	staffInterviewDetail, detailErr := f.Interviews.Detail(ctx, interview.Request{TokenHash: tokenHash[:], Purpose: "interview_followup", RequestID: value.NewID()}, staffInterview.ID, interview.DetailQuery{})
	if detailErr != nil || staffInterviewDetail.Interview.ID != staffInterview.ID || len(staffInterviewDetail.Sections) != 0 || len(staffInterviewDetail.ActionItems) != 0 {
		t.Fatal("staff default interview metadata detail failed", staffInterviewDetail, detailErr)
	}
	_, transitionErr := f.Interviews.Transition(ctx, interview.Request{TokenHash: tokenHash[:], Purpose: "interview_followup", Key: value.NewID(), RequestID: value.NewID()}, staffInterview.ID, interview.TransitionCommand{Action: "cancel", ExpectedRevision: "1", Reason: "not permitted"})
	if !errors.Is(transitionErr, fault.NotFound) {
		t.Fatal("staff default unexpectedly allowed an interview transition", transitionErr)
	}
	if _, listErr = f.Interviews.List(ctx, interview.Request{TokenHash: tokenHash[:], Purpose: "interview_followup", RequestID: value.NewID()}, peer.ID, interview.ListQuery{Limit: 20}); !errors.Is(listErr, fault.NotFound) {
		t.Fatal("staff default exposed peer interview metadata", listErr)
	}
	duplicateStaff := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"staff.duplicate","initial_password":"staff duplicate password","account_type":"staff","staff_code":"STAFF-ACCOUNT-001"}`, "security_administration", value.NewID(), nil, "")
	if duplicateStaff.Status != http.StatusConflict || f.Count(t, "local_account") != 3 || f.Count(t, "staff_account_access") != 1 {
		t.Fatal("duplicate staff binding left partial account", duplicateStaff.Status, string(duplicateStaff.Body))
	}
	missingStaff := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"staff.missing","initial_password":"staff missing password","account_type":"staff","staff_code":"UNKNOWN-STAFF"}`, "security_administration", value.NewID(), nil, "")
	if missingStaff.Status != http.StatusNotFound || f.Count(t, "local_account") != 3 {
		t.Fatal("unknown Staff Code did not fail atomically", missingStaff.Status, string(missingStaff.Body))
	}

	login := send(testsupport.Credential{}, http.MethodPost, "/api/v1/auth/local/login", `{"username":"first.operator","password":"temporary horse battery staple","return_to":"/security/users","totp_code":""}`, "", "", nil, "")
	var loginBody map[string]any
	if login.Status != http.StatusAccepted || json.Unmarshal(login.Body, &loginBody) != nil || loginBody["next"] != "change_password" || len(login.Cookies) != 1 {
		t.Fatal("initial password did not enter restricted change flow", login.Status, string(login.Body))
	}
	restrictedBusiness := send(testsupport.Credential{}, http.MethodGet, "/api/v1/security/users", "", "security_administration", "", login.Cookies[0], "")
	if restrictedBusiness.Status != http.StatusUnauthorized {
		t.Fatal("password-change session entered user administration", restrictedBusiness.Status)
	}
	changed := send(testsupport.Credential{}, http.MethodPost, "/api/v1/auth/local/initial-password", `{"current_password":"temporary horse battery staple","new_password":"permanent horse battery staple"}`, "", "", login.Cookies[0], loginBody["csrf_token"].(string))
	if changed.Status != http.StatusNoContent {
		t.Fatal("initial password change failed", changed.Status, string(changed.Body))
	}
	newLogin := send(testsupport.Credential{}, http.MethodPost, "/api/v1/auth/local/login", `{"username":"first.operator","password":"permanent horse battery staple","return_to":"/","totp_code":""}`, "", "", nil, "")
	var newLoginBody map[string]any
	if newLogin.Status != http.StatusAccepted || json.Unmarshal(newLogin.Body, &newLoginBody) != nil || newLoginBody["next"] != "enroll" {
		t.Fatal("changed password did not continue to MFA enrollment", newLogin.Status, string(newLogin.Body))
	}
	oldLogin := send(testsupport.Credential{}, http.MethodPost, "/api/v1/auth/local/login", `{"username":"first.operator","password":"temporary horse battery staple","return_to":"/","totp_code":""}`, "", "", nil, "")
	if oldLogin.Status != http.StatusUnauthorized {
		t.Fatal("initial password remained usable", oldLogin.Status)
	}
	var createAudits, listAudits int
	if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE operation='OP-SEC-07' AND subject_id=?", f.Owner.SubjectID).Scan(&createAudits); err != nil || createAudits != 3 {
		t.Fatal("user create audit missing or replayed", createAudits, err)
	}
	if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE operation='OP-SEC-08' AND subject_id=?", f.Owner.SubjectID).Scan(&listAudits); err != nil || listAudits != 2 {
		t.Fatal("user list audit missing", listAudits, err)
	}
}

type unavailableUserTestWrapper struct{}

func (unavailableUserTestWrapper) Wrap(context.Context, []byte) (sensitive.WrappedKey, error) {
	return sensitive.WrappedKey{}, sensitive.ErrUnavailable
}

func (unavailableUserTestWrapper) Unwrap(context.Context, sensitive.WrappedKey) ([]byte, error) {
	return nil, sensitive.ErrUnavailable
}
