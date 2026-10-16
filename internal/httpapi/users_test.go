package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
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
	identities, err := identity.NewLocal(ctx, f.Repo, f.Repo, keys, sensitive.Cipher{Wrapper: httpLocalWrapper{}})
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
	created := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"temporary horse battery staple"}`, "security_administration", key, nil, "")
	if created.Status != http.StatusCreated {
		t.Fatal("local user create failed", created.Status, string(created.Body))
	}
	var first identity.LocalUserResult
	if json.Unmarshal(created.Body, &first) != nil || !value.ValidID(first.AccountID) || !value.ValidID(first.SubjectID) {
		t.Fatal("local user create result invalid", string(created.Body))
	}
	replayed := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"temporary horse battery staple"}`, "security_administration", key, nil, "")
	var replayResult identity.LocalUserResult
	if replayed.Status != http.StatusCreated || json.Unmarshal(replayed.Body, &replayResult) != nil || replayResult != first {
		t.Fatal("local user idempotent replay changed result", replayed.Status, string(replayed.Body))
	}
	duplicate := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"first.operator","initial_password":"another temporary password"}`, "security_administration", value.NewID(), nil, "")
	if duplicate.Status != http.StatusConflict {
		t.Fatal("duplicate username was not rejected", duplicate.Status, string(duplicate.Body))
	}
	second := send(f.Owner, http.MethodPost, "/api/v1/security/users", `{"username":"second.operator","initial_password":"second temporary password"}`, "security_administration", value.NewID(), nil, "")
	if second.Status != http.StatusCreated {
		t.Fatal("second local user create failed", second.Status, string(second.Body))
	}
	listed := send(f.Owner, http.MethodGet, "/api/v1/security/users?limit=1", "", "security_administration", "", nil, "")
	var page identity.LocalUserPage
	if listed.Status != http.StatusOK || json.Unmarshal(listed.Body, &page) != nil || len(page.Items) != 1 || page.NextCursor == nil || !page.Items[0].PasswordChangeRequired {
		t.Fatal("first local user page invalid", listed.Status, string(listed.Body))
	}
	nextPageResponse := send(f.Owner, http.MethodGet, "/api/v1/security/users?limit=1&cursor="+url.QueryEscape(*page.NextCursor), "", "security_administration", "", nil, "")
	var nextPage identity.LocalUserPage
	if nextPageResponse.Status != http.StatusOK || json.Unmarshal(nextPageResponse.Body, &nextPage) != nil || len(nextPage.Items) != 1 || nextPage.NextCursor != nil || !nextPage.Items[0].PasswordChangeRequired || nextPage.Items[0].Username == page.Items[0].Username {
		t.Fatal("second local user page invalid", nextPageResponse.Status, string(nextPageResponse.Body))
	}
	names := map[string]bool{page.Items[0].Username: true, nextPage.Items[0].Username: true}
	if !names["first.operator"] || !names["second.operator"] {
		t.Fatal("paginated local user list lost an account", names)
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
	if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE operation='OP-SEC-07' AND subject_id=?", f.Owner.SubjectID).Scan(&createAudits); err != nil || createAudits != 2 {
		t.Fatal("user create audit missing or replayed", createAudits, err)
	}
	if err = f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE operation='OP-SEC-08' AND subject_id=?", f.Owner.SubjectID).Scan(&listAudits); err != nil || listAudits != 2 {
		t.Fatal("user list audit missing", listAudits, err)
	}
}
