package httpapi_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"time"
)

func TestAuthLogoutRevokesCurrentCookieAndSensitiveAccess(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var made organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &made)
			path := "/api/v1/employees/" + made.ID + "?as_of=2026-10-11&include_profile=true"
			var before organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", path, "", ""), http.StatusOK, &before)
			if before.Profile == nil || before.Profile.LocalName != "SYNTHETIC_API_PROFILE" {
				t.Fatal("authorized persisted profile must be readable before logout")
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/auth/logout", "{}", ""), http.StatusNoContent, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/session", "", ""), http.StatusUnauthorized, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, "GET", path, "", ""), http.StatusUnauthorized, nil)
		})
	}
}

func TestAuthLogoutRejectsUntrustedTransportWithoutRevocation(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var made organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &made)
			for _, tc := range []struct {
				name, path, body string
				status           int
				edit             func(*http.Request)
			}{
				{"no CSRF", "/api/v1/auth/logout", "{}", 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
				{"untrusted Origin", "/api/v1/auth/logout", "{}", 403, func(r *http.Request) { r.Header.Set("Origin", "https://untrusted.invalid") }},
				{"cross-site", "/api/v1/auth/logout", "{}", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
				{"form CSRF", "/api/v1/auth/logout", "{}", 415, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
				{"query input", "/api/v1/auth/logout?all=true", "{}", 403, nil},
				{"unknown global logout", "/api/v1/auth/logout", `{"all":true}`, 422, nil},
				{"null command", "/api/v1/auth/logout", "null", 422, nil},
				{"array command", "/api/v1/auth/logout", "[]", 422, nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req := apiRequest(t, f, f.Owner, "POST", tc.path, tc.body, "")
					if tc.edit != nil {
						tc.edit(req)
					}
					apiSend(t, f, req, tc.status, nil)
					var persisted organization.View
					apiSend(t, f, apiRequest(t, f, f.Owner, "GET", "/api/v1/employees/"+made.ID+"?as_of=2026-10-11&include_profile=true", "", ""), 200, &persisted)
					if persisted.Profile == nil || persisted.Profile.LocalName != "SYNTHETIC_API_PROFILE" {
						t.Fatal("untrusted logout revoked or corrupted the authorized persisted profile")
					}
				})
			}
		})
	}
}

func TestAuthStepUpCannotInventMFAOrOpenRedirect(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			for _, body := range []string{
				`{"action":"access_grant.manage","return_to":"https://untrusted.invalid/"}`,
				`{"action":"access_grant.manage","return_to":"//untrusted.invalid/"}`,
				`{"action":"access_grant.manage","return_to":"/security/grants#secret"}`,
				`{"action":"access_grant.manage","return_to":"/security/grants?q=SYNTHETIC_NAME"}`,
				`{"action":"access_grant.manage","return_to":"/security/grants?as_of=2026-02-30"}`,
				`{"action":"set_mfa_true","return_to":"/security/grants"}`,
				`{"action":"access_grant.manage","return_to":"/security/grants","mfa_recent":true}`,
			} {
				apiSend(t, f, apiRequest(t, f, f.Manager, "POST", "/api/v1/auth/step-up", body, ""), 422, nil)
			}
			apiSend(t, f, apiRequest(t, f, f.Manager, "POST", "/api/v1/auth/step-up", `{"action":"access_grant.manage","return_to":"/security/grants"}`, ""), 503, nil)
			apiSend(t, f, apiRequest(t, f, f.Manager, "GET", "/api/v1/auth/login", "", ""), 503, nil)
			apiSend(t, f, apiRequest(t, f, f.Manager, "GET", "/api/v1/session", "", ""), 200, nil)
		})
	}
}

func TestAuthCallbackMissingTrustedMFAKeepsSessionAndReturnsChallenge(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			modeAt := any(f.Now.UnixMicro())
			modeSQL := "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,?)"
			if backend == "postgres" {
				modeAt = f.Now
				modeSQL = "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,$1)"
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), modeSQL, modeAt); err != nil {
				t.Fatal("set OIDC fixture mode:", err)
			}
			idp, err := testsupport.NewOIDCFixture()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(idp.Close)
			idp.Now = f.Service.Now
			server := httptest.NewUnstartedServer(nil)
			t.Cleanup(server.Close)
			origin := "https://" + server.Listener.Addr().String()
			lookup, seal := make([]byte, 32), make([]byte, 32)
			lookup[0], seal[0] = 1, 2
			ctx := context.Background()
			digest, err := identity.IdentityDigest(lookup, idp.Server.URL, idp.Subject)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.BindIdentity(ctx, identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Manager.SubjectID}, value.NewID(), f.Now); err != nil {
				t.Fatal(err)
			}
			service, err := identity.New(ctx, f.Repo, testsupport.MACKeys{Key: f.CSRFKey, DomainKeys: map[sensitive.KeyDomain][]byte{sensitive.DomainIdentitySubjectLookup: lookup}}, &identity.OIDCConfig{
				Issuer: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret,
				RedirectURI: origin + "/api/v1/auth/callback", HTTPClient: idp.Client(),
				IdentityKey: lookup, TransactionKey: seal, MFAACR: "urn:synthetic:mfa", MFAAMR: []string{"pwd", "otp"},
			})
			if err != nil {
				t.Fatal(err)
			}
			service.Now = f.Service.Now
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Synthetic identity consumer</title>"), 0600); err != nil {
				t.Fatal(err)
			}
			handler, err := httpapi.New(f.Service, f.Interviews, f.Assessment, f.Compensation, f.Authz, service, testsupport.MACKeys{Key: f.CSRFKey}, origin, dir, "synthetic-deployment")
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.StartTLS()
			login, err := service.Begin(ctx, identity.BeginRequest{Mode: "login", ReturnTo: "/security/grants", RequestID: value.NewID()})
			if err != nil {
				t.Fatal(err)
			}
			authorized, err := idp.Authorize(login.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			current, err := service.Complete(ctx, identity.CallbackRequest{Code: authorized.Code, State: authorized.State, BrowserCookie: login.BrowserCookie, RequestID: value.NewID()})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(current.SessionCookie)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(raw)
			clear(raw)
			step, err := service.Begin(ctx, identity.BeginRequest{Mode: "step_up", Action: "access_grant.manage", ReturnTo: "/security/grants", RequestID: value.NewID(), SessionHash: hash[:]})
			if err != nil {
				t.Fatal(err)
			}
			authorized, err = idp.Authorize(step.URL, map[string]any{"acr": "urn:synthetic:single", "amr": []string{"pwd"}})
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest("GET", origin+"/api/v1/auth/callback?"+url.Values{"code": {authorized.Code}, "state": {authorized.State}}.Encode(), nil)
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(&http.Cookie{Name: "__Host-teamledger_oidc_binding", Value: step.BrowserCookie})
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var problem struct{ Code string }
			if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 403 || problem.Code != "MFA_REQUIRED" {
				t.Fatalf("missing verified MFA must challenge, got HTTP%d/%s", response.StatusCode, problem.Code)
			}
			for _, cookie := range response.Cookies() {
				if cookie.Name == "__Host-teamledger_session" {
					t.Fatal("failed MFA must not disclose a replacement session")
				}
			}
			request, err = http.NewRequest("GET", origin+"/api/v1/session", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: current.SessionCookie})
			response, err = server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var session struct {
				MFARecent bool `json:"mfa_recent"`
			}
			if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || session.MFARecent {
				t.Fatal("failed MFA must preserve the original single-factor session without elevating it")
			}
		})
	}
}

type httpLocalWrapper struct{}

func (httpLocalWrapper) Wrap(_ context.Context, plain []byte) (sensitive.WrappedKey, error) {
	return sensitive.WrappedKey{KEKID: "00000000-0000-4000-8000-000000000001", Version: 1, Data: bytes.Clone(plain)}, nil
}

func (httpLocalWrapper) Unwrap(_ context.Context, wrapped sensitive.WrappedKey) ([]byte, error) {
	return bytes.Clone(wrapped.Data), nil
}

func httpTOTP(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

func TestLocalMFAHTTPEnrollmentCreatesBusinessSession(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	if _, err := f.Repo.DB.ExecContext(ctx, "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,?)", f.Repo.BindTime(f.Now)); err != nil {
		t.Fatal(err)
	}
	keys := testsupport.MACKeys{Key: f.CSRFKey}
	username, err := identity.LocalUsernameMAC(ctx, keys, "mfa.http.admin")
	if err != nil {
		t.Fatal(err)
	}
	phc, pepper, err := identity.NewPasswordCredential(ctx, keys, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	accountID := value.NewID()
	binding := sensitive.Context{OrgID: f.OrgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	envelope, err := (sensitive.Cipher{Wrapper: httpLocalWrapper{}}).Seal(ctx, binding, []byte("mfa.http.admin"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Repo.CreateLocalAccount(ctx, store.LocalAccountProvision{RequestID: value.NewID(), OrgID: f.OrgID, SubjectID: f.Owner.SubjectID, AccountID: accountID, UsernameDigest: username.Digest, UsernameKey: sensitive.KeyReference{KeyID: username.KeyID, Version: username.Version}, UsernameEnvelope: envelope, PepperKey: pepper, PasswordPHC: phc, Now: f.Now}); err != nil {
		t.Fatal(err)
	}
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
	send := func(path, body, csrf string, cookie *http.Cookie) (*http.Response, map[string]any) {
		t.Helper()
		req, requestErr := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewBufferString(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response, requestErr := server.Client().Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		var payload map[string]any
		if response.StatusCode != http.StatusNoContent {
			if requestErr = json.NewDecoder(response.Body).Decode(&payload); requestErr != nil {
				response.Body.Close()
				t.Fatal(requestErr)
			}
		}
		response.Body.Close()
		return response, payload
	}
	initialResponse, initial := send("/api/v1/auth/local/login", `{"username":"mfa.http.admin","password":"correct horse battery staple","return_to":"/","totp_code":""}`, "", nil)
	if initialResponse.StatusCode != http.StatusAccepted || initial["next"] != "change_password" || initial["csrf_token"] == "" || len(initialResponse.Cookies()) != 1 {
		t.Fatal("initial local login did not require password change", initialResponse.StatusCode, initial)
	}
	passwordResponse, _ := send("/api/v1/auth/local/initial-password", `{"current_password":"correct horse battery staple","new_password":"updated horse battery staple"}`, initial["csrf_token"].(string), initialResponse.Cookies()[0])
	if passwordResponse.StatusCode != http.StatusNoContent {
		t.Fatal("initial password change failed", passwordResponse.StatusCode)
	}
	loginResponse, login := send("/api/v1/auth/local/login", `{"username":"mfa.http.admin","password":"updated horse battery staple","return_to":"/","totp_code":""}`, "", nil)
	if loginResponse.StatusCode != http.StatusAccepted || login["next"] != "enroll" || login["csrf_token"] == "" || len(loginResponse.Cookies()) != 1 {
		t.Fatal("updated local login did not enter enrollment", loginResponse.StatusCode, login)
	}
	restrictedCookie := loginResponse.Cookies()[0]
	csrf := login["csrf_token"].(string)
	beginResponse, pending := send("/api/v1/auth/local/mfa/enrollment", `{}`, csrf, restrictedCookie)
	if beginResponse.StatusCode != http.StatusCreated || pending["mode"] != "initial" || pending["secret"] == "" {
		t.Fatal("MFA enrollment did not start", beginResponse.StatusCode, pending)
	}
	code := httpTOTP(t, pending["secret"].(string), f.Now)
	confirmResponse, confirmed := send("/api/v1/auth/local/mfa/confirm", `{"totp_code":"`+code+`"}`, csrf, restrictedCookie)
	if confirmResponse.StatusCode != http.StatusOK || confirmed["recovery_code"] == "" || confirmed["csrf_token"] == "" || len(confirmResponse.Cookies()) != 1 {
		t.Fatal("MFA enrollment did not confirm", confirmResponse.StatusCode, confirmed)
	}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(confirmResponse.Cookies()[0])
	sessionResponse, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionResponse.Body.Close()
	if sessionResponse.StatusCode != http.StatusOK {
		t.Fatal("confirmed MFA session did not enter business API", sessionResponse.StatusCode)
	}
	var businessSession map[string]any
	if err = json.NewDecoder(sessionResponse.Body).Decode(&businessSession); err != nil {
		t.Fatal(err)
	}
	if businessSession["identity_mode"] != "local" || businessSession["identity_available"] != true {
		t.Fatal("local TOTP was not exposed as an available step-up facility", businessSession)
	}
	f.Now = f.Now.Add(31 * time.Second)
	stepUpBody := `{"action":"audit.read","return_to":"/security/audit","current_password":"updated horse battery staple","totp_code":"` + httpTOTP(t, pending["secret"].(string), f.Now) + `"}`
	stepUpResponse, stepped := send("/api/v1/auth/step-up", stepUpBody, confirmed["csrf_token"].(string), confirmResponse.Cookies()[0])
	if stepUpResponse.StatusCode != http.StatusOK || stepped["return_to"] != "/security/audit" || stepped["csrf_token"] == "" || len(stepUpResponse.Cookies()) != 1 {
		t.Fatal("local audit MFA step-up did not rotate the business session", stepUpResponse.StatusCode, stepped)
	}
}
