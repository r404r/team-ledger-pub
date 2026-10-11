package httpapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
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
			if before.Profile == nil || before.Profile.DisplayName != "SYNTHETIC_API_PROFILE" {
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
					if persisted.Profile == nil || persisted.Profile.DisplayName != "SYNTHETIC_API_PROFILE" {
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
			service, err := identity.New(ctx, f.Repo, f.CSRFKey, &identity.OIDCConfig{
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
			handler, err := httpapi.New(f.Service, f.Interviews, f.Authz, service, f.CSRFKey, origin, dir)
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
