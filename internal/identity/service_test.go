package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

type harness struct {
	f       *testsupport.Fixture
	idp     *testsupport.OIDCFixture
	s       *identity.Service
	cfg     identity.OIDCConfig
	mapping identity.Identity
}

func newIdentityHarness(t *testing.T, backend string) *harness {
	t.Helper()
	f := testsupport.NewHarness(t, backend)
	idp, err := testsupport.NewOIDCFixture()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	idp.Now = func() time.Time { return f.Now }
	cfg := identity.OIDCConfig{Issuer: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURI: f.Server.URL + "/api/v1/auth/callback", HTTPClient: idp.Client(), IdentityKey: bytes.Repeat([]byte{61}, 32), TransactionKey: bytes.Repeat([]byte{62}, 32), MFAACR: "synthetic-approved-mfa", MFAAMR: []string{"pwd", "otp"}}
	s, err := identity.New(context.Background(), f.Repo, f.CSRFKey, &cfg)
	if err != nil {
		t.Fatal("real TLS discovery failed:", err)
	}
	s.Now = func() time.Time { return f.Now }
	digest, err := identity.IdentityDigest(cfg.IdentityKey, cfg.Issuer, idp.Subject)
	if err != nil {
		t.Fatal(err)
	}
	mapping := identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID}
	if err = f.Repo.BindIdentity(context.Background(), mapping, value.NewID(), f.Now); err != nil {
		t.Fatal("approved existing subject binding failed:", err)
	}
	return &harness{f: f, idp: idp, s: s, cfg: cfg, mapping: mapping}
}
func (h *harness) begin(t *testing.T, mode string, hash []byte) identity.Authorization {
	t.Helper()
	action := ""
	if mode == "step_up" {
		action = "pii.write"
	}
	a, err := h.s.Begin(context.Background(), identity.BeginRequest{Mode: mode, Action: action, ReturnTo: "/security/grants?as_of=2026-01-01", RequestID: value.NewID(), SessionHash: hash})
	if err != nil {
		t.Fatal("real authorization begin failed:", err)
	}
	return a
}
func (h *harness) callback(t *testing.T, a identity.Authorization, claims map[string]any) identity.CallbackRequest {
	t.Helper()
	callback, err := h.idp.Authorize(a.URL, claims)
	if err != nil {
		t.Fatal(err)
	}
	return identity.CallbackRequest{Code: callback.Code, State: callback.State, BrowserCookie: a.BrowserCookie, RequestID: value.NewID()}
}
func cookieHash(t *testing.T, cookie string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(raw) != 32 {
		t.Fatal("session must be canonical opaque 256-bit token")
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return digest[:]
}
func (h *harness) login(t *testing.T, previous []byte, claims map[string]any) identity.LoginResult {
	t.Helper()
	a := h.begin(t, "login", previous)
	result, err := h.s.Complete(context.Background(), h.callback(t, a, claims))
	if err != nil {
		t.Fatal("signed mapped login failed:", err)
	}
	return result
}
func rejected(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("invalid identity proof must be rejected")
	}
}
func consumerSession(t *testing.T, h *harness, hash []byte) {
	t.Helper()
	snapshot, err := h.f.Service.Session(context.Background(), organization.Request{TokenHash: hash, RequestID: value.NewID()}, "")
	if err != nil || snapshot.SubjectID != h.mapping.SubjectID || snapshot.OrgID != h.mapping.OrgID {
		t.Fatal("persisted session must authenticate the approved subject:", err)
	}
}

func TestOIDCSignedLoginConsumerRotationLogoutAndRestart(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			created, err := h.f.Service.Create(ctx, h.f.Request(h.f.Owner), h.f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_OIDC_PRIVATE_PROFILE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			grantCount := h.f.Count(t, "access_grant")
			subjectCount := h.f.Count(t, "subject")
			result := h.login(t, h.f.Owner.Hash, nil)
			hash := cookieHash(t, result.SessionCookie)
			consumerSession(t, h, hash)
			view, err := h.f.Service.Read(ctx, organization.Request{TokenHash: hash, RequestID: value.NewID(), Purpose: "organization_management"}, created.ID, "2026-01-01", true)
			if err != nil || view.Profile == nil || view.Profile.DisplayName != "SYNTHETIC_OIDC_PRIVATE_PROFILE" {
				t.Fatal("OIDC session must reach existing encrypted profile consumer:", err)
			}
			_, err = h.f.Service.Session(ctx, h.f.Request(h.f.Owner), "")
			if !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("successful login must revoke previous cookie:", err)
			}
			if h.f.Count(t, "access_grant") != grantCount || h.f.Count(t, "subject") != subjectCount {
				t.Fatal("identity cannot create grants or subjects")
			}
			reopened, err := store.Open(ctx, backend, h.f.DSN)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restarted, err := identity.New(ctx, reopened, h.f.CSRFKey, &h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			restarted.Now = h.s.Now
			if err = restarted.Touch(ctx, hash); err != nil {
				t.Fatal("persisted session must survive process restart:", err)
			}
			if err = restarted.Logout(ctx, hash, value.NewID()); err != nil {
				t.Fatal(err)
			}
			_, err = h.f.Service.Read(ctx, organization.Request{TokenHash: hash, RequestID: value.NewID(), Purpose: "organization_management"}, created.ID, "2026-01-01", true)
			if !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("logout must revoke actual old-cookie PII consumer:", err)
			}
			if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("touch cannot revive logged out session:", err)
			}
			if err = h.s.Logout(ctx, hash, value.NewID()); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("repeated old cookie cannot report logout confirmation:", err)
			}
		})
	}
}

func TestOIDCSignatureClaimsAndUnknownIdentityFailClosed(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			cases := []struct {
				name   string
				claims map[string]any
			}{
				{"unknown_mapping", map[string]any{"sub": "unapproved-synthetic-sub", "email": "synthetic@example.invalid", "groups": []string{"HR"}}},
				{"signature", map[string]any{"test_bad_signature": true}},
				{"none", map[string]any{"test_algorithm": "none"}},
				{"unapproved_algorithm", map[string]any{"test_algorithm": "RS512"}},
				{"issuer", map[string]any{"iss": "https://wrong.invalid"}},
				{"audience", map[string]any{"aud": "wrong-client"}},
				{"multiple_aud_missing_azp", map[string]any{"aud": []string{h.idp.ClientID, "other-client"}}},
				{"wrong_azp", map[string]any{"azp": "wrong-client"}},
				{"expired", map[string]any{"exp": h.f.Now.Unix()}},
				{"future_iat", map[string]any{"iat": h.f.Now.Add(time.Second).Unix()}},
				{"future_not_before", map[string]any{"nbf": h.f.Now.Add(time.Second).Unix()}},
				{"missing_iat", map[string]any{"iat": nil}},
				{"nonce", map[string]any{"nonce": "wrong-nonce"}},
				{"missing_nonce", map[string]any{"nonce": nil}},
				{"future_auth_time", map[string]any{"auth_time": h.f.Now.Add(time.Second).Unix()}},
				{"auth_after_iat", map[string]any{"iat": h.f.Now.Add(-time.Minute).Unix(), "auth_time": h.f.Now.Unix()}},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					before := h.f.Count(t, "session")
					a := h.begin(t, "login", nil)
					request := h.callback(t, a, test.claims)
					result, err := h.s.Complete(context.Background(), request)
					rejected(t, err)
					if result.SessionCookie != "" || h.f.Count(t, "session") != before {
						t.Fatal("invalid proof cannot create or disclose any session")
					}
					_, err = h.s.Complete(context.Background(), request)
					rejected(t, err)
				})
			}
			valid := h.login(t, nil, map[string]any{"aud": []string{h.idp.ClientID, "other-client"}, "azp": h.idp.ClientID})
			consumerSession(t, h, cookieHash(t, valid.SessionCookie))
			if err := h.idp.RotateSigningKey(); err != nil {
				t.Fatal(err)
			}
			rotated := h.login(t, nil, nil)
			consumerSession(t, h, cookieHash(t, rotated.SessionCookie))
		})
	}
}

func TestOIDCStateBrowserPKCEExpiryOnceAndConcurrentCallbacks(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			a := h.begin(t, "login", nil)
			request := h.callback(t, a, nil)
			wrong := request
			wrong.State = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32))
			_, err := h.s.Complete(ctx, wrong)
			rejected(t, err)
			wrong = request
			wrong.BrowserCookie = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{92}, 32))
			_, err = h.s.Complete(ctx, wrong)
			rejected(t, err)
			wrong = request
			wrong.State += "="
			_, err = h.s.Complete(ctx, wrong)
			rejected(t, err)
			// Wrong browser proof cannot consume the legitimate browser's transaction.
			result, err := h.s.Complete(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			consumerSession(t, h, cookieHash(t, result.SessionCookie))
			_, err = h.s.Complete(ctx, request)
			rejected(t, err)
			a = h.begin(t, "login", nil)
			a.URL = testsupport.AlterPKCE(a.URL)
			request = h.callback(t, a, nil)
			_, err = h.s.Complete(ctx, request)
			rejected(t, err)
			a = h.begin(t, "login", nil)
			request = h.callback(t, a, nil)
			h.f.Now = h.f.Now.Add(10 * time.Minute)
			_, err = h.s.Complete(ctx, request)
			rejected(t, err)
			a = h.begin(t, "login", nil)
			request = h.callback(t, a, nil)
			before := h.f.Count(t, "session")
			var group sync.WaitGroup
			accepted := make(chan identity.LoginResult, 8)
			for range 8 {
				group.Add(1)
				go func() {
					defer group.Done()
					result, err := h.s.Complete(ctx, request)
					if err == nil {
						accepted <- result
					}
				}()
			}
			group.Wait()
			close(accepted)
			var successes int
			for result := range accepted {
				successes++
				consumerSession(t, h, cookieHash(t, result.SessionCookie))
			}
			if successes != 1 || h.f.Count(t, "session") != before+1 {
				t.Fatal("once callback races must produce exactly one persisted session")
			}
			// An unfinished encrypted proof also survives a new service/repository instance.
			a = h.begin(t, "login", nil)
			request = h.callback(t, a, nil)
			restarted, err := identity.New(ctx, h.f.Repo, h.f.CSRFKey, &h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			restarted.Now = h.s.Now
			result, err = restarted.Complete(ctx, request)
			if err != nil {
				t.Fatal("persisted proof must survive service restart:", err)
			}
			consumerSession(t, h, cookieHash(t, result.SessionCookie))
		})
	}
}

func TestOIDCTransactionCiphertextBindsMetadata(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			a := h.begin(t, "login", nil)
			request := h.callback(t, a, nil)
			u, _ := url.Parse(a.URL)
			nonce := u.Query().Get("nonce")
			var sealed []byte
			if err := h.f.Repo.DB.QueryRow("SELECT sealed_bytes FROM oidc_transaction").Scan(&sealed); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(sealed, []byte(nonce)) || bytes.Contains(sealed, []byte(request.State)) || bytes.Contains(sealed, []byte(h.idp.Subject)) {
				t.Fatal("persisted ciphertext must not contain plaintext protocol/identity secrets")
			}
			if err := h.f.Exec(context.Background(), "UPDATE oidc_transaction SET return_route='/'", "UPDATE oidc_transaction SET return_route='/'"); err != nil {
				t.Fatal(err)
			}
			_, err := h.s.Complete(context.Background(), request)
			rejected(t, err)
		})
	}
}

func TestOIDCStepUpRequiresSameTrustedFreshIdentityAndRotates(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			ordinary := h.login(t, nil, map[string]any{"acr": "unapproved", "amr": []string{"mfa"}})
			hash := cookieHash(t, ordinary.SessionCookie)
			snapshot, err := h.f.Service.Session(ctx, organization.Request{TokenHash: hash}, "")
			if err != nil || snapshot.MFAUntil.After(h.f.Now) {
				t.Fatal("arbitrary amr cannot grant MFA")
			}
			previousCSRF := bytes.Clone(snapshot.CSRFHash)
			for _, test := range []struct {
				name   string
				claims map[string]any
			}{
				{"missing_auth", map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR, "auth_time": nil}},
				{"old_auth", map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR, "auth_time": h.f.Now.Add(-10 * time.Minute).Unix()}},
				{"one_factor", map[string]any{"acr": h.cfg.MFAACR, "amr": []string{"pwd"}}},
				{"wrong_acr", map[string]any{"acr": "unapproved", "amr": h.cfg.MFAAMR}},
				{"other_identity", map[string]any{"sub": "other-synthetic-sub", "acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR}},
			} {
				t.Run(test.name, func(t *testing.T) {
					a := h.begin(t, "step_up", hash)
					_, err := h.s.Complete(ctx, h.callback(t, a, test.claims))
					if !errors.Is(err, identity.MFARequired) {
						t.Fatal("untrusted step-up must require MFA:", err)
					}
					consumerSession(t, h, hash)
				})
			}
			a := h.begin(t, "step_up", hash)
			u, _ := url.Parse(a.URL)
			if u.Query().Get("max_age") != "0" || u.Query().Get("acr_values") != h.cfg.MFAACR || u.Query().Get("claims") == "" {
				t.Fatal("step-up must really request forced approved reauthentication")
			}
			result, err := h.s.Complete(ctx, h.callback(t, a, map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR, "auth_time": h.f.Now.Add(-time.Minute).Unix()}))
			if err != nil {
				t.Fatal(err)
			}
			fresh := cookieHash(t, result.SessionCookie)
			snapshot, err = h.f.Service.Session(ctx, organization.Request{TokenHash: fresh}, "")
			if err != nil || !snapshot.MFAUntil.After(h.f.Now) || !snapshot.MFAUntil.Equal(time.Unix(h.f.Now.Add(-time.Minute).Unix(), 0).Add(10*time.Minute)) {
				t.Fatal("MFA must expire from verified auth_time, not callback time:", err)
			}
			if bytes.Equal(snapshot.CSRFHash, previousCSRF) {
				t.Fatal("step-up must rotate session-bound CSRF")
			}
			if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("step-up must revoke old token")
			}
			_, err = h.s.Begin(ctx, identity.BeginRequest{Mode: "step_up", Action: "pii.write", ReturnTo: "/", RequestID: value.NewID(), SessionHash: h.f.Observer.Hash})
			if !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("legacy unbound session cannot invent OIDC identity")
			}
		})
	}
}

func TestOIDCRechecksCurrentMappingAndSessionAfterTokenIO(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		for _, change := range []string{"unbind", "logout", "epoch", "inactive"} {
			t.Run(backend+"/"+change, func(t *testing.T) {
				h := newIdentityHarness(t, backend)
				ctx := context.Background()
				result := h.login(t, nil, nil)
				hash := cookieHash(t, result.SessionCookie)
				a := h.begin(t, "step_up", hash)
				request := h.callback(t, a, map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR})
				started := make(chan struct{}, 1)
				release := make(chan struct{})
				h.idp.ExchangeStarted = started
				h.idp.ExchangeRelease = release
				finished := make(chan error, 1)
				go func() { _, err := h.s.Complete(ctx, request); finished <- err }()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					close(release)
					t.Fatal("real token exchange never started")
				}
				switch change {
				case "unbind":
					if err := h.f.Repo.UnbindIdentity(ctx, h.mapping, value.NewID(), h.f.Now); err != nil {
						close(release)
						t.Fatal(err)
					}
				case "logout":
					if err := h.s.Logout(ctx, hash, value.NewID()); err != nil {
						close(release)
						t.Fatal(err)
					}
				case "epoch":
					if err := h.f.Exec(ctx, "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2", h.mapping.OrgID, h.mapping.SubjectID); err != nil {
						close(release)
						t.Fatal(err)
					}
				case "inactive":
					if err := h.f.Exec(ctx, "UPDATE subject SET active=0 WHERE org_id=? AND id=?", "UPDATE subject SET active=false WHERE org_id=$1 AND id=$2", h.mapping.OrgID, h.mapping.SubjectID); err != nil {
						close(release)
						t.Fatal(err)
					}
				}
				before := h.f.Count(t, "session")
				close(release)
				rejected(t, <-finished)
				if h.f.Count(t, "session") != before {
					t.Fatal("post-I/O current revocation must prevent new session")
				}
			})
		}
	}
}

func TestSessionIdleAbsoluteExpiryUnbindAndNoRevival(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			first := h.login(t, nil, nil)
			hash := cookieHash(t, first.SessionCookie)
			start := h.f.Now
			h.f.Now = start.Add(20 * time.Minute)
			if err := h.s.Touch(ctx, hash); err != nil {
				t.Fatal(err)
			}
			current, err := h.f.Repo.IdentitySession(ctx, hash, h.f.Now)
			if err != nil || !current.IdleExpiresAt.Equal(start.Add(50*time.Minute)) {
				t.Fatal("valid activity must extend idle exactly")
			}
			h.f.Now = start.Add(50 * time.Minute)
			if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("idle boundary must reject without revival")
			}
			second := h.login(t, nil, nil)
			hash = cookieHash(t, second.SessionCookie)
			start = h.f.Now
			for i := 1; i <= 23; i++ {
				h.f.Now = start.Add(time.Duration(i) * 20 * time.Minute)
				if err = h.s.Touch(ctx, hash); err != nil {
					t.Fatal(err)
				}
			}
			h.f.Now = start.Add(7*time.Hour + 50*time.Minute)
			if err = h.s.Touch(ctx, hash); err != nil {
				t.Fatal(err)
			}
			current, err = h.f.Repo.IdentitySession(ctx, hash, h.f.Now)
			if err != nil || !current.IdleExpiresAt.Equal(start.Add(8*time.Hour)) {
				t.Fatal("idle must clamp to absolute cap")
			}
			h.f.Now = start.Add(8 * time.Hour)
			if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("absolute boundary must reject")
			}
			third := h.login(t, nil, nil)
			hash = cookieHash(t, third.SessionCookie)
			if err = h.f.Repo.UnbindIdentity(ctx, h.mapping, value.NewID(), h.f.Now); err != nil {
				t.Fatal(err)
			}
			_, err = h.f.Service.Session(ctx, organization.Request{TokenHash: hash}, "")
			if !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("unbind must revoke current actual consumer")
			}
			if err = h.f.Repo.BindIdentity(ctx, h.mapping, value.NewID(), h.f.Now); err != nil {
				t.Fatal(err)
			}
			if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("explicit rebind cannot revive previous sessions")
			}
		})
	}
}

func TestIdentityAuditFailureRollsBackLoginLogoutAndBinding(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			result := h.login(t, nil, nil)
			hash := cookieHash(t, result.SessionCookie)
			a := h.begin(t, "login", hash)
			callback := h.callback(t, a, nil)
			before := h.f.Count(t, "session")
			if _, err := h.f.Repo.DB.Exec("ALTER TABLE audit_event RENAME TO audit_event_unavailable"); err != nil {
				t.Fatal(err)
			}
			result, err := h.s.Complete(ctx, callback)
			if !errors.Is(err, fault.AuditUnavailable) || result.SessionCookie != "" {
				t.Fatal("audit failure cannot disclose committed login:", err)
			}
			if h.f.Count(t, "session") != before {
				t.Fatal("audit failed login must roll back both rotation and creation")
			}
			if err = h.s.Logout(ctx, hash, value.NewID()); !errors.Is(err, fault.AuditUnavailable) {
				t.Fatal("audit failed logout cannot report success:", err)
			}
			if err = h.f.Repo.UnbindIdentity(ctx, h.mapping, value.NewID(), h.f.Now); !errors.Is(err, fault.AuditUnavailable) {
				t.Fatal("audit failed unbind cannot commit:", err)
			}
			mappingsBefore := h.f.Count(t, "subject_identity")
			digest, err := identity.IdentityDigest(h.cfg.IdentityKey, h.cfg.Issuer, "synthetic-audit-failed-binding")
			if err != nil {
				t.Fatal(err)
			}
			if err = h.f.Repo.BindIdentity(ctx, identity.Identity{Digest: digest, KeyVersion: 1, OrgID: h.f.OrgID, SubjectID: h.f.Owner.SubjectID}, value.NewID(), h.f.Now); !errors.Is(err, fault.AuditUnavailable) {
				t.Fatal("audit failed bind cannot commit:", err)
			}
			if h.f.Count(t, "subject_identity") != mappingsBefore {
				t.Fatal("audit failed bind must roll back its inserted mapping")
			}
			if _, err = h.f.Repo.DB.Exec("ALTER TABLE audit_event_unavailable RENAME TO audit_event"); err != nil {
				t.Fatal(err)
			}
			consumerSession(t, h, hash)
			if err = h.s.Touch(ctx, hash); err != nil {
				t.Fatal("audit failure must retain prior valid session:", err)
			}
		})
	}
}

func TestOIDCDisabledAndPartialConfigurationHaveNoLocalFallback(t *testing.T) {
	h := newIdentityHarness(t, "sqlite")
	ctx := context.Background()
	disabled, err := identity.New(ctx, h.f.Repo, h.f.CSRFKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	disabled.Now = h.s.Now
	if _, err = disabled.Begin(ctx, identity.BeginRequest{}); !errors.Is(err, fault.Unavailable) {
		t.Fatal("disabled OIDC must fail safe 503")
	}
	if err = disabled.Touch(ctx, h.f.Owner.Hash); err != nil {
		t.Fatal("disabled OIDC must still validate persisted session:", err)
	}
	if err = disabled.Logout(ctx, h.f.Owner.Hash, value.NewID()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*identity.OIDCConfig){func(c *identity.OIDCConfig) { c.ClientSecret = "" }, func(c *identity.OIDCConfig) { c.IdentityKey = h.f.CSRFKey }, func(c *identity.OIDCConfig) { c.TransactionKey = c.IdentityKey }, func(c *identity.OIDCConfig) { c.Issuer = "http://untrusted.invalid" }, func(c *identity.OIDCConfig) { c.RedirectURI = "https://app.invalid/wrong" }, func(c *identity.OIDCConfig) { c.MFAAMR = nil }} {
		cfg := h.cfg
		change(&cfg)
		if _, err = identity.New(ctx, h.f.Repo, h.f.CSRFKey, &cfg); !errors.Is(err, fault.Unavailable) {
			t.Fatal("partial/untrusted configuration must fail closed")
		}
	}
}

func TestIdentityLogoutLinearizesAgainstInFlightSensitiveRelease(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			created, err := h.f.Service.Create(ctx, h.f.Request(h.f.Owner), h.f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_INFLIGHT_IDENTITY_PII"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			result := h.login(t, nil, nil)
			hash := cookieHash(t, result.SessionCookie)
			arrived := make(chan struct{}, 1)
			release := make(chan struct{})
			h.f.KMS.BlockNextDecrypt(arrived, release)
			type response struct {
				view organization.View
				err  error
			}
			finished := make(chan response, 1)
			go func() {
				view, err := h.f.Service.Read(ctx, organization.Request{TokenHash: hash, RequestID: value.NewID(), Purpose: "organization_management"}, created.ID, "2026-01-01", true)
				finished <- response{view, err}
			}()
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("real sensitive decrypt did not enter")
			}
			if err = h.s.Logout(ctx, hash, value.NewID()); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			released := <-finished
			if !errors.Is(released.err, fault.Unauthenticated) || released.view.Profile != nil {
				t.Fatal("completed logout must forbid subsequent sensitive release", released.err)
			}
		})
	}
}

func TestOIDCReturnRoutesAndActionBindingRejectOpenRedirects(t *testing.T) {
	h := newIdentityHarness(t, "sqlite")
	for _, route := range []string{"https://evil.invalid/", "//evil.invalid/", "/employees/new", "/employees/" + value.NewID() + "?q=private", "/security/grants#fragment", "/security/grants?as_of=2026-01-01&as_of=2026-01-01", "/security/grants?as_of=2026-02-30", "/%73ecurity/grants", "/security/grants?", "/security/grants?other=1", "/employees/00000000-0000-0000-0000-000000000000"} {
		_, err := h.s.Begin(context.Background(), identity.BeginRequest{Mode: "login", ReturnTo: route, RequestID: value.NewID()})
		if !errors.Is(err, fault.Invalid) {
			t.Fatal("unregistered return route must be rejected:", err)
		}
	}
	org, employee := value.NewID(), value.NewID()
	if !identity.AllowedReturn("/employees/"+employee+"/bonuses") || identity.AllowedReturn("/employees/"+employee+"/bonuses?reason=SYNTHETIC_FINANCIAL_BODY") {
		t.Fatal("bonus return route must allow only its canonical body-free path")
	}
	if !identity.AllowedReturn("/security/audit") || identity.AllowedReturn("/security/audit?request_id=SYNTHETIC_AUDIT_PROBE") {
		t.Fatal("audit return route must allow only its canonical body-free path")
	}
	for _, route := range []string{
		"orgs/" + org + "/tree", "/orgs/" + org + "/unknown",
		"/orgs/" + org + "/employees?q=SYNTHETIC_BODY_ONLY_SEARCH",
		"/orgs/" + org + "/tree?as_of=2026-01-01&as_of=2026-01-01",
		"/employees/" + employee + "/organization-history?from=2026-01-01",
		"/employees/" + employee + "/organization-history?from=2026-02-01&to=2026-01-01",
		"/employees/" + employee + "/organization-history?from=2026-01-01&to=2026-02-01&q=private",
		"/employees/" + employee + "/organization-history?from=2026-01-01&to=2026-02-30",
		"/interviews/new", "/interviews/" + employee + "?q=SYNTHETIC_PRIVATE_NOTE",
		"/employees/" + employee + "/interviews?category=hr_confidential",
		"/employees/" + employee + "/compensation?reason=SYNTHETIC_PRIVATE_REASON",
		"/employees/" + employee + "/compensation?as_of=2026-02-30",
		"/employees/" + employee + "/compensation?as_of=2026-01-01&as_of=2026-01-01",
	} {
		if _, err := h.s.Begin(context.Background(), identity.BeginRequest{Mode: "login", ReturnTo: route, RequestID: value.NewID()}); !errors.Is(err, fault.Invalid) {
			t.Fatal("organization identity return must remain canonical, safe and body-search-free:", err)
		}
	}
	for _, request := range []identity.BeginRequest{
		{Mode: "login", Action: "pii.write", ReturnTo: "/", RequestID: value.NewID()},
		{Mode: "step_up", Action: "financial.export", ReturnTo: "/", RequestID: value.NewID(), SessionHash: h.f.Owner.Hash},
		{Mode: "unknown", ReturnTo: "/", RequestID: value.NewID()},
	} {
		if _, err := h.s.Begin(context.Background(), request); !errors.Is(err, fault.Invalid) {
			t.Fatal("unsupported identity action must be rejected")
		}
	}
}

func TestOIDCCrossOrganizationRotationUsesDeterministicCurrentOwnerGuards(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			h := newIdentityHarness(t, backend)
			ctx := context.Background()
			otherSub := "synthetic-explicit-other-org-sub"
			digest, err := identity.IdentityDigest(h.cfg.IdentityKey, h.cfg.Issuer, otherSub)
			if err != nil {
				t.Fatal(err)
			}
			if err = h.f.Repo.BindIdentity(ctx, identity.Identity{Digest: digest, KeyVersion: 1, OrgID: h.f.OtherOrgID, SubjectID: h.f.OtherOwner.SubjectID}, value.NewID(), h.f.Now); err != nil {
				t.Fatal(err)
			}
			first := h.login(t, nil, nil)
			second := h.login(t, nil, map[string]any{"sub": otherSub})
			firstHash, secondHash := cookieHash(t, first.SessionCookie), cookieHash(t, second.SessionCookie)
			a := h.begin(t, "login", firstHash)
			b := h.begin(t, "login", secondHash)
			requests := []identity.CallbackRequest{h.callback(t, a, map[string]any{"sub": otherSub}), h.callback(t, b, nil)}
			type completed struct {
				result identity.LoginResult
				err    error
			}
			results := make(chan completed, 2)
			for _, request := range requests {
				go func(request identity.CallbackRequest) {
					result, err := h.s.Complete(ctx, request)
					results <- completed{result, err}
				}(request)
			}
			owners := map[string]bool{}
			for range 2 {
				select {
				case result := <-results:
					if result.err != nil {
						t.Fatal("cross-owner rotations must serialize without deadlock:", result.err)
					}
					current, err := h.f.Repo.IdentitySession(ctx, cookieHash(t, result.result.SessionCookie), h.f.Now)
					if err != nil {
						t.Fatal(err)
					}
					owners[current.OrgID] = true
				case <-time.After(5 * time.Second):
					t.Fatal("cross-owner lock ordering deadlocked")
				}
			}
			if !owners[h.f.OrgID] || !owners[h.f.OtherOrgID] {
				t.Fatal("new session owner must come only from explicit current identity mapping")
			}
			for _, hash := range [][]byte{firstHash, secondHash} {
				if err = h.s.Touch(ctx, hash); !errors.Is(err, fault.Unauthenticated) {
					t.Fatal("both previous cookies must be revoked atomically")
				}
			}
		})
	}
}

func TestOIDCDiscoveryEndpointsAndTLSAreActuallyTrusted(t *testing.T) {
	h := newIdentityHarness(t, "sqlite")
	ctx := context.Background()
	for _, override := range []map[string]any{
		{"issuer": "https://wrong-synthetic.invalid"},
		{"authorization_endpoint": "http://insecure.invalid/authorize"},
		{"token_endpoint": "http://insecure.invalid/token"},
		{"jwks_uri": "http://insecure.invalid/jwks"},
		{"jwks_uri": "https://user:secret@unapproved.invalid/jwks"},
	} {
		h.idp.SetDiscoveryOverrides(override)
		if _, err := identity.New(ctx, h.f.Repo, h.f.CSRFKey, &h.cfg); !errors.Is(err, fault.Unavailable) {
			t.Fatal("untrusted discovery must fail closed:", err)
		}
	}
	h.idp.SetDiscoveryOverrides(nil)
	cfg := h.cfg
	cfg.HTTPClient = &http.Client{Timeout: time.Second}
	if _, err := identity.New(ctx, h.f.Repo, h.f.CSRFKey, &cfg); !errors.Is(err, fault.Unavailable) {
		t.Fatal("untrusted self-signed IdP TLS cannot be accepted")
	}
	client := h.idp.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	client.Transport = transport
	cfg.HTTPClient = client
	if _, err := identity.New(ctx, h.f.Repo, h.f.CSRFKey, &cfg); !errors.Is(err, fault.Unavailable) {
		t.Fatal("explicit TLS-verification bypass cannot be accepted")
	}
}

func TestStepUpFreshMFAReusesSessionProofButNeverCreatesManagementPermission(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, action := range []string{"pii.write", "access_grant.manage", "note.publish", "sensitive.export", "compensation.read", "compensation.propose", "compensation.approve"} {
				t.Run(action, func(t *testing.T) {
					for _, role := range []string{"manager", "owner", "reader"} {
						t.Run(role, func(t *testing.T) {
							h := newIdentityHarness(t, backend)
							ctx := context.Background()
							subject := h.f.Manager.SubjectID
							if role == "owner" {
								subject = h.f.Owner.SubjectID
							} else if role == "reader" {
								subject = h.f.Reader.SubjectID
							}
							h.idp.Subject = "synthetic-mfa-policy-" + role
							digest, err := identity.IdentityDigest(h.cfg.IdentityKey, h.cfg.Issuer, h.idp.Subject)
							if err != nil {
								t.Fatal(err)
							}
							h.mapping = identity.Identity{Digest: digest, KeyVersion: 1, OrgID: h.f.OrgID, SubjectID: subject}
							if err = h.f.Repo.BindIdentity(ctx, h.mapping, value.NewID(), h.f.Now); err != nil {
								t.Fatal(err)
							}
							login := h.login(t, nil, nil)
							oldHash := cookieHash(t, login.SessionCookie)
							request := authz.Request{TokenHash: oldHash, Purpose: authz.ManagementPurpose, RequestID: value.NewID()}
							filter := authz.Filter{SubjectID: h.f.Owner.SubjectID, Category: "pii", Limit: 25}
							if _, err = h.f.Authz.List(ctx, request, filter); !errors.Is(err, fault.Forbidden) {
								t.Fatal("single-factor authentication cannot satisfy management MFA:", err)
							}
							grantCount := h.f.Count(t, "access_grant")
							assignmentCount := h.f.Count(t, "capability_assignment")
							a, err := h.s.Begin(ctx, identity.BeginRequest{Mode: "step_up", Action: action, ReturnTo: "/security/grants", RequestID: value.NewID(), SessionHash: oldHash})
							if err != nil {
								t.Fatal(err)
							}
							stepped, err := h.s.Complete(ctx, h.callback(t, a, map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR}))
							if err != nil {
								t.Fatal(err)
							}
							request.TokenHash = cookieHash(t, stepped.SessionCookie)
							request.RequestID = value.NewID()
							page, err := h.f.Authz.List(ctx, request, filter)
							if role == "manager" {
								if err != nil {
									t.Fatal("fresh trusted session MFA must allow current explicitly approved PII grants:", err)
								}
								expected := map[string]bool{"pii.read": true, "pii.write": true}
								for _, grant := range page.Items {
									if grant.SubjectID != h.f.Owner.SubjectID || !expected[grant.Capability] {
										t.Fatal("management cannot reveal an unapproved subject/capability")
									}
									delete(expected, grant.Capability)
								}
								if len(expected) != 0 {
									t.Fatal("approved management result lost an expected capability")
								}
								if err = h.f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND capability='access_grant.manage'", "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND capability='access_grant.manage'", h.f.OrgID, subject); err != nil {
									t.Fatal(err)
								}
								request.RequestID = value.NewID()
								if _, err = h.f.Authz.List(ctx, request, filter); !errors.Is(err, fault.Forbidden) {
									t.Fatal("fresh MFA cannot survive current management-grant revocation:", err)
								}
							} else if !errors.Is(err, fault.Forbidden) {
								t.Fatal("requested management action and fresh MFA cannot create management permission:", err)
							}
							if h.f.Count(t, "access_grant") != grantCount || h.f.Count(t, "capability_assignment") != assignmentCount {
								t.Fatal("authentication must never mint business grants or role assignments")
							}
							if _, err = h.f.Service.Session(ctx, organization.Request{TokenHash: oldHash, RequestID: value.NewID()}, ""); !errors.Is(err, fault.Unauthenticated) {
								t.Fatal("step-up must revoke the original session even when its requested action lacked business permission:", err)
							}
						})
					}
				})
			}
		})
	}
}

func TestFinancialStepUpReturnsToRegisteredCompensationPageWithoutGrantingRights(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, action := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
				t.Run(action, func(t *testing.T) {
					h := newIdentityHarness(t, backend)
					ctx := context.Background()
					login := h.login(t, nil, nil)
					oldHash := cookieHash(t, login.SessionCookie)
					route := "/employees/" + value.NewID() + "/compensation?as_of=2026-10-12"
					grants, assignments := h.f.Count(t, "access_grant"), h.f.Count(t, "capability_assignment")
					a, err := h.s.Begin(ctx, identity.BeginRequest{
						Mode: "step_up", Action: action, ReturnTo: route,
						RequestID: value.NewID(), SessionHash: oldHash,
					})
					if err != nil {
						t.Fatal("registered financial intent and safe return must begin real authentication:", err)
					}
					result, err := h.s.Complete(ctx, h.callback(t, a, map[string]any{"acr": h.cfg.MFAACR, "amr": h.cfg.MFAAMR}))
					if err != nil {
						t.Fatal("trusted same-subject financial step-up must complete:", err)
					}
					if result.ReturnTo != route {
						t.Fatal("financial step-up must preserve the explicit safe return")
					}
					if err := h.s.Touch(ctx, cookieHash(t, result.SessionCookie)); err != nil {
						t.Fatal("financial step-up must issue a real valid session:", err)
					}
					if h.f.Count(t, "access_grant") != grants || h.f.Count(t, "capability_assignment") != assignments {
						t.Fatal("financial authentication intent cannot create roles or financial grants")
					}
					if err := h.s.Touch(ctx, oldHash); !errors.Is(err, fault.Unauthenticated) {
						t.Fatal("financial step-up must revoke the old session:", err)
					}
				})
			}
		})
	}
}
