package testsupport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

type OIDCCallback struct{ Code, State string }
type oidcCode struct {
	verifierChallenge, nonce, redirect string
	claims                             map[string]any
}

// OIDCFixture is a real confidential-code TLS server, PKCE verifier, discovery,
// JWKS and RSA signer. All identities and credentials are synthetic test data.
type OIDCFixture struct {
	Server                          *httptest.Server
	ClientID, ClientSecret, Subject string
	Now                             func() time.Time
	mu                              sync.Mutex
	key, otherKey                   *rsa.PrivateKey
	codes                           map[string]oidcCode
	nextClaims                      map[string]any
	discoveryOverrides              map[string]any
	sequence                        int
	ExchangeStarted                 chan struct{}
	ExchangeRelease                 <-chan struct{}
}

func NewOIDCFixture() (*OIDCFixture, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f := &OIDCFixture{ClientID: "synthetic-client", ClientSecret: "synthetic-client-secret", Subject: "synthetic-approved-sub", Now: time.Now, key: key, otherKey: other, codes: map[string]oidcCode{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f, nil
}
func (f *OIDCFixture) Close() { f.Server.Close() }
func (f *OIDCFixture) Client() *http.Client {
	client := *f.Server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
func (f *OIDCFixture) SetDiscoveryOverrides(overrides map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryOverrides = make(map[string]any, len(overrides))
	for key, val := range overrides {
		f.discoveryOverrides[key] = val
	}
}
func (f *OIDCFixture) Authorize(authorizationURL string, claims map[string]any) (OIDCCallback, error) {
	f.mu.Lock()
	f.nextClaims = claims
	f.mu.Unlock()
	response, err := f.Client().Get(authorizationURL)
	if err != nil {
		return OIDCCallback{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		return OIDCCallback{}, fmt.Errorf("controlled authorization rejected")
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		return OIDCCallback{}, err
	}
	return OIDCCallback{Code: callback.Query().Get("code"), State: callback.Query().Get("state")}, nil
}
func (f *OIDCFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		metadata := map[string]any{"issuer": f.Server.URL, "authorization_endpoint": f.Server.URL + "/authorize", "token_endpoint": f.Server.URL + "/token", "jwks_uri": f.Server.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}}
		f.mu.Lock()
		for key, val := range f.discoveryOverrides {
			metadata[key] = val
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(metadata)
	case "/jwks":
		f.mu.Lock()
		public := f.key.PublicKey
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "controlled-key", "n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes())}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != f.ClientID || q.Get("response_type") != "code" || q.Get("scope") != "openid" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("nonce")) != 43 || len(q.Get("state")) != 43 {
			http.Error(w, "invalid authorization", 400)
			return
		}
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || redirect.Scheme != "https" || redirect.Path != "/api/v1/auth/callback" {
			http.Error(w, "invalid redirect", 400)
			return
		}
		f.mu.Lock()
		f.sequence++
		code := fmt.Sprintf("synthetic-code-%d", f.sequence)
		claims := map[string]any{}
		for key, val := range f.nextClaims {
			claims[key] = val
		}
		f.nextClaims = nil
		f.codes[code] = oidcCode{verifierChallenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), claims: claims}
		f.mu.Unlock()
		cq := redirect.Query()
		cq.Set("code", code)
		cq.Set("state", q.Get("state"))
		redirect.RawQuery = cq.Encode()
		w.Header().Set("Location", redirect.String())
		w.WriteHeader(http.StatusFound)
	case "/token":
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			http.Error(w, "invalid token request", 400)
			return
		}
		client, secret, ok := r.BasicAuth()
		if !ok || client != f.ClientID || secret != f.ClientSecret || r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "invalid client", 401)
			return
		}
		f.mu.Lock()
		code, found := f.codes[r.Form.Get("code")]
		if found {
			delete(f.codes, r.Form.Get("code"))
		}
		started, release := f.ExchangeStarted, f.ExchangeRelease
		key, otherKey := f.key, f.otherKey
		f.mu.Unlock()
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !found || code.redirect != r.Form.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(challenge[:]) != code.verifierChallenge {
			http.Error(w, "invalid code proof", 400)
			return
		}
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		if release != nil {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		now := f.Now().UTC()
		claims := map[string]any{"iss": f.Server.URL, "sub": f.Subject, "aud": f.ClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": code.nonce, "auth_time": now.Unix()}
		for name, val := range code.claims {
			if val == nil {
				delete(claims, name)
			} else {
				claims[name] = val
			}
		}
		algorithm := "RS256"
		if alg, ok := claims["test_algorithm"].(string); ok {
			algorithm = alg
			delete(claims, "test_algorithm")
		}
		if bad, ok := claims["test_bad_signature"].(bool); ok && bad {
			key = otherKey
		}
		delete(claims, "test_bad_signature")
		header, _ := json.Marshal(map[string]any{"alg": algorithm, "kid": "controlled-key", "typ": "JWT"})
		payload, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		hash := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		if algorithm == "none" {
			signature = nil
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-discarded-access-token", "token_type": "Bearer", "expires_in": 3600, "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
	default:
		http.NotFound(w, r)
	}
}
func (f *OIDCFixture) RotateSigningKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.key = key
	f.mu.Unlock()
	return nil
}

// AlterPKCE drives a real authorization endpoint with a different challenge;
// the token endpoint will reject the service's genuine decrypted verifier.
func AlterPKCE(authorizationURL string) string {
	u, _ := url.Parse(authorizationURL)
	q := u.Query()
	q.Set("code_challenge", strings.Repeat("x", 43))
	u.RawQuery = q.Encode()
	return u.String()
}
