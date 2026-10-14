package identity

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"golang.org/x/oauth2"
)

const transactionTTL = 10 * time.Minute

type Service struct {
	Store                Store
	Now                  func() time.Time
	keys                 MACKeyService
	seal                 cipher.AEAD
	oauth                oauth2.Config
	verifier             *oidc.IDTokenVerifier
	client               *http.Client
	issuer, mfaACR, mode string
	mfaAMR               []string
	local                *localAuthenticator
}

type httpsTransport struct{ base http.RoundTripper }

func (t httpsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !validHTTPS(r.URL.String()) {
		return nil, fault.Unavailable
	}
	return t.base.RoundTrip(r)
}
func validHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}
func New(ctx context.Context, store Store, keys MACKeyService, cfg *OIDCConfig) (*Service, error) {
	if store == nil || keys == nil {
		return nil, fault.Unavailable
	}
	s := &Service{Store: store, keys: keys, Now: time.Now}
	if cfg == nil {
		return s, nil
	}
	if !validHTTPS(cfg.Issuer) || !validHTTPS(cfg.RedirectURI) || cfg.ClientID == "" || cfg.ClientSecret == "" || len(cfg.TransactionKey) != 32 {
		return nil, fault.Unavailable
	}
	issuerURL, _ := url.Parse(cfg.Issuer)
	redirectURL, _ := url.Parse(cfg.RedirectURI)
	if issuerURL.RawQuery != "" || redirectURL.RawQuery != "" || redirectURL.Path != "/api/v1/auth/callback" {
		return nil, fault.Unavailable
	}
	if (cfg.MFAACR == "") != (len(cfg.MFAAMR) == 0) || len(cfg.MFAAMR) > 16 || len(cfg.MFAACR) > 256 {
		return nil, fault.Unavailable
	}
	seen := map[string]bool{}
	for _, amr := range cfg.MFAAMR {
		if amr == "" || len(amr) > 64 || seen[amr] {
			return nil, fault.Unavailable
		}
		seen[amr] = true
	}
	encodedAMR, err := json.Marshal(cfg.MFAAMR)
	if err != nil || len(encodedAMR) > 1024 {
		return nil, fault.Unavailable
	}
	client := http.Client{Timeout: 10 * time.Second}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	if client.Timeout == 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport.DialTLS != nil || transport.DialTLSContext != nil || transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, fault.Unavailable
	}
	transport = transport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	client.Transport = httpsTransport{base: transport}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects are not accepted") }
	s.client = &client
	ioctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.client), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ioctx, cfg.Issuer)
	if err != nil {
		return nil, fault.Unavailable
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	endpoint := provider.Endpoint()
	if provider.Claims(&metadata) != nil || !validHTTPS(endpoint.AuthURL) || !validHTTPS(endpoint.TokenURL) || !validHTTPS(metadata.JWKS) {
		return nil, fault.Unavailable
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	s.oauth = oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURI, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID}}
	s.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256}, Now: s.now})
	s.issuer, s.mfaACR, s.mfaAMR, s.mode = cfg.Issuer, cfg.MFAACR, append([]string(nil), cfg.MFAAMR...), "oidc"
	block, err := aes.NewCipher(cfg.TransactionKey)
	if err != nil {
		return nil, fault.Unavailable
	}
	s.seal, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fault.Unavailable
	}
	return s, nil
}
func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC().Truncate(time.Microsecond)
	}
	return s.Now().UTC().Truncate(time.Microsecond)
}
func (s *Service) Available() bool { return s != nil && s.verifier != nil }
func (s *Service) Mode() string {
	if s == nil {
		return ""
	}
	return s.mode
}

// AllowedReturn accepts canonical registered pages and safe business dates only.
func AllowedReturn(raw string) bool {
	if len(raw) > 128 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(raw, "\\\r\n#") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	employeePage := len(parts) == 2 && parts[0] == "employees" && value.ValidID(parts[1])
	historyPage := len(parts) == 3 && parts[0] == "employees" && value.ValidID(parts[1]) && parts[2] == "organization-history"
	orgPage := len(parts) == 3 && parts[0] == "orgs" && value.ValidID(parts[1]) && (parts[2] == "tree" || parts[2] == "employees")
	interviewPage := u.Path == "/interviews" || len(parts) == 2 && parts[0] == "interviews" && value.ValidID(parts[1]) || len(parts) == 3 && parts[0] == "employees" && value.ValidID(parts[1]) && parts[2] == "interviews"
	compensationPage := len(parts) == 3 && parts[0] == "employees" && value.ValidID(parts[1]) && parts[2] == "compensation"
	bonusPage := len(parts) == 3 && parts[0] == "employees" && value.ValidID(parts[1]) && parts[2] == "bonuses"
	if u.Path != "/" && u.Path != "/security/grants" && u.Path != "/security/audit" && !employeePage && !historyPage && !orgPage && !interviewPage && !compensationPage && !bonusPage {
		return false
	}
	if strings.Contains(raw, "?") {
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil || u.RawQuery == "" || u.RawQuery != q.Encode() {
			return false
		}
		if historyPage && len(q) == 2 && len(q["from"]) == 1 && len(q["to"]) == 1 {
			return value.ValidDate(q.Get("from")) && value.ValidDate(q.Get("to")) && q.Get("from") < q.Get("to")
		}
		if len(q) != 1 || len(q["as_of"]) != 1 || !value.ValidDate(q.Get("as_of")) {
			return false
		}
	}
	return true
}

// AllowedStepUpAction records intent only; recent MFA remains session-wide.
func AllowedStepUpAction(action string) bool {
	return action == "pii.write" || action == "access_grant.manage" || action == "audit.read" || action == "note.publish" || action == "sensitive.export" || action == "interview_policy.manage" || authz.SupportedPair(action, "financial", "compensation_management")
}
func randomToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fault.Unavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), raw, nil
}
func proofHash(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	defer clear(raw)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, false
	}
	hash := sha256.Sum256(raw)
	return hash[:], true
}

type secretTransaction struct{ Nonce, Verifier string }

func transactionAAD(t Transaction) []byte {
	var b bytes.Buffer
	b.WriteString("TEAMLEDGER-OIDC-TRANSACTION\x00\x01")
	for _, p := range [][]byte{t.StateHash, t.BindingHash, []byte(t.Mode), []byte(t.Action), []byte(t.ReturnTo), t.PreviousHash, []byte(t.ExpectedOrg), []byte(t.ExpectedSubject), t.ExpectedIdentity} {
		binary.Write(&b, binary.BigEndian, uint32(len(p)))
		b.Write(p)
	}
	binary.Write(&b, binary.BigEndian, t.ExpectedEpoch)
	binary.Write(&b, binary.BigEndian, t.CreatedAt.UnixMicro())
	binary.Write(&b, binary.BigEndian, t.ExpiresAt.UnixMicro())
	return b.Bytes()
}
func (s *Service) Begin(ctx context.Context, request BeginRequest) (Authorization, error) {
	if !s.Available() {
		if s != nil && s.mode == "local" && request.Mode == "step_up" {
			return Authorization{}, MFARequired
		}
		return Authorization{}, fault.Unavailable
	}
	if !value.ValidID(request.RequestID) || !AllowedReturn(request.ReturnTo) || (request.Mode != "login" && request.Mode != "step_up") || request.Mode == "login" && request.Action != "" || request.Mode == "step_up" && !AllowedStepUpAction(request.Action) {
		return Authorization{}, fault.Invalid
	}
	now := s.now()
	t := Transaction{Mode: request.Mode, Action: request.Action, ReturnTo: request.ReturnTo, CreatedAt: now, ExpiresAt: now.Add(transactionTTL)}
	if len(request.SessionHash) != 0 {
		current, err := s.Store.IdentitySession(ctx, request.SessionHash, now)
		if err != nil && (request.Mode == "step_up" || !errors.Is(err, fault.Unauthenticated)) {
			return Authorization{}, err
		}
		if err == nil {
			t.PreviousHash = bytes.Clone(current.Hash)
			t.ExpectedOrg, t.ExpectedSubject, t.ExpectedEpoch = current.OrgID, current.SubjectID, current.Epoch
			if request.Mode == "step_up" {
				t.ExpectedIdentity = bytes.Clone(current.IdentityDigest)
			}
		}
	}
	if request.Mode == "step_up" {
		if len(t.ExpectedIdentity) != 32 {
			return Authorization{}, fault.Unauthenticated
		}
		if s.mfaACR == "" {
			return Authorization{}, MFARequired
		}
	}
	state, stateRaw, err := randomToken()
	if err != nil {
		return Authorization{}, err
	}
	defer clear(stateRaw)
	binding, bindingRaw, err := randomToken()
	if err != nil {
		return Authorization{}, err
	}
	defer clear(bindingRaw)
	nonce, nonceRaw, err := randomToken()
	if err != nil {
		return Authorization{}, err
	}
	defer clear(nonceRaw)
	verifier, verifierRaw, err := randomToken()
	if err != nil {
		return Authorization{}, err
	}
	defer clear(verifierRaw)
	stateHash, bindingHash := sha256.Sum256(stateRaw), sha256.Sum256(bindingRaw)
	t.StateHash, t.BindingHash = stateHash[:], bindingHash[:]
	plaintext, err := json.Marshal(secretTransaction{Nonce: nonce, Verifier: verifier})
	if err != nil {
		return Authorization{}, fault.Unavailable
	}
	defer clear(plaintext)
	t.Sealed = s.seal.Seal(nil, nil, plaintext, transactionAAD(t))
	if err = s.Store.SaveOIDCTransaction(ctx, t); err != nil {
		return Authorization{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256")}
	if request.Mode == "step_up" {
		claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{"auth_time": map[string]any{"essential": true}, "acr": map[string]any{"essential": true, "value": s.mfaACR}}})
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("acr_values", s.mfaACR), oauth2.SetAuthURLParam("claims", string(claims)))
	}
	return Authorization{URL: s.oauth.AuthCodeURL(state, opts...), BrowserCookie: binding, ExpiresAt: t.ExpiresAt}, nil
}
func (s *Service) denial(ctx context.Context, operation, requestID string, cause error) (LoginResult, error) {
	if err := s.Store.AuditIdentityDenied(ctx, operation, requestID, s.now()); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{}, cause
}
func (s *Service) Complete(ctx context.Context, request CallbackRequest) (LoginResult, error) {
	if !s.Available() {
		return LoginResult{}, fault.Unavailable
	}
	if !value.ValidID(request.RequestID) {
		return LoginResult{}, fault.Invalid
	}
	operation := "AUTH-LOGIN"
	stateHash, stateOK := proofHash(request.State)
	bindingHash, bindingOK := proofHash(request.BrowserCookie)
	if !stateOK || !bindingOK || request.Code == "" || len(request.Code) > 4096 {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	t, err := s.Store.ConsumeOIDCTransaction(ctx, stateHash, bindingHash, s.now())
	if err != nil {
		return s.denial(ctx, operation, request.RequestID, err)
	}
	if t.Mode == "step_up" {
		operation = "AUTH-STEP-UP"
	}
	plaintext, err := s.seal.Open(nil, nil, t.Sealed, transactionAAD(t))
	if err != nil {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	defer clear(plaintext)
	var secret secretTransaction
	if json.Unmarshal(plaintext, &secret) != nil || !AllowedReturn(t.ReturnTo) {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	ioctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.client), 10*time.Second)
	defer cancel()
	token, err := s.oauth.Exchange(ioctx, request.Code, oauth2.SetAuthURLParam("code_verifier", secret.Verifier))
	if err != nil {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || len(rawID) > 65536 {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	id, err := s.verifier.Verify(ioctx, rawID)
	if err != nil {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	var claims struct {
		AZP       string   `json:"azp"`
		AuthTime  *int64   `json:"auth_time"`
		NotBefore *int64   `json:"nbf"`
		ACR       string   `json:"acr"`
		AMR       []string `json:"amr"`
	}
	now := s.now()
	if id.Claims(&claims) != nil || id.Issuer != s.issuer || id.Subject == "" || len(id.Subject) > 4096 || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(secret.Nonce)) != 1 || id.IssuedAt.IsZero() || id.IssuedAt.After(now) || !id.Expiry.After(now) || !id.Expiry.After(id.IssuedAt) || len(id.Audience) == 0 || len(id.Audience) > 16 || len(id.Audience) > 1 && claims.AZP != s.oauth.ClientID || claims.AZP != "" && claims.AZP != s.oauth.ClientID || len(claims.ACR) > 256 || len(claims.AMR) > 16 {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	if claims.NotBefore != nil && *claims.NotBefore > now.Unix() {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	var authTime time.Time
	if claims.AuthTime != nil {
		if *claims.AuthTime <= 0 || *claims.AuthTime > now.Unix() || *claims.AuthTime > id.IssuedAt.Unix() {
			return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
		}
		authTime = time.Unix(*claims.AuthTime, 0).UTC()
	}
	trustedMFA := s.mfaACR != "" && claims.ACR == s.mfaACR && !authTime.IsZero() && authTime.Add(transactionTTL).After(now)
	for _, required := range s.mfaAMR {
		found := false
		for _, actual := range claims.AMR {
			if actual == required {
				found = true
			}
		}
		trustedMFA = trustedMFA && found
	}
	digestValue, err := IdentityMAC(ctx, s.keys, s.issuer, id.Subject)
	if err != nil {
		return s.denial(ctx, operation, request.RequestID, fault.Unauthenticated)
	}
	digest := digestValue.Digest
	if t.Mode == "step_up" && (!trustedMFA || !bytes.Equal(digest, t.ExpectedIdentity)) {
		return s.denial(ctx, operation, request.RequestID, MFARequired)
	}
	cookie, raw, err := randomToken()
	if err != nil {
		return LoginResult{}, err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	csrf, csrfKey, err := CSRFToken(ctx, s.keys, raw)
	if err != nil {
		return LoginResult{}, err
	}
	csrfHash := sha256.Sum256([]byte(csrf))
	mfaUntil := time.Unix(0, 0).UTC()
	if trustedMFA {
		mfaUntil = authTime.Add(transactionTTL)
	}
	issue := SessionIssue{Transaction: t, IdentityDigest: digest, IdentityKeyID: digestValue.KeyID, IdentityVersion: digestValue.Version, TokenHash: hash[:], CSRFHash: csrfHash[:], CSRFKeyID: csrfKey.KeyID, CSRFVersion: csrfKey.Version, Now: now, ExpiresAt: now.Add(8 * time.Hour), IdleExpiresAt: now.Add(30 * time.Minute), MFAUntil: mfaUntil, AuthTime: authTime, RequestID: request.RequestID}
	// Persist only deployment-approved authentication labels, never arbitrary IdP claims.
	if trustedMFA {
		issue.ACR, issue.AMR = s.mfaACR, append([]string(nil), s.mfaAMR...)
	}
	if err = s.Store.IssueSession(ctx, issue); err != nil {
		return s.denial(ctx, operation, request.RequestID, err)
	}
	return LoginResult{SessionCookie: cookie, ReturnTo: t.ReturnTo, ExpiresAt: issue.ExpiresAt}, nil
}
func (s *Service) Touch(ctx context.Context, hash []byte) error {
	if s == nil || len(hash) != 32 {
		return fault.Unauthenticated
	}
	return s.Store.TouchSession(ctx, hash, s.now())
}
func (s *Service) Logout(ctx context.Context, hash []byte, requestID string) error {
	if s == nil || len(hash) != 32 {
		return fault.Unauthenticated
	}
	if !value.ValidID(requestID) {
		return fault.Invalid
	}
	return s.Store.LogoutSession(ctx, hash, requestID, s.now())
}

// IdentityDigest is the fixed independent version-1 lookup domain. Issuer/sub
// are length-framed, avoiding delimiter ambiguity; neither is stored plaintext.
func IdentityDigest(key []byte, issuer, subject string) ([]byte, error) {
	if len(key) != 32 || !validHTTPS(issuer) || subject == "" || len(subject) > 4096 || !utf8.ValidString(subject) {
		return nil, fault.Invalid
	}
	u, _ := url.Parse(issuer)
	if u.RawQuery != "" {
		return nil, fault.Invalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("TEAMLEDGER-IDENTITY\x00\x01"))
	var size [4]byte
	for _, text := range []string{issuer, subject} {
		binary.BigEndian.PutUint32(size[:], uint32(len(text)))
		mac.Write(size[:])
		mac.Write([]byte(text))
	}
	return mac.Sum(nil), nil
}

func IdentityLookupFrame(issuer, subject string) ([]byte, error) {
	if !validHTTPS(issuer) || subject == "" || len(subject) > 4096 || !utf8.ValidString(subject) {
		return nil, fault.Invalid
	}
	u, _ := url.Parse(issuer)
	if u.RawQuery != "" {
		return nil, fault.Invalid
	}
	frame := make([]byte, 0, len(issuer)+len(subject)+32)
	frame = append(frame, "TEAMLEDGER-IDENTITY\x00\x01"...)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(issuer)))
	frame = append(frame, issuer...)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(subject)))
	return append(frame, subject...), nil
}

func IdentityMAC(ctx context.Context, keys MACKeyService, issuer, subject string) (sensitive.MACValue, error) {
	if keys == nil {
		return sensitive.MACValue{}, fault.Invalid
	}
	frame, err := IdentityLookupFrame(issuer, subject)
	if err != nil {
		return sensitive.MACValue{}, err
	}
	defer clear(frame)
	value, err := keys.MAC(ctx, sensitive.DomainIdentitySubjectLookup, frame)
	if err != nil || value.Version == 0 || value.KeyID == "" || len(value.Digest) != sha256.Size {
		clear(value.Digest)
		return sensitive.MACValue{}, fault.Unavailable
	}
	return value, nil
}
