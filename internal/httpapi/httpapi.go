package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

var bodyTooLarge = &fault.Fault{Status: 413, Code: "INVALID_INPUT", Reason: "BODY_TOO_LARGE"}
var unsupportedMedia = &fault.Fault{Status: 415, Code: "INVALID_INPUT", Reason: "UNSUPPORTED_MEDIA_TYPE"}

type handler struct {
	service        *organization.Service
	grants         *authz.Service
	identities     *identity.Service
	key            []byte
	origin, static string
}

func New(service *organization.Service, grants *authz.Service, identities *identity.Service, csrfKey []byte, origin, staticDir string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || service == nil || grants == nil || identities == nil || len(csrfKey) != 32 {
		return nil, errors.New("invalid HTTP configuration")
	}
	root, err := filepath.EvalSymlinks(staticDir)
	if err != nil {
		return nil, errors.New("invalid static directory")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, errors.New("invalid static directory")
	}
	info, err := os.Stat(filepath.Join(root, "index.html"))
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("missing production index")
	}
	return &handler{service: service, grants: grants, identities: identities, key: bytes.Clone(csrfKey), origin: strings.TrimSuffix(origin, "/"), static: root}, nil
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := value.NewID()
	w.Header().Set("X-Request-ID", requestID)
	if r.TLS == nil || r.Host != strings.TrimPrefix(h.origin, "https://") {
		h.fail(w, fault.Forbidden, requestID)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		h.staticFile(w, r, requestID)
		return
	}
	if h.publicIdentityRoute(w, r, requestID) {
		return
	}
	req := organization.Request{RequestID: requestID, Purpose: r.Header.Get("X-Access-Purpose"), Key: r.Header.Get("Idempotency-Key")}
	raw, err := sessionCookie(r)
	if err != nil {
		h.fail(w, fault.Unauthenticated, requestID)
		return
	}
	hash := sha256.Sum256(raw)
	req.TokenHash = hash[:]
	employeeScope, teamScope := "", ""
	invalidScope := false
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) > 1 || !singleQuery(q, []string{"employee_id", "team_id"}) {
			invalidScope = true
		} else if len(q) == 1 {
			employeeScope, teamScope = q.Get("employee_id"), q.Get("team_id")
			if !value.ValidID(employeeScope) && !value.ValidID(teamScope) {
				invalidScope = true
			}
		}
	}
	snap, err := h.service.Session(r.Context(), req, employeeScope)
	if err != nil {
		h.fail(w, err, requestID)
		return
	}
	if invalidScope {
		h.fail(w, fault.Invalid, requestID)
		return
	}
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte("TEAMLEDGER-CSRF\x00"))
	mac.Write(raw)
	token := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	tokenHash := sha256.Sum256([]byte(token))
	if snap.CSRFVersion != 1 || subtle.ConstantTimeCompare(snap.CSRFHash, tokenHash[:]) != 1 {
		h.fail(w, fault.Unauthenticated, requestID)
		return
	}
	if r.Method != http.MethodGet {
		if r.URL.RawQuery != "" || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(token)) != 1 {
			h.fail(w, fault.Forbidden, requestID)
			return
		}
		media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && strings.ToLower(params["charset"]) != "utf-8") {
			h.fail(w, unsupportedMedia, requestID)
			return
		}
	}
	if e := h.identities.Touch(r.Context(), req.TokenHash); e != nil {
		h.fail(w, e, requestID)
		return
	}
	if h.authenticatedIdentityRoute(w, r, req.TokenHash, requestID) {
		return
	}
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet {
		now := time.Now().UTC().Truncate(time.Microsecond)
		if h.grants.Now != nil {
			now = h.grants.Now().UTC().Truncate(time.Microsecond)
		}
		authorities, e := h.grants.SessionAuthorities(r.Context(), authz.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: authz.ManagementPurpose})
		if e != nil {
			h.fail(w, e, requestID)
			return
		}
		if authorities == nil {
			authorities = []authz.AuthorityHint{}
		}
		caps := make([]string, 0, 4)
		for _, cap := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
			category := "metadata"
			if strings.HasPrefix(cap, "pii.") {
				category = "pii"
			}
			allowed := snap.Allows(cap, category, employeeScope, "organization_management", now)
			if teamScope != "" {
				allowed = snap.AllowsTeam(cap, category, teamScope, "organization_management", now)
			}
			if allowed {
				caps = append(caps, cap)
			}
		}
		if len(authorities) > 0 {
			caps = append(caps, "access_grant.manage")
		}
		scopeKind, scopeID := "org", snap.OrgID
		if employeeScope != "" {
			scopeKind, scopeID = "employee", employeeScope
		}
		if teamScope != "" {
			scopeKind, scopeID = "team", teamScope
		}
		h.reply(w, 200, struct {
			Subject           string                `json:"subject_id"`
			Org               string                `json:"org_id"`
			Epoch             string                `json:"auth_epoch"`
			Capabilities      []string              `json:"capabilities"`
			CSRF              string                `json:"csrf_token"`
			ScopeKind         string                `json:"scope_kind"`
			ScopeID           string                `json:"scope_id"`
			MFARecent         bool                  `json:"mfa_recent"`
			MFAUntil          time.Time             `json:"mfa_valid_until"`
			Authorities       []authz.AuthorityHint `json:"grant_authorities"`
			IdentityAvailable bool                  `json:"identity_available"`
		}{snap.SubjectID, snap.OrgID, strconv.FormatInt(snap.AuthEpoch, 10), caps, token, scopeKind, scopeID, now.Before(snap.MFAUntil), snap.MFAUntil, authorities, h.identities.Available()})
		return
	}
	if r.URL.Path == "/api/v1/access-grants" || strings.HasPrefix(r.URL.Path, "/api/v1/access-grants/") {
		h.grantRoute(w, r, authz.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose, Key: req.Key})
		return
	}
	if h.structureRoute(w, r, req) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	create := len(parts) == 3 && parts[0] == "orgs" && parts[2] == "employees" && r.Method == http.MethodPost
	update := len(parts) == 3 && parts[0] == "employees" && parts[2] == "profile" && r.Method == http.MethodPatch
	get := len(parts) == 2 && parts[0] == "employees" && r.Method == http.MethodGet
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || (!create && !update && !get) {
		h.fail(w, fault.NotFound, requestID)
		return
	}
	if !value.ValidID(parts[1]) || req.Purpose != "organization_management" {
		h.fail(w, fault.Invalid, requestID)
		return
	}
	if get {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 2 || len(q["as_of"]) != 1 || len(q["include_profile"]) != 1 || !value.ValidDate(q.Get("as_of")) || (q.Get("include_profile") != "true" && q.Get("include_profile") != "false") {
			h.fail(w, fault.Invalid, requestID)
			return
		}
		result, e := h.service.Read(r.Context(), req, parts[1], q.Get("as_of"), q.Get("include_profile") == "true")
		if e != nil {
			h.fail(w, e, requestID)
			return
		}
		h.reply(w, 200, result)
		return
	}
	if !value.ValidID(req.Key) || req.Key[14] != '4' || !strings.ContainsRune("89ab", rune(req.Key[19])) {
		h.fail(w, fault.Invalid, requestID)
		return
	}
	if create {
		var cmd organization.CreateCommand
		if err := strictBody(w, r, &cmd); err != nil {
			h.fail(w, err, requestID)
			return
		}
		result, e := h.service.Create(r.Context(), req, parts[1], cmd)
		if e != nil {
			h.fail(w, e, requestID)
			return
		}
		h.reply(w, 201, result)
		return
	}
	var cmd organization.UpdateCommand
	if err := strictBody(w, r, &cmd); err != nil {
		h.fail(w, err, requestID)
		return
	}
	result, e := h.service.Update(r.Context(), req, parts[1], cmd)
	if e != nil {
		h.fail(w, e, requestID)
		return
	}
	h.reply(w, 200, result)
}
func sessionCookie(r *http.Request) ([]byte, error) {
	var token string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == "__Host-teamledger_session" {
			token = c.Value
			count++
		}
	}
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if count != 1 || e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, fault.Unauthenticated
	}
	return raw, nil
}
func strictBody(w http.ResponseWriter, r *http.Request, out any) error {
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if e != nil {
		var limit *http.MaxBytesError
		if errors.As(e, &limit) {
			return bodyTooLarge
		}
		return fault.Invalid
	}
	defer clear(data)
	if !utf8.Valid(data) {
		return fault.Invalid
	}
	root := ""
	switch out.(type) {
	case *organization.CreateCommand:
		root = "create"
	case *organization.UpdateCommand:
		root = "update"
	case *organization.CreateTeamCommand:
		root = "create_team"
	case *organization.StructureCommand:
		root = "structure_command"
	case *organization.DirectoryQuery:
		root = "directory_query"
	case *authz.IssueCommand:
		root = "issue"
	case *authz.RevokeCommand:
		root = "revoke"
	case *authStepUpCommand:
		root = "step_up"
	case *authLogoutCommand:
		root = "logout"
	default:
		return fault.Invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if e = walkJSON(d, 0, root); e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return fault.Invalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return fault.Invalid
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fault.Invalid
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int, object string) error {
	if depth > 8 {
		return fault.Invalid
	}
	t, e := d.Token()
	if e != nil {
		return fault.Invalid
	}
	switch object {
	case "subject_id", "capability", "category", "kind", "id", "purpose", "expires_at", "authority_id", "expected_revision", "expected_auth_epoch", "reason", "code", "label", "expected_graph_revision", "action", "ref", "employee_id", "team_id", "parent_team_id", "manager_employee_id", "reporting_kind", "end_date", "title", "position_code", "description", "as_of", "q", "cursor":
		if _, ok := t.(string); !ok {
			return fault.Invalid
		}
		return nil
	}
	if object == "object_ref" || object == "relation_ref" && t == nil {
		if t != nil {
			return fault.Invalid
		}
		return nil
	}
	if object == "changes" {
		if t != json.Delim('[') {
			return fault.Invalid
		}
		count := 0
		for d.More() {
			count++
			if count > 100 {
				return fault.Invalid
			}
			if e = walkJSON(d, depth+1, "change_item"); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') || count == 0 {
			return fault.Invalid
		}
		return nil
	}
	if object == "limit" {
		if _, ok := t.(json.Number); !ok {
			return fault.Invalid
		}
		return nil
	}
	if object == "mfa_required" || object == "relation_bound" || object == "is_primary" || object == "include_profile" {
		if _, ok := t.(bool); !ok {
			return fault.Invalid
		}
		return nil
	}
	if object == "issue" || object == "revoke" || object == "scope" || object == "relation_ref" || object == "create_team" || object == "structure_command" || object == "directory_query" || object == "change_item" || object == "position" {
		if t != json.Delim('{') {
			return fault.Invalid
		}
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' {
		return fault.Invalid
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		s, ok := key.(string)
		if e != nil || !ok || seen[s] || !allowedField(object, s) {
			return fault.Invalid
		}
		seen[s] = true
		if e = walkJSON(d, depth+1, s); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if (object == "issue" && len(seen) != 13) || (object == "revoke" && len(seen) != 3) || (object == "scope" && len(seen) != 2) || (object == "relation_ref" && len(seen) != 2) {
		return fault.Invalid
	}
	if e != nil || end != json.Delim('}') {
		return fault.Invalid
	}
	return nil
}
func allowedField(object, key string) bool {
	switch object {
	case "step_up":
		return key == "action" || key == "return_to"
	case "issue":
		switch key {
		case "subject_id", "capability", "category", "scope", "purpose", "valid_from", "expires_at", "mfa_required", "relation_bound", "relation_ref", "object_ref", "authority_id", "expected_revision":
			return true
		}
		return false
	case "revoke":
		return key == "expected_revision" || key == "expected_auth_epoch" || key == "reason"
	case "scope", "relation_ref":
		return key == "kind" || key == "id"
	case "create":
		return key == "profile" || key == "lifecycle"
	case "update":
		return key == "expected_profile_revision" || key == "profile" || key == "edit_reason"
	case "create_team":
		return key == "code" || key == "lifecycle" || key == "label"
	case "structure_command":
		return key == "expected_graph_revision" || key == "changes" || key == "reason"
	case "change_item":
		switch key {
		case "action", "kind", "ref", "employee_id", "team_id", "parent_team_id", "manager_employee_id", "reporting_kind", "is_primary", "lifecycle", "end_date", "position":
			return true
		}
		return false
	case "position":
		return key == "title" || key == "position_code" || key == "description"
	case "directory_query":
		switch key {
		case "as_of", "team_id", "employee_id", "lifecycle", "q", "cursor", "limit", "include_profile":
			return true
		}
		return false
	case "profile":
		return key == "display_name" || key == "work_contact" || key == "profile_summary"
	case "work_contact":
		return key == "email" || key == "phone"
	case "lifecycle":
		return key == "valid_from" || key == "valid_to"
	default:
		return false
	}
}
func (h *handler) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (h *handler) fail(w http.ResponseWriter, err error, id string) {
	public := fault.Unavailable
	// Only declared faults cross the boundary, never arbitrary error strings.
	for _, known := range []*fault.Fault{bodyTooLarge, unsupportedMedia, fault.Invalid, fault.Unauthenticated, identity.MFARequired, fault.NotFound, fault.Forbidden, fault.Conflict, fault.Mismatch, fault.Unavailable, fault.AuditUnavailable, fault.Busy} {
		if errors.Is(err, known) {
			public = known
			break
		}
	}
	h.reply(w, public.Status, struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}{public.Code, id, public.Reason})
}
func (h *handler) staticFile(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.fail(w, fault.NotFound, id)
		return
	}
	name := ""
	if identity.AllowedReturn(r.URL.RequestURI()) {
		name = "index.html"
	} else if strings.HasPrefix(r.URL.Path, "/assets/") && r.URL.RawQuery == "" {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if filepath.Clean(rel) != rel || strings.Contains(rel, "\\") {
			h.fail(w, fault.NotFound, id)
			return
		}
		switch filepath.Ext(rel) {
		case ".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".woff", ".woff2":
			name = rel
		}
	}
	if name == "" {
		h.fail(w, fault.NotFound, id)
		return
	}
	file, e := filepath.EvalSymlinks(filepath.Join(h.static, name))
	if e != nil || !strings.HasPrefix(file, h.static+string(filepath.Separator)) {
		h.fail(w, fault.NotFound, id)
		return
	}
	f, e := os.Open(file)
	if e != nil {
		h.fail(w, fault.NotFound, id)
		return
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		h.fail(w, fault.NotFound, id)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}
