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

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

var bodyTooLarge = &organization.Fault{Status: 413, Code: "INVALID_INPUT", Reason: "BODY_TOO_LARGE"}
var unsupportedMedia = &organization.Fault{Status: 415, Code: "INVALID_INPUT", Reason: "UNSUPPORTED_MEDIA_TYPE"}

type handler struct {
	service        *organization.Service
	key            []byte
	origin, static string
}

func New(service *organization.Service, csrfKey []byte, origin, staticDir string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || service == nil || len(csrfKey) != 32 {
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
	return &handler{service: service, key: bytes.Clone(csrfKey), origin: strings.TrimSuffix(origin, "/"), static: root}, nil
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := value.NewID()
	w.Header().Set("X-Request-ID", requestID)
	if r.TLS == nil || r.Host != strings.TrimPrefix(h.origin, "https://") {
		h.fail(w, organization.Forbidden, requestID)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		h.staticFile(w, r, requestID)
		return
	}
	req := organization.Request{RequestID: requestID, Purpose: r.Header.Get("X-Access-Purpose"), Key: r.Header.Get("Idempotency-Key")}
	raw, err := sessionCookie(r)
	if err != nil {
		h.fail(w, organization.Unauthenticated, requestID)
		return
	}
	hash := sha256.Sum256(raw)
	req.TokenHash = hash[:]
	employeeScope := ""
	invalidScope := false
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || (len(q) != 0 && (len(q) != 1 || len(q["employee_id"]) != 1 || !value.ValidID(q.Get("employee_id")))) {
			invalidScope = true
		} else {
			employeeScope = q.Get("employee_id")
		}
	}
	snap, err := h.service.Session(r.Context(), req, employeeScope)
	if err != nil {
		h.fail(w, err, requestID)
		return
	}
	if invalidScope {
		h.fail(w, organization.Invalid, requestID)
		return
	}
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte("TEAMLEDGER-CSRF\x00"))
	mac.Write(raw)
	token := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	tokenHash := sha256.Sum256([]byte(token))
	if snap.CSRFVersion != 1 || subtle.ConstantTimeCompare(snap.CSRFHash, tokenHash[:]) != 1 {
		h.fail(w, organization.Unauthenticated, requestID)
		return
	}
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet {
		now := time.Now().UTC()
		caps := make([]string, 0, 4)
		for _, cap := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
			category := "metadata"
			if strings.HasPrefix(cap, "pii.") {
				category = "pii"
			}
			if snap.Allows(cap, category, employeeScope, "organization_management", now) {
				caps = append(caps, cap)
			}
		}
		scopeKind, scopeID := "org", snap.OrgID
		if employeeScope != "" {
			scopeKind, scopeID = "employee", employeeScope
		}
		h.reply(w, 200, struct {
			Subject      string    `json:"subject_id"`
			Org          string    `json:"org_id"`
			Epoch        string    `json:"auth_epoch"`
			Capabilities []string  `json:"capabilities"`
			CSRF         string    `json:"csrf_token"`
			ScopeKind    string    `json:"scope_kind"`
			ScopeID      string    `json:"scope_id"`
			MFARecent    bool      `json:"mfa_recent"`
			MFAUntil     time.Time `json:"mfa_valid_until"`
		}{snap.SubjectID, snap.OrgID, strconv.FormatInt(snap.AuthEpoch, 10), caps, token, scopeKind, scopeID, now.Before(snap.MFAUntil), snap.MFAUntil})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	create := len(parts) == 3 && parts[0] == "orgs" && parts[2] == "employees" && r.Method == http.MethodPost
	update := len(parts) == 3 && parts[0] == "employees" && parts[2] == "profile" && r.Method == http.MethodPatch
	get := len(parts) == 2 && parts[0] == "employees" && r.Method == http.MethodGet
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || (!create && !update && !get) {
		h.fail(w, organization.NotFound, requestID)
		return
	}
	if !value.ValidID(parts[1]) || req.Purpose != "organization_management" {
		h.fail(w, organization.Invalid, requestID)
		return
	}
	if get {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 2 || len(q["as_of"]) != 1 || len(q["include_profile"]) != 1 || !value.ValidDate(q.Get("as_of")) || (q.Get("include_profile") != "true" && q.Get("include_profile") != "false") {
			h.fail(w, organization.Invalid, requestID)
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
	if r.URL.RawQuery != "" || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(token)) != 1 {
		h.fail(w, organization.Forbidden, requestID)
		return
	}
	media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && strings.ToLower(params["charset"]) != "utf-8") {
		h.fail(w, unsupportedMedia, requestID)
		return
	}
	if !value.ValidID(req.Key) || req.Key[14] != '4' || !strings.ContainsRune("89ab", rune(req.Key[19])) {
		h.fail(w, organization.Invalid, requestID)
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
		return nil, organization.Unauthenticated
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
		return organization.Invalid
	}
	defer clear(data)
	if !utf8.Valid(data) {
		return organization.Invalid
	}
	root := ""
	switch out.(type) {
	case *organization.CreateCommand:
		root = "create"
	case *organization.UpdateCommand:
		root = "update"
	default:
		return organization.Invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if e = walkJSON(d, 0, root); e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return organization.Invalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return organization.Invalid
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return organization.Invalid
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int, object string) error {
	if depth > 8 {
		return organization.Invalid
	}
	t, e := d.Token()
	if e != nil {
		return organization.Invalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' {
		return organization.Invalid
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		s, ok := key.(string)
		if e != nil || !ok || seen[s] || !allowedField(object, s) {
			return organization.Invalid
		}
		seen[s] = true
		if e = walkJSON(d, depth+1, s); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') {
		return organization.Invalid
	}
	return nil
}
func allowedField(object, key string) bool {
	switch object {
	case "create":
		return key == "profile" || key == "lifecycle"
	case "update":
		return key == "expected_profile_revision" || key == "profile" || key == "edit_reason"
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
	fault := organization.Unavailable
	// Only declared faults cross the boundary, never arbitrary error strings.
	for _, known := range []*organization.Fault{bodyTooLarge, unsupportedMedia, organization.Invalid, organization.Unauthenticated, organization.NotFound, organization.Forbidden, organization.Conflict, organization.Mismatch, organization.Unavailable, organization.AuditUnavailable, organization.Busy} {
		if errors.Is(err, known) {
			fault = known
			break
		}
	}
	h.reply(w, fault.Status, struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}{fault.Code, id, fault.Reason})
}
func (h *handler) staticFile(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.fail(w, organization.NotFound, id)
		return
	}
	if r.URL.RawQuery != "" {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 1 || len(q["as_of"]) != 1 || !value.ValidDate(q.Get("as_of")) || strings.HasPrefix(r.URL.Path, "/assets/") {
			h.fail(w, organization.NotFound, id)
			return
		}
	}
	name := ""
	if r.URL.Path == "/" {
		name = "index.html"
	} else if strings.HasPrefix(r.URL.Path, "/employees/") && value.ValidID(strings.TrimPrefix(r.URL.Path, "/employees/")) {
		name = "index.html"
	} else if strings.HasPrefix(r.URL.Path, "/assets/") {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if filepath.Clean(rel) != rel || strings.Contains(rel, "\\") {
			h.fail(w, organization.NotFound, id)
			return
		}
		switch filepath.Ext(rel) {
		case ".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".woff", ".woff2":
			name = rel
		}
	}
	if name == "" {
		h.fail(w, organization.NotFound, id)
		return
	}
	file, e := filepath.EvalSymlinks(filepath.Join(h.static, name))
	if e != nil || !strings.HasPrefix(file, h.static+string(filepath.Separator)) {
		h.fail(w, organization.NotFound, id)
		return
	}
	f, e := os.Open(file)
	if e != nil {
		h.fail(w, organization.NotFound, id)
		return
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		h.fail(w, organization.NotFound, id)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}
