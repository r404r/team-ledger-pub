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

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

var bodyTooLarge = &fault.Fault{Status: 413, Code: "INVALID_INPUT", Reason: "BODY_TOO_LARGE"}
var unsupportedMedia = &fault.Fault{Status: 415, Code: "INVALID_INPUT", Reason: "UNSUPPORTED_MEDIA_TYPE"}

type handler struct {
	service        *organization.Service
	grants         *authz.Service
	interviews     *interview.Service
	assessment     *assessment.Service
	compensation   *compensation.Service
	audit          *audit.Service
	identities     *identity.Service
	key            []byte
	origin, static string
}

func New(service *organization.Service, interviews *interview.Service, assessmentService *assessment.Service, compensation *compensation.Service, grants *authz.Service, identities *identity.Service, csrfKey []byte, origin, staticDir string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || service == nil || interviews == nil || assessmentService == nil || compensation == nil || grants == nil || identities == nil || len(csrfKey) != 32 {
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
	var auditService *audit.Service
	if auditStore, ok := grants.Store.(audit.Store); ok {
		auditService = &audit.Service{Store: auditStore, CursorKey: grants.CursorKey, Now: grants.Now}
	}
	return &handler{service: service, interviews: interviews, assessment: assessmentService, compensation: compensation, grants: grants, audit: auditService, identities: identities, key: bytes.Clone(csrfKey), origin: strings.TrimSuffix(origin, "/"), static: root}, nil
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-TeamLedger-Identity-Mode", h.identities.Mode())
	w.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := value.NewID()
	w.Header().Set("X-Request-ID", requestID)
	if r.TLS == nil || r.Host != strings.TrimPrefix(h.origin, "https://") {
		h.fail(w, fault.Forbidden, requestID)
		return
	}
	if h.healthRoute(w, r, requestID) {
		return
	}
	if h.assessmentWorkerRoute(w, r, requestID) {
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
	employeeScope, departmentScope := "", ""
	invalidScope := false
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) > 1 || !singleQuery(q, []string{"employee_id", "department_id"}) {
			invalidScope = true
		} else if len(q) == 1 {
			employeeScope, departmentScope = q.Get("employee_id"), q.Get("department_id")
			if !value.ValidID(employeeScope) && !value.ValidID(departmentScope) {
				invalidScope = true
			}
		}
	}
	financeSession := r.URL.Path == "/api/v1/session" && r.Method == http.MethodGet && req.Purpose == "compensation_management"
	authEmployee := employeeScope
	if financeSession {
		authEmployee = ""
	}
	snap, err := h.service.Session(r.Context(), req, authEmployee)
	if err != nil {
		h.fail(w, err, requestID)
		return
	}
	if invalidScope {
		h.fail(w, fault.Invalid, requestID)
		return
	}
	if financeSession && employeeScope != "" {
		now := time.Now().UTC().Truncate(time.Microsecond)
		if h.compensation.Now != nil {
			now = h.compensation.Now().UTC().Truncate(time.Microsecond)
		}
		if !now.Before(snap.MFAUntil) {
			// Without recent MFA release only the caller's unscoped session;
			// the requested employee is not an authority or an existence hint.
			employeeScope = ""
		} else {
			scoped, e := h.compensationSession(r, req, employeeScope, now)
			if e != nil {
				h.fail(w, e, requestID)
				return
			}
			snap = scoped
		}
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
		workbookUpload := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/compensation-adjustment-batches/") && strings.HasSuffix(r.URL.Path, "/imports")
		if r.URL.RawQuery != "" && !workbookUpload || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(token)) != 1 {
			h.fail(w, fault.Forbidden, requestID)
			return
		}
		media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		validMedia := media == "application/json" && len(params) <= 1 && (len(params) == 0 || strings.ToLower(params["charset"]) == "utf-8")
		if workbookUpload {
			validMedia = media == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" && len(params) == 0
		}
		if e != nil || !validMedia {
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
			if departmentScope != "" {
				allowed = snap.AllowsDepartment(cap, category, departmentScope, "organization_management", now)
			}
			if allowed {
				caps = append(caps, cap)
			}
		}
		if len(authorities) > 0 {
			caps = append(caps, "access_grant.manage")
		}
		if snap.Allows("audit.read", "audit", employeeScope, authz.ManagementPurpose, now) {
			caps = append(caps, "audit.read")
		}
		sensitivityUntil, e := sensitivityDeadline(snap, now)
		if e != nil {
			h.fail(w, e, requestID)
			return
		}
		interviewPermissions := currentInterviewPermissions(snap, employeeScope, departmentScope, now)
		compensationPermissions := []compensation.Permission{}
		if financeSession && h.compensation.Policy.Enabled {
			compensationPermissions = currentCompensationPermissions(snap, employeeScope, departmentScope, now)
		}
		for _, permission := range compensationPermissions {
			present := false
			for _, cap := range caps {
				if cap == permission.Capability {
					present = true
					break
				}
			}
			if !present {
				caps = append(caps, permission.Capability)
			}
		}
		for _, permission := range interviewPermissions {
			present := false
			for _, cap := range caps {
				if cap == permission.Capability {
					present = true
					break
				}
			}
			if !present {
				caps = append(caps, permission.Capability)
			}
		}
		scopeKind, scopeID := "org", snap.OrgID
		if employeeScope != "" {
			scopeKind, scopeID = "employee", employeeScope
		}
		if departmentScope != "" {
			scopeKind, scopeID = "department", departmentScope
		}
		h.reply(w, 200, struct {
			Subject                 string                    `json:"subject_id"`
			Org                     string                    `json:"org_id"`
			Epoch                   string                    `json:"auth_epoch"`
			Capabilities            []string                  `json:"capabilities"`
			CSRF                    string                    `json:"csrf_token"`
			ScopeKind               string                    `json:"scope_kind"`
			ScopeID                 string                    `json:"scope_id"`
			MFARecent               bool                      `json:"mfa_recent"`
			MFAUntil                time.Time                 `json:"mfa_valid_until"`
			Authorities             []authz.AuthorityHint     `json:"grant_authorities"`
			IdentityAvailable       bool                      `json:"identity_available"`
			IdentityMode            string                    `json:"identity_mode"`
			InterviewPermissions    []interview.Permission    `json:"interview_permissions"`
			CompensationPermissions []compensation.Permission `json:"compensation_permissions"`
			SensitivityUntil        time.Time                 `json:"sensitivity_valid_until"`
		}{snap.SubjectID, snap.OrgID, strconv.FormatInt(snap.AuthEpoch, 10), caps, token, scopeKind, scopeID, now.Before(snap.MFAUntil), snap.MFAUntil, authorities, h.identities.Available(), h.identities.Mode(), interviewPermissions, compensationPermissions, sensitivityUntil})
		return
	}
	if r.URL.Path == "/api/v1/access-grants" || strings.HasPrefix(r.URL.Path, "/api/v1/access-grants/") {
		h.grantRoute(w, r, authz.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose, Key: req.Key})
		return
	}
	if h.auditRoute(w, r, audit.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose}) {
		return
	}
	if h.profileExportRoute(w, r, req) {
		return
	}
	if h.compensationRoute(w, r, compensation.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose, Key: req.Key}) {
		return
	}
	if h.assessmentRoute(w, r, assessment.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose, Key: req.Key}) {
		return
	}
	if h.interviewRoute(w, r, interview.Request{TokenHash: req.TokenHash, RequestID: req.RequestID, Purpose: req.Purpose, Key: req.Key}) {
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
	case *organization.CatalogChangeCommand:
		root = "catalog_command"
	case *organization.WorkforceChangeCommand:
		root = "workforce_command"
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
	case *interview.CreateCommand:
		root = "interview_create"
	case *interview.TransitionCommand:
		root = "interview_transition"
	case *interview.NoteCommand:
		root = "note_command"
	case *interview.ActionCommand:
		root = "action_command"
	case *interview.ActionTransitionCommand:
		root = "action_transition"
	case *interview.ExportCommand:
		root = "export_command"
	case *organization.ExportCommand:
		root = "export_command"
	case *compensation.ProposalCommand:
		root = "finance_proposal"
	case *compensation.DraftCommand:
		root = "finance_draft"
	case *compensation.TransitionCommand:
		root = "finance_transition"
	case *compensation.ExportCommand:
		root = "export_command"
	case *compensation.BonusTargetCommand, *compensation.BonusTargetTransition, *compensation.BonusAwardCommand, *compensation.BonusAwardEditCommand, *compensation.BonusAwardTransition, *compensation.BonusPaymentCommand, *compensation.BonusExtensionCommand:
		root = "bonus_command"
	case *compensation.CreateBatchCommand, *compensation.ReplaceBatchLinesCommand, *compensation.BatchTransitionCommand, *compensation.BatchCorrectionCommand:
		root = "batch_command"
	case *compensation.SalaryRangeChangeCommand:
		root = "batch_command"
	case *assessment.PolicyCommand, *assessment.AssessmentCommand, *assessment.ApproveCommand, *assessment.ResultCommand:
		root = "assessment_command"
	case *workerClaimCommand, *workerLeaseCommand, *workerHeartbeatCommand, *workerResultCommand, *workerFailCommand:
		root = "assessment_worker"
	case *authLocalLoginCommand:
		root = "local_login"
	case *authPasswordChangeCommand:
		root = "local_password_change"
	default:
		return fault.Invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if strings.HasPrefix(root, "finance_") {
		e = walkFinancialJSON(d, 0, root, false)
	} else if root == "local_login" || root == "local_password_change" || root == "bonus_command" || root == "batch_command" || root == "assessment_command" || root == "assessment_worker" || root == "catalog_command" || root == "workforce_command" {
		e = walkUniqueJSON(d, 0)
	} else {
		e = walkJSON(d, 0, root)
	}
	if e != nil {
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
func walkUniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fault.Invalid
	}
	token, err := d.Token()
	if err != nil {
		return fault.Invalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return fault.Invalid
			}
			seen[name] = true
			if err = walkUniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return fault.Invalid
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 100 || walkUniqueJSON(d, depth+1) != nil {
				return fault.Invalid
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return fault.Invalid
		}
	default:
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
	case "head_id", "supersedes_version_id", "actual_started_at", "actual_ended_at", "due_date":
		if t == nil {
			return nil
		}
		if _, ok := t.(string); !ok {
			return fault.Invalid
		}
		return nil
	}
	switch object {
	case "subject_id", "capability", "category", "kind", "id", "purpose", "expires_at", "authority_id", "expected_revision", "expected_auth_epoch", "reason", "code", "label", "expected_graph_revision", "action", "ref", "employee_id", "department_id", "manager_employee_id", "reporting_kind", "end_date", "title", "position_code", "description", "as_of", "q", "cursor", "scheduled_at", "expected_head_revision", "text", "edit_reason", "expected_version", "minimal_shared_text", "safe_blocker_text", "format", "return_to":
		if _, ok := t.(string); !ok {
			return fault.Invalid
		}
		return nil
	}
	if (object == "object_ref" || object == "relation_ref") && t == nil {
		return nil
	}
	if object == "approved_source_refs" && t == nil {
		return nil
	}
	element, maximum, minimum := "", 0, 0
	switch object {
	case "changes":
		element, maximum, minimum = "change_item", 100, 1
	case "participants":
		element, maximum = "party", 20
	case "source_refs":
		element, maximum = "source_ref", 10
	case "approved_source_refs":
		element, maximum = "object_ref", 10
	case "objects":
		element, maximum, minimum = "export_object", 100, 1
	}
	if element != "" {
		if t != json.Delim('[') {
			return fault.Invalid
		}
		count := 0
		for d.More() {
			count++
			if count > maximum {
				return fault.Invalid
			}
			if e = walkJSON(d, depth+1, element); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') || count < minimum {
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
	if object == "mfa_required" || object == "relation_bound" || object == "is_primary" || object == "include_profile" || object == "backfilled" || object == "confirm_minimized" {
		if _, ok := t.(bool); !ok {
			return fault.Invalid
		}
		return nil
	}
	if object == "issue" || object == "revoke" || object == "scope" || object == "relation_ref" || object == "object_ref" || object == "create_team" || object == "structure_command" || object == "directory_query" || object == "change_item" || object == "position" || strings.HasPrefix(object, "interview_") || object == "note_command" || object == "action_command" || object == "action_transition" || object == "export_command" || object == "export_object" || object == "owner" || object == "party" || object == "source_ref" {
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
	if !requiredFields(object, seen) {
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
		case "subject_id", "capability", "category", "scope", "purpose", "valid_from", "expires_at", "mfa_required", "relation_bound", "relation_ref", "object_ref", "authority_id", "expected_revision", "approved_source_refs":
			return true
		}
		return false
	case "revoke":
		return key == "expected_revision" || key == "expected_auth_epoch" || key == "reason"
	case "scope", "relation_ref", "object_ref", "party", "owner":
		return key == "kind" || key == "id"
	case "interview_create":
		return key == "scheduled_at" || key == "participants" || key == "backfilled" || key == "actual_started_at" || key == "actual_ended_at"
	case "interview_transition":
		return key == "action" || key == "expected_revision" || key == "backfilled" || key == "actual_started_at" || key == "actual_ended_at" || key == "reason"
	case "note_command":
		return key == "head_id" || key == "category" || key == "expected_head_revision" || key == "text" || key == "edit_reason" || key == "action" || key == "supersedes_version_id" || key == "source_refs" || key == "confirm_minimized"
	case "action_command":
		return key == "expected_revision" || key == "minimal_shared_text" || key == "owner" || key == "due_date" || key == "source_refs" || key == "confirm_minimized"
	case "action_transition":
		return key == "action" || key == "expected_revision" || key == "safe_blocker_text"
	case "source_ref":
		return key == "kind" || key == "id" || key == "expected_version"
	case "export_command":
		return key == "objects" || key == "format"
	case "export_object":
		return key == "kind" || key == "id" || key == "expected_revision"
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
		case "action", "kind", "ref", "employee_id", "department_id", "manager_employee_id", "reporting_kind", "is_primary", "lifecycle", "end_date", "position":
			return true
		}
		return false
	case "position":
		return key == "title" || key == "position_code" || key == "description"
	case "directory_query":
		switch key {
		case "as_of", "department_id", "employee_id", "lifecycle", "q", "cursor", "limit", "include_profile":
			return true
		}
		return false
	case "profile":
		return key == "local_name" || key == "english_name" || key == "work_contact" || key == "profile_summary"
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
