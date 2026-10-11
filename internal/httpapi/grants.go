package httpapi

import (
	"crypto/subtle"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) grantRoute(w http.ResponseWriter, r *http.Request, req authz.Request, csrf string) {
	if req.Purpose != authz.ManagementPurpose {
		h.fail(w, fault.Invalid, req.RequestID)
		return
	}
	if r.URL.Path == "/api/v1/access-grants" && r.Method == http.MethodGet {
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil {
			h.fail(w, fault.Invalid, req.RequestID)
			return
		}
		for k, v := range q {
			switch k {
			case "subject_id", "scope_kind", "scope_id", "category", "purpose", "state", "grant_id", "cursor", "limit":
			default:
				h.fail(w, fault.Invalid, req.RequestID)
				return
			}
			if len(v) != 1 || v[0] == "" {
				h.fail(w, fault.Invalid, req.RequestID)
				return
			}
		}
		if (q.Get("scope_kind") == "") != (q.Get("scope_id") == "") {
			h.fail(w, fault.Invalid, req.RequestID)
			return
		}
		limit := 50
		if q.Has("limit") {
			limit, e = strconv.Atoi(q.Get("limit"))
			if e != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != q.Get("limit") {
				h.fail(w, fault.Invalid, req.RequestID)
				return
			}
		}
		result, e := h.grants.List(r.Context(), req, authz.Filter{SubjectID: q.Get("subject_id"), ScopeKind: q.Get("scope_kind"), ScopeID: q.Get("scope_id"), Category: q.Get("category"), Purpose: q.Get("purpose"), State: q.Get("state"), GrantID: q.Get("grant_id"), Cursor: q.Get("cursor"), Limit: limit})
		if e != nil {
			h.fail(w, e, req.RequestID)
			return
		}
		h.reply(w, 200, result)
		return
	}
	issue := r.URL.Path == "/api/v1/access-grants" && r.Method == http.MethodPost
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/access-grants/"), "/")
	revoke := r.Method == http.MethodPost && len(parts) == 2 && value.ValidID(parts[0]) && parts[1] == "revoke"
	if !issue && !revoke {
		h.fail(w, fault.NotFound, req.RequestID)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
		h.fail(w, fault.Forbidden, req.RequestID)
		return
	}
	media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && strings.ToLower(params["charset"]) != "utf-8" {
		h.fail(w, unsupportedMedia, req.RequestID)
		return
	}
	if !value.ValidID(req.Key) || req.Key[14] != '4' || !strings.ContainsRune("89ab", rune(req.Key[19])) {
		h.fail(w, fault.Invalid, req.RequestID)
		return
	}
	if issue {
		var cmd authz.IssueCommand
		if e := strictBody(w, r, &cmd); e != nil {
			h.fail(w, e, req.RequestID)
			return
		}
		result, e := h.grants.Issue(r.Context(), req, cmd)
		if e != nil {
			h.fail(w, e, req.RequestID)
			return
		}
		h.reply(w, 201, result)
		return
	}
	var cmd authz.RevokeCommand
	if e := strictBody(w, r, &cmd); e != nil {
		h.fail(w, e, req.RequestID)
		return
	}
	result, e := h.grants.Revoke(r.Context(), req, parts[0], cmd)
	if e != nil {
		h.fail(w, e, req.RequestID)
		return
	}
	h.reply(w, 200, result)
}
