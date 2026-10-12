package httpapi

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/fault"
)

func (h *handler) auditRoute(w http.ResponseWriter, r *http.Request, request audit.Request) bool {
	if r.URL.Path != "/api/v1/audit-events" {
		return false
	}
	if r.Method != http.MethodGet || request.Purpose != audit.Purpose {
		h.fail(w, fault.Invalid, request.RequestID)
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	allowed := []string{"subject_id", "employee_id", "grant_id", "operation", "purpose", "outcome", "from", "to", "cursor", "limit"}
	if err != nil || !singleQuery(query, allowed) {
		h.fail(w, fault.Invalid, request.RequestID)
		return true
	}
	limit := 50
	if h.audit == nil {
		h.fail(w, fault.Unavailable, request.RequestID)
		return true
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || strconv.Itoa(limit) != raw {
			h.fail(w, fault.Invalid, request.RequestID)
			return true
		}
	}
	page, err := h.audit.List(r.Context(), request, audit.Filter{
		SubjectID: query.Get("subject_id"), EmployeeID: query.Get("employee_id"), GrantID: query.Get("grant_id"), Operation: query.Get("operation"), Purpose: query.Get("purpose"), Outcome: query.Get("outcome"), From: query.Get("from"), To: query.Get("to"), Cursor: query.Get("cursor"), Limit: limit,
	})
	if err != nil {
		h.fail(w, err, request.RequestID)
		return true
	}
	h.reply(w, http.StatusOK, page)
	return true
}
