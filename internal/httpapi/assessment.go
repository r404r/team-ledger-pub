package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) assessmentRoute(w http.ResponseWriter, r *http.Request, req assessment.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	policy := len(parts) == 3 && parts[0] == "employees" && parts[2] == "interview-policy" && r.Method == http.MethodPut
	status := len(parts) == 3 && parts[0] == "employees" && parts[2] == "interview-status" && r.Method == http.MethodGet
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || (!policy && !status) {
		return false
	}
	if req.Purpose != "interview_followup" || !value.ValidID(parts[1]) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if policy {
		if !value.ValidID(req.Key) || req.Key[14] != '4' || !strings.ContainsRune("89ab", rune(req.Key[19])) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		var command assessment.PolicyCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		result, err := h.assessment.PutPolicy(r.Context(), req, parts[1], command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, result)
		}
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singleQuery(query, []string{"window_id", "from", "to"}) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	result, err := h.assessment.Status(r.Context(), req, parts[1], assessment.StatusQuery{WindowID: query.Get("window_id"), From: query.Get("from"), To: query.Get("to")})
	if err != nil {
		h.fail(w, err, req.RequestID)
	} else {
		h.reply(w, http.StatusOK, result)
	}
	return true
}
