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
	request := len(parts) == 4 && parts[0] == "employees" && parts[2] == "assessments" && parts[3] == "request" && r.Method == http.MethodPost
	approve := len(parts) == 4 && parts[0] == "employees" && parts[2] == "assessment-inputs" && parts[3] == "approve" && r.Method == http.MethodPost
	jobs := len(parts) == 3 && parts[0] == "employees" && parts[2] == "assessment-jobs" && r.Method == http.MethodGet
	resultRoute := len(parts) == 4 && parts[0] == "employees" && parts[2] == "assessment-results" && value.ValidID(parts[3]) && (r.Method == http.MethodGet || r.Method == http.MethodPost)
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || (!policy && !status && !request && !approve && !jobs && !resultRoute) {
		return false
	}
	if req.Purpose != "interview_followup" || !value.ValidID(parts[1]) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if r.Method != http.MethodGet && (!value.ValidID(req.Key) || req.Key[14] != '4' || !strings.ContainsRune("89ab", rune(req.Key[19]))) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if policy {
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
	if request {
		var command assessment.AssessmentCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		output, err := h.assessment.RequestAssessment(r.Context(), req, parts[1], command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, output)
		}
		return true
	}
	if approve {
		var command assessment.ApproveCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		output, err := h.assessment.ApproveAssessment(r.Context(), req, parts[1], command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, output)
		}
		return true
	}
	if jobs {
		if r.URL.RawQuery != "" {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		output, err := h.assessment.Jobs(r.Context(), req, parts[1])
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, output)
		}
		return true
	}
	if resultRoute {
		if r.Method == http.MethodGet {
			if r.URL.RawQuery != "" {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			output, err := h.assessment.GetResult(r.Context(), req, parts[1], parts[3])
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, output)
			}
			return true
		}
		var command assessment.ResultCommand
		if err := strictBody(w, r, &command); err != nil || command.ResultID != parts[3] {
			if err == nil {
				err = fault.Invalid
			}
			h.fail(w, err, req.RequestID)
			return true
		}
		output, err := h.assessment.TransitionResult(r.Context(), req, parts[1], command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, output)
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
