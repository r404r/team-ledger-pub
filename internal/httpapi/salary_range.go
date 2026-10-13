package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) salaryRangeRoute(w http.ResponseWriter, r *http.Request, req compensation.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	if len(parts) != 3 || parts[0] != "orgs" || parts[2] != "salary-ranges" && parts[2] != "salary-range-changes" {
		return false
	}
	if !value.ValidID(parts[1]) || req.Purpose != "compensation_management" {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	org := parts[1]
	if parts[2] == "salary-ranges" && r.Method == http.MethodGet {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !singleQuery(q, []string{"legal_entity_id", "location", "job_family_id", "career_level_id", "currency", "as_of"}) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		view, err := h.compensation.SalaryRanges(r.Context(), req, org, compensation.SalaryRangeQuery{LegalEntityID: q.Get("legal_entity_id"), Location: q.Get("location"), JobFamilyID: q.Get("job_family_id"), CareerLevelID: q.Get("career_level_id"), Currency: q.Get("currency"), AsOf: q.Get("as_of")})
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, map[string]any{"salary_ranges": view})
		}
		return true
	}
	if parts[2] == "salary-range-changes" && r.Method == http.MethodPost {
		if !validCommandKey(req.Key) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		var command compensation.SalaryRangeChangeCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.ChangeSalaryRanges(r.Context(), req, org, command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, map[string]any{"salary_ranges": view})
		}
		return true
	}
	return false
}
