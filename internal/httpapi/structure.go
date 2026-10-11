package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

// structureRoute handles registered R2 operations only. Employee create/profile
// operations remain independent commands in the existing dispatcher.
func (h *handler) structureRoute(w http.ResponseWriter, r *http.Request, req organization.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	teamCreate := len(parts) == 3 && parts[0] == "orgs" && parts[2] == "teams" && r.Method == http.MethodPost
	change := len(parts) == 3 && parts[0] == "orgs" && parts[2] == "structure-changes" && r.Method == http.MethodPost
	tree := len(parts) == 3 && parts[0] == "orgs" && parts[2] == "tree" && r.Method == http.MethodGet
	directory := len(parts) == 4 && parts[0] == "orgs" && parts[2] == "employees" && parts[3] == "query" && r.Method == http.MethodPost
	history := len(parts) == 3 && parts[0] == "employees" && parts[2] == "organization-history" && r.Method == http.MethodGet
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || !(teamCreate || change || tree || directory || history) {
		return false
	}
	if !value.ValidID(parts[1]) || req.Purpose != "organization_management" {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if teamCreate || change {
		if !validCommandKey(req.Key) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		if teamCreate {
			var cmd organization.CreateTeamCommand
			if err := strictBody(w, r, &cmd); err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			result, err := h.service.CreateTeam(r.Context(), req, parts[1], cmd)
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusCreated, result)
			}
			return true
		}
		var cmd organization.StructureCommand
		if err := strictBody(w, r, &cmd); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		result, err := h.service.ChangeStructure(r.Context(), req, parts[1], cmd)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, result)
		}
		return true
	}
	if directory {
		var query organization.DirectoryQuery
		if err := strictBody(w, r, &query); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		result, err := h.service.Directory(r.Context(), req, parts[1], query)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, result)
		}
		return true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	allowed := []string{"as_of", "root_team_id", "depth", "limit", "include_labels"}
	if history {
		allowed = []string{"from", "to", "cursor", "limit"}
	}
	if err != nil || !singleQuery(q, allowed) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	limit, err := queryBound(q, "limit", 100, 1, 100)
	if history && !q.Has("limit") {
		limit = 50
	}
	if err != nil {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if tree {
		depth, err := queryBound(q, "depth", 10, 1, 10)
		if err != nil || !value.ValidDate(q.Get("as_of")) || (q.Has("root_team_id") && !value.ValidID(q.Get("root_team_id"))) || (q.Has("include_labels") && q.Get("include_labels") != "true" && q.Get("include_labels") != "false") {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		result, err := h.service.Tree(r.Context(), req, parts[1], organization.TreeQuery{AsOf: q.Get("as_of"), RootTeamID: q.Get("root_team_id"), Depth: depth, Limit: limit, IncludeLabels: q.Get("include_labels") == "true"})
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, result)
		}
		return true
	}
	if q.Has("from") != q.Has("to") || (q.Has("from") && (!value.ValidDate(q.Get("from")) || !value.ValidDate(q.Get("to")) || q.Get("from") >= q.Get("to"))) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	result, err := h.service.History(r.Context(), req, parts[1], organization.HistoryQuery{From: q.Get("from"), To: q.Get("to"), Cursor: q.Get("cursor"), Limit: limit})
	if err != nil {
		h.fail(w, err, req.RequestID)
	} else {
		h.reply(w, http.StatusOK, result)
	}
	return true
}

func validCommandKey(key string) bool {
	return value.ValidID(key) && key[14] == '4' && strings.ContainsRune("89ab", rune(key[19]))
}

func singleQuery(q url.Values, allowed []string) bool {
	for key, values := range q {
		if len(values) != 1 || values[0] == "" {
			return false
		}
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func queryBound(q url.Values, key string, fallback, min, max int) (int, error) {
	if !q.Has(key) {
		return fallback, nil
	}
	n, err := strconv.Atoi(q.Get(key))
	if err != nil || n < min || n > max || strconv.Itoa(n) != q.Get(key) {
		return 0, fault.Invalid
	}
	return n, nil
}
