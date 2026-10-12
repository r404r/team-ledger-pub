package httpapi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/value"
)

func requiredFields(object string, seen map[string]bool) bool {
	switch object {
	case "finance_proposal":
		return len(seen) == 7
	case "finance_draft", "finance_terms":
		return len(seen) == 8
	case "finance_transition":
		return len(seen) == 4
	case "finance_member", "finance_component":
		return len(seen) == 6
	case "finance_before":
		return len(seen) >= 1 && len(seen) <= 2
	case "issue":
		return len(seen) == 13 && !seen["approved_source_refs"] || len(seen) == 14
	case "revoke", "source_ref", "export_object", "action_transition":
		return len(seen) == 3
	case "scope", "relation_ref", "object_ref", "party", "owner", "export_command":
		return len(seen) == 2
	case "interview_create":
		return len(seen) == 5
	case "interview_transition":
		return len(seen) == 6
	case "note_command":
		return len(seen) == 9
	case "action_command":
		return len(seen) == 6
	default:
		return true
	}
}

func currentInterviewPermissions(snapshot authz.Snapshot, employee, team string, now time.Time) []interview.Permission {
	permissions := make([]interview.Permission, 0, 17)
	add := func(capability, category string) {
		allowed := snapshot.Allows(capability, category, employee, "interview_followup", now)
		if team != "" {
			allowed = snapshot.AllowsTeam(capability, category, team, "interview_followup", now)
		}
		if allowed {
			permissions = append(permissions, interview.Permission{Capability: capability, Category: category})
		}
	}
	for _, capability := range [...]string{"interview.read", "interview.write"} {
		add(capability, "metadata")
	}
	for _, category := range [...]string{"shared", "manager_private", "hr_confidential"} {
		for _, capability := range [...]string{"note.read", "note.write", "note.publish", "sensitive.export"} {
			add(capability, category)
		}
	}
	for _, capability := range [...]string{"action.read", "action.write"} {
		add(capability, "shared")
	}
	add("sensitive.export", "metadata")
	return permissions
}

func (h *handler) interviewRoute(w http.ResponseWriter, r *http.Request, req interview.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	collection := len(parts) == 3 && parts[0] == "employees" && parts[2] == "interviews" && (r.Method == http.MethodGet || r.Method == http.MethodPost)
	detail := len(parts) == 2 && parts[0] == "interviews" && r.Method == http.MethodGet
	transition := len(parts) == 3 && parts[0] == "interviews" && parts[2] == "transitions" && r.Method == http.MethodPost
	note := len(parts) == 3 && parts[0] == "interviews" && parts[2] == "note-versions" && r.Method == http.MethodPost
	version := len(parts) == 2 && parts[0] == "note-versions" && r.Method == http.MethodGet
	action := len(parts) == 3 && parts[0] == "interviews" && parts[2] == "action-items" && r.Method == http.MethodPost
	actionTransition := len(parts) == 3 && parts[0] == "action-items" && parts[2] == "transitions" && r.Method == http.MethodPost
	export := r.URL.Path == "/api/v1/sensitive-exports" && r.Method == http.MethodPost
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || !(collection || detail || transition || note || version || action || actionTransition || export) {
		return false
	}
	if req.Purpose != "interview_followup" || !export && !value.ValidID(parts[1]) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if r.Method == http.MethodGet {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		if version {
			if len(q) != 0 {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			view, err := h.interviews.NoteVersion(r.Context(), req, parts[1])
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, view)
			}
			return true
		}
		if collection {
			if !singleQuery(q, []string{"from", "to", "status", "cursor", "limit"}) {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			limit, err := queryBound(q, "limit", 20, 1, 100)
			if err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			view, err := h.interviews.List(r.Context(), req, parts[1], interview.ListQuery{From: q.Get("from"), To: q.Get("to"), Status: q.Get("status"), Cursor: q.Get("cursor"), Limit: limit})
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, view)
			}
			return true
		}
		if !singleQuery(q, []string{"include_sections", "include_actions", "category", "cursor", "limit"}) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		query := interview.DetailQuery{Category: q.Get("category"), Cursor: q.Get("cursor")}
		query.Limit, err = queryBound(q, "limit", 100, 1, 100)
		if err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		if q.Has("include_sections") {
			query.IncludeSections = strings.Split(q.Get("include_sections"), ",")
			if len(query.IncludeSections) > 3 {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			seen := make(map[string]bool, 3)
			for _, category := range query.IncludeSections {
				if category != "shared" && category != "manager_private" && category != "hr_confidential" || seen[category] {
					h.fail(w, fault.Invalid, req.RequestID)
					return true
				}
				seen[category] = true
			}
		}
		if q.Has("include_actions") {
			if q.Get("include_actions") != "true" && q.Get("include_actions") != "false" {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			query.IncludeActions = q.Get("include_actions") == "true"
		}
		view, err := h.interviews.Detail(r.Context(), req, parts[1], query)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, view)
		}
		return true
	}
	if !validCommandKey(req.Key) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if export {
		var command interview.ExportCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		started := false
		_, err := h.interviews.Export(r.Context(), req, command, func(event interview.ExportEvent) error {
			if r.Context().Err() != nil {
				return r.Context().Err()
			}
			if len(event.EncodedJSON) == 0 {
				return fault.Unavailable
			}
			if !started {
				w.Header().Set("Content-Type", "application/x-ndjson")
				w.WriteHeader(http.StatusOK)
				started = true
			}
			n, err := w.Write(event.EncodedJSON)
			if err != nil {
				return err
			}
			if n != len(event.EncodedJSON) {
				return io.ErrShortWrite
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return nil
		})
		if err != nil && !started {
			h.fail(w, err, req.RequestID)
		}
		return true
	}
	var result interview.Result
	var err error
	switch {
	case collection:
		var command interview.CreateCommand
		err = strictBody(w, r, &command)
		if err == nil {
			result, err = h.interviews.Create(r.Context(), req, parts[1], command)
		}
	case transition:
		var command interview.TransitionCommand
		err = strictBody(w, r, &command)
		if err == nil {
			result, err = h.interviews.Transition(r.Context(), req, parts[1], command)
		}
	case note:
		var command interview.NoteCommand
		err = strictBody(w, r, &command)
		if err == nil {
			result, err = h.interviews.SaveNote(r.Context(), req, parts[1], command)
		}
	case action:
		var command interview.ActionCommand
		err = strictBody(w, r, &command)
		if err == nil {
			result, err = h.interviews.CreateAction(r.Context(), req, parts[1], command)
		}
	case actionTransition:
		var command interview.ActionTransitionCommand
		err = strictBody(w, r, &command)
		if err == nil {
			result, err = h.interviews.TransitionAction(r.Context(), req, parts[1], command)
		}
	}
	if err != nil {
		h.fail(w, err, req.RequestID)
	} else if transition || actionTransition {
		h.reply(w, http.StatusOK, result)
	} else {
		h.reply(w, http.StatusCreated, result)
	}
	return true
}

func sensitivityDeadline(snapshot authz.Snapshot, now time.Time) (time.Time, error) {
	zone, err := time.LoadLocation(snapshot.Timezone)
	if err != nil || snapshot.Timezone == "" {
		return time.Time{}, fault.Unavailable
	}
	local := now.In(zone)
	deadline := time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, zone)
	earlier := func(candidate time.Time) {
		if candidate.After(now) && candidate.Before(deadline) {
			deadline = candidate
		}
	}
	earlier(snapshot.ExpiresAt)
	earlier(snapshot.IdleExpiresAt)
	earlier(snapshot.MFAUntil)
	for _, grant := range snapshot.Grants {
		if !grant.Revoked {
			earlier(grant.ValidFrom)
			earlier(grant.ExpiresAt)
		}
	}
	return deadline.UTC(), nil
}
