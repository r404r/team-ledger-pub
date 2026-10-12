package httpapi

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) compensationSession(r *http.Request, req organization.Request, employee string, now time.Time) (authz.Snapshot, error) {
	snapshot, err := h.compensation.Store.Security(r.Context(), req.TokenHash, "", employee)
	if err != nil {
		return authz.Snapshot{}, err
	}
	denied := func(err error) (authz.Snapshot, error) {
		audit := organization.Audit{ID: value.NewID(), OrgID: snapshot.OrgID, SubjectID: snapshot.SubjectID, Operation: "OP-SEC-01", Purpose: "compensation_management", RequestID: req.RequestID, Outcome: "denied", At: now}
		if auditErr := h.compensation.Store.AuditDenied(r.Context(), audit); auditErr != nil {
			log.Printf("DENIED_AUDIT_UNAVAILABLE request_id=%s operation=OP-SEC-01", req.RequestID)
		}
		return authz.Snapshot{}, err
	}
	if !snapshot.Valid(now) {
		return denied(fault.Unauthenticated)
	}
	if !h.compensation.Policy.Enabled || !snapshot.Allows("compensation.read", "financial", employee, "compensation_management", now) {
		return denied(fault.NotFound)
	}
	object, err := h.compensation.Store.Employee(r.Context(), employee)
	if err != nil {
		return denied(err)
	}
	if object.OrgID != snapshot.OrgID {
		return denied(fault.NotFound)
	}
	return snapshot, nil
}

func currentCompensationPermissions(snapshot authz.Snapshot, employee, team string, now time.Time) []compensation.Permission {
	permissions := make([]compensation.Permission, 0, 4)
	for _, capability := range [...]string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
		allowed := snapshot.Allows(capability, "financial", employee, "compensation_management", now)
		if team != "" {
			allowed = snapshot.AllowsTeam(capability, "financial", team, "compensation_management", now)
		}
		if allowed {
			permissions = append(permissions, compensation.Permission{Capability: capability, Category: "financial"})
		}
	}
	return permissions
}

func (h *handler) compensationRoute(w http.ResponseWriter, r *http.Request, req compensation.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	current := len(parts) == 3 && parts[0] == "employees" && parts[2] == "compensation" && r.Method == http.MethodGet
	changes := len(parts) == 4 && parts[0] == "employees" && parts[2] == "compensation" && parts[3] == "changes" && r.Method == http.MethodGet
	create := len(parts) == 4 && parts[0] == "employees" && parts[2] == "compensation" && parts[3] == "proposals" && r.Method == http.MethodPost
	edit := len(parts) == 3 && parts[0] == "compensation" && parts[1] == "proposals" && r.Method == http.MethodPatch
	transition := len(parts) == 4 && parts[0] == "compensation" && parts[1] == "proposals" && parts[3] == "transitions" && r.Method == http.MethodPost
	export := r.URL.Path == "/api/v1/sensitive-exports" && r.Method == http.MethodPost && req.Purpose == "compensation_management"
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || !(current || changes || create || edit || transition || export) {
		return false
	}
	id := ""
	if current || changes || create {
		id = parts[1]
	} else if edit || transition {
		id = parts[2]
	}
	if req.Purpose != "compensation_management" || !export && !value.ValidID(id) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if current || changes {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		if current {
			if !singleQuery(q, []string{"as_of", "future_limit"}) || !q.Has("as_of") || !value.ValidDate(q.Get("as_of")) {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			limit, err := queryBound(q, "future_limit", 20, 1, 100)
			if err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			view, err := h.compensation.Current(r.Context(), req, id, compensation.CurrentQuery{AsOf: q.Get("as_of"), FutureLimit: limit})
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, view)
			}
		} else {
			kind := q.Get("record_kind")
			revisions := kind == "proposal_revisions"
			allowed, defaultLimit := []string{"from", "to", "record_kind", "proposal_id", "status", "cursor", "limit"}, 50
			if revisions {
				allowed, defaultLimit = []string{"record_kind", "proposal_id", "cursor", "limit"}, 20
			}
			if !singleQuery(q, allowed) || !q.Has("record_kind") || revisions && (!q.Has("proposal_id") || !value.ValidID(q.Get("proposal_id"))) || !revisions && (!q.Has("from") || !q.Has("to") || kind != "approvals" && kind != "proposals") || q.Has("proposal_id") && !value.ValidID(q.Get("proposal_id")) || kind == "approvals" && q.Has("status") {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			limit, err := queryBound(q, "limit", defaultLimit, 1, 100)
			if err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			view, err := h.compensation.Changes(r.Context(), req, id, compensation.ChangesQuery{From: q.Get("from"), To: q.Get("to"), RecordKind: q.Get("record_kind"), ProposalID: q.Get("proposal_id"), Status: q.Get("status"), Cursor: q.Get("cursor"), Limit: limit})
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, view)
			}
		}
		return true
	}
	if !validCommandKey(req.Key) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if export {
		var command compensation.ExportCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		started := false
		_, err := h.compensation.Export(r.Context(), req, command, func(event compensation.ExportEvent) error {
			if err := r.Context().Err(); err != nil {
				return err
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
	var result compensation.Result
	var err error
	switch {
	case create:
		var command compensation.ProposalCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.CreateProposal(r.Context(), req, id, command)
		}
	case edit:
		var command compensation.DraftCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.EditProposal(r.Context(), req, id, command)
		}
	case transition:
		var command compensation.TransitionCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.TransitionProposal(r.Context(), req, id, command)
		}
	}
	if err != nil {
		h.fail(w, err, req.RequestID)
	} else if create {
		h.reply(w, http.StatusCreated, result)
	} else {
		h.reply(w, http.StatusOK, result)
	}
	return true
}

// The finance schema is context-specific: after, members and before_ref cannot
// borrow permissive scalar/null handling from unrelated request schemas.
func walkFinancialJSON(d *json.Decoder, depth int, object string, nullable bool) error {
	if depth > 8 {
		return fault.Invalid
	}
	token, err := d.Token()
	if err != nil {
		return fault.Invalid
	}
	if token == nil {
		if nullable {
			return nil
		}
		return fault.Invalid
	}
	if object == "string" {
		if _, ok := token.(string); !ok {
			return fault.Invalid
		}
		return nil
	}
	if object == "scale" {
		number, ok := token.(json.Number)
		if !ok {
			return fault.Invalid
		}
		n, err := number.Int64()
		if err != nil || n < 0 || n > 9 {
			return fault.Invalid
		}
		return nil
	}
	if object == "members" || object == "components" {
		if token != json.Delim('[') {
			return fault.Invalid
		}
		element, maximum := "finance_member", 100
		if object == "components" {
			element, maximum = "finance_component", 20
		}
		count := 0
		for d.More() {
			count++
			if count > maximum {
				return fault.Invalid
			}
			if err := walkFinancialJSON(d, depth+1, element, false); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return fault.Invalid
		}
		return nil
	}
	if token != json.Delim('{') {
		return fault.Invalid
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		field, ok := key.(string)
		if err != nil || !ok || seen[field] {
			return fault.Invalid
		}
		child, allowNull, ok := financialField(object, field)
		if !ok {
			return fault.Invalid
		}
		seen[field] = true
		if err := walkFinancialJSON(d, depth+1, child, allowNull); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || !requiredFields(object, seen) {
		return fault.Invalid
	}
	return nil
}

func financialField(object, field string) (string, bool, bool) {
	switch object {
	case "finance_proposal", "finance_draft":
		switch field {
		case "kind", "effective_date", "comp_revision", "reason":
			return "string", false, true
		case "revision":
			return "string", false, object == "finance_draft"
		case "before_term_id":
			return "string", true, true
		case "after":
			return "finance_terms", true, true
		case "members":
			return "members", false, true
		}
	case "finance_transition":
		switch field {
		case "action", "revision", "comp_revision", "decision_reason":
			return "string", false, true
		}
	case "finance_member":
		switch field {
		case "member_key", "action", "original_event_id", "effective_date":
			return "string", false, true
		case "before_ref":
			return "finance_before", true, true
		case "after":
			return "finance_terms", true, true
		}
	case "finance_before":
		if field == "term_id" || field == "member_key" {
			return "string", true, true
		}
	case "finance_terms", "finance_component":
		switch field {
		case "currency":
			return "string", false, object == "finance_terms"
		case "scale":
			return "scale", false, object == "finance_terms"
		case "code":
			return "string", false, object == "finance_component"
		case "unit", "payment_frequency", "tax_basis":
			return "string", false, true
		case "amount_minor", "rate":
			return "string", true, true
		case "components":
			return "components", false, object == "finance_terms"
		}
	}
	return "", false, false
}
