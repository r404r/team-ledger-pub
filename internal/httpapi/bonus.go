package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) bonusRoute(w http.ResponseWriter, r *http.Request, req compensation.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") || req.Purpose != "compensation_management" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	get := len(parts) == 3 && parts[0] == "employees" && parts[2] == "bonuses" && r.Method == http.MethodGet
	createTarget := len(parts) == 3 && parts[0] == "employees" && parts[2] == "bonus-targets" && r.Method == http.MethodPost
	targetTransition := len(parts) == 3 && parts[0] == "bonus-targets" && parts[2] == "transitions" && r.Method == http.MethodPost
	createAward := len(parts) == 3 && parts[0] == "employees" && parts[2] == "bonus-awards" && r.Method == http.MethodPost
	editAward := len(parts) == 2 && parts[0] == "bonus-awards" && r.Method == http.MethodPatch
	awardTransition := len(parts) == 3 && parts[0] == "bonus-awards" && parts[2] == "transitions" && r.Method == http.MethodPost
	payment := len(parts) == 3 && parts[0] == "employees" && parts[2] == "bonus-payments" && r.Method == http.MethodPost
	extension := len(parts) == 4 && parts[0] == "employees" && parts[2] == "compensation" && parts[3] == "extensions" && r.Method == http.MethodPost
	if !(get || createTarget || targetTransition || createAward || editAward || awardTransition || payment || extension) {
		return false
	}
	id := ""
	if get || createTarget || createAward || payment || extension {
		id = parts[1]
	} else {
		id = parts[1]
	}
	if !value.ValidID(id) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if get {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !singleQuery(q, []string{"period_start", "period_end", "record_kind", "record_id", "cursor", "limit"}) || q.Has("period_start") && !value.ValidDate(q.Get("period_start")) || q.Has("period_end") && !value.ValidDate(q.Get("period_end")) || q.Has("record_id") && !value.ValidID(q.Get("record_id")) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		limit, err := queryBound(q, "limit", 50, 1, 100)
		if err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.Bonuses(r.Context(), req, id, compensation.BonusQuery{PeriodStart: q.Get("period_start"), PeriodEnd: q.Get("period_end"), RecordKind: q.Get("record_kind"), RecordID: q.Get("record_id"), Cursor: q.Get("cursor"), Limit: limit})
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
	var result compensation.BonusResult
	var err error
	created := false
	switch {
	case createTarget:
		var command compensation.BonusTargetCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.CreateBonusTarget(r.Context(), req, id, command)
			created = true
		}
	case targetTransition:
		var command compensation.BonusTargetTransition
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.TransitionBonusTarget(r.Context(), req, id, command)
		}
	case createAward:
		var command compensation.BonusAwardCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.CreateBonusAward(r.Context(), req, id, command)
			created = true
		}
	case editAward:
		var command compensation.BonusAwardEditCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.EditBonusAward(r.Context(), req, id, command)
		}
	case awardTransition:
		var command compensation.BonusAwardTransition
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.TransitionBonusAward(r.Context(), req, id, command)
		}
	case payment:
		var command compensation.BonusPaymentCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.RecordBonusPayment(r.Context(), req, id, command)
			created = true
		}
	case extension:
		var command compensation.BonusExtensionCommand
		if err = strictBody(w, r, &command); err == nil {
			result, err = h.compensation.AppendCompensationExtension(r.Context(), req, id, command)
			created = true
		}
	}
	if err != nil {
		h.fail(w, err, req.RequestID)
	} else if created {
		h.reply(w, http.StatusCreated, result)
	} else {
		h.reply(w, http.StatusOK, result)
	}
	return true
}
