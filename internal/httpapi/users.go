package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/value"
)

type localUserCreateCommand struct {
	Username        string `json:"username"`
	InitialPassword string `json:"initial_password"`
}

func (h *handler) localUserRoute(w http.ResponseWriter, r *http.Request, tokenHash []byte, requestID, purpose, key string) bool {
	if r.URL.Path != "/api/v1/security/users" {
		return false
	}
	if purpose != authz.ManagementPurpose {
		h.fail(w, fault.Invalid, requestID)
		return true
	}
	if r.Method == http.MethodGet {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			h.fail(w, fault.Invalid, requestID)
			return true
		}
		for name, values := range q {
			if name != "cursor" && name != "limit" || len(values) != 1 || values[0] == "" {
				h.fail(w, fault.Invalid, requestID)
				return true
			}
		}
		limit := 50
		if q.Has("limit") {
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != q.Get("limit") {
				h.fail(w, fault.Invalid, requestID)
				return true
			}
		}
		page, err := h.identities.ListLocalUsers(r.Context(), identity.LocalUserQuery{SessionHash: tokenHash, Cursor: q.Get("cursor"), Limit: limit, RequestID: requestID})
		if err != nil {
			h.fail(w, err, requestID)
			return true
		}
		h.reply(w, http.StatusOK, page)
		return true
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !value.ValidID(key) || key[14] != '4' || !strings.ContainsRune("89ab", rune(key[19])) {
		h.fail(w, fault.Invalid, requestID)
		return true
	}
	var command localUserCreateCommand
	if err := strictBody(w, r, &command); err != nil {
		h.fail(w, err, requestID)
		return true
	}
	result, err := h.identities.CreateLocalUser(r.Context(), identity.LocalUserRequest{SessionHash: tokenHash, Username: command.Username, InitialPassword: command.InitialPassword, Key: key, RequestID: requestID})
	if err != nil {
		h.fail(w, err, requestID)
		return true
	}
	h.reply(w, http.StatusCreated, result)
	return true
}
