package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
)

const bindingCookieName = "__Host-teamledger_oidc_binding"

type authStepUpCommand struct {
	Action   string `json:"action"`
	ReturnTo string `json:"return_to"`
}
type authLogoutCommand struct{}

func protectedCookie(name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires}
}
func clearProtectedCookie(w http.ResponseWriter, name string) {
	cookie := protectedCookie(name, "", time.Unix(1, 0).UTC())
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}
func bindingCookie(r *http.Request) (string, error) {
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == bindingCookieName {
			value = cookie.Value
			count++
		}
	}
	raw, e := base64.RawURLEncoding.DecodeString(value)
	if count != 1 || e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return "", fault.Unauthenticated
	}
	return value, nil
}

func (h *handler) publicIdentityRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	login := r.URL.Path == "/api/v1/auth/login"
	callback := r.URL.Path == "/api/v1/auth/callback"
	if !login && !callback {
		return false
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		h.fail(w, fault.NotFound, requestID)
		return true
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		h.fail(w, fault.Invalid, requestID)
		return true
	}
	if login {
		if len(q) > 1 || len(q) == 1 && (len(q["return_to"]) != 1 || !q.Has("return_to")) {
			h.fail(w, fault.Invalid, requestID)
			return true
		}
		returnTo := "/"
		if q.Has("return_to") {
			returnTo = q.Get("return_to")
		}
		var hash []byte
		if raw, e := sessionCookie(r); e == nil {
			sum := sha256.Sum256(raw)
			hash = sum[:]
		}
		authorization, e := h.identities.Begin(r.Context(), identity.BeginRequest{Mode: "login", ReturnTo: returnTo, SessionHash: hash, RequestID: requestID})
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie(bindingCookieName, authorization.BrowserCookie, authorization.ExpiresAt))
		http.Redirect(w, r, authorization.URL, http.StatusFound)
		return true
	}
	for key, values := range q {
		if len(values) != 1 || len(values[0]) > 8192 {
			h.fail(w, fault.Invalid, requestID)
			return true
		}
		switch key {
		case "code", "state", "error", "error_description", "error_uri", "iss", "session_state":
		default:
			h.fail(w, fault.Invalid, requestID)
			return true
		}
	}
	browserCookie, e := bindingCookie(r)
	if e != nil {
		h.fail(w, e, requestID)
		return true
	}
	clearProtectedCookie(w, bindingCookieName)
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") == "" {
		h.fail(w, fault.Unauthenticated, requestID)
		return true
	}
	result, e := h.identities.Complete(r.Context(), identity.CallbackRequest{Code: q.Get("code"), State: q.Get("state"), BrowserCookie: browserCookie, RequestID: requestID})
	if e != nil {
		h.fail(w, e, requestID)
		return true
	}
	if !identity.AllowedReturn(result.ReturnTo) {
		h.fail(w, fault.Unavailable, requestID)
		return true
	}
	http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
	http.Redirect(w, r, result.ReturnTo, http.StatusFound)
	return true
}

func (h *handler) authenticatedIdentityRoute(w http.ResponseWriter, r *http.Request, hash []byte, requestID string) bool {
	logout := r.URL.Path == "/api/v1/auth/logout"
	stepUp := r.URL.Path == "/api/v1/auth/step-up"
	if !logout && !stepUp {
		return false
	}
	if r.Method != http.MethodPost {
		h.fail(w, fault.NotFound, requestID)
		return true
	}
	if logout {
		var command authLogoutCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if e := h.identities.Logout(r.Context(), hash, requestID); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		clearProtectedCookie(w, "__Host-teamledger_session")
		clearProtectedCookie(w, bindingCookieName)
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	var command authStepUpCommand
	if e := strictBody(w, r, &command); e != nil {
		h.fail(w, e, requestID)
		return true
	}
	if !identity.AllowedReturn(command.ReturnTo) || !identity.AllowedStepUpAction(command.Action) {
		h.fail(w, fault.Invalid, requestID)
		return true
	}
	authorization, e := h.identities.Begin(r.Context(), identity.BeginRequest{Mode: "step_up", Action: command.Action, ReturnTo: command.ReturnTo, SessionHash: hash, RequestID: requestID})
	if e != nil {
		h.fail(w, e, requestID)
		return true
	}
	http.SetCookie(w, protectedCookie(bindingCookieName, authorization.BrowserCookie, authorization.ExpiresAt))
	h.reply(w, http.StatusOK, struct {
		URL string `json:"authorization_url"`
	}{authorization.URL})
	return true
}
