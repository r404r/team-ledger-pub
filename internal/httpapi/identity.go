package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
)

const bindingCookieName = "__Host-teamledger_oidc_binding"

type authStepUpCommand struct {
	Action          string `json:"action"`
	ReturnTo        string `json:"return_to"`
	CurrentPassword string `json:"current_password"`
	TOTPCode        string `json:"totp_code"`
}
type authLogoutCommand struct{}
type authLocalLoginCommand struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ReturnTo string `json:"return_to"`
	TOTPCode string `json:"totp_code"`
}
type authLocalRecoveryCommand struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	RecoveryCode string `json:"recovery_code"`
	ReturnTo     string `json:"return_to"`
}
type authLocalMFACommand struct {
	CurrentPassword string `json:"current_password"`
	TOTPCode        string `json:"totp_code"`
}
type authLocalMFAConfirmCommand struct {
	TOTPCode string `json:"totp_code"`
}
type authPasswordChangeCommand struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

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
	modeRoute := r.URL.Path == "/api/v1/auth/mode"
	recovery := r.URL.Path == "/api/v1/auth/local/recover"
	localLogin := r.URL.Path == "/api/v1/auth/local/login"
	login := r.URL.Path == "/api/v1/auth/login"
	callback := r.URL.Path == "/api/v1/auth/callback"
	if !login && !callback && !localLogin && !recovery && !modeRoute {
		return false
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	if modeRoute {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			h.fail(w, fault.NotFound, requestID)
			return true
		}
		h.reply(w, http.StatusOK, struct {
			Mode string `json:"mode"`
		}{h.identities.Mode()})
		return true
	}
	if localLogin || recovery {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Content-Type") != "application/json" {
			h.fail(w, fault.Forbidden, requestID)
			return true
		}
		result := identity.LoginResult{}
		var e error
		if localLogin {
			var command authLocalLoginCommand
			if e = strictBody(w, r, &command); e == nil {
				result, e = h.identities.LocalLogin(r.Context(), identity.LocalLoginRequest{Username: command.Username, Password: command.Password, TOTPCode: command.TOTPCode, ReturnTo: command.ReturnTo, RequestID: requestID})
			}
		} else {
			var command authLocalRecoveryCommand
			key := r.Header.Get("Idempotency-Key")
			if e = strictBody(w, r, &command); e == nil {
				result, e = h.identities.LocalMFARecover(r.Context(), identity.LocalMFARecoveryRequest{Username: command.Username, Password: command.Password, RecoveryCode: command.RecoveryCode, ReturnTo: command.ReturnTo, RequestID: key})
			}
		}
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
		status := http.StatusOK
		if result.Next != "" {
			status = http.StatusAccepted
		}
		h.reply(w, status, struct {
			ReturnTo  string `json:"return_to"`
			Next      string `json:"next,omitempty"`
			CSRFToken string `json:"csrf_token"`
		}{result.ReturnTo, result.Next, result.CSRFToken})
		return true
	}
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
	passwordChange := r.URL.Path == "/api/v1/auth/local/password"
	mfaReplace := r.URL.Path == "/api/v1/auth/local/mfa/replace"
	mfaConfirm := r.URL.Path == "/api/v1/auth/local/mfa/confirm"
	mfaCancel := r.URL.Path == "/api/v1/auth/local/mfa/cancel"
	recoveryCode := r.URL.Path == "/api/v1/auth/local/mfa/recovery-code"
	logout := r.URL.Path == "/api/v1/auth/logout"
	stepUp := r.URL.Path == "/api/v1/auth/step-up"
	if !logout && !stepUp && !passwordChange && !mfaReplace && !mfaConfirm && !mfaCancel && !recoveryCode {
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
	if passwordChange {
		var command authPasswordChangeCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if e := h.identities.ChangeLocalPassword(r.Context(), identity.LocalPasswordChangeRequest{SessionHash: hash, CurrentPassword: command.CurrentPassword, NewPassword: command.NewPassword, RequestID: requestID}); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		clearProtectedCookie(w, "__Host-teamledger_session")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	if mfaCancel {
		var command authLogoutCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if e := h.identities.LocalMFACancel(r.Context(), hash, requestID); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		clearProtectedCookie(w, "__Host-teamledger_session")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	if mfaReplace || recoveryCode {
		var command authLocalMFACommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if mfaReplace {
			result, e := h.identities.LocalMFABegin(r.Context(), hash, identity.LocalMFAReplaceRequest{SessionHash: hash, Password: command.CurrentPassword, TOTPCode: command.TOTPCode, RequestID: requestID})
			if e != nil {
				h.fail(w, e, requestID)
				return true
			}
			h.reply(w, http.StatusCreated, struct {
				Secret    string    `json:"secret"`
				URI       string    `json:"uri"`
				Mode      string    `json:"mode"`
				ExpiresAt time.Time `json:"expires_at"`
			}{result.Secret, result.URI, result.Mode, result.ExpiresAt})
			return true
		}
		result, e := h.identities.LocalMFARecoveryCode(r.Context(), identity.LocalMFARecoveryCodeRequest{SessionHash: hash, Password: command.CurrentPassword, TOTPCode: command.TOTPCode, RequestID: requestID})
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
		h.reply(w, http.StatusOK, struct {
			RecoveryCode string `json:"recovery_code"`
			CSRFToken    string `json:"csrf_token"`
		}{result.RecoveryCode, result.CSRFToken})
		return true
	}
	if mfaConfirm {
		var command authLocalMFAConfirmCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		result, e := h.identities.LocalMFAConfirm(r.Context(), hash, command.TOTPCode, requestID)
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
		h.reply(w, http.StatusOK, struct {
			RecoveryCode string `json:"recovery_code"`
			CSRFToken    string `json:"csrf_token"`
		}{result.RecoveryCode, result.CSRFToken})
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
	if h.identities.Mode() == "local" {
		result, e := h.identities.LocalStepUp(r.Context(), identity.LocalMFAStepUpRequest{SessionHash: hash, Password: command.CurrentPassword, TOTPCode: command.TOTPCode, Action: command.Action, ReturnTo: command.ReturnTo, RequestID: requestID})
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
		h.reply(w, http.StatusOK, struct {
			ReturnTo  string `json:"return_to"`
			CSRFToken string `json:"csrf_token"`
		}{result.ReturnTo, result.CSRFToken})
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

func (h *handler) preAuthorizationIdentityRoute(w http.ResponseWriter, r *http.Request, raw, hash []byte, requestID string) bool {
	enrollment := r.URL.Path == "/api/v1/auth/local/mfa/enrollment"
	pending := r.URL.Path == "/api/v1/auth/local/mfa/pending"
	confirm := r.URL.Path == "/api/v1/auth/local/mfa/confirm"
	cancel := r.URL.Path == "/api/v1/auth/local/mfa/cancel"
	logout := r.URL.Path == "/api/v1/auth/logout"
	if !enrollment && !pending && !confirm && !cancel && !logout {
		return false
	}
	session, err := h.identities.CurrentSession(r.Context(), hash)
	if err != nil {
		h.fail(w, err, requestID)
		return true
	}
	if session.AccessKind == "business" {
		return false
	}
	if session.AccessKind != "mfa_enrollment" && session.AccessKind != "mfa_recovery" {
		h.fail(w, fault.Unauthenticated, requestID)
		return true
	}
	token, key, err := identity.CSRFToken(r.Context(), h.keys, raw)
	tokenHash := sha256.Sum256([]byte(token))
	if err != nil || session.CSRFKeyID != key.KeyID || session.CSRFVersion != key.Version || subtle.ConstantTimeCompare(session.CSRFHash, tokenHash[:]) != 1 {
		h.fail(w, fault.Unauthenticated, requestID)
		return true
	}
	if r.URL.RawQuery != "" {
		h.fail(w, fault.Invalid, requestID)
		return true
	}
	if r.Method != http.MethodGet {
		if r.Method != http.MethodPost || r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Content-Type") != "application/json" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(token)) != 1 {
			h.fail(w, fault.Forbidden, requestID)
			return true
		}
	} else if !pending {
		h.fail(w, fault.NotFound, requestID)
		return true
	}
	if err = h.identities.Touch(r.Context(), hash); err != nil {
		h.fail(w, err, requestID)
		return true
	}
	switch {
	case pending:
		result, e := h.identities.LocalMFAPending(r.Context(), hash)
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		h.reply(w, http.StatusOK, struct {
			Secret    string    `json:"secret"`
			URI       string    `json:"uri"`
			Mode      string    `json:"mode"`
			ExpiresAt time.Time `json:"expires_at"`
		}{result.Secret, result.URI, result.Mode, result.ExpiresAt})
	case enrollment:
		var command authLocalMFACommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		result, e := h.identities.LocalMFABegin(r.Context(), hash, identity.LocalMFAReplaceRequest{SessionHash: hash, RequestID: requestID})
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		h.reply(w, http.StatusCreated, struct {
			Secret    string    `json:"secret"`
			URI       string    `json:"uri"`
			Mode      string    `json:"mode"`
			ExpiresAt time.Time `json:"expires_at"`
		}{result.Secret, result.URI, result.Mode, result.ExpiresAt})
	case confirm:
		var command authLocalMFAConfirmCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		result, e := h.identities.LocalMFAConfirm(r.Context(), hash, command.TOTPCode, requestID)
		if e != nil {
			h.fail(w, e, requestID)
			return true
		}
		http.SetCookie(w, protectedCookie("__Host-teamledger_session", result.SessionCookie, result.ExpiresAt))
		h.reply(w, http.StatusOK, struct {
			RecoveryCode string `json:"recovery_code"`
			CSRFToken    string `json:"csrf_token"`
		}{result.RecoveryCode, result.CSRFToken})
	case cancel:
		var command authLogoutCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if err = h.identities.LocalMFACancel(r.Context(), hash, requestID); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		clearProtectedCookie(w, "__Host-teamledger_session")
		w.WriteHeader(http.StatusNoContent)
	case logout:
		var command authLogoutCommand
		if e := strictBody(w, r, &command); e != nil {
			h.fail(w, e, requestID)
			return true
		}
		if err = h.identities.Logout(r.Context(), hash, requestID); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		clearProtectedCookie(w, "__Host-teamledger_session")
		w.WriteHeader(http.StatusNoContent)
	}
	return true
}
