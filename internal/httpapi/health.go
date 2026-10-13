package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type readinessStore interface {
	CheckSchema(context.Context) error
	AuditDeliveryBacklog(context.Context, time.Time) (int64, *time.Time, error)
	AuditReceiverAvailable(context.Context, string, time.Time, time.Duration) error
}

type readyWrapper interface {
	Ready(context.Context) error
}

func probeWrapper(ctx context.Context, wrapper sensitive.Wrapper) bool {
	if wrapper == nil {
		return false
	}
	if ready, ok := wrapper.(readyWrapper); ok {
		return ready.Ready(ctx) == nil
	}
	dek := make([]byte, 32)
	defer clear(dek)
	wrapped, err := wrapper.Wrap(ctx, dek)
	defer clear(wrapped.Data)
	return err == nil && wrapped.KEKID != "" && wrapped.Version > 0 && len(wrapped.Data) > 0
}

func (h *handler) healthRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if r.URL.Path != "/health/live" && r.URL.Path != "/health/ready" {
		return false
	}
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		h.fail(w, fault.NotFound, requestID)
		return true
	}
	if r.URL.Path == "/health/live" {
		h.reply(w, 200, struct {
			Status string `json:"status"`
		}{"live"})
		return true
	}
	store, ok := h.service.Store.(readinessStore)
	if !ok {
		h.reply(w, 503, struct {
			Status string `json:"status"`
		}{"unavailable"})
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	count, oldest, err := store.AuditDeliveryBacklog(ctx, now)
	keys := err == nil && probeWrapper(ctx, h.service.Cipher.Wrapper) && probeWrapper(ctx, h.interviews.Cipher.Wrapper) && probeWrapper(ctx, h.assessment.Cipher.Wrapper) && probeWrapper(ctx, h.compensation.Cipher.Wrapper)
	if err != nil || store.CheckSchema(ctx) != nil || store.AuditReceiverAvailable(ctx, h.deployment, now, 15*time.Second) != nil || !keys || count > 1000 || oldest != nil && now.Sub(*oldest) > 5*time.Minute {
		h.reply(w, 503, struct {
			Status string `json:"status"`
		}{"unavailable"})
		return true
	}
	h.reply(w, 200, struct {
		Status string `json:"status"`
	}{"ready"})
	return true
}
