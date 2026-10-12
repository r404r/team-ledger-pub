package httpapi

import (
	"net/http"

	"github.com/r404r/team-ledger/internal/organization"
)

func (h *handler) profileExportRoute(w http.ResponseWriter, r *http.Request, request organization.Request) bool {
	if r.URL.Path != "/api/v1/sensitive-exports" || r.Method != http.MethodPost || request.Purpose != "organization_management" {
		return false
	}
	var command organization.ExportCommand
	if err := strictBody(w, r, &command); err != nil {
		h.fail(w, err, request.RequestID)
		return true
	}
	started := false
	_, err := h.service.ExportProfiles(r.Context(), request, command, func(event organization.ExportEvent) error {
		if err := r.Context().Err(); err != nil {
			return err
		}
		if !started {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			started = true
		}
		_, writeErr := w.Write(event.EncodedJSON)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return writeErr
	})
	if err != nil && !started {
		h.fail(w, err, request.RequestID)
	}
	return true
}
