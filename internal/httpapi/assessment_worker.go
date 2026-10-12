package httpapi

import (
	"crypto/sha256"
	"net/http"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/fault"
)

type workerClaimCommand struct{}
type workerLeaseCommand struct {
	Lease assessment.Lease `json:"lease"`
}
type workerHeartbeatCommand struct {
	Lease assessment.Lease `json:"lease"`
}
type workerResultCommand struct {
	Lease    assessment.Lease          `json:"lease"`
	Document assessment.ResultDocument `json:"document"`
}
type workerFailCommand struct {
	Lease assessment.Lease `json:"lease"`
	Code  string           `json:"code"`
}

func (h *handler) assessmentWorkerRoute(w http.ResponseWriter, r *http.Request, requestID string) bool {
	if r.URL.Path != "/internal/v1/assessment/jobs/claim" && r.URL.Path != "/internal/v1/assessment/jobs/heartbeat" && r.URL.Path != "/internal/v1/assessment/jobs/result" && r.URL.Path != "/internal/v1/assessment/jobs/fail" {
		return false
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 {
		h.fail(w, fault.Unauthenticated, requestID)
		return true
	}
	workerID := r.Header.Get("X-TeamLedger-Worker-ID")
	digest := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	request := assessment.WorkerRequest{WorkerID: workerID, CertDigest: digest[:], RequestID: requestID, Key: r.Header.Get("Idempotency-Key")}
	switch r.URL.Path {
	case "/internal/v1/assessment/jobs/claim":
		var command workerClaimCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		output, err := h.assessment.Claim(r.Context(), request)
		if err != nil {
			h.fail(w, err, requestID)
		} else {
			h.reply(w, http.StatusOK, output)
		}
	case "/internal/v1/assessment/jobs/heartbeat":
		var command workerHeartbeatCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		expires, err := h.assessment.Heartbeat(r.Context(), request, command.Lease.JobID, command.Lease.Token, command.Lease.Fence)
		if err != nil {
			h.fail(w, err, requestID)
		} else {
			h.reply(w, http.StatusOK, map[string]any{"expires_at": expires})
		}
	case "/internal/v1/assessment/jobs/result":
		var command workerResultCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		output, err := h.assessment.Submit(r.Context(), request, command.Lease, command.Document)
		if err != nil {
			h.fail(w, err, requestID)
		} else {
			h.reply(w, http.StatusCreated, output)
		}
	case "/internal/v1/assessment/jobs/fail":
		var command workerFailCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, requestID)
			return true
		}
		if err := h.assessment.Fail(r.Context(), request, command.Lease, command.Code); err != nil {
			h.fail(w, err, requestID)
		} else {
			h.reply(w, http.StatusNoContent, nil)
		}
	}
	return true
}
