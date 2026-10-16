package httpapi

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

func (h *handler) compensationBatchRoute(w http.ResponseWriter, r *http.Request, req compensation.Request) bool {
	if r.URL.Path != "/api/v1/compensation-adjustment-batches" && !strings.HasPrefix(r.URL.Path, "/api/v1/compensation-adjustment-batches/") {
		return false
	}
	if req.Purpose != "compensation_management" {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	snapshot, err := h.compensation.Store.Security(r.Context(), req.TokenHash, "", "")
	if err != nil || !value.ValidID(snapshot.OrgID) {
		h.fail(w, fault.Unauthenticated, req.RequestID)
		return true
	}
	org := snapshot.OrgID
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/compensation-adjustment-batches"), "/")
	if len(parts) == 1 && parts[0] == "" {
		switch r.Method {
		case http.MethodGet:
			q, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil || !singleQuery(q, []string{"cycle_year", "adjustment_type", "limit"}) {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			year := 0
			if q.Get("cycle_year") != "" {
				year, err = strconv.Atoi(q.Get("cycle_year"))
				if err != nil {
					h.fail(w, fault.Invalid, req.RequestID)
					return true
				}
			}
			limit, err := queryBound(q, "limit", 50, 1, 100)
			if err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			views, err := h.compensation.AdjustmentBatches(r.Context(), req, org, year, q.Get("adjustment_type"), limit)
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusOK, map[string]any{"batches": views})
			}
		case http.MethodPost:
			if !validCommandKey(req.Key) {
				h.fail(w, fault.Invalid, req.RequestID)
				return true
			}
			var command compensation.CreateBatchCommand
			if err := strictBody(w, r, &command); err != nil {
				h.fail(w, err, req.RequestID)
				return true
			}
			view, err := h.compensation.CreateAdjustmentBatch(r.Context(), req, org, command)
			if err != nil {
				h.fail(w, err, req.RequestID)
			} else {
				h.reply(w, http.StatusCreated, view)
			}
		default:
			return false
		}
		return true
	}
	if len(parts) == 2 && parts[1] == "import-template" && r.Method == http.MethodGet {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !singleQuery(q, []string{"adjustment_type"}) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		raw, err := h.compensation.AdjustmentBatchTemplate(r.Context(), req, org, q.Get("adjustment_type"))
		if err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", `attachment; filename="teamledger-salary-baseline.xlsx"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		clear(raw)
		return true
	}
	if len(parts) == 2 && parts[1] == "options" && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		view, err := h.compensation.AdjustmentBatchOptions(r.Context(), req, org)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, view)
		}
		return true
	}
	if len(parts) < 2 || !value.ValidID(parts[1]) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	id := parts[1]
	if len(parts) == 2 && r.Method == http.MethodGet {
		view, err := h.compensation.AdjustmentBatch(r.Context(), req, org, id)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, view)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "imports" && r.Method == http.MethodPost {
		if !validCommandKey(req.Key) || r.Header.Get("Content-Type") != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !singleQuery(q, []string{"revision"}) || q.Get("revision") == "" {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if err != nil {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		defer clear(raw)
		view, err := h.compensation.ImportAdjustmentWorkbook(r.Context(), req, org, id, q.Get("revision"), raw)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, view)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "previews" && r.Method == http.MethodPost {
		if !validCommandKey(req.Key) {
			h.fail(w, fault.Invalid, req.RequestID)
			return true
		}
		var command compensation.PreviewBatchLinesCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.PreviewAdjustmentBatch(r.Context(), req, org, id, command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, view)
		}
		return true
	}
	if !validCommandKey(req.Key) {
		h.fail(w, fault.Invalid, req.RequestID)
		return true
	}
	if len(parts) == 3 && parts[2] == "draft" && r.Method == http.MethodPatch {
		var command compensation.ReplaceBatchLinesCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.ReplaceAdjustmentBatchLines(r.Context(), req, org, id, command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, view)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "corrections" && r.Method == http.MethodPost {
		var command compensation.BatchCorrectionCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.CorrectAdjustmentBatch(r.Context(), req, org, id, command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusCreated, view)
		}
		return true
	}
	if len(parts) == 3 && parts[2] == "transitions" && r.Method == http.MethodPost {
		var command compensation.BatchTransitionCommand
		if err := strictBody(w, r, &command); err != nil {
			h.fail(w, err, req.RequestID)
			return true
		}
		view, err := h.compensation.TransitionAdjustmentBatch(r.Context(), req, org, id, command)
		if err != nil {
			h.fail(w, err, req.RequestID)
		} else {
			h.reply(w, http.StatusOK, view)
		}
		return true
	}
	return false
}
