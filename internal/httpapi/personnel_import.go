package httpapi

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

const personnelWorkbookBodyLimit = 5 << 20

func personnelWorkbookUpload(r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	return r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "orgs" && parts[2] == "employees" && parts[3] == "import-preview"
}

func (h *handler) personnelImportRoute(w http.ResponseWriter, r *http.Request, request organization.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	if len(parts) != 4 || parts[0] != "orgs" || parts[2] != "employees" || (parts[3] != "import-template" && parts[3] != "import-preview") {
		return false
	}
	if !value.ValidID(parts[1]) || request.Purpose != "organization_management" {
		h.fail(w, fault.Invalid, request.RequestID)
		return true
	}
	if parts[3] == "import-template" {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			h.fail(w, fault.NotFound, request.RequestID)
			return true
		}
		workbook, err := h.service.PersonnelImportTemplate(r.Context(), request, parts[1])
		if err != nil {
			h.fail(w, err, request.RequestID)
			return true
		}
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", `attachment; filename="teamledger-personnel-import.xlsx"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(workbook)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(workbook)
		return true
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		h.fail(w, fault.NotFound, request.RequestID)
		return true
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, personnelWorkbookBodyLimit))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			h.fail(w, bodyTooLarge, request.RequestID)
		} else {
			h.fail(w, fault.Invalid, request.RequestID)
		}
		return true
	}
	defer clear(raw)
	preview, err := h.service.PreviewPersonnelImport(r.Context(), request, parts[1], raw)
	if err != nil {
		var workbookErr *organization.PersonnelImportWorkbookError
		if errors.As(err, &workbookErr) {
			log.Printf("PERSONNEL_IMPORT_REJECTED request_id=%s sheet=%q cell=%q code=%s", request.RequestID, workbookErr.Diagnostic.Sheet, workbookErr.Diagnostic.Cell, workbookErr.Diagnostic.Code)
			h.reply(w, fault.Invalid.Status, struct {
				Code          string                                         `json:"code"`
				RequestID     string                                         `json:"request_id"`
				Reason        string                                         `json:"reason"`
				WorkbookError organization.PersonnelImportWorkbookDiagnostic `json:"workbook_error"`
			}{fault.Invalid.Code, request.RequestID, fault.Invalid.Reason, workbookErr.Diagnostic})
			return true
		}
		h.fail(w, err, request.RequestID)
		return true
	}
	for _, issue := range preview.Errors {
		log.Printf("PERSONNEL_IMPORT_ROW_REJECTED request_id=%s sheet=%q cell=%q row=%d field=%s code=%s", request.RequestID, issue.Sheet, issue.Cell, issue.RowNumber, issue.Field, issue.Code)
	}
	h.reply(w, http.StatusOK, preview)
	return true
}
