package httpapi_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/xlsx"
)

func TestAPIPersonnelImportTemplateAndPreviewAreAuthorizedAndReadOnly(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			templatePath := "/api/v1/orgs/" + f.OrgID + "/employees/import-template"
			response, err := f.Server.Client().Do(apiRequest(t, f, f.Owner, http.MethodGet, templatePath, "", ""))
			if err != nil {
				t.Fatal(err)
			}
			raw, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" || response.Header.Get("Content-Disposition") != `attachment; filename="teamledger-personnel-import.xlsx"` {
				t.Fatalf("template response status=%d headers=%v read=%v", response.StatusCode, response.Header, readErr)
			}
			rows, err := xlsx.ReadFirstSheet(raw, xlsx.Limits{CompressedBytes: 5 << 20, ExpandedBytes: 20 << 20, Entries: 1_000})
			if err != nil || len(rows) != 1 || rows[0].Cells[1].Text != "staff_code" || rows[0].Cells[9].Text != "departure_date" {
				t.Fatalf("downloaded template = %#v err=%v", rows, err)
			}
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, templatePath, "", ""), http.StatusForbidden, nil)

			headers := []string{"staff_code", "local_name", "english_name", "email", "phone", "profile_summary", "manager_staff_code", "hire_date", "departure_date"}
			row := []string{"EMP-IMPORT-001", "合成导入员工", "", "", "", "", "", "2026-10-16", ""}
			workbook := batchWorkbook(t, headers, row)
			previewPath := "/api/v1/orgs/" + f.OrgID + "/employees/import-preview"
			request := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(workbook), "")
			request.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var preview organization.PersonnelImportPreview
			apiSend(t, f, request, http.StatusOK, &preview)
			if preview.RowCount != 1 || len(preview.Rows) != 1 || len(preview.Errors) != 0 || preview.Rows[0].StaffCode != "EMP-IMPORT-001" || f.Count(t, "employee") != 0 {
				t.Fatalf("read-only preview = %#v employees=%d", preview, f.Count(t, "employee"))
			}

			crossSite := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(workbook), "")
			crossSite.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
			apiSend(t, f, crossSite, http.StatusForbidden, nil)
		})
	}
}
