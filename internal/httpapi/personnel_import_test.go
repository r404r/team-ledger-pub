package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"github.com/r404r/team-ledger/internal/xlsx"
)

func TestAPIPersonnelImportTemplateAndPreviewAreAuthorizedAndReadOnly(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			catalogs := seedCompleteEmployeeCatalogs(t, f)
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
			rows, err := xlsx.ReadFirstSheet(raw, xlsx.Limits{CompressedBytes: 5 << 20, ExpandedBytes: 20 << 20, Entries: 1_000, Rows: 101, Cells: 1_818, XMLNodes: 20_000})
			if err != nil || len(rows) != 1 || rows[0].Cells[1].Text != "工号 Staff Code" || rows[0].Cells[18].Text != "资料摘要 Profile Summary" {
				t.Fatalf("downloaded template = %#v err=%v", rows, err)
			}
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, templatePath, "", ""), http.StatusForbidden, nil)

			headers := []string{"工号 Staff Code", "姓名 Staff Name", "姓名 English Name", "地点 Location", "所在公司 Branch Code", "业务单元 Business Group Code", "目前事业部 Division Code", "目前部门 Department Code", "学历 Latest Education", "雇佣起始日 Date of Employment", "职位 Position", "职系 Job Family Code", "职级 Career Level Code", "直属主管 HOD Staff Code", "退职日 Departure Date", "业务邮箱 Work Email", "业务电话 Work Phone", "资料摘要 Profile Summary"}
			row := []string{"EMP-IMPORT-001", "合成导入员工", "", "Shanghai", "BR", "BG", "DIV", "DEP", "Master", "2026-10-16", "Consultant", "CONSULTING", "P1", "", "", "", "", ""}
			workbook := batchWorkbook(t, headers, row)
			previewPath := "/api/v1/orgs/" + f.OrgID + "/employees/import-preview"
			request := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(workbook), "")
			request.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var preview organization.PersonnelImportPreview
			apiSend(t, f, request, http.StatusOK, &preview)
			if preview.RowCount != 1 || len(preview.Rows) != 1 || len(preview.Errors) != 0 || preview.CatalogRevision != "3" || preview.GraphRevision != "3" || preview.Rows[0].StaffCode != "EMP-IMPORT-001" || preview.Rows[0].BranchID != catalogs.Items[0].ID || preview.Rows[0].DepartmentID != catalogs.Items[3].ID || preview.Rows[0].JobFamilyID != catalogs.Items[4].ID || preview.Rows[0].CareerLevelID != catalogs.Items[5].ID || f.Count(t, "employee") != 0 {
				t.Fatalf("read-only preview = %#v employees=%d", preview, f.Count(t, "employee"))
			}

			headers[0] = "旧版工号表头"
			invalidWorkbook := batchWorkbook(t, headers, row)
			invalidRequest := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(invalidWorkbook), "")
			invalidRequest.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			invalidResponse, requestErr := f.Server.Client().Do(invalidRequest)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			var invalidBody struct {
				Code          string                                         `json:"code"`
				RequestID     string                                         `json:"request_id"`
				WorkbookError organization.PersonnelImportWorkbookDiagnostic `json:"workbook_error"`
			}
			decodeErr := json.NewDecoder(invalidResponse.Body).Decode(&invalidBody)
			_ = invalidResponse.Body.Close()
			if decodeErr != nil || invalidResponse.StatusCode != http.StatusUnprocessableEntity || invalidBody.Code != "INVALID_INPUT" || !value.ValidID(invalidBody.RequestID) || invalidBody.WorkbookError.Sheet != "Employees" || invalidBody.WorkbookError.Cell != "A1" || invalidBody.WorkbookError.Code != "header_mismatch" {
				t.Fatalf("workbook diagnostic status=%d body=%#v err=%v", invalidResponse.StatusCode, invalidBody, decodeErr)
			}

			crossSite := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(workbook), "")
			crossSite.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
			apiSend(t, f, crossSite, http.StatusForbidden, nil)
		})
	}
}

func seedCompleteEmployeeCatalogs(t *testing.T, f *testsupport.Fixture) organization.CatalogChangeResult {
	t.Helper()
	catalogPath := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
	createCatalogs := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"legal_entity","code":"BR","label":"Synthetic Branch","valid_from":"2020-01-01"},{"action":"create","kind":"business_group","code":"BG","label":"Synthetic Group","valid_from":"2020-01-01"},{"action":"create","kind":"division","code":"DIV","label":"Synthetic Division","valid_from":"2020-01-01"},{"action":"create","kind":"department","code":"DEP","label":"Synthetic Department","valid_from":"2020-01-01"},{"action":"create","kind":"job_family","code":"CONSULTING","label":"Consulting","valid_from":"2020-01-01"},{"action":"create","kind":"career_level","code":"P1","label":"P1","rank":1,"valid_from":"2020-01-01"}]}`
	var catalogs organization.CatalogChangeResult
	apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, catalogPath, createCatalogs, value.NewID()), http.StatusCreated, &catalogs)
	createHierarchy := `{"expected_catalog_revision":"2","expected_graph_revision":"2","changes":[{"action":"create","kind":"org_unit_parent","ref":"` + catalogs.Items[2].ID + `","parent_ref":"` + catalogs.Items[1].ID + `","valid_from":"2020-01-01"},{"action":"create","kind":"org_unit_parent","ref":"` + catalogs.Items[3].ID + `","parent_ref":"` + catalogs.Items[2].ID + `","valid_from":"2020-01-01"}]}`
	apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, catalogPath, createHierarchy, value.NewID()), http.StatusCreated, nil)
	return catalogs
}
