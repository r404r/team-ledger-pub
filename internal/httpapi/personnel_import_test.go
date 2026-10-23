package httpapi_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
			row := []string{"EMP-IMPORT-001", "合成导入员工", "", "Shanghai", "BR", "BG", "DIV", "DEP", "Master", "10/16/2026", "Consultant", "CONSULTING", "P1", "", "", "", "", ""}
			workbook := batchWorkbook(t, headers, row)
			previewPath := "/api/v1/orgs/" + f.OrgID + "/employees/import-preview"
			request := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(workbook), "")
			request.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var preview organization.PersonnelImportPreview
			apiSend(t, f, request, http.StatusOK, &preview)
			if preview.RowCount != 1 || len(preview.Rows) != 1 || len(preview.Errors) != 0 || preview.CatalogRevision != "3" || preview.GraphRevision != "3" || preview.Rows[0].StaffCode != "EMP-IMPORT-001" || preview.Rows[0].HireDate != "2026-10-16" || preview.Rows[0].BranchID != catalogs.Items[0].ID || preview.Rows[0].DepartmentID != catalogs.Items[3].ID || preview.Rows[0].JobFamilyID != catalogs.Items[4].ID || preview.Rows[0].CareerLevelID != catalogs.Items[5].ID || f.Count(t, "employee") != 0 {
				t.Fatalf("read-only preview = %#v employees=%d", preview, f.Count(t, "employee"))
			}
			if len(preview.LegalEntities) != 1 || preview.LegalEntities[0].Code != "BR" || preview.LegalEntities[0].Label != "Synthetic Branch" ||
				len(preview.BusinessGroups) != 1 || len(preview.Divisions) != 1 || len(preview.Departments) != 1 ||
				len(preview.JobFamilies) != 1 || len(preview.CareerLevels) != 1 || preview.CareerLevels[0].Rank != 1 {
				t.Fatalf("catalog mapping options = %#v", preview)
			}

			numericRow := append([]string(nil), row...)
			numericRow[0], numericRow[9] = "7107", "46311"
			numericRequest := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(personnelTypedWorkbook(t, headers, numericRow, map[int]bool{0: true, 9: true})), "")
			numericRequest.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var numericPreview organization.PersonnelImportPreview
			apiSend(t, f, numericRequest, http.StatusOK, &numericPreview)
			warningCodes := make(map[string]bool, len(numericPreview.Warnings))
			for _, warning := range numericPreview.Warnings {
				warningCodes[warning.Code] = true
			}
			if len(numericPreview.Errors) != 0 || numericPreview.Rows[0].StaffCode != "7107" || numericPreview.Rows[0].HireDate != "2026-10-16" || !warningCodes["numeric_staff_code_coerced"] || !warningCodes["excel_date_coerced"] {
				t.Fatalf("numeric/date preview = %#v", numericPreview)
			}

			labelRow := append([]string(nil), row...)
			labelRow[4], labelRow[5], labelRow[6], labelRow[7], labelRow[11] = " synthetic branch ", "SYNTHETIC GROUP", "Synthetic Division", "Synthetic Department", "Consulting"
			labelRequest := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(batchWorkbook(t, headers, labelRow)), "")
			labelRequest.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var labelPreview organization.PersonnelImportPreview
			apiSend(t, f, labelRequest, http.StatusOK, &labelPreview)
			if len(labelPreview.Errors) != 0 || labelPreview.Rows[0].BranchCode != "BR" || labelPreview.Rows[0].DepartmentCode != "DEP" || labelPreview.Rows[0].JobFamilyCode != "CONSULTING" {
				t.Fatalf("label-resolved preview = %#v", labelPreview)
			}

			reviewPath := "/api/v1/orgs/" + f.OrgID + "/employees/import-review"
			review := organization.PersonnelImportReviewCommand{Rows: []organization.PersonnelImportReviewRow{{
				RowNumber: 2, StaffCode: "7107", LocalName: "可编辑员工", Location: "shanghai",
				BranchCode: "Synthetic Branch", BusinessGroupCode: "BG", DivisionCode: "DIV",
				DepartmentCode: "DEP", EducationLevel: "Doctor", HireDate: "2026/10/16",
				Position: "Consultant", JobFamilyCode: "CONSULTING", CareerLevelCode: "P1",
			}}}
			reviewJSON, err := json.Marshal(review)
			if err != nil {
				t.Fatal(err)
			}
			var reviewed organization.PersonnelImportPreview
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, reviewPath, string(reviewJSON), ""), http.StatusOK, &reviewed)
			if len(reviewed.Errors) != 1 || reviewed.Errors[0].Code != "unknown_education_level" || reviewed.Rows[0].Location != "Shanghai" || reviewed.Rows[0].HireDate != "2026-10-16" || reviewed.Rows[0].BranchCode != "BR" {
				t.Fatalf("editable review = %#v", reviewed)
			}
			optionalReview := organization.PersonnelImportReviewCommand{Rows: []organization.PersonnelImportReviewRow{{
				RowNumber: 2, StaffCode: "OPTIONAL-001", LocalName: "可选字段员工", Location: "Shanghai",
				BranchCode: "BR", BusinessGroupCode: "BG", DivisionCode: "DIV", DepartmentCode: "DEP",
				HireDate: "2026-10-16",
			}}}
			optionalJSON, err := json.Marshal(optionalReview)
			if err != nil {
				t.Fatal(err)
			}
			var optionalPreview organization.PersonnelImportPreview
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, reviewPath, string(optionalJSON), ""), http.StatusOK, &optionalPreview)
			if len(optionalPreview.Errors) != 0 || optionalPreview.Rows[0].JobFamilyID != "" || optionalPreview.Rows[0].CareerLevelID != "" {
				t.Fatalf("optional review = %#v", optionalPreview)
			}

			largeReview := organization.PersonnelImportReviewCommand{Rows: make([]organization.PersonnelImportReviewRow, 100)}
			for index := range largeReview.Rows {
				largeReview.Rows[index] = organization.PersonnelImportReviewRow{
					RowNumber: index + 2, StaffCode: fmt.Sprintf("LARGE-%03d", index), LocalName: "大批量可编辑员工",
					Location: "Shanghai", BranchCode: "BR", BusinessGroupCode: "BG", DivisionCode: "DIV",
					DepartmentCode: "DEP", EducationLevel: "Master", HireDate: "2026-10-16",
					Position: "Consultant", JobFamilyCode: "CONSULTING", CareerLevelCode: "P1",
					ProfileSummary: strings.Repeat("可编辑资料", 600),
				}
			}
			largeReviewJSON, err := json.Marshal(largeReview)
			if err != nil || len(largeReviewJSON) <= 256<<10 {
				t.Fatalf("large review bytes=%d err=%v", len(largeReviewJSON), err)
			}
			var largeReviewed organization.PersonnelImportPreview
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, reviewPath, string(largeReviewJSON), ""), http.StatusOK, &largeReviewed)
			if largeReviewed.RowCount != 100 || len(largeReviewed.Errors) != 0 {
				t.Fatalf("large editable review = %#v", largeReviewed)
			}
			addEducation := `{"expected_catalog_revision":"3","expected_graph_revision":"3","changes":[{"action":"create","kind":"education_level","code":"Doctor","rank":4}]}`
			var educationResult organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-catalog-changes", addEducation, value.NewID()), http.StatusCreated, &educationResult)
			if educationResult.CatalogRevision != "4" || educationResult.GraphRevision != "3" {
				t.Fatalf("education result = %#v", educationResult)
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, reviewPath, string(reviewJSON), ""), http.StatusOK, &reviewed)
			if len(reviewed.Errors) != 0 || reviewed.CatalogRevision != "4" || reviewed.Rows[0].EducationLevel != "Doctor" {
				t.Fatalf("review after education append = %#v", reviewed)
			}

			row[9] = "31/12/2026"
			dateWorkbook := batchWorkbook(t, headers, row)
			dateRequest := apiRequest(t, f, f.Owner, http.MethodPost, previewPath, string(dateWorkbook), "")
			dateRequest.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var datePreview organization.PersonnelImportPreview
			apiSend(t, f, dateRequest, http.StatusOK, &datePreview)
			if datePreview.RowCount != 1 || len(datePreview.Errors) != 1 || datePreview.Errors[0].Sheet != "Employees" || datePreview.Errors[0].Cell != "J2" || datePreview.Errors[0].Code != "invalid_date" || datePreview.CatalogRevision != "" || datePreview.GraphRevision != "" {
				t.Fatalf("date diagnostic preview = %#v", datePreview)
			}
			row[9] = "10/16/2026"

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

func personnelTypedWorkbook(t *testing.T, headers, row []string, numericColumns map[int]bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range map[string]string{
		"xl/workbook.xml":            `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><workbookPr date1904="0"/><sheets><sheet name="Employees" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprint(entry, body)
	}
	entry, err := writer.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(entry, `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for index, text := range headers {
		_, _ = fmt.Fprintf(entry, `<c r="%c1" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+index, text)
	}
	_, _ = fmt.Fprint(entry, `</row><row r="2">`)
	for index, text := range row {
		if numericColumns[index] {
			_, _ = fmt.Fprintf(entry, `<c r="%c2" t="n"><v>%s</v></c>`, 'A'+index, text)
		} else {
			_, _ = fmt.Fprintf(entry, `<c r="%c2" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+index, text)
		}
	}
	_, _ = fmt.Fprint(entry, `</row></sheetData></worksheet>`)
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func hodReviewRow(rowNumber int, staffCode, manager string) organization.PersonnelImportReviewRow {
	return organization.PersonnelImportReviewRow{
		RowNumber: rowNumber, StaffCode: staffCode, LocalName: "合成层级员工", Location: "Shanghai",
		BranchCode: "BR", BusinessGroupCode: "BG", DivisionCode: "DIV", DepartmentCode: "DEP",
		HireDate: "2026-10-16", ManagerStaffCode: manager,
	}
}

func hodImportCreateBody(imported organization.PersonnelImportRow, preview organization.PersonnelImportPreview) string {
	return fmt.Sprintf(`{"profile":{"local_name":%q},"lifecycle":{"valid_from":%q,"valid_to":null},"staff_code":%q,"employment":{"legal_entity_id":%q,"location_code":%q},"job_assignment":{"department_id":%q},"expected_catalog_revision":%q,"expected_graph_revision":%q}`,
		imported.LocalName, imported.HireDate, imported.StaffCode, imported.BranchID, imported.Location, imported.DepartmentID, preview.CatalogRevision, preview.GraphRevision)
}

func TestAPIPersonnelImportResolvesHODCodesAcrossBatchAndExistingStaff(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			seedCompleteEmployeeCatalogs(t, f)
			reviewPath := "/api/v1/orgs/" + f.OrgID + "/employees/import-review"
			review := func(rows ...organization.PersonnelImportReviewRow) organization.PersonnelImportPreview {
				t.Helper()
				var out organization.PersonnelImportPreview
				apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, reviewPath, structureJSON(t, organization.PersonnelImportReviewCommand{Rows: rows}), ""), http.StatusOK, &out)
				return out
			}

			// An existing employee is persisted before the import so the batch can report to it.
			existing := review(hodReviewRow(2, "EXIST001", ""))
			var existingResult organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", hodImportCreateBody(existing.Rows[0], existing), value.NewID()), http.StatusCreated, &existingResult)

			clean := review(
				hodReviewRow(2, "SUB001", "MID001-Synthetic Mid"),
				hodReviewRow(3, "MID001", "TOP001 - Synthetic Top"),
				hodReviewRow(4, "TOP001", "EXIST001-Synthetic Existing"),
				hodReviewRow(5, "LEAF001", "SUB001"),
			)
			managers := []string{clean.Rows[0].ManagerStaffCode, clean.Rows[1].ManagerStaffCode, clean.Rows[2].ManagerStaffCode, clean.Rows[3].ManagerStaffCode}
			if len(clean.Errors) != 0 || managers[0] != "MID001" || managers[1] != "TOP001" || managers[2] != "EXIST001" || managers[3] != "SUB001" {
				t.Fatalf("reverse-order batch with composite HOD = managers %v errors %#v", managers, clean.Errors)
			}
			extracted := map[string]bool{}
			for _, warning := range clean.Warnings {
				if warning.Code == "hod_staff_code_extracted" {
					extracted[warning.Cell] = true
				}
			}
			if len(extracted) != 3 || !extracted["N2"] || !extracted["N3"] || !extracted["N4"] {
				t.Fatalf("extraction warnings = %#v", clean.Warnings)
			}
			if f.Count(t, "employee") != 1 {
				t.Fatalf("review persisted employees: %d", f.Count(t, "employee"))
			}

			invalid := review(
				hodReviewRow(2, "OK001", "EXIST001-Synthetic Existing"),
				hodReviewRow(3, "ORPHAN001", "GHOST999-Synthetic Ghost"),
				hodReviewRow(4, "SELF001", "SELF001-Synthetic Self"),
				hodReviewRow(5, "CYC001", "CYC002"),
				hodReviewRow(6, "CYC002", "CYC001 - Synthetic Cycle"),
			)
			got := map[string]string{}
			for _, issue := range invalid.Errors {
				got[issue.Cell] = issue.Code
			}
			want := map[string]string{"N3": "manager_not_found", "N4": "manager_self_reference", "N5": "manager_cycle", "N6": "manager_cycle"}
			if len(got) != len(want) || len(invalid.Errors) != len(want) {
				t.Fatalf("invalid batch issues = %#v, want %#v", invalid.Errors, want)
			}
			for cell, code := range want {
				if got[cell] != code {
					t.Fatalf("invalid batch issues = %#v, want %#v", invalid.Errors, want)
				}
			}

			// Preview from an uploaded workbook takes the same HOD path as the editable review.
			headers := []string{"工号 Staff Code", "姓名 Staff Name", "姓名 English Name", "地点 Location", "所在公司 Branch Code", "业务单元 Business Group Code", "目前事业部 Division Code", "目前部门 Department Code", "学历 Latest Education", "雇佣起始日 Date of Employment", "职位 Position", "职系 Job Family Code", "职级 Career Level Code", "直属主管 HOD Staff Code", "退职日 Departure Date", "业务邮箱 Work Email", "业务电话 Work Phone", "资料摘要 Profile Summary"}
			workbookRow := []string{"UP001", "合成上传员工", "", "Shanghai", "BR", "BG", "DIV", "DEP", "", "2026-10-16", "", "", "", "EXIST001 - Synthetic Existing", "", "", "", ""}
			upload := apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees/import-preview", string(batchWorkbook(t, headers, workbookRow)), "")
			upload.Header.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			var uploaded organization.PersonnelImportPreview
			apiSend(t, f, upload, http.StatusOK, &uploaded)
			if len(uploaded.Errors) != 0 || uploaded.Rows[0].ManagerStaffCode != "EXIST001" {
				t.Fatalf("uploaded composite HOD = %#v", uploaded)
			}

			// Commit: pass 1 creates every employee in file order (subordinate first), pass 2 binds all
			// reporting lines from the complete staff_code -> employee_id map in one command.
			ids := map[string]string{"EXIST001": existingResult.ID}
			revisions := map[string]string{}
			for index := range clean.Rows {
				var created organization.Result
				apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", hodImportCreateBody(clean.Rows[index], clean), value.NewID()), http.StatusCreated, &created)
				ids[clean.Rows[index].StaffCode] = created.ID
				revisions[created.ID] = created.WorkforceRevision
				if created.GraphRevision != "" {
					clean.GraphRevision = created.GraphRevision
				}
			}
			if f.Count(t, "reporting_line") != 0 {
				t.Fatal("reporting lines must not exist before pass 2")
			}
			changes := make([]map[string]any, 0, len(clean.Rows))
			for _, row := range clean.Rows {
				changes = append(changes, map[string]any{"action": "add", "kind": "reporting", "employee_id": ids[row.StaffCode], "manager_employee_id": ids[row.ManagerStaffCode], "reporting_kind": "administrative", "valid_from": row.HireDate})
			}
			var reported organization.WorkforceChangeResult
			body := structureJSON(t, map[string]any{"expected_catalog_revision": clean.CatalogRevision, "expected_graph_revision": clean.GraphRevision, "expected_employee_revisions": revisions, "reason": "Personnel XLSX import", "changes": changes})
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-changes", body, value.NewID()), http.StatusCreated, &reported)
			if f.Count(t, "employee") != 5 || f.Count(t, "reporting_line") != 4 {
				t.Fatalf("after commit employees=%d reporting_line=%d", f.Count(t, "employee"), f.Count(t, "reporting_line"))
			}
		})
	}
}

func TestAPIPersonnelImportCommitIsAtomicAndReplayable(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			seedCompleteEmployeeCatalogs(t, f)
			path := "/api/v1/orgs/" + f.OrgID + "/employees/import-commit"
			rows := []organization.PersonnelImportReviewRow{hodReviewRow(5, "SUB001", "MID001-Synthetic Mid"), hodReviewRow(80, "MID001", "TOP001 - Synthetic Top"), hodReviewRow(95, "TOP001", "")}
			command := map[string]any{"rows": rows, "expected_catalog_revision": "3", "expected_graph_revision": "3"}
			body := structureJSON(t, command)
			key := value.NewID()
			var result organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &result)
			if len(result.Items) != 3 || f.Count(t, "employee") != 3 || f.Count(t, "reporting_line") != 2 {
				t.Fatalf("batch not committed: %#v", result)
			}
			for i, managerIndex := range []int{1, 2} {
				var view organization.View
				apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/employees/"+result.Items[i].ID+"?as_of=2026-10-16&include_profile=true", "", ""), http.StatusOK, &view)
				if view.DirectManager == nil || view.DirectManager.ManagerEmployeeID != result.Items[managerIndex].ID {
					t.Fatalf("wrong manager at row %d: %#v", rows[i].RowNumber, view)
				}
			}
			var replay organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &replay)
			if structureJSON(t, result) != structureJSON(t, replay) || f.Count(t, "employee") != 3 {
				t.Fatal("replay changed result")
			}
			rows[0].StaffCode = "CHANGED001"
			command["rows"] = rows
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), key), http.StatusConflict, nil)

			for name, invalid := range map[string][]organization.PersonnelImportReviewRow{
				"self":            {hodReviewRow(5, "SELF001", "SELF001-Synthetic Self")},
				"cycle":           {hodReviewRow(5, "CYCLE001", "CYCLE002"), hodReviewRow(80, "CYCLE002", "CYCLE001-Synthetic Cycle")},
				"duplicate":       {hodReviewRow(5, "DUP001", ""), hodReviewRow(80, "DUP001", "")},
				"missing code":    {hodReviewRow(5, "BAD001", " - ")},
				"missing manager": {hodReviewRow(5, "BAD001", "UNKNOWN001-Synthetic Unknown")},
			} {
				t.Run(name, func(t *testing.T) {
					command["expected_graph_revision"] = result.GraphRevision
					command["rows"] = invalid
					apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), value.NewID()), http.StatusUnprocessableEntity, nil)
					if f.Count(t, "employee") != 3 {
						t.Fatal("invalid batch created employees")
					}
				})
			}

			command["expected_graph_revision"] = result.GraphRevision
			// A conflict on a later row must also roll back the first employee, facts and receipts.
			rows = []organization.PersonnelImportReviewRow{hodReviewRow(8, "FRESH001", ""), hodReviewRow(90, "TOP001", "")}
			command["rows"] = rows
			beforeProfiles, beforeFacts, beforeReceipts := f.Count(t, "employee_profile_version"), f.Count(t, "employee_business_identifier"), f.Count(t, "command_receipt")
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "employee") != 3 || f.Count(t, "employee_profile_version") != beforeProfiles || f.Count(t, "employee_business_identifier") != beforeFacts || f.Count(t, "command_receipt") != beforeReceipts {
				t.Fatal("failed batch left partial writes")
			}
			// The manager exists, but starts after the subordinate: Pass 2 must roll back Pass 1.
			rows = []organization.PersonnelImportReviewRow{hodReviewRow(8, "EARLY001", "LATE001-Synthetic Late"), hodReviewRow(90, "LATE001", "")}
			rows[1].HireDate = "2026-11-01"
			command["rows"] = rows
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "employee") != 3 || f.Count(t, "reporting_line") != 2 {
				t.Fatal("reporting failure left partial writes")
			}
			rows = []organization.PersonnelImportReviewRow{hodReviewRow(22, "EXTSUB001", "TOP001-Synthetic Existing")}
			command["rows"] = rows
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodPost, path, structureJSON(t, command), value.NewID()), http.StatusForbidden, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), value.NewID()), http.StatusCreated, nil)
			if f.Count(t, "employee") != 4 || f.Count(t, "reporting_line") != 3 {
				t.Fatal("existing manager not resolved")
			}
		})
	}
}

func TestAPIPersonnelImportCommitAcceptsFullBatchWithoutManagers(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			seedCompleteEmployeeCatalogs(t, f)
			rows := make([]organization.PersonnelImportReviewRow, 100)
			for i := range rows {
				rows[i] = hodReviewRow(i+2, fmt.Sprintf("BATCH%03d", i), "")
			}
			command := organization.PersonnelImportCommitCommand{Rows: rows, ExpectedCatalogRevision: "3", ExpectedGraphRevision: "3"}
			path := "/api/v1/orgs/" + f.OrgID + "/employees/import-commit"
			key := value.NewID()
			var result organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), key), http.StatusCreated, &result)
			if len(result.Items) != 100 || result.GraphRevision != "3" || f.Count(t, "employee") != 100 || f.Count(t, "education_record") != 0 || f.Count(t, "job_assignment") != 100 || f.Count(t, "reporting_line") != 0 {
				t.Fatal("full batch/optional facts mismatch")
			}
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, structureJSON(t, command), key), http.StatusCreated, nil)
			if f.Count(t, "employee") != 100 {
				t.Fatal("no-manager batch replay duplicated employees")
			}
		})
	}
}
