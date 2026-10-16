package organization

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestParsePersonnelWorkbookReturnsCanonicalPreviewWithoutPersistence(t *testing.T) {
	row := personnelRow("EMP-001", "合成员工", "MGR-001")
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, [][]string{row}, -1))
	if err != nil {
		t.Fatal(err)
	}
	if preview.RowCount != 1 || len(preview.Rows) != 1 || len(preview.Errors) != 0 {
		t.Fatalf("preview = %#v", preview)
	}
	got := preview.Rows[0]
	if got.RowNumber != 2 || got.StaffCode != "EMP-001" || got.ManagerStaffCode != "MGR-001" || got.HireDate != "2026-10-16" || got.Location != "Shanghai" || got.DepartmentCode != "DEP" || got.DepartureDate != nil {
		t.Fatalf("canonical row = %#v", got)
	}
}

func TestParsePersonnelWorkbookReportsDuplicateCycleAndTypedDate(t *testing.T) {
	rows := [][]string{
		personnelRow("EMP-001", "员工甲", "EMP-002"),
		personnelRow("EMP-002", "员工乙", "EMP-001"),
		personnelRow("DUP-001", "员工丙", ""),
		personnelRow("DUP-001", "员工丁", ""),
	}
	rows[3][9] = "46000"
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, rows, 9))
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]int{}
	for _, issue := range preview.Errors {
		codes[issue.Code]++
	}
	if codes["duplicate_staff_code"] != 2 || codes["manager_cycle"] != 2 || codes["text_required"] != 1 || codes["invalid_employment_dates"] != 1 {
		t.Fatalf("issues = %#v", preview.Errors)
	}
}

func TestParsePersonnelWorkbookOmitsOversizedValuesFromPreview(t *testing.T) {
	row := personnelRow("EMP-003", "合成员工", "")
	row[17] = strings.Repeat("x", (16<<10)+1)
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, [][]string{row}, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Rows) != 1 || preview.Rows[0].ProfileSummary != "" {
		t.Fatalf("oversized content escaped into preview: %#v", preview.Rows)
	}
	found := false
	for _, issue := range preview.Errors {
		found = found || issue.RowNumber == 2 && issue.Field == "profile_summary" && issue.Code == "field_too_large"
	}
	if !found {
		t.Fatalf("missing bounded preview issue: %#v", preview.Errors)
	}
}

func personnelRow(staffCode, name, manager string) []string {
	return []string{
		staffCode, name, "Synthetic Employee", "Shanghai", "BR", "BG", "DIV", "DEP", "Master",
		"2026-10-16", "Consultant", "CONSULTING", "P1", manager, "", "employee@example.invalid", "+86-000", "Synthetic summary",
	}
}

func personnelWorkbook(t *testing.T, rows [][]string, numericColumn int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range map[string]string{
		"xl/workbook.xml":            `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Employees" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
	} {
		manifestEntry, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, _ = fmt.Fprint(manifestEntry, body)
	}
	entry, err := writer.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(entry, `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for index, header := range personnelImportHeaders {
		_, _ = fmt.Fprintf(entry, `<c r="%c1" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+index, header)
	}
	_, _ = fmt.Fprint(entry, `</row>`)
	for rowIndex, row := range rows {
		_, _ = fmt.Fprintf(entry, `<row r="%d">`, rowIndex+2)
		for column, value := range row {
			if rowIndex == len(rows)-1 && column == numericColumn && value != "" {
				_, _ = fmt.Fprintf(entry, `<c r="%c%d"><v>%s</v></c>`, 'A'+column, rowIndex+2, value)
			} else {
				_, _ = fmt.Fprintf(entry, `<c r="%c%d" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+column, rowIndex+2, value)
			}
		}
		_, _ = fmt.Fprint(entry, `</row>`)
	}
	_, _ = fmt.Fprint(entry, `</sheetData></worksheet>`)
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
