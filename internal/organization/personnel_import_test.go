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
func TestParsePersonnelWorkbookCanonicalizesSupportedTextDates(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"2026-1-2", "2026-01-02"},
		{"2026/3/4", "2026-03-04"},
		{"2026.5.6", "2026-05-06"},
		{"7/3/2023", "2023-07-03"},
		{"8-9-2024", "2024-08-09"},
		{"10.11.2025", "2025-10-11"},
		{"2028年2月29日", "2028-02-29"},
	}
	rows := make([][]string, 0, len(cases))
	for index, dateCase := range cases {
		row := personnelRow(fmt.Sprintf("DATE-%03d", index+1), "日期兼容员工", "")
		row[9] = dateCase.input
		rows = append(rows, row)
	}
	rows[0][14] = "2/3/2026"
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, rows, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Errors) != 0 || len(preview.Rows) != len(cases) {
		t.Fatalf("preview = %#v", preview)
	}
	for index, dateCase := range cases {
		if preview.Rows[index].HireDate != dateCase.want {
			t.Fatalf("row %d hire_date = %q, want %q", index+2, preview.Rows[index].HireDate, dateCase.want)
		}
	}
	if preview.Rows[0].DepartureDate == nil || *preview.Rows[0].DepartureDate != "2026-02-03" {
		t.Fatalf("departure_date = %#v, want 2026-02-03", preview.Rows[0].DepartureDate)
	}
}

func TestParsePersonnelWorkbookPinsDateErrorsToTheirCells(t *testing.T) {
	rows := [][]string{
		personnelRow("DATE-INVALID-1", "日期错误员工甲", ""),
		personnelRow("DATE-INVALID-2", "日期错误员工乙", ""),
		personnelRow("DATE-INVALID-3", "日期错误员工丙", ""),
	}
	rows[0][9] = "2026-02-30"
	rows[1][9] = "31/12/2025"
	rows[2][14] = "2026-10-16"
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, rows, -1))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, issue := range preview.Errors {
		got[issue.Cell] = issue.Code
	}
	want := map[string]string{"J2": "invalid_date", "J3": "invalid_date", "O4": "departure_not_after_hire"}
	if len(got) != len(want) {
		t.Fatalf("date issues = %#v, want %#v", got, want)
	}
	for cell, code := range want {
		if got[cell] != code {
			t.Fatalf("date issues = %#v, want %#v", got, want)
		}
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
	typedCell := false
	for _, issue := range preview.Errors {
		codes[issue.Code]++
		typedCell = typedCell || issue.Code == "text_required" && issue.Sheet == "Employees" && issue.Cell == "J5" && issue.Field == "hire_date"
	}
	if codes["duplicate_staff_code"] != 2 || codes["manager_cycle"] != 2 || codes["text_required"] != 1 || codes["invalid_date"] != 0 || !typedCell {
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
				_, _ = fmt.Fprintf(entry, `<c r="%c%d" t="n"><v>%s</v></c>`, 'A'+column, rowIndex+2, value)
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
