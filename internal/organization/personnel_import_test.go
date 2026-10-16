package organization

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
)

func TestParsePersonnelWorkbookReturnsCanonicalPreviewWithoutPersistence(t *testing.T) {
	row := []string{"EMP-001", "合成员工", "Synthetic Employee", "employee@example.invalid", "+86-000", "Synthetic summary", "MGR-001", "2026-10-16", ""}
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, [][]string{row}, -1))
	if err != nil {
		t.Fatal(err)
	}
	if preview.RowCount != 1 || len(preview.Rows) != 1 || len(preview.Errors) != 0 {
		t.Fatalf("preview = %#v", preview)
	}
	got := preview.Rows[0]
	if got.RowNumber != 2 || got.StaffCode != "EMP-001" || got.ManagerStaffCode != "MGR-001" || got.HireDate != "2026-10-16" || got.DepartureDate != nil {
		t.Fatalf("canonical row = %#v", got)
	}
}

func TestParsePersonnelWorkbookReportsDuplicateCycleAndTypedDate(t *testing.T) {
	rows := [][]string{
		{"EMP-001", "员工甲", "", "", "", "", "EMP-002", "2026-10-16", ""},
		{"EMP-002", "员工乙", "", "", "", "", "EMP-001", "2026-10-16", ""},
		{"DUP-001", "员工丙", "", "", "", "", "", "2026-10-16", ""},
		{"DUP-001", "员工丁", "", "", "", "", "", "46000", ""},
	}
	preview, err := parsePersonnelWorkbook(personnelWorkbook(t, rows, 7))
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

func personnelWorkbook(t *testing.T, rows [][]string, numericColumn int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
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
