package compensation

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
)

func TestParseAdjustmentWorkbookRequiresTextMoneyAndBoundsRows(t *testing.T) {
	headers := []string{"Employee ID", "Staff Code", "Currency", "Salary Before Adjustment", "Increase amount", "Salary After Adjustment", "Performance Grade", "Effective Date"}
	row := []string{"employee-1", "S001", "CNY", "10000", "500", "10500", "A", "2026-01-01"}
	lines, err := ParseAdjustmentWorkbook(testWorkbook(t, headers, row, -1), BatchNormal)
	if err != nil {
		t.Fatalf("parse valid workbook: %v", err)
	}
	if len(lines) != 1 || lines[0].IncreaseAmount != "500" || lines[0].EmployeeID != "employee-1" {
		t.Fatalf("unexpected normalized lines: %#v", lines)
	}
	if _, err = ParseAdjustmentWorkbook(testWorkbook(t, headers, row, 4), BatchNormal); err == nil {
		t.Fatal("numeric money cell must be rejected instead of converted through floating point")
	}
	if _, err = ParseAdjustmentWorkbook(testFormulaWorkbook(t, headers, row), BatchNormal); err == nil {
		t.Fatal("empty shared formula element with cached value must be rejected")
	}
}

func testWorkbook(t *testing.T, headers, row []string, numericColumn int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entry, err := archive.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(entry, `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for index, value := range headers {
		_, _ = fmt.Fprintf(entry, `<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>`, testColumn(index+1), value)
	}
	_, _ = fmt.Fprint(entry, `</row><row r="2">`)
	for index, value := range row {
		if index == numericColumn {
			_, _ = fmt.Fprintf(entry, `<c r="%s2"><v>%s</v></c>`, testColumn(index+1), value)
		} else {
			_, _ = fmt.Fprintf(entry, `<c r="%s2" t="inlineStr"><is><t>%s</t></is></c>`, testColumn(index+1), value)
		}
	}
	_, _ = fmt.Fprint(entry, `</row></sheetData></worksheet>`)
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testFormulaWorkbook(t *testing.T, headers, row []string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entry, err := archive.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(entry, `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for index, value := range headers {
		_, _ = fmt.Fprintf(entry, `<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>`, testColumn(index+1), value)
	}
	_, _ = fmt.Fprint(entry, `</row><row r="2">`)
	for index, value := range row {
		if index == 4 {
			_, _ = fmt.Fprintf(entry, `<c r="%s2" t="str"><f/><v>%s</v></c>`, testColumn(index+1), value)
		} else {
			_, _ = fmt.Fprintf(entry, `<c r="%s2" t="inlineStr"><is><t>%s</t></is></c>`, testColumn(index+1), value)
		}
	}
	_, _ = fmt.Fprint(entry, `</row></sheetData></worksheet>`)
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testColumn(column int) string {
	var out string
	for column > 0 {
		column--
		out = string(rune('A'+column%26)) + out
		column /= 26
	}
	return out
}
