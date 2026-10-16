package xlsx

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"testing"
)

var testLimits = Limits{CompressedBytes: 1 << 20, ExpandedBytes: 4 << 20, Entries: 100}

func TestBuildTemplateProducesTextHeadersAndSingleFrozenSheet(t *testing.T) {
	headers := []string{"staff_code", "local_name", "hire_date"}
	raw, err := BuildTemplate("Employees", headers)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ReadFirstSheet(raw, testLimits)
	if err != nil {
		t.Fatalf("read generated workbook: %v", err)
	}
	if len(rows) != 1 || rows[0].Number != 1 {
		t.Fatalf("template rows = %#v", rows)
	}
	for index, want := range headers {
		cell := rows[0].Cells[index+1]
		if !cell.IsText || cell.Text != want {
			t.Fatalf("header %d = %#v, want %q text", index+1, cell, want)
		}
	}
}

func TestReadFirstSheetRejectsFormulaDirectiveExternalRelationshipAndSecondSheet(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"formula", map[string]string{"xl/worksheets/sheet1.xml": sheet(`<c r="A1" t="str"><f>1+1</f><v>2</v></c>`)}},
		{"directive", map[string]string{"xl/worksheets/sheet1.xml": `<?xml version="1.0"?><!DOCTYPE worksheet [<!ENTITY x "boom">]><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>`}},
		{"external relationship", map[string]string{"xl/worksheets/sheet1.xml": sheet(`<c r="A1" t="inlineStr"><is><t>x</t></is></c>`), "xl/worksheets/_rels/sheet1.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" TargetMode="External" Target="https://invalid.example/"/></Relationships>`}},
		{"second sheet", map[string]string{"xl/worksheets/sheet1.xml": sheet(`<c r="A1" t="inlineStr"><is><t>x</t></is></c>`), "xl/worksheets/sheet2.xml": sheet(`<c r="A1" t="inlineStr"><is><t>hidden</t></is></c>`)}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadFirstSheet(workbook(t, test.files), testLimits); err == nil {
				t.Fatal("hostile workbook was accepted")
			}
		})
	}
}

func TestReadFirstSheetDistinguishesTextFromNumericCells(t *testing.T) {
	raw := workbook(t, map[string]string{"xl/worksheets/sheet1.xml": sheet(`<c r="A1" t="inlineStr"><is><t>001</t></is></c><c r="B1"><v>1</v></c>`)})
	rows, err := ReadFirstSheet(raw, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !rows[0].Cells[1].IsText || rows[0].Cells[1].Text != "001" || rows[0].Cells[2].IsText {
		t.Fatalf("cell types were not preserved: %#v", rows[0].Cells)
	}
}

func sheet(cells string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">%s</row></sheetData></worksheet>`, cells)
}

func workbook(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(entry, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
