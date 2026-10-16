package xlsx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

type Limits struct {
	CompressedBytes int
	ExpandedBytes   uint64
	Entries         int
}

type Cell struct {
	Text   string
	IsText bool
}

type Row struct {
	Number int
	Cells  map[int]Cell
}

type sharedStrings struct {
	Items []richText `xml:"si"`
}

type richText struct {
	Text string `xml:"t"`
	Runs []struct {
		Text string `xml:"t"`
	} `xml:"r"`
}

type worksheet struct {
	Rows []struct {
		Number int `xml:"r,attr"`
		Cells  []struct {
			Reference string   `xml:"r,attr"`
			Type      string   `xml:"t,attr"`
			Formula   *string  `xml:"f"`
			Value     string   `xml:"v"`
			Inline    richText `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

type relationships struct {
	Items []struct {
		TargetMode string `xml:"TargetMode,attr"`
	} `xml:"Relationship"`
}

func ReadFirstSheet(raw []byte, limits Limits) ([]Row, error) {
	if len(raw) == 0 || limits.CompressedBytes <= 0 || len(raw) > limits.CompressedBytes || limits.ExpandedBytes == 0 || limits.Entries <= 0 {
		return nil, errors.New("invalid workbook")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(zr.File) == 0 || len(zr.File) > limits.Entries {
		return nil, errors.New("invalid workbook")
	}
	var expanded uint64
	worksheets := 0
	for _, file := range zr.File {
		if !safeEntryName(file.Name) {
			return nil, errors.New("invalid workbook entry")
		}
		expanded += file.UncompressedSize64
		if expanded > limits.ExpandedBytes {
			return nil, errors.New("expanded workbook is too large")
		}
		if strings.HasPrefix(file.Name, "xl/worksheets/") && strings.HasSuffix(file.Name, ".xml") {
			worksheets++
		}
		if strings.EqualFold(file.Name, "xl/vbaProject.bin") {
			return nil, errors.New("macros are not accepted")
		}
		if strings.HasSuffix(file.Name, ".rels") {
			var rels relationships
			if err := decodeZipXML(file, limits.ExpandedBytes, &rels); err != nil {
				return nil, errors.New("invalid workbook relationships")
			}
			for _, relationship := range rels.Items {
				if strings.EqualFold(relationship.TargetMode, "External") {
					return nil, errors.New("external workbook relationships are not accepted")
				}
			}
		}
	}
	if worksheets != 1 {
		return nil, errors.New("workbook must contain exactly one worksheet")
	}

	shared := []string{}
	if file := zipEntry(zr.File, "xl/sharedStrings.xml"); file != nil {
		var values sharedStrings
		if err := decodeZipXML(file, limits.ExpandedBytes, &values); err != nil {
			return nil, errors.New("invalid shared strings")
		}
		shared = make([]string, 0, len(values.Items))
		for _, item := range values.Items {
			shared = append(shared, richTextValue(item))
		}
	}

	sheetFile := zipEntry(zr.File, "xl/worksheets/sheet1.xml")
	if sheetFile == nil {
		return nil, errors.New("sheet1 is required")
	}
	var sheet worksheet
	if err := decodeZipXML(sheetFile, limits.ExpandedBytes, &sheet); err != nil {
		return nil, errors.New("invalid worksheet")
	}
	rows := make([]Row, 0, len(sheet.Rows))
	lastRow := 0
	for index, source := range sheet.Rows {
		number := source.Number
		if number == 0 {
			number = index + 1
		}
		if number <= lastRow {
			return nil, errors.New("worksheet rows are not ordered")
		}
		lastRow = number
		row := Row{Number: number, Cells: make(map[int]Cell, len(source.Cells))}
		for _, sourceCell := range source.Cells {
			if sourceCell.Formula != nil {
				return nil, errors.New("formulas are not accepted")
			}
			column, ok := columnNumber(sourceCell.Reference)
			if !ok {
				return nil, errors.New("invalid cell reference")
			}
			if _, duplicate := row.Cells[column]; duplicate {
				return nil, errors.New("duplicate cell reference")
			}
			cell := Cell{Text: sourceCell.Value}
			switch sourceCell.Type {
			case "s":
				sharedIndex, parseErr := strconv.Atoi(sourceCell.Value)
				if parseErr != nil || sharedIndex < 0 || sharedIndex >= len(shared) {
					return nil, errors.New("invalid shared string")
				}
				cell.Text, cell.IsText = shared[sharedIndex], true
			case "inlineStr":
				cell.Text, cell.IsText = richTextValue(sourceCell.Inline), true
			case "str":
				cell.IsText = true
			case "":
				cell.IsText = sourceCell.Value == ""
			default:
				return nil, errors.New("unsupported cell type")
			}
			cell.Text = strings.TrimSpace(cell.Text)
			row.Cells[column] = cell
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func safeEntryName(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != "." && !strings.HasPrefix(name, "../")
}

func richTextValue(value richText) string {
	var out strings.Builder
	out.WriteString(value.Text)
	for _, run := range value.Runs {
		out.WriteString(run.Text)
	}
	return out.String()
}

func zipEntry(files []*zip.File, name string) *zip.File {
	for _, file := range files {
		if file.Name == name {
			return file
		}
	}
	return nil
}

func decodeZipXML(file *zip.File, limit uint64, out any) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	if limit > uint64(^uint(0)>>1)-1 {
		return errors.New("invalid XML limit")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || uint64(len(raw)) > limit {
		return errors.New("XML exceeds workbook limit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	for {
		token, tokenErr := decoder.Token()
		if tokenErr == io.EOF {
			break
		}
		if tokenErr != nil {
			return tokenErr
		}
		switch value := token.(type) {
		case xml.Directive:
			return errors.New("XML directives are not accepted")
		case xml.StartElement:
			if value.Name.Space == "http://www.w3.org/2001/XInclude" {
				return errors.New("XInclude is not accepted")
			}
		}
	}
	return xml.NewDecoder(bytes.NewReader(raw)).Decode(out)
}

func columnNumber(reference string) (int, bool) {
	column := 0
	position := 0
	for position < len(reference) && reference[position] >= 'A' && reference[position] <= 'Z' {
		column = column*26 + int(reference[position]-'A'+1)
		position++
	}
	if column == 0 || position == len(reference) {
		return 0, false
	}
	row, err := strconv.Atoi(reference[position:])
	if err != nil || row <= 0 {
		return 0, false
	}
	return column, true
}

func BuildTemplate(sheetName string, headers []string) ([]byte, error) {
	if sheetName == "" || len(headers) == 0 || len(headers) > 26 {
		return nil, errors.New("invalid template")
	}
	var output bytes.Buffer
	zw := zip.NewWriter(&output)
	files := []struct {
		name, body string
	}{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="` + escape(sheetName) + `" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
		{"xl/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font/><font><b/><color rgb="FFFFFFFF"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF166A61"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs></styleSheet>`},
		{"xl/worksheets/sheet1.xml", templateSheet(headers)},
	}
	for _, file := range files {
		entry, err := zw.Create(file.name)
		if err != nil {
			return nil, err
		}
		if _, err = io.WriteString(entry, file.body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func templateSheet(headers []string) string {
	var cells strings.Builder
	for index, header := range headers {
		column := string(rune('A' + index))
		fmt.Fprintf(&cells, `<c r="%s1" s="1" t="inlineStr"><is><t>%s</t></is></c>`, column, escape(header))
	}
	last := string(rune('A' + len(headers) - 1))
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:` + last + `101"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols><col min="1" max="` + strconv.Itoa(len(headers)) + `" width="22" customWidth="1" style="2"/></cols><sheetData><row r="1">` + cells.String() + `</row></sheetData><autoFilter ref="A1:` + last + `101"/></worksheet>`
}

func escape(value string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}
