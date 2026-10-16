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
	Rows            int
	Cells           int
	XMLNodes        int
}

// ParseError reports a safe workbook location and a fixed diagnostic code.
// It never includes cell contents, formulas, relationship targets, or file paths.
type ParseError struct {
	Code  string
	Sheet string
	Cell  string
}

func (e *ParseError) Error() string { return e.Code }

func parseError(code, sheet, cell string) error {
	return &ParseError{Code: code, Sheet: sheet, Cell: cell}
}

type CellKind string

const (
	CellBlank   CellKind = "blank"
	CellText    CellKind = "text"
	CellNumber  CellKind = "number"
	CellDate    CellKind = "date"
	CellBoolean CellKind = "boolean"
	CellError   CellKind = "error"
)

type Cell struct {
	Text   string
	IsText bool
	Kind   CellKind
}

type Row struct {
	Number   int
	Cells    map[int]Cell
	Date1904 bool
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
		ID         string `xml:"Id,attr"`
		Type       string `xml:"Type,attr"`
		Target     string `xml:"Target,attr"`
		TargetMode string `xml:"TargetMode,attr"`
	} `xml:"Relationship"`
}

type workbookManifest struct {
	Properties struct {
		Date1904 string `xml:"date1904,attr"`
	} `xml:"workbookPr"`
	Sheets []struct {
		Name           string `xml:"name,attr"`
		RelationshipID string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
	} `xml:"sheets>sheet"`
}

func ReadFirstSheet(raw []byte, limits Limits) ([]Row, error) {
	if len(raw) == 0 || limits.CompressedBytes <= 0 || len(raw) > limits.CompressedBytes || limits.ExpandedBytes == 0 || limits.Entries <= 0 || limits.Rows <= 0 || limits.Cells <= 0 || limits.XMLNodes <= 0 {
		return nil, parseError("invalid_package", "", "")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(zr.File) == 0 || len(zr.File) > limits.Entries {
		return nil, parseError("invalid_package", "", "")
	}
	var expanded uint64
	worksheets := 0
	worksheetName := ""
	for _, file := range zr.File {
		if !safeEntryName(file.Name) {
			return nil, parseError("unsafe_package_entry", "", "")
		}
		expanded += file.UncompressedSize64
		if expanded > limits.ExpandedBytes {
			return nil, parseError("expanded_size_limit", "", "")
		}
		if strings.HasPrefix(file.Name, "xl/worksheets/") && strings.HasSuffix(file.Name, ".xml") {
			worksheets++
			worksheetName = file.Name
		}
		if strings.EqualFold(file.Name, "xl/vbaProject.bin") {
			return nil, parseError("macros_not_allowed", "", "")
		}
		if strings.HasSuffix(file.Name, ".rels") {
			var rels relationships
			if err := decodeZipXML(file, limits.ExpandedBytes, xmlBounds{Nodes: limits.XMLNodes}, &rels); err != nil {
				return nil, parseError("invalid_relationships", "", "")
			}
			for _, relationship := range rels.Items {
				if strings.EqualFold(relationship.TargetMode, "External") {
					return nil, parseError("external_relationship_not_allowed", "", "")
				}
			}
		}
	}
	if worksheets != 1 {
		return nil, parseError("worksheet_count", "", "")
	}
	var manifest workbookManifest
	workbookFile := zipEntry(zr.File, "xl/workbook.xml")
	workbookRelsFile := zipEntry(zr.File, "xl/_rels/workbook.xml.rels")
	if workbookFile == nil || workbookRelsFile == nil || decodeZipXML(workbookFile, limits.ExpandedBytes, xmlBounds{Nodes: limits.XMLNodes}, &manifest) != nil || len(manifest.Sheets) != 1 {
		return nil, parseError("worksheet_manifest", "", "")
	}
	date1904, validDateSystem := workbookDate1904(manifest.Properties.Date1904)
	if !validDateSystem {
		return nil, parseError("worksheet_manifest", "", "")
	}
	sheetName := safeSheetName(manifest.Sheets[0].Name)
	var workbookRels relationships
	if decodeZipXML(workbookRelsFile, limits.ExpandedBytes, xmlBounds{Nodes: limits.XMLNodes}, &workbookRels) != nil {
		return nil, parseError("invalid_relationships", sheetName, "")
	}
	declaredWorksheet := ""
	for _, relationship := range workbookRels.Items {
		if relationship.ID == manifest.Sheets[0].RelationshipID && strings.HasSuffix(relationship.Type, "/worksheet") {
			if strings.HasPrefix(relationship.Target, "/") {
				declaredWorksheet = strings.TrimPrefix(path.Clean(relationship.Target), "/")
			} else {
				declaredWorksheet = path.Clean(path.Join("xl", relationship.Target))
			}
			break
		}
	}
	if declaredWorksheet != worksheetName || !strings.HasPrefix(declaredWorksheet, "xl/worksheets/") {
		return nil, parseError("invalid_worksheet_relationship", sheetName, "")
	}

	shared := []string{}
	if file := zipEntry(zr.File, "xl/sharedStrings.xml"); file != nil {
		var values sharedStrings
		if err := decodeZipXML(file, limits.ExpandedBytes, xmlBounds{SharedStrings: limits.Cells, Nodes: limits.XMLNodes}, &values); err != nil {
			return nil, parseError("invalid_shared_strings", sheetName, "")
		}
		shared = make([]string, 0, len(values.Items))
		for _, item := range values.Items {
			shared = append(shared, richTextValue(item))
		}
	}

	sheetFile := zipEntry(zr.File, declaredWorksheet)
	if sheetFile == nil {
		return nil, parseError("worksheet_missing", sheetName, "")
	}
	var sheet worksheet
	if err := decodeZipXML(sheetFile, limits.ExpandedBytes, xmlBounds{Rows: limits.Rows, Cells: limits.Cells, Nodes: limits.XMLNodes}, &sheet); err != nil {
		return nil, parseError("invalid_worksheet_xml", sheetName, "")
	}
	rows := make([]Row, 0, len(sheet.Rows))
	lastRow := 0
	for index, source := range sheet.Rows {
		number := source.Number
		if number == 0 {
			number = index + 1
		}
		if number <= lastRow {
			return nil, parseError("unordered_rows", sheetName, "")
		}
		lastRow = number
		row := Row{Number: number, Cells: make(map[int]Cell, len(source.Cells)), Date1904: date1904}
		for _, sourceCell := range source.Cells {
			column, referencedRow, ok := cellPosition(sourceCell.Reference)
			if !ok || referencedRow != number {
				return nil, parseError("invalid_cell_reference", sheetName, "")
			}
			if sourceCell.Formula != nil {
				return nil, parseError("formula_not_allowed", sheetName, sourceCell.Reference)
			}
			if _, duplicate := row.Cells[column]; duplicate {
				return nil, parseError("duplicate_cell_reference", sheetName, sourceCell.Reference)
			}
			cell := Cell{Text: sourceCell.Value}
			switch sourceCell.Type {
			case "s":
				sharedIndex, parseErr := strconv.Atoi(sourceCell.Value)
				if parseErr != nil || sharedIndex < 0 || sharedIndex >= len(shared) {
					return nil, parseError("invalid_shared_string", sheetName, sourceCell.Reference)
				}
				cell.Text, cell.IsText, cell.Kind = shared[sharedIndex], true, CellText
			case "inlineStr":
				cell.Text, cell.IsText, cell.Kind = richTextValue(sourceCell.Inline), true, CellText
			case "str":
				cell.IsText, cell.Kind = true, CellText
			case "", "n":
				if sourceCell.Value == "" {
					cell.IsText, cell.Kind = true, CellBlank
				} else {
					cell.Kind = CellNumber
				}
			case "d":
				cell.Kind = CellDate
			case "b":
				cell.Kind = CellBoolean
			case "e":
				cell.Kind = CellError
			default:
				return nil, parseError("unsupported_cell_type", sheetName, sourceCell.Reference)
			}
			cell.Text = strings.TrimSpace(cell.Text)
			row.Cells[column] = cell
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func workbookDate1904(raw string) (bool, bool) {
	switch raw {
	case "", "0", "false":
		return false, true
	case "1", "true":
		return true, true
	default:
		return false, false
	}
}

func safeEntryName(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != "." && !strings.HasPrefix(name, "../")
}

func safeSheetName(name string) string {
	if name == "" || len(name) > 31 || strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return ""
	}
	return name
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

type xmlBounds struct {
	Rows          int
	Cells         int
	SharedStrings int
	Nodes         int
}

func decodeZipXML(file *zip.File, limit uint64, bounds xmlBounds, out any) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	if limit > uint64(^uint(0)>>1)-1 || bounds.Nodes <= 0 {
		return errors.New("invalid XML limit")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || uint64(len(raw)) > limit {
		return errors.New("XML exceeds workbook limit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	rows, cells, sharedStrings, nodes := 0, 0, 0, 0
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
			nodes++
			if nodes > bounds.Nodes {
				return errors.New("XML contains too many elements")
			}
			if value.Name.Space == "http://www.w3.org/2001/XInclude" {
				return errors.New("XInclude is not accepted")
			}
			switch value.Name.Local {
			case "row":
				rows++
				if bounds.Rows > 0 && rows > bounds.Rows {
					return errors.New("worksheet contains too many rows")
				}
			case "c":
				cells++
				if bounds.Cells > 0 && cells > bounds.Cells {
					return errors.New("worksheet contains too many cells")
				}
			case "si":
				sharedStrings++
				if bounds.SharedStrings > 0 && sharedStrings > bounds.SharedStrings {
					return errors.New("workbook contains too many shared strings")
				}
			}
		}
	}
	return xml.NewDecoder(bytes.NewReader(raw)).Decode(out)
}

func cellPosition(reference string) (int, int, bool) {
	const maxColumn = 16_384
	column := 0
	position := 0
	for position < len(reference) && reference[position] >= 'A' && reference[position] <= 'Z' {
		digit := int(reference[position]-'A') + 1
		if column > (maxColumn-digit)/26 {
			return 0, 0, false
		}
		column = column*26 + digit
		position++
	}
	if column == 0 || column > maxColumn || position == len(reference) {
		return 0, 0, false
	}
	row, err := strconv.Atoi(reference[position:])
	if err != nil || row <= 0 || row > 1_048_576 {
		return 0, 0, false
	}
	return column, row, true
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
