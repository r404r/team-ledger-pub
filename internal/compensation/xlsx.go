package compensation

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

const (
	maxWorkbookCompressed = 10 << 20
	maxWorkbookExpanded   = 50 << 20
	maxWorkbookEntries    = 10_000
)

type WorkbookSafetyError struct {
	message string
}

func (e *WorkbookSafetyError) Error() string { return e.message }

func workbookSafetyError(message string) error {
	return &WorkbookSafetyError{message: message}
}

type xlsxSharedStrings struct {
	Items []struct {
		Text string `xml:"t"`
		Runs []struct {
			Text string `xml:"t"`
		} `xml:"r"`
	} `xml:"si"`
}

type xlsxWorksheet struct {
	Rows []struct {
		Cells []struct {
			Reference string  `xml:"r,attr"`
			Type      string  `xml:"t,attr"`
			Formula   *string `xml:"f"`
			Value     string  `xml:"v"`
			Inline    struct {
				Text string `xml:"t"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

func ParseAdjustmentWorkbook(raw []byte, typ string) ([]BatchLineCommand, error) {
	if len(raw) == 0 || len(raw) > maxWorkbookCompressed || typ != BatchNormal && typ != BatchSpecial {
		return nil, workbookSafetyError("invalid workbook")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(zr.File) > maxWorkbookEntries {
		return nil, workbookSafetyError("invalid workbook")
	}
	var expanded uint64
	for _, file := range zr.File {
		expanded += file.UncompressedSize64
		if expanded > maxWorkbookExpanded {
			return nil, workbookSafetyError("expanded workbook is too large")
		}
	}
	shared := []string{}
	if file := zipEntry(zr.File, "xl/sharedStrings.xml"); file != nil {
		var values xlsxSharedStrings
		if err = decodeZipXML(file, &values); err != nil {
			return nil, workbookSafetyError("invalid shared strings")
		}
		for _, item := range values.Items {
			text := item.Text
			for _, run := range item.Runs {
				text += run.Text
			}
			shared = append(shared, text)
		}
	}
	sheetFile := zipEntry(zr.File, "xl/worksheets/sheet1.xml")
	if sheetFile == nil {
		return nil, errors.New("sheet1 is required")
	}
	var sheet xlsxWorksheet
	if err = decodeZipXML(sheetFile, &sheet); err != nil {
		return nil, workbookSafetyError("invalid worksheet")
	}
	rows := make([]map[int]string, 0, len(sheet.Rows))
	for _, source := range sheet.Rows {
		row := make(map[int]string)
		for _, cell := range source.Cells {
			if cell.Formula != nil {
				return nil, errors.New("formulas are not accepted")
			}
			column, ok := xlsxColumn(cell.Reference)
			if !ok {
				return nil, errors.New("invalid cell reference")
			}
			value := cell.Value
			switch cell.Type {
			case "s":
				index, parseErr := strconv.Atoi(value)
				if parseErr != nil || index < 0 || index >= len(shared) {
					return nil, errors.New("invalid shared string")
				}
				value = shared[index]
			case "inlineStr":
				value = cell.Inline.Text
			case "str":
			case "":
				if value != "" {
					value = "#NUMERIC#" + value
				}
			default:
				return nil, errors.New("unsupported cell type")
			}
			row[column] = strings.TrimSpace(value)
		}
		rows = append(rows, row)
	}
	return workbookLines(rows, typ)
}

func workbookLines(rows []map[int]string, typ string) ([]BatchLineCommand, error) {
	aliases := map[string]string{
		"employeeid": "employee_id", "staffcode": "staff_code", "currency": "currency",
		"salarybeforeadjustment": "salary_before", "monthlybasesalarybefore": "salary_before", "monthlybasesalarybeforeadjustment": "salary_before",
		"increaseamount": "increase_amount", "salaryafteradjustment": "salary_after", "monthlybasesalaryafteradjustment": "salary_after",
		"performancegrade": "performance_grade", "averagemeritincrease": "average_merit_increase", "increaserangesuggestedbydepartment": "department_suggested_increase",
		"effectivedate": "effective_date", "specialsalaryadjustmentstartingmonth": "effective_month", "adjustmentreasoncode": "reason_code", "adjustmentreason": "reason_text",
	}
	headerRow := -1
	columns := map[string]int{}
	for rowIndex, row := range rows {
		if rowIndex >= 10 {
			break
		}
		for column, raw := range row {
			if field := aliases[normalizeHeader(raw)]; field != "" {
				columns[field] = column
			}
		}
		if columns["employee_id"] != 0 && columns["staff_code"] != 0 && columns["currency"] != 0 && columns["increase_amount"] != 0 {
			headerRow = rowIndex
			break
		}
	}
	required := []string{"employee_id", "staff_code", "currency", "salary_before", "increase_amount", "salary_after"}
	if typ == BatchNormal {
		required = append(required, "performance_grade")
	} else {
		required = append(required, "effective_month", "reason_code", "reason_text")
	}
	if headerRow < 0 {
		return nil, errors.New("required headers are missing")
	}
	for _, field := range required {
		if columns[field] == 0 {
			return nil, fmt.Errorf("required header %s is missing", field)
		}
	}
	out := make([]BatchLineCommand, 0)
	for rowIndex := headerRow + 1; rowIndex < len(rows); rowIndex++ {
		row := rows[rowIndex]
		if strings.TrimSpace(row[columns["employee_id"]]) == "" {
			continue
		}
		text := func(field string) string {
			value := strings.TrimSpace(row[columns[field]])
			if strings.HasPrefix(value, "#NUMERIC#") {
				return ""
			}
			return value
		}
		line := BatchLineCommand{EmployeeID: text("employee_id"), StaffCode: text("staff_code"), Currency: text("currency"), SalaryBefore: text("salary_before"), IncreaseAmount: text("increase_amount"), SalaryAfter: text("salary_after"), PerformanceGrade: text("performance_grade"), AverageMeritIncrease: text("average_merit_increase"), DepartmentSuggestedIncrease: text("department_suggested_increase"), EffectiveDate: text("effective_date"), EffectiveMonth: text("effective_month"), ReasonCode: text("reason_code"), ReasonText: text("reason_text")}
		for _, field := range required {
			if text(field) == "" {
				return nil, fmt.Errorf("row %d field %s must be text and non-empty", rowIndex+1, field)
			}
		}
		out = append(out, line)
		if len(out) > 500 {
			return nil, errors.New("workbook exceeds 500 employees")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("workbook has no employee rows")
	}
	return out, nil
}

func zipEntry(files []*zip.File, name string) *zip.File {
	for _, file := range files {
		if file.Name == name {
			return file
		}
	}
	return nil
}

func decodeZipXML(file *zip.File, out any) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	decoder := xml.NewDecoder(io.LimitReader(reader, maxWorkbookExpanded+1))
	return decoder.Decode(out)
}

func xlsxColumn(reference string) (int, bool) {
	column := 0
	for _, char := range reference {
		if char >= 'A' && char <= 'Z' {
			column = column*26 + int(char-'A'+1)
			continue
		}
		if char >= '0' && char <= '9' && column > 0 {
			return column, true
		}
		return 0, false
	}
	return 0, false
}

func normalizeHeader(value string) string {
	var out strings.Builder
	for _, char := range strings.ToLower(value) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			out.WriteRune(char)
		}
	}
	return out.String()
}
