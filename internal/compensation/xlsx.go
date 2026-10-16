package compensation

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/r404r/team-ledger/internal/xlsx"
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

func ParseAdjustmentWorkbook(raw []byte, typ string) ([]BatchLineCommand, error) {
	if typ != BatchNormal && typ != BatchSpecial {
		return nil, workbookSafetyError("invalid workbook")
	}
	rows, err := xlsx.ReadFirstSheet(raw, xlsx.Limits{
		CompressedBytes: maxWorkbookCompressed,
		ExpandedBytes:   maxWorkbookExpanded,
		Entries:         maxWorkbookEntries,
		Rows:            510,
		Cells:           20_000,
		XMLNodes:        200_000,
	})
	if err != nil {
		return nil, workbookSafetyError(err.Error())
	}
	legacyRows := make([]map[int]string, 0, len(rows))
	for _, source := range rows {
		row := make(map[int]string, len(source.Cells))
		for column, cell := range source.Cells {
			value := cell.Text
			if !cell.IsText && value != "" {
				value = "#NUMERIC#" + value
			}
			row[column] = value
		}
		legacyRows = append(legacyRows, row)
	}
	return workbookLines(legacyRows, typ)
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

func normalizeHeader(value string) string {
	var out strings.Builder
	for _, char := range strings.ToLower(value) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			out.WriteRune(char)
		}
	}
	return out.String()
}
