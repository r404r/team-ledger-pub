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

func BuildAdjustmentWorkbookTemplate(typ string) ([]byte, error) {
	var sheet string
	var headers []string
	switch typ {
	case BatchBaseline:
		sheet = "Salary Baseline"
		headers = []string{"Staff Code", "Currency", "Salary at Date"}
	case BatchNormal:
		sheet = "Normal Adjustment"
		headers = []string{"Staff Code", "Currency", "Salary Before Adjustment", "Increase amount", "Salary After Adjustment", "Performance Grade", "Average Merit Increase", "Increase range suggested by department", "Effective Date"}
	case BatchSpecial:
		sheet = "Special Adjustment"
		headers = []string{"Staff Code", "Currency", "Salary Before Adjustment", "Increase amount", "Salary After Adjustment", "Special Salary Adjustment Starting Month", "Adjustment Reason Code", "Adjustment Reason"}
	default:
		return nil, workbookSafetyError("invalid workbook type")
	}
	return xlsx.BuildTemplate(sheet, headers)
}

func ParseAdjustmentWorkbook(raw []byte, typ string) ([]BatchLineCommand, error) {
	if typ != BatchNormal && typ != BatchSpecial && typ != BatchBaseline {
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
		"employeeid": "employee_id", "工号staffcode": "staff_code", "staffcode": "staff_code", "currency": "currency", "币种currency": "currency",
		"salarybeforeadjustment": "salary_before", "monthlybasesalarybefore": "salary_before", "monthlybasesalarybeforeadjustment": "salary_before", "调整前薪资salarybeforespecialadjustment": "salary_before",
		"increaseamount": "increase_amount", "调薪额度increaseamount": "increase_amount", "salaryafteradjustment": "salary_after", "monthlybasesalaryafteradjustment": "salary_after", "调整后薪资salaryafterspecialadjustment": "salary_after",
		"salaryatdate": "salary_after", "指定日工资salaryatdate": "salary_after", "指定日工资": "salary_after",
		"performancegrade": "performance_grade", "绩效等级performancegrade": "performance_grade", "averagemeritincrease": "average_merit_increase", "increaserangesuggestedbydepartment": "department_suggested_increase",
		"effectivedate": "effective_date", "specialsalaryadjustmentstartingmonth": "effective_month", "调整月份specialsalaryadjustmentstartingmonth": "effective_month", "adjustmentreasoncode": "reason_code", "adjustmentreason": "reason_text", "调整原因adjustmentreason": "reason_text",
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
		requiredHeadersPresent := columns["staff_code"] != 0 && columns["currency"] != 0
		if typ == BatchBaseline {
			requiredHeadersPresent = requiredHeadersPresent && columns["salary_after"] != 0
		} else {
			requiredHeadersPresent = requiredHeadersPresent && columns["increase_amount"] != 0
		}
		if requiredHeadersPresent {
			headerRow = rowIndex
			break
		}
	}
	required := []string{"staff_code", "currency", "salary_before", "increase_amount", "salary_after"}
	if typ == BatchBaseline {
		required = []string{"staff_code", "currency", "salary_after"}
	} else if typ == BatchNormal {
		required = append(required, "performance_grade")
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
		if strings.TrimSpace(row[columns["staff_code"]]) == "" {
			continue
		}
		text := func(field string) string {
			value := strings.TrimSpace(row[columns[field]])
			if strings.HasPrefix(value, "#NUMERIC#") {
				return ""
			}
			return value
		}
		line := BatchLineCommand{StaffCode: text("staff_code"), Currency: text("currency"), SalaryBefore: text("salary_before"), IncreaseAmount: text("increase_amount"), SalaryAfter: text("salary_after"), PerformanceGrade: text("performance_grade"), AverageMeritIncrease: text("average_merit_increase"), DepartmentSuggestedIncrease: text("department_suggested_increase"), EffectiveDate: text("effective_date"), EffectiveMonth: text("effective_month"), ReasonCode: text("reason_code"), ReasonText: text("reason_text")}
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
