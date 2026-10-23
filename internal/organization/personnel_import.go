package organization

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"github.com/r404r/team-ledger/internal/xlsx"
)

const (
	personnelWorkbookCompressed = 5 << 20
	personnelWorkbookExpanded   = 20 << 20
	personnelWorkbookEntries    = 1_000
	personnelWorkbookRows       = 100
)

var personnelImportHeaders = []string{
	"工号 Staff Code",
	"姓名 Staff Name",
	"姓名 English Name",
	"地点 Location",
	"所在公司 Branch Code",
	"业务单元 Business Group Code",
	"目前事业部 Division Code",
	"目前部门 Department Code",
	"学历 Latest Education",
	"雇佣起始日 Date of Employment",
	"职位 Position",
	"职系 Job Family Code",
	"职级 Career Level Code",
	"直属主管 HOD Staff Code",
	"退职日 Departure Date",
	"业务邮箱 Work Email",
	"业务电话 Work Phone",
	"资料摘要 Profile Summary",
}

var personnelImportFields = []string{
	"staff_code", "local_name", "english_name", "location", "branch_code", "business_group_code",
	"division_code", "department_code", "education_level", "hire_date", "position", "job_family_code",
	"career_level_code", "manager_staff_code", "departure_date", "email", "phone", "profile_summary",
}

// The HOD Staff Code column accepts "<Staff Code>-<Staff Name>", so its raw limit is wider than
// a Staff Code; the extracted code is still bound to the 64-byte Staff Code limit.
var personnelImportFieldLimits = []int{64, 256, 256, 16, 64, 64, 64, 64, 64, 32, 1024, 32, 32, 320, 32, 320, 64, 16 << 10}

type PersonnelImportRow struct {
	RowNumber         int     `json:"row_number"`
	StaffCode         string  `json:"staff_code"`
	LocalName         string  `json:"local_name,omitempty"`
	EnglishName       string  `json:"english_name,omitempty"`
	Location          string  `json:"location"`
	BranchCode        string  `json:"branch_code"`
	BusinessGroupCode string  `json:"business_group_code"`
	DivisionCode      string  `json:"division_code"`
	DepartmentCode    string  `json:"department_code"`
	EducationLevel    string  `json:"education_level"`
	HireDate          string  `json:"hire_date"`
	Position          string  `json:"position"`
	JobFamilyCode     string  `json:"job_family_code"`
	CareerLevelCode   string  `json:"career_level_code"`
	ManagerStaffCode  string  `json:"manager_staff_code,omitempty"`
	DepartureDate     *string `json:"departure_date"`
	Email             string  `json:"email,omitempty"`
	Phone             string  `json:"phone,omitempty"`
	ProfileSummary    string  `json:"profile_summary,omitempty"`
	BranchID          string  `json:"branch_id,omitempty"`
	BusinessGroupID   string  `json:"business_group_id,omitempty"`
	DivisionID        string  `json:"division_id,omitempty"`
	DepartmentID      string  `json:"department_id,omitempty"`
	JobFamilyID       string  `json:"job_family_id,omitempty"`
	CareerLevelID     string  `json:"career_level_id,omitempty"`
}

type PersonnelImportIssue struct {
	RowNumber int    `json:"row_number"`
	Sheet     string `json:"sheet"`
	Cell      string `json:"cell,omitempty"`
	Field     string `json:"field"`
	Code      string `json:"code"`
}

type PersonnelImportWorkbookDiagnostic struct {
	Sheet string `json:"sheet,omitempty"`
	Cell  string `json:"cell,omitempty"`
	Code  string `json:"code"`
}

type PersonnelImportWorkbookError struct {
	Diagnostic PersonnelImportWorkbookDiagnostic
}

func (e *PersonnelImportWorkbookError) Error() string { return e.Diagnostic.Code }
func (e *PersonnelImportWorkbookError) Unwrap() error { return fault.Invalid }

func personnelWorkbookError(code, sheet, cell string) error {
	return &PersonnelImportWorkbookError{Diagnostic: PersonnelImportWorkbookDiagnostic{Sheet: sheet, Cell: cell, Code: code}}
}

func personnelImportIssue(row int, field, code string) PersonnelImportIssue {
	column := 0
	for index, name := range personnelImportFields {
		if name == field {
			column = index + 1
			break
		}
	}
	if field == "profile" {
		column = 2
	}
	cell := ""
	if column > 0 {
		cell = personnelCellReference(column, row)
	}
	return PersonnelImportIssue{RowNumber: row, Sheet: "Employees", Cell: cell, Field: field, Code: code}
}

func personnelCellReference(column, row int) string {
	letters := ""
	for column > 0 {
		column--
		letters = string(rune('A'+column%26)) + letters
		column /= 26
	}
	return letters + strconv.Itoa(row)
}

type PersonnelImportCatalogOption struct {
	ID    string `json:"id"`
	Code  string `json:"code"`
	Label string `json:"label,omitempty"`
	Rank  int    `json:"rank,omitempty"`
}

type PersonnelImportPreview struct {
	Rows            []PersonnelImportRow           `json:"rows"`
	Errors          []PersonnelImportIssue         `json:"errors"`
	Warnings        []PersonnelImportIssue         `json:"warnings"`
	EducationLevels []EducationLevelView           `json:"education_levels"`
	LegalEntities   []PersonnelImportCatalogOption `json:"legal_entities"`
	BusinessGroups  []PersonnelImportCatalogOption `json:"business_groups"`
	Divisions       []PersonnelImportCatalogOption `json:"divisions"`
	Departments     []PersonnelImportCatalogOption `json:"departments"`
	JobFamilies     []PersonnelImportCatalogOption `json:"job_families"`
	CareerLevels    []PersonnelImportCatalogOption `json:"career_levels"`
	RowCount        int                            `json:"row_count"`
	CatalogRevision string                         `json:"catalog_revision,omitempty"`
	GraphRevision   string                         `json:"graph_revision,omitempty"`
}
type PersonnelImportReviewCommand struct {
	Rows []PersonnelImportReviewRow `json:"rows"`
}

type PersonnelImportReviewRow struct {
	RowNumber         int     `json:"row_number"`
	StaffCode         string  `json:"staff_code"`
	LocalName         string  `json:"local_name"`
	EnglishName       string  `json:"english_name"`
	Location          string  `json:"location"`
	BranchCode        string  `json:"branch_code"`
	BusinessGroupCode string  `json:"business_group_code"`
	DivisionCode      string  `json:"division_code"`
	DepartmentCode    string  `json:"department_code"`
	EducationLevel    string  `json:"education_level"`
	HireDate          string  `json:"hire_date"`
	Position          string  `json:"position"`
	JobFamilyCode     string  `json:"job_family_code"`
	CareerLevelCode   string  `json:"career_level_code"`
	ManagerStaffCode  string  `json:"manager_staff_code"`
	DepartureDate     *string `json:"departure_date"`
	Email             string  `json:"email"`
	Phone             string  `json:"phone"`
	ProfileSummary    string  `json:"profile_summary"`
}

func (s *Service) ReviewPersonnelImport(ctx context.Context, request Request, org string, command PersonnelImportReviewCommand) (PersonnelImportPreview, error) {
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-05")
	if err != nil {
		return PersonnelImportPreview{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	if len(command.Rows) == 0 || len(command.Rows) > personnelWorkbookRows {
		return PersonnelImportPreview{}, fault.Invalid
	}
	preview := newPersonnelImportPreview(len(command.Rows))
	rowNumbers := make(map[int]struct{}, len(command.Rows))
	for _, input := range command.Rows {
		if input.RowNumber < 2 || input.RowNumber > 1_048_576 {
			return PersonnelImportPreview{}, fault.Invalid
		}
		if _, duplicate := rowNumbers[input.RowNumber]; duplicate {
			return PersonnelImportPreview{}, fault.Invalid
		}
		rowNumbers[input.RowNumber] = struct{}{}
		values := []string{
			input.StaffCode, input.LocalName, input.EnglishName, input.Location, input.BranchCode,
			input.BusinessGroupCode, input.DivisionCode, input.DepartmentCode, input.EducationLevel,
			input.HireDate, input.Position, input.JobFamilyCode, input.CareerLevelCode, input.ManagerStaffCode,
			optionalText(input.DepartureDate), input.Email, input.Phone, input.ProfileSummary,
		}
		for column, text := range values {
			if len(text) > personnelImportFieldLimits[column] {
				return PersonnelImportPreview{}, fault.Invalid
			}
		}
		row := PersonnelImportRow{
			RowNumber: input.RowNumber, StaffCode: input.StaffCode, LocalName: input.LocalName,
			EnglishName: input.EnglishName, Location: input.Location, BranchCode: input.BranchCode,
			BusinessGroupCode: input.BusinessGroupCode, DivisionCode: input.DivisionCode,
			DepartmentCode: input.DepartmentCode, EducationLevel: input.EducationLevel,
			HireDate: input.HireDate, Position: input.Position, JobFamilyCode: input.JobFamilyCode,
			CareerLevelCode: input.CareerLevelCode, ManagerStaffCode: input.ManagerStaffCode,
			DepartureDate: input.DepartureDate, Email: input.Email, Phone: input.Phone,
			ProfileSummary: input.ProfileSummary,
		}
		preview.Rows = append(preview.Rows, row)
		validatePersonnelRow(xlsx.Row{Number: input.RowNumber}, &preview, len(preview.Rows)-1)
	}
	preview.RowCount = len(preview.Rows)
	validatePersonnelReferences(&preview)
	if err := s.resolvePersonnelImportCatalogs(ctx, org, &preview, snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock())); err != nil {
		return PersonnelImportPreview{}, err
	}
	if err := s.resolvePersonnelManagers(ctx, org, &preview); err != nil {
		return PersonnelImportPreview{}, err
	}
	return preview, nil
}

func optionalText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Service) PersonnelImportTemplate(ctx context.Context, request Request, org string) ([]byte, error) {
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-05")
	if err != nil {
		return nil, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	workbook, err := xlsx.BuildTemplate("Employees", personnelImportHeaders)
	if err != nil {
		return nil, fault.Unavailable
	}
	return workbook, nil
}

func (s *Service) PreviewPersonnelImport(ctx context.Context, request Request, org string, raw []byte) (PersonnelImportPreview, error) {
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-05")
	if err != nil {
		return PersonnelImportPreview{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	preview, err := parsePersonnelWorkbook(raw)
	if err != nil {
		return PersonnelImportPreview{}, err
	}
	if err = s.resolvePersonnelImportCatalogs(ctx, org, &preview, snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock())); err != nil {
		return PersonnelImportPreview{}, err
	}
	if err = s.resolvePersonnelManagers(ctx, org, &preview); err != nil {
		return PersonnelImportPreview{}, err
	}
	return preview, nil
}

func parsePersonnelWorkbook(raw []byte) (PersonnelImportPreview, error) {
	rows, err := xlsx.ReadFirstSheet(raw, xlsx.Limits{
		CompressedBytes: personnelWorkbookCompressed,
		ExpandedBytes:   personnelWorkbookExpanded,
		Entries:         personnelWorkbookEntries,
		Rows:            personnelWorkbookRows + 1,
		Cells:           (personnelWorkbookRows + 1) * len(personnelImportHeaders),
		XMLNodes:        20_000,
	})
	if err != nil {
		var parseErr *xlsx.ParseError
		if errors.As(err, &parseErr) {
			return PersonnelImportPreview{}, personnelWorkbookError(parseErr.Code, parseErr.Sheet, parseErr.Cell)
		}
		return PersonnelImportPreview{}, personnelWorkbookError("invalid_package", "", "")
	}
	if len(rows) == 0 {
		return PersonnelImportPreview{}, personnelWorkbookError("empty_worksheet", "Employees", "A1")
	}
	if rows[0].Number != 1 {
		return PersonnelImportPreview{}, personnelWorkbookError("header_row_missing", "Employees", "A1")
	}
	if err := validatePersonnelHeaders(rows[0]); err != nil {
		return PersonnelImportPreview{}, err
	}
	preview := newPersonnelImportPreview(0)
	for _, source := range rows[1:] {
		if rowEmpty(source) {
			continue
		}
		if len(preview.Rows) >= personnelWorkbookRows {
			return PersonnelImportPreview{}, personnelWorkbookError("row_limit", "Employees", "")
		}
		values := make([]string, len(personnelImportHeaders))
		for column, limit := range personnelImportFieldLimits {
			cell, ok := source.Cells[column+1]
			if !ok {
				continue
			}
			text, warning, issue := personnelImportCellValue(cell, column, source.Date1904)
			if len(text) > limit {
				preview.Errors = append(preview.Errors, personnelImportIssue(source.Number, personnelImportFields[column], "field_too_large"))
				continue
			}
			values[column] = text
			if warning != "" {
				preview.Warnings = append(preview.Warnings, personnelImportIssue(source.Number, personnelImportFields[column], warning))
			}
			if issue != "" {
				preview.Errors = append(preview.Errors, personnelImportIssue(source.Number, personnelImportFields[column], issue))
			}
		}
		row := PersonnelImportRow{
			RowNumber:         source.Number,
			StaffCode:         values[0],
			LocalName:         values[1],
			EnglishName:       values[2],
			Location:          values[3],
			BranchCode:        values[4],
			BusinessGroupCode: values[5],
			DivisionCode:      values[6],
			DepartmentCode:    values[7],
			EducationLevel:    values[8],
			HireDate:          values[9],
			Position:          values[10],
			JobFamilyCode:     values[11],
			CareerLevelCode:   values[12],
			ManagerStaffCode:  values[13],
			Email:             values[15],
			Phone:             values[16],
			ProfileSummary:    values[17],
		}
		if values[14] != "" {
			row.DepartureDate = &values[14]
		}
		preview.Rows = append(preview.Rows, row)
		validatePersonnelRow(source, &preview, len(preview.Rows)-1)
	}
	if len(preview.Rows) == 0 {
		return PersonnelImportPreview{}, personnelWorkbookError("empty_worksheet", "Employees", "A2")
	}
	validatePersonnelReferences(&preview)
	preview.RowCount = len(preview.Rows)
	return preview, nil
}

func newPersonnelImportPreview(capacity int) PersonnelImportPreview {
	return PersonnelImportPreview{
		Rows:            make([]PersonnelImportRow, 0, capacity),
		Errors:          []PersonnelImportIssue{},
		Warnings:        []PersonnelImportIssue{},
		EducationLevels: []EducationLevelView{},
		LegalEntities:   []PersonnelImportCatalogOption{},
		BusinessGroups:  []PersonnelImportCatalogOption{},
		Divisions:       []PersonnelImportCatalogOption{},
		Departments:     []PersonnelImportCatalogOption{},
		JobFamilies:     []PersonnelImportCatalogOption{},
		CareerLevels:    []PersonnelImportCatalogOption{},
	}
}

func validatePersonnelHeaders(row xlsx.Row) error {
	for column, header := range personnelImportHeaders {
		cell, ok := row.Cells[column+1]
		reference := personnelCellReference(column+1, 1)
		if !ok {
			return personnelWorkbookError("header_missing", "Employees", reference)
		}
		if !cell.IsText {
			return personnelWorkbookError("header_text_required", "Employees", reference)
		}
		if cell.Text != header {
			return personnelWorkbookError("header_mismatch", "Employees", reference)
		}
	}
	for column, cell := range row.Cells {
		if column > len(personnelImportHeaders) && cell.Text != "" {
			return personnelWorkbookError("unexpected_column", "Employees", personnelCellReference(column, 1))
		}
	}
	return nil
}

func rowEmpty(row xlsx.Row) bool {
	for _, cell := range row.Cells {
		if cell.Text != "" {
			return false
		}
	}
	return true
}
func personnelImportCellValue(cell xlsx.Cell, column int, date1904 bool) (string, string, string) {
	switch cell.Kind {
	case xlsx.CellText, xlsx.CellBlank:
		return cell.Text, "", ""
	case xlsx.CellNumber:
		switch column {
		case 0:
			if cell.Text == "" || !asciiDigits(cell.Text) {
				return cell.Text, "", "numeric_staff_code_not_integer"
			}
			return cell.Text, "numeric_staff_code_coerced", ""
		case 9, 14:
			canonical, ok := normalizeExcelSerialDate(cell.Text, date1904)
			if !ok {
				return cell.Text, "", "invalid_excel_date"
			}
			return canonical, "excel_date_coerced", ""
		default:
			return cell.Text, "numeric_cell_coerced", ""
		}
	case xlsx.CellDate:
		if column == 9 || column == 14 {
			canonical, ok := normalizeOOXMLDate(cell.Text)
			if !ok {
				return cell.Text, "", "invalid_excel_date"
			}
			return canonical, "excel_date_coerced", ""
		}
		return cell.Text, "", "cell_type_requires_edit"
	case xlsx.CellBoolean, xlsx.CellError:
		return cell.Text, "", "cell_type_requires_edit"
	default:
		return cell.Text, "", "cell_type_requires_edit"
	}
}

func asciiDigits(raw string) bool {
	if raw == "" {
		return false
	}
	for index := range len(raw) {
		if raw[index] < '0' || raw[index] > '9' {
			return false
		}
	}
	return true
}

func normalizeExcelSerialDate(raw string, date1904 bool) (string, bool) {
	if !asciiDigits(raw) {
		return "", false
	}
	serial, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return "", false
	}
	var parsed time.Time
	if date1904 {
		if serial > 2_958_465 {
			return "", false
		}
		parsed = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(serial))
	} else {
		if serial < 1 || serial == 60 || serial > 2_958_465 {
			return "", false
		}
		if serial > 60 {
			serial--
		}
		parsed = time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(serial))
	}
	canonical := parsed.Format("2006-01-02")
	return canonical, value.ValidDate(canonical)
}

func normalizeOOXMLDate(raw string) (string, bool) {
	if canonical, ok := normalizePersonnelImportDate(raw); ok {
		return canonical, true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05"} {
		parsed, err := time.Parse(layout, raw)
		if err == nil && parsed.Hour() == 0 && parsed.Minute() == 0 && parsed.Second() == 0 && parsed.Nanosecond() == 0 && len(raw) >= 10 && value.ValidDate(raw[:10]) {
			return raw[:10], true
		}
	}
	return "", false
}

func normalizePersonnelImportDate(raw string) (string, bool) {
	var yearText, monthText, dayText string
	if strings.HasSuffix(raw, "日") {
		withoutDay := strings.TrimSuffix(raw, "日")
		var remainder string
		var ok bool
		yearText, remainder, ok = strings.Cut(withoutDay, "年")
		if !ok || strings.Contains(remainder, "年") {
			return "", false
		}
		monthText, dayText, ok = strings.Cut(remainder, "月")
		if !ok || strings.Contains(dayText, "月") {
			return "", false
		}
	} else {
		separator := ""
		for _, candidate := range []string{"-", "/", "."} {
			count := strings.Count(raw, candidate)
			if count == 0 {
				continue
			}
			if count != 2 || separator != "" {
				return "", false
			}
			separator = candidate
		}
		if separator == "" {
			return "", false
		}
		parts := strings.Split(raw, separator)
		if len(parts) != 3 {
			return "", false
		}
		switch {
		case len(parts[0]) == 4:
			yearText, monthText, dayText = parts[0], parts[1], parts[2]
		case len(parts[2]) == 4:
			monthText, dayText, yearText = parts[0], parts[1], parts[2]
		default:
			return "", false
		}
	}
	if len(yearText) != 4 || len(monthText) < 1 || len(monthText) > 2 || len(dayText) < 1 || len(dayText) > 2 {
		return "", false
	}
	year, yearErr := strconv.Atoi(yearText)
	month, monthErr := strconv.Atoi(monthText)
	day, dayErr := strconv.Atoi(dayText)
	if yearErr != nil || monthErr != nil || dayErr != nil || year == 0 {
		return "", false
	}
	parsed := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if parsed.Year() != year || int(parsed.Month()) != month || parsed.Day() != day {
		return "", false
	}
	canonical := parsed.Format("2006-01-02")
	return canonical, value.ValidDate(canonical)
}

func canonicalLocation(raw string) (string, bool) {
	switch strings.ToLower(raw) {
	case strings.ToLower(LocationShanghai):
		return LocationShanghai, true
	case strings.ToLower(LocationWuxi):
		return LocationWuxi, true
	case strings.ToLower(LocationTokyo):
		return LocationTokyo, true
	default:
		return "", false
	}
}

func validatePersonnelRow(source xlsx.Row, preview *PersonnelImportPreview, index int) {
	row := &preview.Rows[index]
	issue := func(field, code string) {
		preview.Errors = append(preview.Errors, personnelImportIssue(row.RowNumber, field, code))
	}
	warning := func(field, code string) {
		preview.Warnings = append(preview.Warnings, personnelImportIssue(row.RowNumber, field, code))
	}
	hasIssue := func(field string) bool {
		for _, existing := range preview.Errors {
			if existing.RowNumber == row.RowNumber && existing.Field == field {
				return true
			}
		}
		return false
	}
	for column, cell := range source.Cells {
		if column > len(personnelImportHeaders) && cell.Text != "" {
			preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: row.RowNumber, Sheet: "Employees", Cell: personnelCellReference(column, row.RowNumber), Field: "workbook", Code: "unexpected_column"})
		}
	}
	if row.StaffCode == "" {
		issue("staff_code", "staff_code_required")
	} else if !hasIssue("staff_code") {
		if normalized, ok := NormalizeStaffCode(row.StaffCode); !ok {
			issue("staff_code", "invalid_staff_code")
		} else {
			row.StaffCode = normalized
		}
	}
	profile := Profile{LocalName: row.LocalName, EnglishName: row.EnglishName, ProfileSummary: row.ProfileSummary}
	if row.Email != "" || row.Phone != "" {
		profile.WorkContact = &Contact{Email: row.Email, Phone: row.Phone}
	}
	if !validProfile(profile) {
		issue("profile", "invalid_profile")
	}
	hireValid := !hasIssue("hire_date")
	if hireValid {
		original := row.HireDate
		normalized, ok := normalizePersonnelImportDate(original)
		if !ok {
			issue("hire_date", "invalid_date")
			hireValid = false
		} else {
			row.HireDate = normalized
			if original != normalized {
				warning("hire_date", "date_text_normalized")
			}
		}
	}
	departureValid := !hasIssue("departure_date")
	if departureValid && row.DepartureDate != nil {
		original := *row.DepartureDate
		normalized, ok := normalizePersonnelImportDate(original)
		if !ok {
			issue("departure_date", "invalid_date")
			departureValid = false
		} else {
			row.DepartureDate = &normalized
			if original != normalized {
				warning("departure_date", "date_text_normalized")
			}
		}
	}
	if hireValid && departureValid && !validLifecycle(Lifecycle{ValidFrom: row.HireDate, ValidTo: row.DepartureDate}) {
		issue("departure_date", "departure_not_after_hire")
	}
	if !hasIssue("location") && !validLocation(row.Location) {
		if canonical, ok := canonicalLocation(row.Location); ok {
			row.Location = canonical
			warning("location", "location_case_normalized")
		} else {
			issue("location", "invalid_location")
		}
	}
	if row.EducationLevel != "" && !hasIssue("education_level") {
		normalized := strings.TrimSpace(row.EducationLevel)
		if !validEducationLevel(normalized) {
			issue("education_level", "invalid_education_level")
		} else if normalized != row.EducationLevel {
			row.EducationLevel = normalized
			warning("education_level", "catalog_label_resolved")
		}
	}
	if row.Position != "" && !hasIssue("position") && !positionValid(PositionPayload{Title: row.Position}) {
		issue("position", "invalid_position")
	}
	for _, field := range []struct {
		name     string
		value    string
		limit    int
		required bool
	}{
		{"branch_code", row.BranchCode, 64, true},
		{"business_group_code", row.BusinessGroupCode, 64, true},
		{"division_code", row.DivisionCode, 64, true},
		{"department_code", row.DepartmentCode, 64, true},
		{"job_family_code", row.JobFamilyCode, 32, false},
		{"career_level_code", row.CareerLevelCode, 32, false},
	} {
		normalized := strings.TrimSpace(field.value)
		if !hasIssue(field.name) && (field.required && normalized == "" || normalized != "" && len(normalized) > field.limit) {
			issue(field.name, "invalid_catalog_code")
		}
	}
	if row.ManagerStaffCode != "" && !hasIssue("manager_staff_code") {
		extracted := NormalizeHODStaffCode(row.ManagerStaffCode)
		if normalized, ok := NormalizeStaffCode(extracted); !ok {
			issue("manager_staff_code", "invalid_staff_code")
		} else {
			if extracted != row.ManagerStaffCode {
				warning("manager_staff_code", "hod_staff_code_extracted")
			}
			row.ManagerStaffCode = normalized
		}
	}
}

// NormalizeHODStaffCode reduces a "HOD Staff Code" cell to the manager's plain Staff Code.
// A real Staff Code never contains a hyphen, so a non-empty value with one is the composite
// "<Staff Code>-<Staff Name>": the text before the first hyphen is kept, trimmed. Values without
// a hyphen, including blank, are returned unchanged. Every import path that reads a HOD cell
// must use this function so Preview and Commit resolve the same manager code.
func NormalizeHODStaffCode(raw string) string {
	code, _, composite := strings.Cut(raw, "-")
	if !composite {
		return raw
	}
	return strings.TrimSpace(code)
}

type personnelCatalogEntry struct {
	ID    string
	Code  string
	Label string
}

func resolvePersonnelCatalog(raw string, entries []personnelCatalogEntry) (string, string, bool, bool) {
	normalized := strings.TrimSpace(raw)
	codeMatches := 0
	var codeMatch personnelCatalogEntry
	for _, entry := range entries {
		if strings.EqualFold(entry.Code, normalized) {
			codeMatches++
			codeMatch = entry
		}
	}
	if codeMatches == 1 {
		return codeMatch.ID, codeMatch.Code, codeMatch.Code != raw, false
	}
	if codeMatches > 1 {
		return "", "", false, true
	}
	labelMatches := 0
	var labelMatch personnelCatalogEntry
	for _, entry := range entries {
		if entry.Label != "" && strings.EqualFold(strings.TrimSpace(entry.Label), normalized) {
			labelMatches++
			labelMatch = entry
		}
	}
	if labelMatches == 1 {
		return labelMatch.ID, labelMatch.Code, true, false
	}
	return "", "", false, labelMatches > 1
}

func appendPersonnelCatalogOption(target *[]PersonnelImportCatalogOption, option PersonnelImportCatalogOption) {
	for _, existing := range *target {
		if existing.ID == option.ID {
			return
		}
	}
	*target = append(*target, option)
}

func (s *Service) resolvePersonnelImportCatalogs(ctx context.Context, org string, preview *PersonnelImportPreview, includeLabels bool) error {
	catalogsByDate := make(map[string]WorkforceCatalogs)
	for index := range preview.Rows {
		row := &preview.Rows[index]
		if !value.ValidDate(row.HireDate) {
			continue
		}
		catalogs, ok := catalogsByDate[row.HireDate]
		if !ok {
			var err error
			catalogs, err = s.Store.WorkforceCatalogs(ctx, org, row.HireDate)
			if err != nil {
				return err
			}
			if includeLabels {
				for index := range catalogs.LegalEntities {
					var label legalEntityLabel
					entry := &catalogs.LegalEntities[index]
					if err = s.openWorkforcePayload(ctx, org, "", entry.ID, entry.LabelPayloadID, "legal_entity", "pii.legal_entity_label.v1", &label); err != nil {
						return err
					}
					entry.DisplayName = label.DisplayName
				}
				for index := range catalogs.OrgUnits {
					var label catalogLabel
					entry := &catalogs.OrgUnits[index]
					if err = s.openWorkforcePayload(ctx, org, "", entry.ID, entry.LabelPayloadID, "org_unit", "pii.org_unit_label.v1", &label); err != nil {
						return err
					}
					entry.Label = label.Label
				}
			}
			catalogsByDate[row.HireDate] = catalogs
		}
		if preview.CatalogRevision == "" {
			preview.CatalogRevision, preview.GraphRevision = catalogs.CatalogRevision, catalogs.GraphRevision
		} else if preview.CatalogRevision != catalogs.CatalogRevision || preview.GraphRevision != catalogs.GraphRevision {
			return fault.Conflict
		}
		issue := func(field, code string) {
			preview.Errors = append(preview.Errors, personnelImportIssue(row.RowNumber, field, code))
		}
		warning := func(field, code string) {
			preview.Warnings = append(preview.Warnings, personnelImportIssue(row.RowNumber, field, code))
		}
		hasIssue := func(field string) bool {
			for _, existing := range preview.Errors {
				if existing.RowNumber == row.RowNumber && existing.Field == field {
					return true
				}
			}
			return false
		}
		for _, level := range catalogs.EducationLevels {
			found := false
			for _, existing := range preview.EducationLevels {
				found = found || existing.Code == level.Code
			}
			if !found {
				preview.EducationLevels = append(preview.EducationLevels, level)
			}
		}
		resolve := func(field string, raw *string, target *string, entries []personnelCatalogEntry, required bool) {
			if hasIssue(field) || *raw == "" && !required {
				return
			}
			id, code, normalized, ambiguous := resolvePersonnelCatalog(*raw, entries)
			switch {
			case ambiguous:
				issue(field, "ambiguous_catalog_label")
			case id == "":
				issue(field, "unknown_catalog_code")
			default:
				*raw, *target = code, id
				if normalized {
					warning(field, "catalog_label_resolved")
				}
			}
		}
		legalEntities := make([]personnelCatalogEntry, 0, len(catalogs.LegalEntities))
		for _, entry := range catalogs.LegalEntities {
			if entry.Active {
				legalEntities = append(legalEntities, personnelCatalogEntry{ID: entry.ID, Code: entry.Code, Label: entry.DisplayName})
				appendPersonnelCatalogOption(&preview.LegalEntities, PersonnelImportCatalogOption{ID: entry.ID, Code: entry.Code, Label: entry.DisplayName})
			}
		}
		orgUnits := make(map[string][]personnelCatalogEntry, 3)
		for _, entry := range catalogs.OrgUnits {
			if entry.Active {
				orgUnits[entry.Kind] = append(orgUnits[entry.Kind], personnelCatalogEntry{ID: entry.ID, Code: entry.Code, Label: entry.Label})
				option := PersonnelImportCatalogOption{ID: entry.ID, Code: entry.Code, Label: entry.Label}
				switch entry.Kind {
				case "business_group":
					appendPersonnelCatalogOption(&preview.BusinessGroups, option)
				case "division":
					appendPersonnelCatalogOption(&preview.Divisions, option)
				case "department":
					appendPersonnelCatalogOption(&preview.Departments, option)
				}
			}
		}
		jobFamilies := make([]personnelCatalogEntry, 0, len(catalogs.JobFamilies))
		for _, entry := range catalogs.JobFamilies {
			if entry.Active {
				jobFamilies = append(jobFamilies, personnelCatalogEntry{ID: entry.ID, Code: entry.Code, Label: entry.Label})
				appendPersonnelCatalogOption(&preview.JobFamilies, PersonnelImportCatalogOption{ID: entry.ID, Code: entry.Code, Label: entry.Label})
			}
		}
		careerLevels := make([]personnelCatalogEntry, 0, len(catalogs.CareerLevels))
		for _, entry := range catalogs.CareerLevels {
			if entry.Active {
				careerLevels = append(careerLevels, personnelCatalogEntry{ID: entry.ID, Code: entry.Code, Label: entry.Label})
				appendPersonnelCatalogOption(&preview.CareerLevels, PersonnelImportCatalogOption{ID: entry.ID, Code: entry.Code, Label: entry.Label, Rank: entry.Rank})
			}
		}
		resolve("branch_code", &row.BranchCode, &row.BranchID, legalEntities, true)
		resolve("business_group_code", &row.BusinessGroupCode, &row.BusinessGroupID, orgUnits["business_group"], true)
		resolve("division_code", &row.DivisionCode, &row.DivisionID, orgUnits["division"], true)
		resolve("department_code", &row.DepartmentCode, &row.DepartmentID, orgUnits["department"], true)
		resolve("job_family_code", &row.JobFamilyCode, &row.JobFamilyID, jobFamilies, false)
		resolve("career_level_code", &row.CareerLevelCode, &row.CareerLevelID, careerLevels, false)
		if row.EducationLevel != "" && !hasIssue("education_level") {
			educationFound := false
			for _, level := range catalogs.EducationLevels {
				educationFound = educationFound || strings.EqualFold(level.Code, strings.TrimSpace(row.EducationLevel))
				if strings.EqualFold(level.Code, strings.TrimSpace(row.EducationLevel)) && row.EducationLevel != level.Code {
					row.EducationLevel = level.Code
					warning("education_level", "catalog_label_resolved")
				}
			}
			if !educationFound {
				issue("education_level", "unknown_education_level")
			}
		}
		if row.BusinessGroupID != "" && row.DivisionID != "" && row.DepartmentID != "" {
			divisionParent, departmentParent := false, false
			for _, relation := range catalogs.OrgUnitParents {
				if !relation.Active {
					continue
				}
				divisionParent = divisionParent || relation.ChildUnitID == row.DivisionID && relation.ParentUnitID == row.BusinessGroupID
				departmentParent = departmentParent || relation.ChildUnitID == row.DepartmentID && relation.ParentUnitID == row.DivisionID
			}
			if !divisionParent || !departmentParent {
				issue("department_code", "organization_hierarchy_mismatch")
			}
		}
	}
	return nil
}

func validatePersonnelReferences(preview *PersonnelImportPreview) {
	byCode := make(map[string][]int, len(preview.Rows))
	for index, row := range preview.Rows {
		if row.StaffCode != "" {
			byCode[row.StaffCode] = append(byCode[row.StaffCode], index)
		}
	}
	for _, indexes := range byCode {
		if len(indexes) < 2 {
			continue
		}
		for _, index := range indexes {
			preview.Errors = append(preview.Errors, personnelImportIssue(preview.Rows[index].RowNumber, "staff_code", "duplicate_staff_code"))
		}
	}

	selfReporting := map[int]bool{}
	for index, row := range preview.Rows {
		if row.ManagerStaffCode != "" && row.ManagerStaffCode == row.StaffCode {
			selfReporting[index] = true
			preview.Errors = append(preview.Errors, personnelImportIssue(row.RowNumber, "manager_staff_code", "manager_self_reference"))
		}
	}

	state := make([]uint8, len(preview.Rows))
	stack := make([]int, 0, len(preview.Rows))
	stackAt := make(map[int]int, len(preview.Rows))
	cycleRows := map[int]bool{}
	var visit func(int)
	visit = func(index int) {
		state[index] = 1
		stackAt[index] = len(stack)
		stack = append(stack, index)
		managerIndexes := byCode[preview.Rows[index].ManagerStaffCode]
		if len(managerIndexes) == 1 && !selfReporting[index] {
			manager := managerIndexes[0]
			if state[manager] == 0 {
				visit(manager)
			} else if state[manager] == 1 {
				for _, member := range stack[stackAt[manager]:] {
					cycleRows[member] = true
				}
			}
		}
		stack = stack[:len(stack)-1]
		delete(stackAt, index)
		state[index] = 2
	}
	for index := range preview.Rows {
		if state[index] == 0 {
			visit(index)
		}
	}
	for index := range cycleRows {
		preview.Errors = append(preview.Errors, personnelImportIssue(preview.Rows[index].RowNumber, "manager_staff_code", "manager_cycle"))
	}
}

// resolvePersonnelManagers checks every HOD Staff Code against the union of this batch's Staff Codes
// and the organization's existing Staff Codes. A manager listed on a later row, or in the database,
// is valid; a code in neither set blocks only the row that cites it. Rows keep their original numbers.
func (s *Service) resolvePersonnelManagers(ctx context.Context, org string, preview *PersonnelImportPreview) error {
	batch := make(map[string]struct{}, len(preview.Rows))
	for _, row := range preview.Rows {
		if row.StaffCode != "" {
			batch[row.StaffCode] = struct{}{}
		}
	}
	existing := map[string]bool{}
	for _, row := range preview.Rows {
		code := row.ManagerStaffCode
		if code == "" || previewHasIssue(preview, row.RowNumber, "manager_staff_code") {
			continue
		}
		if _, inBatch := batch[code]; inBatch {
			continue
		}
		found, checked := existing[code]
		if !checked {
			digest, keyID, version, err := s.staffCodeLookup(ctx, org, code)
			if err != nil {
				return err
			}
			found, err = s.Store.StaffCodeExists(ctx, org, keyID, version, digest)
			clear(digest)
			if err != nil {
				return err
			}
			existing[code] = found
		}
		if !found {
			preview.Errors = append(preview.Errors, personnelImportIssue(row.RowNumber, "manager_staff_code", "manager_not_found"))
		}
	}
	return nil
}

func previewHasIssue(preview *PersonnelImportPreview, rowNumber int, field string) bool {
	for _, existing := range preview.Errors {
		if existing.RowNumber == rowNumber && existing.Field == field {
			return true
		}
	}
	return false
}
