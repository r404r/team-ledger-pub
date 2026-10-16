package organization

import (
	"context"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/xlsx"
)

const (
	personnelWorkbookCompressed = 5 << 20
	personnelWorkbookExpanded   = 20 << 20
	personnelWorkbookEntries    = 1_000
	personnelWorkbookRows       = 100
)

var personnelImportHeaders = []string{
	"staff_code",
	"local_name",
	"english_name",
	"email",
	"phone",
	"profile_summary",
	"manager_staff_code",
	"hire_date",
	"departure_date",
}

type PersonnelImportRow struct {
	RowNumber        int     `json:"row_number"`
	StaffCode        string  `json:"staff_code"`
	LocalName        string  `json:"local_name,omitempty"`
	EnglishName      string  `json:"english_name,omitempty"`
	Email            string  `json:"email,omitempty"`
	Phone            string  `json:"phone,omitempty"`
	ProfileSummary   string  `json:"profile_summary,omitempty"`
	ManagerStaffCode string  `json:"manager_staff_code,omitempty"`
	HireDate         string  `json:"hire_date"`
	DepartureDate    *string `json:"departure_date"`
}

type PersonnelImportIssue struct {
	RowNumber int    `json:"row_number"`
	Field     string `json:"field"`
	Code      string `json:"code"`
}

type PersonnelImportPreview struct {
	Rows     []PersonnelImportRow   `json:"rows"`
	Errors   []PersonnelImportIssue `json:"errors"`
	RowCount int                    `json:"row_count"`
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
		return PersonnelImportPreview{}, fault.Invalid
	}
	return preview, nil
}

func parsePersonnelWorkbook(raw []byte) (PersonnelImportPreview, error) {
	rows, err := xlsx.ReadFirstSheet(raw, xlsx.Limits{
		CompressedBytes: personnelWorkbookCompressed,
		ExpandedBytes:   personnelWorkbookExpanded,
		Entries:         personnelWorkbookEntries,
	})
	if err != nil || len(rows) == 0 || rows[0].Number != 1 {
		return PersonnelImportPreview{}, fault.Invalid
	}
	if err := validatePersonnelHeaders(rows[0]); err != nil {
		return PersonnelImportPreview{}, err
	}
	preview := PersonnelImportPreview{Rows: []PersonnelImportRow{}, Errors: []PersonnelImportIssue{}}
	for _, source := range rows[1:] {
		if rowEmpty(source) {
			continue
		}
		if len(preview.Rows) >= personnelWorkbookRows {
			return PersonnelImportPreview{}, fault.Invalid
		}
		row := PersonnelImportRow{
			RowNumber:        source.Number,
			StaffCode:        textCell(source, 1),
			LocalName:        textCell(source, 2),
			EnglishName:      textCell(source, 3),
			Email:            textCell(source, 4),
			Phone:            textCell(source, 5),
			ProfileSummary:   textCell(source, 6),
			ManagerStaffCode: textCell(source, 7),
			HireDate:         textCell(source, 8),
		}
		if departure := textCell(source, 9); departure != "" {
			row.DepartureDate = &departure
		}
		preview.Rows = append(preview.Rows, row)
		validatePersonnelRow(source, &preview, len(preview.Rows)-1)
	}
	if len(preview.Rows) == 0 {
		return PersonnelImportPreview{}, fault.Invalid
	}
	validatePersonnelReferences(&preview)
	preview.RowCount = len(preview.Rows)
	return preview, nil
}

func validatePersonnelHeaders(row xlsx.Row) error {
	for column, header := range personnelImportHeaders {
		cell, ok := row.Cells[column+1]
		if !ok || !cell.IsText || cell.Text != header {
			return fault.Invalid
		}
	}
	for column, cell := range row.Cells {
		if column > len(personnelImportHeaders) && cell.Text != "" {
			return fault.Invalid
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

func textCell(row xlsx.Row, column int) string {
	cell, ok := row.Cells[column]
	if !ok || !cell.IsText {
		return ""
	}
	return cell.Text
}

func validatePersonnelRow(source xlsx.Row, preview *PersonnelImportPreview, index int) {
	row := &preview.Rows[index]
	issue := func(field, code string) {
		preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: row.RowNumber, Field: field, Code: code})
	}
	for column, cell := range source.Cells {
		if column > len(personnelImportHeaders) && cell.Text != "" {
			issue("workbook", "unexpected_column")
		}
		if column <= len(personnelImportHeaders) && cell.Text != "" && !cell.IsText {
			issue(personnelImportHeaders[column-1], "text_required")
		}
	}
	if normalized, ok := NormalizeStaffCode(row.StaffCode); !ok {
		issue("staff_code", "invalid_staff_code")
	} else {
		row.StaffCode = normalized
	}
	profile := Profile{LocalName: row.LocalName, EnglishName: row.EnglishName, ProfileSummary: row.ProfileSummary}
	if row.Email != "" || row.Phone != "" {
		profile.WorkContact = &Contact{Email: row.Email, Phone: row.Phone}
	}
	if !validProfile(profile) {
		issue("profile", "invalid_profile")
	}
	lifecycle := Lifecycle{ValidFrom: row.HireDate, ValidTo: row.DepartureDate}
	if !validLifecycle(lifecycle) {
		issue("hire_date", "invalid_employment_dates")
	}
	if row.ManagerStaffCode != "" {
		if normalized, ok := NormalizeStaffCode(row.ManagerStaffCode); !ok {
			issue("manager_staff_code", "invalid_staff_code")
		} else {
			row.ManagerStaffCode = normalized
		}
	}
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
			preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: preview.Rows[index].RowNumber, Field: "staff_code", Code: "duplicate_staff_code"})
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
		if len(managerIndexes) == 1 {
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
		preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: preview.Rows[index].RowNumber, Field: "manager_staff_code", Code: "manager_cycle"})
	}
}
