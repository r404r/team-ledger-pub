package organization

import (
	"context"
	"strings"

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

var personnelImportFieldLimits = []int{64, 256, 256, 16, 64, 64, 64, 64, 16, 10, 1024, 32, 32, 64, 10, 320, 64, 16 << 10}

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
	Field     string `json:"field"`
	Code      string `json:"code"`
}

type PersonnelImportPreview struct {
	Rows            []PersonnelImportRow   `json:"rows"`
	Errors          []PersonnelImportIssue `json:"errors"`
	RowCount        int                    `json:"row_count"`
	CatalogRevision string                 `json:"catalog_revision,omitempty"`
	GraphRevision   string                 `json:"graph_revision,omitempty"`
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
	if err = s.resolvePersonnelImportCatalogs(ctx, org, &preview); err != nil {
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
		values := make([]string, len(personnelImportHeaders))
		for column, limit := range personnelImportFieldLimits {
			cell, ok := source.Cells[column+1]
			if !ok || !cell.IsText {
				continue
			}
			if len(cell.Text) > limit {
				preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: source.Number, Field: personnelImportFields[column], Code: "field_too_large"})
				continue
			}
			values[column] = cell.Text
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
			issue(personnelImportFields[column-1], "text_required")
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
	if !validLocation(row.Location) {
		issue("location", "invalid_location")
	}
	if !validEducationLevel(row.EducationLevel) {
		issue("education_level", "invalid_education_level")
	}
	if !positionValid(PositionPayload{Title: row.Position}) {
		issue("position", "invalid_position")
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"branch_code", row.BranchCode, 64},
		{"business_group_code", row.BusinessGroupCode, 64},
		{"division_code", row.DivisionCode, 64},
		{"department_code", row.DepartmentCode, 64},
		{"job_family_code", row.JobFamilyCode, 32},
		{"career_level_code", row.CareerLevelCode, 32},
	} {
		if field.value == "" || strings.TrimSpace(field.value) != field.value || len(field.value) > field.limit {
			issue(field.name, "invalid_catalog_code")
		}
	}
	if row.ManagerStaffCode != "" {
		if normalized, ok := NormalizeStaffCode(row.ManagerStaffCode); !ok {
			issue("manager_staff_code", "invalid_staff_code")
		} else {
			row.ManagerStaffCode = normalized
		}
	}
}

func (s *Service) resolvePersonnelImportCatalogs(ctx context.Context, org string, preview *PersonnelImportPreview) error {
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
			catalogsByDate[row.HireDate] = catalogs
		}
		if preview.CatalogRevision == "" {
			preview.CatalogRevision, preview.GraphRevision = catalogs.CatalogRevision, catalogs.GraphRevision
		} else if preview.CatalogRevision != catalogs.CatalogRevision || preview.GraphRevision != catalogs.GraphRevision {
			return fault.Conflict
		}
		issue := func(field, code string) {
			preview.Errors = append(preview.Errors, PersonnelImportIssue{RowNumber: row.RowNumber, Field: field, Code: code})
		}
		for _, entry := range catalogs.LegalEntities {
			if entry.Active && entry.Code == row.BranchCode {
				if row.BranchID != "" {
					row.BranchID = ""
					break
				}
				row.BranchID = entry.ID
			}
		}
		for _, entry := range catalogs.OrgUnits {
			if !entry.Active {
				continue
			}
			switch {
			case entry.Kind == "business_group" && entry.Code == row.BusinessGroupCode:
				if row.BusinessGroupID != "" {
					row.BusinessGroupID = ""
				} else {
					row.BusinessGroupID = entry.ID
				}
			case entry.Kind == "division" && entry.Code == row.DivisionCode:
				if row.DivisionID != "" {
					row.DivisionID = ""
				} else {
					row.DivisionID = entry.ID
				}
			case entry.Kind == "department" && entry.Code == row.DepartmentCode:
				if row.DepartmentID != "" {
					row.DepartmentID = ""
				} else {
					row.DepartmentID = entry.ID
				}
			}
		}
		for _, entry := range catalogs.JobFamilies {
			if entry.Active && entry.Code == row.JobFamilyCode {
				if row.JobFamilyID != "" {
					row.JobFamilyID = ""
					break
				}
				row.JobFamilyID = entry.ID
			}
		}
		for _, entry := range catalogs.CareerLevels {
			if entry.Active && entry.Code == row.CareerLevelCode {
				if row.CareerLevelID != "" {
					row.CareerLevelID = ""
					break
				}
				row.CareerLevelID = entry.ID
			}
		}
		for _, resolved := range []struct {
			field string
			id    string
		}{
			{"branch_code", row.BranchID},
			{"business_group_code", row.BusinessGroupID},
			{"division_code", row.DivisionID},
			{"department_code", row.DepartmentID},
			{"job_family_code", row.JobFamilyID},
			{"career_level_code", row.CareerLevelID},
		} {
			if resolved.id == "" {
				issue(resolved.field, "unknown_catalog_code")
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
