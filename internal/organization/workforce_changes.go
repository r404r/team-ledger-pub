package organization

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/value"
)

const maxWorkforceChanges = 100

type CatalogChangeCommand struct {
	ExpectedCatalogRevision string              `json:"expected_catalog_revision"`
	ExpectedGraphRevision   string              `json:"expected_graph_revision"`
	Changes                 []CatalogChangeItem `json:"changes"`
}

type CatalogChangeItem struct {
	Action      string  `json:"action"`
	Kind        string  `json:"kind"`
	Ref         *string `json:"ref,omitempty"`
	Code        *string `json:"code,omitempty"`
	Label       *string `json:"label,omitempty"`
	Rank        *int    `json:"rank,omitempty"`
	ParentRef   *string `json:"parent_ref,omitempty"`
	ValidFrom   *string `json:"valid_from,omitempty"`
	ValidTo     *string `json:"valid_to,omitempty"`
	EffectiveTo *string `json:"effective_to,omitempty"`
}

type WorkforceChangeCommand struct {
	ExpectedCatalogRevision  string                `json:"expected_catalog_revision"`
	ExpectedGraphRevision    string                `json:"expected_graph_revision"`
	ExpectedEmployeeRevision map[string]string     `json:"expected_employee_revisions"`
	Reason                   *string               `json:"reason,omitempty"`
	Changes                  []WorkforceChangeItem `json:"changes"`
}

type WorkforceChangeItem struct {
	Action            string           `json:"action"`
	Kind              string           `json:"kind"`
	Ref               *string          `json:"ref,omitempty"`
	EmployeeID        string           `json:"employee_id"`
	StaffCode         *string          `json:"staff_code,omitempty"`
	LegalEntityID     *string          `json:"legal_entity_id,omitempty"`
	EmploymentKind    *string          `json:"employment_kind,omitempty"`
	LocationCode      *string          `json:"location_code,omitempty"`
	EducationLevel    *string          `json:"education_level,omitempty"`
	Institution       *string          `json:"institution,omitempty"`
	Field             *string          `json:"field,omitempty"`
	AwardDate         *string          `json:"award_date,omitempty"`
	DepartmentID      *string          `json:"department_id,omitempty"`
	JobFamilyID       *string          `json:"job_family_id,omitempty"`
	CareerLevelID     *string          `json:"career_level_id,omitempty"`
	Position          *PositionPayload `json:"position,omitempty"`
	ManagerEmployeeID *string          `json:"manager_employee_id,omitempty"`
	ReportingKind     *string          `json:"reporting_kind,omitempty"`
	ValidFrom         *string          `json:"valid_from,omitempty"`
	ValidTo           *string          `json:"valid_to,omitempty"`
	EffectiveTo       *string          `json:"effective_to,omitempty"`
}

type CatalogChangeItemResult struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	VersionID string `json:"version_id,omitempty"`
}

type CatalogChangeResult struct {
	ID              string                    `json:"id"`
	CatalogRevision string                    `json:"catalog_revision"`
	GraphRevision   string                    `json:"graph_revision"`
	Items           []CatalogChangeItemResult `json:"items"`
}

type CatalogPreparedItem struct {
	Command   CatalogChangeItem
	ID        string
	VersionID string
	Payload   *WorkforcePayload
}

type CatalogWrite struct {
	ID, OrgID, SubjectID string
	RecordedAt           time.Time
	Items                []CatalogPreparedItem
}

type WorkforceCommandReceipt struct {
	Digest []byte
	Result CatalogChangeResult
}

func validCatalogChange(command CatalogChangeCommand) bool {
	if !validExpectedRevision(command.ExpectedCatalogRevision) || !validExpectedRevision(command.ExpectedGraphRevision) || len(command.Changes) < 1 || len(command.Changes) > maxWorkforceChanges {
		return false
	}
	for _, item := range command.Changes {
		if !validCatalogChangeItem(item) {
			return false
		}
	}
	return true
}

func validCatalogChangeItem(item CatalogChangeItem) bool {
	if !oneOf(item.Action, "create", "end", "replace") || !oneOf(item.Kind, "legal_entity", "business_group", "division", "department", "org_unit_parent", "job_family", "career_level") {
		return false
	}
	if item.Ref != nil && !value.ValidID(*item.Ref) || item.ParentRef != nil && !value.ValidID(*item.ParentRef) {
		return false
	}
	if item.ValidFrom != nil && !value.ValidDate(*item.ValidFrom) || item.ValidTo != nil && !value.ValidDate(*item.ValidTo) || item.EffectiveTo != nil && !value.ValidDate(*item.EffectiveTo) {
		return false
	}
	if item.Label != nil && (!utf8.ValidString(*item.Label) || strings.TrimSpace(*item.Label) == "" || len(*item.Label) > 256) {
		return false
	}
	if item.Code != nil && (!utf8.ValidString(*item.Code) || strings.TrimSpace(*item.Code) == "" || len(*item.Code) > 64) {
		return false
	}
	if item.Rank != nil && *item.Rank < 1 {
		return false
	}
	switch item.Action {
	case "create":
		if item.ValidFrom == nil || item.EffectiveTo != nil {
			return false
		}
		if item.Kind == "org_unit_parent" {
			return validIDPointer(item.Ref) && validIDPointer(item.ParentRef) && item.Code == nil && item.Label == nil && item.Rank == nil
		}
		if item.Ref != nil || item.Code == nil || item.Label == nil || item.ParentRef != nil {
			return false
		}
		return item.Kind != "career_level" && item.Rank == nil || item.Kind == "career_level" && item.Rank != nil
	case "end":
		return item.Ref != nil && item.EffectiveTo != nil && item.Code == nil && item.Label == nil && item.Rank == nil && item.ParentRef == nil && item.ValidFrom == nil
	case "replace":
		if item.Ref == nil || item.EffectiveTo == nil || item.Code != nil || item.ValidFrom != nil {
			return false
		}
		if item.Kind == "org_unit_parent" {
			return validIDPointer(item.ParentRef) && item.Label == nil && item.Rank == nil
		}
		if item.Label == nil || item.ParentRef != nil {
			return false
		}
		return item.Kind != "career_level" && item.Rank == nil || item.Kind == "career_level" && item.Rank != nil
	}
	return false
}

func validWorkforceChange(command WorkforceChangeCommand) bool {
	if !validExpectedRevision(command.ExpectedCatalogRevision) || !validExpectedRevision(command.ExpectedGraphRevision) || len(command.ExpectedEmployeeRevision) == 0 || len(command.Changes) < 1 || len(command.Changes) > maxWorkforceChanges {
		return false
	}
	if command.Reason != nil && (!utf8.ValidString(*command.Reason) || strings.TrimSpace(*command.Reason) == "" || len(*command.Reason) > 4096) {
		return false
	}
	for employee, revision := range command.ExpectedEmployeeRevision {
		if !value.ValidID(employee) || !validExpectedRevision(revision) {
			return false
		}
	}
	for _, item := range command.Changes {
		if !validWorkforceChangeItem(item) {
			return false
		}
		if _, ok := command.ExpectedEmployeeRevision[item.EmployeeID]; !ok {
			return false
		}
	}
	return true
}

func validWorkforceChangeItem(item WorkforceChangeItem) bool {
	if !value.ValidID(item.EmployeeID) || !oneOf(item.Action, "add", "end", "replace") || !oneOf(item.Kind, "identifier", "employment", "education", "job_assignment", "reporting", "employee_lifecycle") {
		return false
	}
	if item.Ref != nil && !value.ValidID(*item.Ref) || item.ValidFrom != nil && !value.ValidDate(*item.ValidFrom) || item.ValidTo != nil && !value.ValidDate(*item.ValidTo) || item.EffectiveTo != nil && !value.ValidDate(*item.EffectiveTo) {
		return false
	}
	if item.Action == "end" {
		return item.Ref != nil && item.EffectiveTo != nil && item.ValidFrom == nil && item.ValidTo == nil && noWorkforcePayload(item)
	}
	if item.ValidFrom == nil || item.EffectiveTo != nil || item.Action == "add" && item.Ref != nil || item.Action == "replace" && item.Ref == nil {
		return false
	}
	switch item.Kind {
	case "identifier":
		if item.StaffCode == nil || !onlyWorkforceFields(item, "identifier") {
			return false
		}
		_, ok := NormalizeStaffCode(*item.StaffCode)
		return ok
	case "employment":
		return validIDPointer(item.LegalEntityID) && item.LocationCode != nil && validLocation(*item.LocationCode) &&
			item.EmploymentKind != nil && oneOf(*item.EmploymentKind, "hire", "rehire", "transfer") && onlyWorkforceFields(item, "employment")
	case "education":
		return item.EducationLevel != nil && validEducationLevel(*item.EducationLevel) &&
			textValid(item.Institution, 256, false) && textValid(item.Field, 256, false) &&
			(item.AwardDate == nil || value.ValidDate(*item.AwardDate)) && onlyWorkforceFields(item, "education")
	case "job_assignment":
		return validIDPointer(item.DepartmentID) && (item.JobFamilyID == nil || value.ValidID(*item.JobFamilyID)) &&
			(item.CareerLevelID == nil || value.ValidID(*item.CareerLevelID)) && (item.Position == nil || positionValid(*item.Position)) &&
			onlyWorkforceFields(item, "job_assignment")
	case "reporting":
		return validIDPointer(item.ManagerEmployeeID) && *item.ManagerEmployeeID != item.EmployeeID &&
			item.ReportingKind != nil && oneOf(*item.ReportingKind, "administrative", "dotted") && onlyWorkforceFields(item, "reporting")
	case "employee_lifecycle":
		return onlyWorkforceFields(item, "employee_lifecycle")
	}
	return false
}

func noWorkforcePayload(item WorkforceChangeItem) bool {
	return item.StaffCode == nil && item.EmploymentKind == nil && item.LegalEntityID == nil && item.LocationCode == nil &&
		item.EducationLevel == nil && item.Institution == nil && item.Field == nil && item.AwardDate == nil &&
		item.DepartmentID == nil && item.JobFamilyID == nil && item.CareerLevelID == nil && item.Position == nil &&
		item.ManagerEmployeeID == nil && item.ReportingKind == nil
}

func onlyWorkforceFields(item WorkforceChangeItem, kind string) bool {
	switch kind {
	case "identifier":
		return item.EmploymentKind == nil && item.LegalEntityID == nil && item.LocationCode == nil && item.EducationLevel == nil && item.Institution == nil && item.Field == nil && item.AwardDate == nil && item.DepartmentID == nil && item.JobFamilyID == nil && item.CareerLevelID == nil && item.Position == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil
	case "employment":
		return item.StaffCode == nil && item.EducationLevel == nil && item.Institution == nil && item.Field == nil && item.AwardDate == nil && item.DepartmentID == nil && item.JobFamilyID == nil && item.CareerLevelID == nil && item.Position == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil
	case "education":
		return item.StaffCode == nil && item.EmploymentKind == nil && item.LegalEntityID == nil && item.LocationCode == nil && item.DepartmentID == nil && item.JobFamilyID == nil && item.CareerLevelID == nil && item.Position == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil
	case "job_assignment":
		return item.StaffCode == nil && item.EmploymentKind == nil && item.LegalEntityID == nil && item.LocationCode == nil && item.EducationLevel == nil && item.Institution == nil && item.Field == nil && item.AwardDate == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil
	case "reporting":
		return item.StaffCode == nil && item.EmploymentKind == nil && item.LegalEntityID == nil && item.LocationCode == nil && item.EducationLevel == nil && item.Institution == nil && item.Field == nil && item.AwardDate == nil && item.DepartmentID == nil && item.JobFamilyID == nil && item.CareerLevelID == nil && item.Position == nil
	case "employee_lifecycle":
		return noWorkforcePayload(item)
	}
	return false
}

func validExpectedRevision(revision string) bool {
	_, ok := value.Revision(revision)
	return ok
}

func validIDPointer(id *string) bool { return id != nil && value.ValidID(*id) }

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
