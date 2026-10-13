package organization

import (
	"strings"
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
		return item.Ref != nil && item.EffectiveTo != nil && item.ValidFrom == nil
	}
	if item.ValidFrom == nil || item.EffectiveTo != nil || item.Action == "add" && item.Ref != nil || item.Action == "replace" && item.Ref == nil {
		return false
	}
	switch item.Kind {
	case "identifier":
		if item.StaffCode == nil {
			return false
		}
		_, ok := NormalizeStaffCode(*item.StaffCode)
		return ok
	case "employment":
		return item.LegalEntityID != nil && value.ValidID(*item.LegalEntityID) && item.LocationCode != nil && validLocation(*item.LocationCode)
	case "education":
		return item.EducationLevel != nil && validEducationLevel(*item.EducationLevel)
	case "job_assignment":
		return validIDPointer(item.DepartmentID) && validIDPointer(item.JobFamilyID) && validIDPointer(item.CareerLevelID) && item.Position != nil
	case "reporting":
		return validIDPointer(item.ManagerEmployeeID) && item.ManagerEmployeeID != nil && *item.ManagerEmployeeID != item.EmployeeID && item.ReportingKind != nil && oneOf(*item.ReportingKind, "administrative", "dotted")
	case "employee_lifecycle":
		return true
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
