package organization

import "testing"

const (
	workforceEmployee = "10000000-0000-4000-8000-000000000001"
	workforceManager  = "10000000-0000-4000-8000-000000000002"
	workforceEntity   = "10000000-0000-4000-8000-000000000003"
	workforceDept     = "10000000-0000-4000-8000-000000000004"
	workforceFamily   = "10000000-0000-4000-8000-000000000005"
	workforceLevel    = "10000000-0000-4000-8000-000000000006"
)

func workforceCommand(item WorkforceChangeItem) WorkforceChangeCommand {
	return WorkforceChangeCommand{
		ExpectedCatalogRevision:  "1",
		ExpectedGraphRevision:    "1",
		ExpectedEmployeeRevision: map[string]string{workforceEmployee: "1"},
		Changes:                  []WorkforceChangeItem{item},
	}
}

func TestWorkforceChangesAcceptOnlyFixedMasterDataShapes(t *testing.T) {
	date := "2026-10-13"
	staff := "001 AbC"
	location := LocationShanghai
	level := EducationMaster
	employmentKind := "hire"
	administrative := "administrative"
	for _, item := range []WorkforceChangeItem{
		{Action: "add", Kind: "identifier", EmployeeID: workforceEmployee, StaffCode: &staff, ValidFrom: &date},
		{Action: "add", Kind: "employment", EmployeeID: workforceEmployee, LegalEntityID: ptr(workforceEntity), LocationCode: &location, EmploymentKind: &employmentKind, ValidFrom: &date},
		{Action: "add", Kind: "education", EmployeeID: workforceEmployee, EducationLevel: &level, ValidFrom: &date},
		{Action: "add", Kind: "job_assignment", EmployeeID: workforceEmployee, DepartmentID: ptr(workforceDept), JobFamilyID: ptr(workforceFamily), CareerLevelID: ptr(workforceLevel), Position: &PositionPayload{Title: "Engineer"}, ValidFrom: &date},
		{Action: "add", Kind: "reporting", EmployeeID: workforceEmployee, ManagerEmployeeID: ptr(workforceManager), ReportingKind: &administrative, ValidFrom: &date},
	} {
		if !validWorkforceChange(workforceCommand(item)) {
			t.Fatalf("valid workforce change rejected: %#v", item)
		}
	}
}

func TestWorkforceChangesRejectHODSecondaryUnknownEmployeeAndPartialSets(t *testing.T) {
	date := "2026-10-13"
	for _, item := range []WorkforceChangeItem{
		{Action: "add", Kind: "hod", EmployeeID: workforceEmployee, ManagerEmployeeID: ptr(workforceManager), ValidFrom: &date},
		{Action: "add", Kind: "secondary_assignment", EmployeeID: workforceEmployee, ValidFrom: &date},
		{Action: "add", Kind: "reporting", EmployeeID: workforceEmployee, ManagerEmployeeID: ptr(workforceEmployee), ReportingKind: ptr("administrative"), ValidFrom: &date},
		{Action: "add", Kind: "employment", EmployeeID: workforceEmployee, LegalEntityID: ptr(workforceEntity), LocationCode: ptr("Osaka"), ValidFrom: &date},
	} {
		if validWorkforceChange(workforceCommand(item)) {
			t.Fatalf("forbidden workforce shape accepted: %#v", item)
		}
	}
	missingEmploymentKind := workforceCommand(WorkforceChangeItem{Action: "add", Kind: "employment", EmployeeID: workforceEmployee, LegalEntityID: ptr(workforceEntity), LocationCode: ptr(LocationShanghai), ValidFrom: &date})
	if validWorkforceChange(missingEmploymentKind) {
		t.Fatal("employment without typed hire/rehire/transfer kind accepted")
	}
	endWithPayload := workforceCommand(WorkforceChangeItem{Action: "end", Kind: "education", EmployeeID: workforceEmployee, Ref: ptr(workforceEntity), EffectiveTo: &date, EducationLevel: ptr(EducationMaster)})
	if validWorkforceChange(endWithPayload) {
		t.Fatal("end command with replacement payload accepted")
	}
	unknown := workforceCommand(WorkforceChangeItem{Action: "add", Kind: "education", EmployeeID: workforceManager, EducationLevel: ptr(EducationMaster), ValidFrom: &date})
	if validWorkforceChange(unknown) {
		t.Fatal("change without expected employee revision accepted")
	}
	extra := workforceCommand(WorkforceChangeItem{Action: "add", Kind: "education", EmployeeID: workforceEmployee, EducationLevel: ptr(EducationMaster), ValidFrom: &date})
	extra.ExpectedEmployeeRevision[workforceManager] = "1"
	if validWorkforceChange(extra) {
		t.Fatal("change with an unrelated employee revision accepted")
	}
	empty := workforceCommand(WorkforceChangeItem{})
	empty.Changes = nil
	if validWorkforceChange(empty) {
		t.Fatal("empty atomic change set accepted")
	}
}

func TestCatalogChangesRequireCASBoundedTypedItems(t *testing.T) {
	date := "2026-10-13"
	code, label := "BG-01", "Business Group 01"
	valid := CatalogChangeCommand{ExpectedCatalogRevision: "1", ExpectedGraphRevision: "1", Changes: []CatalogChangeItem{{Action: "create", Kind: "business_group", Code: &code, Label: &label, ValidFrom: &date}}}
	if !validCatalogChange(valid) {
		t.Fatal("valid catalog create rejected")
	}
	valid.Changes[0].Kind = "team"
	if validCatalogChange(valid) {
		t.Fatal("fourth-level team catalog accepted")
	}
	valid.Changes = make([]CatalogChangeItem, maxWorkforceChanges+1)
	if validCatalogChange(valid) {
		t.Fatal("oversized catalog command accepted")
	}
}

func ptr[T any](value T) *T { return &value }
