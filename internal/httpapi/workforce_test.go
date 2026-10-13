package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestAPIWorkforceCatalogsExposeFixedSeedsWithoutPIIPayloads(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID + "/workforce-catalogs"
			var catalogs organization.WorkforceCatalogs
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, path, "", ""), http.StatusOK, &catalogs)
			if catalogs.CatalogRevision != "1" || catalogs.GraphRevision != "1" {
				t.Fatalf("catalog revisions = %s/%s", catalogs.CatalogRevision, catalogs.GraphRevision)
			}
			if !reflect.DeepEqual(catalogs.Locations, []string{"Shanghai", "Tokyo", "Wuxi"}) || !reflect.DeepEqual(catalogs.EducationLevels, []organization.EducationLevelView{{Code: "Master", Rank: 3}, {Code: "Bachelor", Rank: 2}, {Code: "Diploma", Rank: 1}}) {
				t.Fatalf("fixed catalogs = locations %#v education %#v", catalogs.Locations, catalogs.EducationLevels)
			}
			if catalogs.LegalEntities == nil || catalogs.OrgUnits == nil || catalogs.JobFamilies == nil || catalogs.CareerLevels == nil {
				t.Fatal("empty catalogs encoded as null")
			}
			var filtered organization.WorkforceCatalogs
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, path+"?kind=education_level&as_of=2026-10-13&limit=2", "", ""), http.StatusOK, &filtered)
			if filtered.AsOf != "2026-10-13" || !reflect.DeepEqual(filtered.EducationLevels, []organization.EducationLevelView{{Code: "Master", Rank: 3}, {Code: "Bachelor", Rank: 2}}) ||
				len(filtered.Locations) != 0 || len(filtered.LegalEntities) != 0 || len(filtered.OrgUnits) != 0 || len(filtered.JobFamilies) != 0 || len(filtered.CareerLevels) != 0 {
				t.Fatalf("filtered catalog response = %#v", filtered)
			}
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, path+"?include_labels=1", "", ""), http.StatusUnprocessableEntity, nil)
		})
	}
}

func TestAPIWorkforceCatalogCreateReplaceEndIsAtomicAndReplaySafe(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			path := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
			body := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"job_family","code":"ENG","label":"Engineering","valid_from":"2026-01-01"}]}`
			key := value.NewID()
			var first, replay organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &first)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &replay)
			if !reflect.DeepEqual(first, replay) || first.CatalogRevision != "2" || first.GraphRevision != "1" || f.Count(t, "job_family") != 1 || f.Count(t, "job_family_version") != 1 {
				t.Fatalf("catalog create/replay = first %#v replay %#v", first, replay)
			}
			familyID := first.Items[0].ID
			replace := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","changes":[{"action":"replace","kind":"job_family","ref":%q,"label":"Product Engineering","effective_to":"2026-07-01"}]}`, familyID)
			var replaced organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, replace, value.NewID()), http.StatusCreated, &replaced)
			if replaced.CatalogRevision != "3" || replaced.GraphRevision != "1" || f.Count(t, "job_family_version") != 2 {
				t.Fatalf("catalog replacement = %#v", replaced)
			}
			var before, after organization.WorkforceCatalogs
			catalogPath := "/api/v1/orgs/" + f.OrgID + "/workforce-catalogs?kind=job_family&as_of="
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, catalogPath+"2026-06-30", "", ""), http.StatusOK, &before)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, catalogPath+"2026-07-01", "", ""), http.StatusOK, &after)
			if len(before.JobFamilies) != 1 || before.JobFamilies[0].Label != "Engineering" || len(after.JobFamilies) != 1 || after.JobFamilies[0].Label != "Product Engineering" {
				t.Fatalf("catalog effective replacement before=%#v after=%#v", before.JobFamilies, after.JobFamilies)
			}
			end := fmt.Sprintf(`{"expected_catalog_revision":"3","expected_graph_revision":"1","changes":[{"action":"end","kind":"job_family","ref":%q,"effective_to":"2027-01-01"}]}`, familyID)
			var ended organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, end, value.NewID()), http.StatusCreated, &ended)
			if ended.CatalogRevision != "4" || ended.GraphRevision != "1" {
				t.Fatalf("catalog end = %#v", ended)
			}
			var inactive organization.WorkforceCatalogs
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, catalogPath+"2027-01-01", "", ""), http.StatusOK, &inactive)
			if len(inactive.JobFamilies) != 0 {
				t.Fatalf("ended catalog remained active: %#v", inactive.JobFamilies)
			}
		})
	}
}

func TestAPIWorkforceHierarchyBuildsAcrossCatalogTransactions(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/teams", `{}`, value.NewID()), http.StatusNotFound, nil)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/structure-changes", `{}`, value.NewID()), http.StatusNotFound, nil)
			path := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
			create := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"business_group","code":"BG","label":"Business Group","valid_from":"2026-01-01"},{"action":"create","kind":"division","code":"DIV","label":"Division","valid_from":"2026-01-01"},{"action":"create","kind":"department","code":"DEP","label":"Department","valid_from":"2026-01-01"},{"action":"create","kind":"job_family","code":"ENG","label":"Engineering","valid_from":"2026-01-01"},{"action":"create","kind":"career_level","code":"L1","label":"Level 1","rank":1,"valid_from":"2026-01-01"},{"action":"create","kind":"legal_entity","code":"BR-SH","label":"Shanghai Branch","valid_from":"2026-01-01"}]}`
			var units organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, create, value.NewID()), http.StatusCreated, &units)
			if units.CatalogRevision != "2" || units.GraphRevision != "2" {
				t.Fatalf("unit creation = %#v", units)
			}
			parentDivision := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"2","changes":[{"action":"create","kind":"org_unit_parent","ref":%q,"parent_ref":%q,"valid_from":"2026-01-01"}]}`, units.Items[1].ID, units.Items[0].ID)
			var divisionEdge organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, parentDivision, value.NewID()), http.StatusCreated, &divisionEdge)
			parentDepartment := fmt.Sprintf(`{"expected_catalog_revision":"3","expected_graph_revision":"3","changes":[{"action":"create","kind":"org_unit_parent","ref":%q,"parent_ref":%q,"valid_from":"2026-01-01"}]}`, units.Items[2].ID, units.Items[1].ID)
			var departmentEdge organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, parentDepartment, value.NewID()), http.StatusCreated, &departmentEdge)
			if departmentEdge.CatalogRevision != "4" || departmentEdge.GraphRevision != "4" {
				t.Fatalf("department edge = %#v", departmentEdge)
			}
			var parents organization.WorkforceCatalogs
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/orgs/"+f.OrgID+"/workforce-catalogs?kind=org_unit_parent&as_of=2026-06-01", "", ""), http.StatusOK, &parents)
			if parents.CatalogRevision != "4" || parents.GraphRevision != "4" || len(parents.OrgUnitParents) != 2 {
				t.Fatalf("hierarchy projection = %#v", parents)
			}
			var employee, manager organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &manager)
			workforce := fmt.Sprintf(`{"expected_catalog_revision":"4","expected_graph_revision":"4","expected_employee_revisions":{%q:"1"},"changes":[{"action":"add","kind":"identifier","employee_id":%q,"staff_code":"0007","valid_from":"2026-10-11"},{"action":"add","kind":"employment","employee_id":%q,"legal_entity_id":%q,"employment_kind":"hire","location_code":"Shanghai","valid_from":"2026-10-11"},{"action":"add","kind":"education","employee_id":%q,"education_level":"Master","institution":"Synthetic University","field":"Engineering","award_date":"2025-07-01","valid_from":"2026-10-11"},{"action":"add","kind":"job_assignment","employee_id":%q,"department_id":%q,"job_family_id":%q,"career_level_id":%q,"position":{"title":"Engineer","position_code":"ENG-1"},"valid_from":"2026-10-11"},{"action":"add","kind":"reporting","employee_id":%q,"manager_employee_id":%q,"reporting_kind":"administrative","valid_from":"2026-10-11"}]}`, employee.ID, employee.ID, employee.ID, units.Items[5].ID, employee.ID, employee.ID, units.Items[2].ID, units.Items[3].ID, units.Items[4].ID, employee.ID, manager.ID)
			var assigned organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-changes", workforce, value.NewID()), http.StatusCreated, &assigned)
			if assigned.GraphRevision != "5" || assigned.EmployeeRevisions[employee.ID] != "2" || f.Count(t, "job_assignment") != 1 || f.Count(t, "reporting_line") != 1 {
				t.Fatalf("assignment/reporting write = %#v", assigned)
			}
			var detail organization.View
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/employees/"+employee.ID+"?as_of=2026-10-11&include_profile=true", "", ""), http.StatusOK, &detail)
			if len(detail.Identifiers) != 1 || detail.Identifiers[0].StaffCode != "0007" || len(detail.Employment) != 1 || detail.Employment[0].LocationCode != "Shanghai" || len(detail.Education) != 1 || detail.Education[0].Institution == nil || *detail.Education[0].Institution != "Synthetic University" || len(detail.JobAssignments) != 1 || detail.JobAssignments[0].Position == nil || detail.JobAssignments[0].Position.Title != "Engineer" || detail.DirectManager == nil || detail.HOD == nil || detail.DirectManager.ID != detail.HOD.ID {
				t.Fatalf("workforce detail projection = %#v", detail)
			}
			var metadata organization.View
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, "/api/v1/employees/"+employee.ID+"?as_of=2026-10-11&include_profile=true", "", ""), http.StatusOK, &metadata)
			if len(metadata.Identifiers) != 0 || len(metadata.Education) != 0 || metadata.JobAssignments[0].Position != nil || len(metadata.Employment) != 1 || metadata.DirectManager == nil {
				t.Fatalf("metadata detail leaked PII or hid workforce metadata = %#v", metadata)
			}
			var directory organization.DirectoryPage
			query := fmt.Sprintf(`{"as_of":"2026-10-11","department_id":%q,"q":"0007","include_profile":true,"limit":10}`, units.Items[2].ID)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees/query", query, ""), http.StatusOK, &directory)
			if len(directory.Items) != 1 || directory.Items[0].ID != employee.ID || directory.Items[0].Identifiers[0].StaffCode != "0007" {
				t.Fatalf("department/staff-code directory = %#v", directory)
			}
			var tree organization.TreeView
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/orgs/"+f.OrgID+"/tree?as_of=2026-10-11&depth=3&include_labels=true", "", ""), http.StatusOK, &tree)
			if len(tree.Nodes) != 3 || len(tree.Edges) != 2 || len(tree.Employees) != 1 || tree.Employees[0].DepartmentID != units.Items[2].ID || tree.Employees[0].Profile == nil {
				t.Fatalf("workforce organization tree = %#v", tree)
			}
			var history organization.HistoryPage
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodGet, "/api/v1/employees/"+employee.ID+"/organization-history?from=2026-10-01&to=2026-11-01&limit=10", "", ""), http.StatusOK, &history)
			if len(history.Items) != 1 || len(history.Items[0].Items) != 5 || history.Items[0].Items[0].EmployeeID != employee.ID {
				t.Fatalf("workforce history projection = %#v", history)
			}
		})
	}
}

func TestAPIAdministrativeReportingCycleRollsBackWholeCommand(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var first, second organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &first)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &second)
			body := fmt.Sprintf(`{"expected_catalog_revision":"1","expected_graph_revision":"1","expected_employee_revisions":{%q:"1",%q:"1"},"changes":[{"action":"add","kind":"reporting","employee_id":%q,"manager_employee_id":%q,"reporting_kind":"administrative","valid_from":"2026-10-11"},{"action":"add","kind":"reporting","employee_id":%q,"manager_employee_id":%q,"reporting_kind":"administrative","valid_from":"2026-10-11"}]}`, first.ID, second.ID, first.ID, second.ID, second.ID, first.ID)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-changes", body, value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "reporting_line") != 0 || f.Count(t, "structure_change") != 0 || f.Count(t, "workforce_command_receipt") != 0 {
				t.Fatal("cyclic reporting command persisted partial facts")
			}
		})
	}
}

func TestAPIWorkforceFactsCommitAtomicallyAndReplay(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)

			catalogPath := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
			catalogBody := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"legal_entity","code":"CN01","label":"China Branch","valid_from":"2026-01-01"}]}`
			var catalog organization.CatalogChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, catalogPath, catalogBody, value.NewID()), http.StatusCreated, &catalog)

			path := "/api/v1/orgs/" + f.OrgID + "/workforce-changes"
			body := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","expected_employee_revisions":{%q:"1"},"reason":"initial workforce facts","changes":[{"action":"add","kind":"identifier","employee_id":%q,"staff_code":"0007","valid_from":"2026-10-11"},{"action":"add","kind":"employment","employee_id":%q,"legal_entity_id":%q,"employment_kind":"hire","location_code":"Shanghai","valid_from":"2026-10-11"},{"action":"add","kind":"education","employee_id":%q,"education_level":"Master","institution":"Example University","field":"Engineering","award_date":"2024-06-30","valid_from":"2026-10-11"}]}`, employee.ID, employee.ID, employee.ID, catalog.Items[0].ID, employee.ID)
			key := value.NewID()
			var first, replay organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &first)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, body, key), http.StatusCreated, &replay)
			if !reflect.DeepEqual(first, replay) || first.CatalogRevision != "2" || first.GraphRevision != "1" || first.EmployeeRevisions[employee.ID] != "2" {
				t.Fatalf("workforce write/replay first=%#v replay=%#v", first, replay)
			}
			identifierID := first.Items[0].ID
			replace := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","expected_employee_revisions":{%q:"2"},"changes":[{"action":"replace","kind":"identifier","ref":%q,"employee_id":%q,"staff_code":"0008","valid_from":"2027-01-01","effective_to":"2027-01-01"}]}`, employee.ID, identifierID, employee.ID)
			var replaced organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, replace, value.NewID()), http.StatusCreated, &replaced)
			if replaced.EmployeeRevisions[employee.ID] != "3" {
				t.Fatalf("identifier replacement = %#v", replaced)
			}
			end := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","expected_employee_revisions":{%q:"3"},"changes":[{"action":"end","kind":"identifier","ref":%q,"employee_id":%q,"effective_to":"2028-01-01"}]}`, employee.ID, replaced.Items[0].ID, employee.ID)
			var ended organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, end, value.NewID()), http.StatusCreated, &ended)
			if ended.EmployeeRevisions[employee.ID] != "4" {
				t.Fatalf("identifier end = %#v", ended)
			}
			employmentID := first.Items[1].ID
			transfer := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","expected_employee_revisions":{%q:"4"},"changes":[{"action":"add","kind":"employment","employee_id":%q,"legal_entity_id":%q,"employment_kind":"transfer","location_code":"Wuxi","valid_from":"2027-02-01"},{"action":"end","kind":"employment","ref":%q,"employee_id":%q,"effective_to":"2027-02-01"}]}`, employee.ID, employee.ID, catalog.Items[0].ID, employmentID, employee.ID)
			var transferred organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, transfer, value.NewID()), http.StatusCreated, &transferred)
			if transferred.EmployeeRevisions[employee.ID] != "5" {
				t.Fatalf("employment transfer = %#v", transferred)
			}
			overlap := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"1","expected_employee_revisions":{%q:"5"},"changes":[{"action":"add","kind":"employment","employee_id":%q,"legal_entity_id":%q,"employment_kind":"transfer","location_code":"Tokyo","valid_from":"2027-03-01"}]}`, employee.ID, employee.ID, catalog.Items[0].ID)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, overlap, value.NewID()), http.StatusConflict, nil)
			for table, want := range map[string]int{"employee_business_identifier": 2, "employment_spell": 2, "education_record": 1, "workforce_payload": 4, "workforce_command_receipt": 5} {
				if got := f.Count(t, table); got != want {
					t.Fatalf("%s rows=%d want %d", table, got, want)
				}
			}
		})
	}
}

func TestAPIEmployeeLifecycleEndAppendsImmutableCorrection(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			query := "SELECT id FROM employee_lifecycle_history WHERE org_id=? AND employee_id=? AND supersedes_id IS NULL"
			if backend == "postgres" {
				query = "SELECT id FROM employee_lifecycle_history WHERE org_id=$1 AND employee_id=$2 AND supersedes_id IS NULL"
			}
			var lifecycleID string
			if err := f.Repo.DB.QueryRow(query, f.OrgID, employee.ID).Scan(&lifecycleID); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"expected_catalog_revision":"1","expected_graph_revision":"1","expected_employee_revisions":{%q:"1"},"changes":[{"action":"end","kind":"employee_lifecycle","ref":%q,"employee_id":%q,"effective_to":"2027-01-01"}]}`, employee.ID, lifecycleID, employee.ID)
			var result organization.WorkforceChangeResult
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-changes", body, value.NewID()), http.StatusCreated, &result)
			if result.GraphRevision != "2" || result.EmployeeRevisions[employee.ID] != "2" || result.Items[0].ID == lifecycleID || f.Count(t, "employee_lifecycle_history") != 2 {
				t.Fatalf("lifecycle end result = %#v", result)
			}
		})
	}
}

func TestAPIWorkforceChangeAuthorizesEveryEmployeeEndpoint(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var allowed, denied organization.Result
			createPath := "/api/v1/orgs/" + f.OrgID + "/employees"
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, createPath, createJSON, value.NewID()), http.StatusCreated, &allowed)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, createPath, createJSON, value.NewID()), http.StatusCreated, &denied)
			ctx := context.Background()
			if err := f.Exec(ctx, "DELETE FROM capability_assignment WHERE subject_id=?", "DELETE FROM capability_assignment WHERE subject_id=$1", f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			if err := f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE subject_id=?", "UPDATE access_grant SET revoked=true WHERE subject_id=$1", f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			for _, capability := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
				category := "pii"
				if capability == "organization.read" || capability == "organization.write" {
					category = "metadata"
				}
				if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES(?,?,?,'employee',?,?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES($1,$2,$3,'employee',$4,$5)", f.OrgID, f.Owner.SubjectID, capability, allowed.ID, allowed.ID); err != nil {
					t.Fatal(err)
				}
				if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,?,?,'employee',?,?,'organization_management',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,$4,$5,'employee',$6,$7,'organization_management',$8,$9,true)", value.NewID(), f.OrgID, f.Owner.SubjectID, capability, category, allowed.ID, allowed.ID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
					t.Fatal(err)
				}
			}
			path := "/api/v1/orgs/" + f.OrgID + "/workforce-changes"
			allowedBody := fmt.Sprintf(`{"expected_catalog_revision":"1","expected_graph_revision":"1","expected_employee_revisions":{%q:"1"},"changes":[{"action":"add","kind":"identifier","employee_id":%q,"staff_code":"SCOPE-1","valid_from":"2026-10-11"}]}`, allowed.ID, allowed.ID)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, allowedBody, value.NewID()), http.StatusCreated, nil)
			deniedBody := fmt.Sprintf(`{"expected_catalog_revision":"1","expected_graph_revision":"2","expected_employee_revisions":{%q:"1"},"changes":[{"action":"add","kind":"identifier","employee_id":%q,"staff_code":"SCOPE-2","valid_from":"2026-10-11"}]}`, denied.ID, denied.ID)
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, path, deniedBody, value.NewID()), http.StatusForbidden, nil)
		})
	}
}
