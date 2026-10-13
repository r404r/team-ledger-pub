package httpapi_test

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

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
			path := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
			create := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"business_group","code":"BG","label":"Business Group","valid_from":"2026-01-01"},{"action":"create","kind":"division","code":"DIV","label":"Division","valid_from":"2026-01-01"},{"action":"create","kind":"department","code":"DEP","label":"Department","valid_from":"2026-01-01"}]}`
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
			for table, want := range map[string]int{"employee_business_identifier": 2, "employment_spell": 1, "education_record": 1, "workforce_payload": 4, "workforce_command_receipt": 4} {
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
