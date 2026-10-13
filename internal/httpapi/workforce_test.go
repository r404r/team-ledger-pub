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
