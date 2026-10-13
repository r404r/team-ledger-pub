package httpapi_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
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
