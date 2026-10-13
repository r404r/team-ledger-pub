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
			if !reflect.DeepEqual(catalogs.Locations, []string{"Shanghai", "Tokyo", "Wuxi"}) || !reflect.DeepEqual(catalogs.EducationLevels, []string{"Bachelor", "Diploma", "Master"}) {
				t.Fatalf("fixed catalogs = locations %#v education %#v", catalogs.Locations, catalogs.EducationLevels)
			}
			if catalogs.LegalEntities == nil || catalogs.OrgUnits == nil || catalogs.JobFamilies == nil || catalogs.CareerLevels == nil {
				t.Fatal("empty catalogs encoded as null")
			}
			apiSend(t, f, apiRequest(t, f, f.Observer, http.MethodGet, path+"?include_labels=1", "", ""), http.StatusUnprocessableEntity, nil)
		})
	}
}
