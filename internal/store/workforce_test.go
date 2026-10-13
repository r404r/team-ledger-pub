package store_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestWorkforceCatalogsReturnFixedSeedsAndSafeEmptyCollections(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			catalogs, err := f.Repo.WorkforceCatalogs(context.Background(), f.OrgID)
			if err != nil {
				t.Fatal(err)
			}
			if catalogs.CatalogRevision != "1" || catalogs.GraphRevision != "1" {
				t.Fatalf("catalog revisions = %s/%s", catalogs.CatalogRevision, catalogs.GraphRevision)
			}
			if !reflect.DeepEqual(catalogs.Locations, []string{"Shanghai", "Tokyo", "Wuxi"}) || !reflect.DeepEqual(catalogs.EducationLevels, []string{"Bachelor", "Diploma", "Master"}) {
				t.Fatalf("fixed catalogs = locations %#v education %#v", catalogs.Locations, catalogs.EducationLevels)
			}
			if catalogs.LegalEntities == nil || catalogs.OrgUnits == nil || catalogs.JobFamilies == nil || catalogs.CareerLevels == nil {
				t.Fatal("empty mutable catalogs must encode as arrays, not null")
			}
		})
	}
}
