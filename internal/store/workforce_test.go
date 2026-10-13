package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestWorkforceCatalogsReturnFixedSeedsAndSafeEmptyCollections(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			catalogs, err := f.Repo.WorkforceCatalogs(context.Background(), f.OrgID, "2026-10-13")
			if err != nil {
				t.Fatal(err)
			}
			if catalogs.CatalogRevision != "1" || catalogs.GraphRevision != "1" {
				t.Fatalf("catalog revisions = %s/%s", catalogs.CatalogRevision, catalogs.GraphRevision)
			}
			if !reflect.DeepEqual(catalogs.Locations, []string{"Shanghai", "Tokyo", "Wuxi"}) || !reflect.DeepEqual(catalogs.EducationLevels, []organization.EducationLevelView{{Code: "Master", Rank: 3}, {Code: "Bachelor", Rank: 2}, {Code: "Diploma", Rank: 1}}) {
				t.Fatalf("fixed catalogs = locations %#v education %#v", catalogs.Locations, catalogs.EducationLevels)
			}
			if catalogs.LegalEntities == nil || catalogs.OrgUnits == nil || catalogs.JobFamilies == nil || catalogs.CareerLevels == nil {
				t.Fatal("empty mutable catalogs must encode as arrays, not null")
			}
		})
	}
}

func TestWorkforceCatalogProjectionUsesHalfOpenVersionWindow(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			entityID, versionID, payloadID := value.NewID(), value.NewID(), value.NewID()
			if _, err := f.Repo.DB.ExecContext(ctx, statement(backend,
				"INSERT INTO legal_entity(org_id,id,code,kind) VALUES(?,?,?,'branch_company')",
				"INSERT INTO legal_entity(org_id,id,code,kind) VALUES($1,$2,$3,'branch_company')"),
				f.OrgID, entityID, "SYNTHETIC-BRANCH"); err != nil {
				t.Fatal(err)
			}
			payloadArgs := []any{f.OrgID, payloadID, "legal_entity", entityID, entityID, payloadID, "pii", "pii.legal_entity_label.v1", 1, 1, "A256GCM-RANDOMNONCE", value.NewID(), "synthetic-kek", 1, []byte{1}, make([]byte, 28)}
			if _, err := f.Repo.DB.ExecContext(ctx, statement(backend,
				"INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,1)",
				"INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,NULL,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,now())"),
				payloadArgs...); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Repo.DB.ExecContext(ctx, statement(backend,
				"INSERT INTO legal_entity_version(org_id,id,legal_entity_id,label_payload_id,valid_from,valid_to,revision) VALUES(?,?,?,?,?,?,1)",
				"INSERT INTO legal_entity_version(org_id,id,legal_entity_id,label_payload_id,valid_from,valid_to,revision) VALUES($1,$2,$3,$4,$5,$6,1)"),
				f.OrgID, versionID, entityID, payloadID, "2026-01-01", "2027-01-01"); err != nil {
				t.Fatal(err)
			}
			before, err := f.Repo.WorkforceCatalogs(ctx, f.OrgID, "2025-12-31")
			if err != nil {
				t.Fatal(err)
			}
			during, err := f.Repo.WorkforceCatalogs(ctx, f.OrgID, "2026-12-31")
			if err != nil {
				t.Fatal(err)
			}
			after, err := f.Repo.WorkforceCatalogs(ctx, f.OrgID, "2027-01-01")
			if err != nil {
				t.Fatal(err)
			}
			if len(before.LegalEntities) != 0 || len(during.LegalEntities) != 1 || during.LegalEntities[0].ID != entityID || len(after.LegalEntities) != 0 {
				t.Fatalf("half-open projection before/during/after = %d/%#v/%d", len(before.LegalEntities), during.LegalEntities, len(after.LegalEntities))
			}
		})
	}
}

func statement(backend, sqlite, postgres string) string {
	if backend == "postgres" {
		return postgres
	}
	return sqlite
}

func TestCatalogCreateTransactionAdvancesOnlyCatalogRevision(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			code, label, from := "SYNTHETIC-ENGINEERING", "Synthetic Engineering", "2026-01-01"
			write := organization.CatalogWrite{
				ID: value.NewID(), OrgID: f.OrgID, SubjectID: f.Owner.SubjectID, RecordedAt: f.Now,
				Items: []organization.CatalogPreparedItem{{Command: organization.CatalogChangeItem{Action: "create", Kind: "job_family", Code: &code, Label: &label, ValidFrom: &from}, ID: value.NewID(), VersionID: value.NewID()}},
			}
			var catalogRevision, graphRevision int64
			err := f.Repo.WithTx(ctx, f.OrgID, func(tx organization.Tx) error {
				if err := tx.LockGraph(ctx, f.OrgID); err != nil {
					return err
				}
				var err error
				catalogRevision, graphRevision, err = tx.CommitCatalogChange(ctx, f.OrgID, 1, 1, write)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if catalogRevision != 2 || graphRevision != 1 || f.Count(t, "job_family") != 1 || f.Count(t, "job_family_version") != 1 {
				t.Fatalf("catalog/graph revisions = %d/%d", catalogRevision, graphRevision)
			}
		})
	}
}

func TestCatalogEndRejectsFactsOutsideRemainingCoverage(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			code, label, from := "SYNTHETIC-BRANCH", "Synthetic Branch", "2026-01-01"
			catalog, err := f.Service.ChangeCatalogs(ctx, f.Request(f.Owner), f.OrgID, organization.CatalogChangeCommand{
				ExpectedCatalogRevision: "1",
				ExpectedGraphRevision:   "1",
				Changes: []organization.CatalogChangeItem{{
					Action: "create", Kind: "legal_entity", Code: &code, Label: &label, ValidFrom: &from,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			employee, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{
				Profile:   organization.Profile{LocalName: "SYNTHETIC_CATALOG_REFERENCE"},
				Lifecycle: organization.Lifecycle{ValidFrom: from},
			})
			if err != nil {
				t.Fatal(err)
			}
			location, employmentKind := "Shanghai", "hire"
			assigned, err := f.Service.ChangeWorkforce(ctx, f.Request(f.Owner), f.OrgID, organization.WorkforceChangeCommand{
				ExpectedCatalogRevision:  catalog.CatalogRevision,
				ExpectedGraphRevision:    catalog.GraphRevision,
				ExpectedEmployeeRevision: map[string]string{employee.ID: "1"},
				Changes: []organization.WorkforceChangeItem{{
					Action: "add", Kind: "employment", EmployeeID: employee.ID, LegalEntityID: &catalog.Items[0].ID,
					LocationCode: &location, EmploymentKind: &employmentKind, ValidFrom: &from,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			end := "2027-01-01"
			_, err = f.Service.ChangeCatalogs(ctx, f.Request(f.Owner), f.OrgID, organization.CatalogChangeCommand{
				ExpectedCatalogRevision: assigned.CatalogRevision,
				ExpectedGraphRevision:   assigned.GraphRevision,
				Changes: []organization.CatalogChangeItem{{
					Action: "end", Kind: "legal_entity", Ref: &catalog.Items[0].ID, EffectiveTo: &end,
				}},
			})
			if !errors.Is(err, fault.Conflict) {
				t.Fatal("referenced legal entity ended before open employment spell:", err)
			}
		})
	}
}
