package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestBonusTypedPaginationTraversesHistoryBeyondReconciliationBound(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			created, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "SYNTHETIC_BONUS_PAGING"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := f.Repo.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			targetSQL := "INSERT INTO bonus_target(org_id,employee_id,id,state,version_id,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
			extensionSQL := "INSERT INTO compensation_extension_version(org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,recorded_at) VALUES(?,?,?,?,? ,?,?,?,?)"
			if backend == "postgres" {
				targetSQL = "INSERT INTO bonus_target(org_id,employee_id,id,state,version_id,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
				extensionSQL = "INSERT INTO compensation_extension_version(org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)"
			}
			for n := 0; n < 1005; n++ {
				at := f.Now.Add(time.Duration(n) * time.Microsecond)
				if _, err = tx.Exec(targetSQL, f.OrgID, created.ID, value.NewID(), "confirmed", value.NewID(), value.NewID(), "2026-01-01", "2026-12-31", f.Owner.SubjectID, 1, 1, f.Repo.BindTime(at)); err != nil {
					_ = tx.Rollback()
					t.Fatal("seed target", n, err)
				}
			}
			for n := 0; n < 1001; n++ {
				at := f.Now.Add(time.Duration(n) * time.Microsecond)
				if _, err = tx.Exec(extensionSQL, f.OrgID, created.ID, value.NewID(), value.NewID(), "compensation_memo/v1", 1, n+1, 1, f.Repo.BindTime(at)); err != nil {
					_ = tx.Rollback()
					t.Fatal("seed unrelated extension", n, err)
				}
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}

			seen := make(map[string]bool, 1005)
			after := ""
			for pageNumber := 0; ; pageNumber++ {
				if pageNumber > 11 {
					t.Fatal("pagination did not terminate")
				}
				page, pageErr := f.Repo.BonusSnapshotPage(context.Background(), f.OrgID, created.ID, compensation.BonusPageQuery{Kind: "targets", After: after, Limit: 100})
				if pageErr != nil {
					t.Fatal(pageErr)
				}
				if len(page.Snapshot.Targets) == 0 {
					t.Fatal("empty page before terminal cursor")
				}
				for _, target := range page.Snapshot.Targets {
					if seen[target.ID] {
						t.Fatal("duplicate target", target.ID)
					}
					seen[target.ID] = true
				}
				last := page.Snapshot.Targets[len(page.Snapshot.Targets)-1]
				after = fmt.Sprintf("%s|%s", last.RecordedAt.UTC().Format(time.RFC3339Nano), last.ID)
				if !page.More {
					break
				}
			}
			if len(seen) != 1005 {
				t.Fatalf("typed cursor lost complete history: got %d", len(seen))
			}
		})
	}
}
