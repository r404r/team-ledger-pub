package store_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/maintenance"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestKeyRewrapFencesWritesAndCASChangesOnlyWrapper(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			if _, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "REWRAP_SOURCE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}); err != nil {
				t.Fatal(err)
			}
			plan := maintenance.Target{OrgID: f.OrgID, Domain: "pii", KEKID: "synthetic-pii-key-next", Version: 2, ManifestDigest: bytes.Repeat([]byte{7}, 32)}
			if err := f.Repo.BeginKeyRewrap(ctx, plan, f.Now); err != nil {
				t.Fatal(err)
			}
			before := f.Count(t, "employee")
			if _, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "MUST_NOT_COMMIT"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}); err == nil || f.Count(t, "employee") != before {
				t.Fatal("maintenance fence admitted a sensitive write", err)
			}
			renewed := plan
			renewed.ManifestDigest = bytes.Repeat([]byte{8}, 32)
			if err := f.Repo.BeginKeyRewrap(ctx, renewed, f.Now.Add(time.Second)); err != nil {
				t.Fatal("same-target approval renewal was rejected", err)
			}
			if f.Count(t, "key_rewrap_approval_audit") != 2 {
				t.Fatal("approval start and renewal were not retained")
			}
			if _, _, err := f.Repo.NextKeyRewrap(ctx, plan); err == nil {
				t.Fatal("superseded approval remained usable")
			}
			plan = renewed
			item, found, err := f.Repo.NextKeyRewrap(ctx, plan)
			if err != nil || !found {
				t.Fatal("missing existing encrypted payload", item, err)
			}
			query := fmt.Sprintf("SELECT sealed_bytes FROM %s WHERE org_id=? AND id=?", item.Table)
			if backend == "postgres" {
				query = fmt.Sprintf("SELECT sealed_bytes FROM %s WHERE org_id=$1 AND id=$2", item.Table)
			}
			var sealedBefore []byte
			if err = f.Repo.DB.QueryRowContext(ctx, query, f.OrgID, item.ID).Scan(&sealedBefore); err != nil {
				t.Fatal(err)
			}
			next := sensitive.WrappedKey{KEKID: plan.KEKID, Version: plan.Version, Data: bytes.Repeat([]byte{9}, 48)}
			if err = f.Repo.CommitKeyRewrap(ctx, plan, item, next, f.Now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var sealedAfter []byte
			if err = f.Repo.DB.QueryRowContext(ctx, query, f.OrgID, item.ID).Scan(&sealedAfter); err != nil || !bytes.Equal(sealedBefore, sealedAfter) {
				t.Fatal("rewrap altered payload ciphertext", err)
			}
			if err = f.Repo.CommitKeyRewrap(ctx, plan, item, next, f.Now.Add(2*time.Second)); err == nil {
				t.Fatal("stale wrapper CAS succeeded")
			}
			for {
				pending, ok, nextErr := f.Repo.NextKeyRewrap(ctx, plan)
				if nextErr != nil {
					t.Fatal(nextErr)
				}
				if !ok {
					break
				}
				replacement := sensitive.WrappedKey{KEKID: plan.KEKID, Version: plan.Version, Data: bytes.Repeat([]byte{10}, 48)}
				if err = f.Repo.CommitKeyRewrap(ctx, plan, pending, replacement, f.Now.Add(3*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			actor := maintenance.Actor{UID: 1000, HostDigest: bytes.Repeat([]byte{11}, 32)}
			if err = f.Repo.CompleteKeyRewrap(ctx, plan, actor, f.Now.Add(4*time.Second)); err != nil {
				t.Fatal(err)
			}
			before = f.Count(t, "employee")
			if _, err = f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "OLD_WRAPPER_AFTER_ROTATION"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}); err == nil || f.Count(t, "employee") != before {
				t.Fatal("completed rotation admitted an old wrapper", err)
			}
			second := maintenance.Target{OrgID: f.OrgID, Domain: "pii", KEKID: "synthetic-pii-key-final", Version: 3, ManifestDigest: bytes.Repeat([]byte{12}, 32)}
			if err = f.Repo.BeginKeyRewrap(ctx, second, f.Now.Add(5*time.Second)); err != nil {
				t.Fatal("completed job did not admit a later rotation", err)
			}
			if _, found, err = f.Repo.NextKeyRewrap(ctx, second); err != nil || !found {
				t.Fatal("later rotation did not restart from existing wrappers", found, err)
			}
		})
	}
}
