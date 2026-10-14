package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestStaffIndexReplacementMovesEveryFactAndOwnerAtomically(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			defer f.Close()
			ctx := context.Background()
			employee, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "STAFF_REINDEX_SOURCE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			identifierID, payloadID, changeID := value.NewID(), value.NewID(), value.NewID()
			oldDigest := sha256.Sum256([]byte("staff-index-source"))
			tx, err := f.Repo.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var now any = f.Now.UnixMicro()
			if backend == "postgres" {
				now = f.Now
			}
			statements := []struct {
				sqlite, postgres string
				args             []any
			}{
				{"INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after) VALUES(?,?,?,?,1,1,1,1)", "INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after) VALUES($1,$2,$3,$4,1,1,1,1)", []any{f.OrgID, changeID, f.Owner.SubjectID, now}},
				{"INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,'employee_identifier',?,?,?,?,'pii','pii.employee_identifier.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,?,?,?)", "INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,'employee_identifier',$3,$4,$5,$6,'pii','pii.employee_identifier.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,$7,$8,$9)", []any{f.OrgID, payloadID, identifierID, employee.ID, identifierID, payloadID, []byte{1}, bytes.Repeat([]byte{2}, 28), now}},
				{"INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) VALUES(?,'staff_code','staff-code-v1',1,?,?,?)", "INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) VALUES($1,'staff_code','staff-code-v1',1,$2,$3,$4)", []any{f.OrgID, oldDigest[:], employee.ID, now}},
				{"INSERT INTO employee_business_identifier(org_id,id,employee_id,kind,lookup_key_id,lookup_key_version,lookup_digest,payload_id,valid_from,recorded_at,change_id,revision) VALUES(?,?,?,'staff_code','staff-code-v1',1,?,?,'2026-01-01',?,?,1)", "INSERT INTO employee_business_identifier(org_id,id,employee_id,kind,lookup_key_id,lookup_key_version,lookup_digest,payload_id,valid_from,recorded_at,change_id,revision) VALUES($1,$2,$3,'staff_code','staff-code-v1',1,$4,$5,'2026-01-01',$6,$7,1)", []any{f.OrgID, identifierID, employee.ID, oldDigest[:], payloadID, now, changeID}},
			}
			for _, statement := range statements {
				query := statement.sqlite
				if backend == "postgres" {
					query = statement.postgres
				}
				if _, err = tx.ExecContext(ctx, query, statement.args...); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			sources, err := f.Repo.StaffIndexSources(ctx)
			if err != nil || len(sources) == 0 {
				t.Fatal("fixture must expose encrypted staff-code sources", len(sources), err)
			}
			replacements := make([]store.StaffIndexReplacement, 0, len(sources))
			byOld := make(map[string][]byte)
			for _, source := range sources {
				key := string(source.OldDigest)
				digest := byOld[key]
				if digest == nil {
					sum := sha256.Sum256(append([]byte("rotated-staff-index\x00"), source.OldDigest...))
					digest = append([]byte(nil), sum[:]...)
					byOld[key] = digest
				}
				replacements = append(replacements, store.StaffIndexReplacement{ID: source.ID, OrgID: source.OrgID, EmployeeID: source.EmployeeID, OldDigest: source.OldDigest, NewDigest: digest})
			}
			target := sensitive.KeyReference{KeyID: "staff-code-v2", Version: 2}
			if err = f.Repo.ApplyStaffIndexReplacements(ctx, target, replacements); err != nil {
				t.Fatal(err)
			}
			for _, replacement := range replacements {
				var keyID string
				var version int64
				var digest []byte
				query := "SELECT lookup_key_id,lookup_key_version,lookup_digest FROM employee_business_identifier WHERE org_id=? AND id=?"
				if backend == "postgres" {
					query = "SELECT lookup_key_id,lookup_key_version,lookup_digest FROM employee_business_identifier WHERE org_id=$1 AND id=$2"
				}
				if err = f.Repo.DB.QueryRowContext(ctx, query, replacement.OrgID, replacement.ID).Scan(&keyID, &version, &digest); err != nil || keyID != target.KeyID || version != int64(target.Version) || !bytes.Equal(digest, replacement.NewDigest) {
					t.Fatal("staff index replacement mismatch", keyID, version, err)
				}
			}
			var stale int
			query := "SELECT count(*) FROM employee_identifier_owner WHERE key_id<>? OR key_version<>?"
			if backend == "postgres" {
				query = "SELECT count(*) FROM employee_identifier_owner WHERE key_id<>$1 OR key_version<>$2"
			}
			if err = f.Repo.DB.QueryRowContext(ctx, query, target.KeyID, target.Version).Scan(&stale); err != nil || stale != 0 {
				t.Fatal("stale owner index survived replacement", stale, err)
			}
		})
	}
}
