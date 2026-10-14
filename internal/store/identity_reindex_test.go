package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func dialect(backend, sqlite, postgres string) string {
	if backend == "postgres" {
		return postgres
	}
	return sqlite
}

func databaseTime(f *testsupport.Fixture) any {
	if f.Backend == "postgres" {
		return f.Now
	}
	return f.Now.UnixMicro()
}

func TestIdentityIndexReplacementPreservesHistoricalMappingAndMovesCanonicalSource(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			defer f.Close()
			ctx := context.Background()
			mappingID := value.NewID()
			oldDigest := sha256.Sum256([]byte("identity-old"))
			newDigest := sha256.Sum256([]byte("identity-new"))
			if _, err := f.Repo.DB.ExecContext(ctx, dialect(backend, "INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES(?,'identity-v1',1,?,?,0)", "INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES($1,'identity-v1',1,$2,$3,false)"), oldDigest[:], f.OrgID, f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Repo.DB.ExecContext(ctx, dialect(backend, "INSERT INTO identity_mapping_source(mapping_id,digest,org_id,subject_id,key_id,key_version,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,'identity-v1',1,?,?,'identity','identity.mapping.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,?,?,?)", "INSERT INTO identity_mapping_source(mapping_id,digest,org_id,subject_id,key_id,key_version,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,'identity-v1',1,$5,$6,'identity','identity.mapping.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,$7,$8,$9)"), mappingID, oldDigest[:], f.OrgID, f.Owner.SubjectID, mappingID, mappingID, []byte{1}, bytes.Repeat([]byte{2}, 28), databaseTime(f)); err != nil {
				t.Fatal(err)
			}
			target := sensitive.KeyReference{KeyID: "identity-v2", Version: 2}
			replacement := store.IdentityIndexReplacement{SourceID: mappingID, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID, OldDigest: oldDigest[:], NewDigest: newDigest[:]}
			if err := f.Repo.ApplyIdentityIndexReplacements(ctx, false, target, []store.IdentityIndexReplacement{replacement}); err != nil {
				t.Fatal(err)
			}
			var digest []byte
			var keyID string
			var version int64
			if err := f.Repo.DB.QueryRowContext(ctx, dialect(backend, "SELECT digest,key_id,key_version FROM identity_mapping_source WHERE mapping_id=?", "SELECT digest,key_id,key_version FROM identity_mapping_source WHERE mapping_id=$1"), mappingID).Scan(&digest, &keyID, &version); err != nil || !bytes.Equal(digest, newDigest[:]) || keyID != target.KeyID || version != int64(target.Version) {
				t.Fatal("canonical identity source did not move to the target index", keyID, version, err)
			}
			var historical, current int
			if err := f.Repo.DB.QueryRowContext(ctx, dialect(backend, "SELECT count(*) FROM subject_identity WHERE digest=?", "SELECT count(*) FROM subject_identity WHERE digest=$1"), oldDigest[:]).Scan(&historical); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRowContext(ctx, dialect(backend, "SELECT count(*) FROM subject_identity WHERE digest=? AND key_id=? AND key_version=? AND active=0", "SELECT count(*) FROM subject_identity WHERE digest=$1 AND key_id=$2 AND key_version=$3 AND active=false"), newDigest[:], target.KeyID, target.Version).Scan(&current); err != nil || historical != 1 || current != 1 {
				t.Fatal("inactive identity history or replacement mapping missing", historical, current, err)
			}
		})
	}
}

func TestLocalUsernameIndexReplacementMovesSessionIdentity(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			defer f.Close()
			ctx := context.Background()
			accountID := value.NewID()
			oldDigest := sha256.Sum256([]byte("local-old"))
			newDigest := sha256.Sum256([]byte("local-new"))
			if _, err := f.Repo.DB.ExecContext(ctx, dialect(backend,
				"INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES(?,'username-v1',1,?,?,1)",
				"INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES($1,'username-v1',1,$2,$3,true)"),
				oldDigest[:], f.OrgID, f.Owner.SubjectID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Repo.DB.ExecContext(ctx, dialect(backend, "INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,'username-v1',1,1,?,?,'identity','identity.local_username.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,?,?,?)", "INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,'username-v1',1,true,$5,$6,'identity','identity.local_username.v1',1,1,'A256GCM-RANDOMNONCE','dek','kek',1,$7,$8,$9)"), accountID, f.OrgID, f.Owner.SubjectID, oldDigest[:], accountID, accountID, []byte{1}, bytes.Repeat([]byte{2}, 28), databaseTime(f)); err != nil {
				t.Fatal(err)
			}
			target := sensitive.KeyReference{KeyID: "username-v2", Version: 2}
			replacement := store.IdentityIndexReplacement{SourceID: accountID, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID, OldDigest: oldDigest[:], NewDigest: newDigest[:], Local: true}
			if err := f.Repo.ApplyIdentityIndexReplacements(ctx, true, target, []store.IdentityIndexReplacement{replacement}); err != nil {
				t.Fatal(err)
			}
			var local, identity int
			if err := f.Repo.DB.QueryRowContext(ctx, dialect(backend, "SELECT count(*) FROM local_account WHERE id=? AND username_digest=? AND username_key_id=? AND username_key_version=?", "SELECT count(*) FROM local_account WHERE id=$1 AND username_digest=$2 AND username_key_id=$3 AND username_key_version=$4"), accountID, newDigest[:], target.KeyID, target.Version).Scan(&local); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRowContext(ctx, dialect(backend, "SELECT count(*) FROM subject_identity WHERE digest=? AND key_id=? AND key_version=? AND active=1", "SELECT count(*) FROM subject_identity WHERE digest=$1 AND key_id=$2 AND key_version=$3 AND active=true"), newDigest[:], target.KeyID, target.Version).Scan(&identity); err != nil || local != 1 || identity != 1 {
				t.Fatal("local username and session identity did not move together", local, identity, err)
			}
		})
	}
}
