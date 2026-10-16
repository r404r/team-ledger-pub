package store

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func TestV16ExpandsOnlyBootstrapAdminAuthorities(t *testing.T) {
	ctx := context.Background()
	repo, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "v15.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	tx, err := repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 15; version++ {
		ddl, checksum, migrationErr := repo.migration(version)
		if migrationErr != nil {
			t.Fatal(migrationErr)
		}
		for _, statement := range migrationStatements(ddl) {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				t.Fatalf("apply v%d: %v", version, err)
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_version(version,backend,checksum) VALUES(?,?,?)", version, "sqlite", checksum); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	orgID, adminID, accountID := value.NewID(), value.NewID(), value.NewID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := sha256.Sum256([]byte("v15-bootstrap"))
	_, err = repo.BootstrapLocal(ctx, LocalBootstrap{
		RequestID: value.NewID(), OrgID: orgID, SubjectID: adminID, AccountID: accountID, Timezone: "Asia/Shanghai",
		InputDigest: digest[:], UsernameDigest: digest[:], UsernameKey: sensitive.KeyReference{KeyID: "test-key", Version: 1},
		UsernameEnvelope: sensitive.Envelope{Context: sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)},
		PepperKey:        sensitive.KeyReference{KeyID: "pepper", Version: 1}, PasswordPHC: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	otherSubject := value.NewID()
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", orgID, otherSubject); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.DB.ExecContext(ctx, "DROP TRIGGER authority_no_delete"); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.DB.ExecContext(ctx, "DROP TRIGGER authority_no_update"); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.DB.ExecContext(ctx, "DELETE FROM delegation_authority"); err != nil {
		t.Fatal(err)
	}
	expires := repo.BindTime(now.AddDate(100, 0, 0))
	at := repo.BindTime(now)
	for _, authority := range []bootstrapAuthority{{"audit.read", "audit", "security_administration"}, {"identity.manage", "audit", "security_administration"}} {
		if _, err = repo.DB.ExecContext(ctx, "INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,?,?,'org',?,?,?,?,1,?,?,'bootstrap_admin.v1')", value.NewID(), orgID, adminID, authority.capability, authority.category, orgID, authority.purpose, at, expires, adminID, at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = repo.DB.ExecContext(ctx, "INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,'organization.read','metadata','org',?,'organization_management',?,?,1,?,?,'operator_policy.v1')", value.NewID(), orgID, otherSubject, orgID, at, expires, adminID, at); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.DB.ExecContext(ctx, "CREATE TRIGGER authority_no_update BEFORE UPDATE ON delegation_authority BEGIN SELECT RAISE(ABORT,'immutable authority'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.DB.ExecContext(ctx, "CREATE TRIGGER authority_no_delete BEFORE DELETE ON delegation_authority BEGIN SELECT RAISE(ABORT,'immutable authority'); END"); err != nil {
		t.Fatal(err)
	}

	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var adminCount, unrelatedCount, version int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM delegation_authority WHERE org_id=? AND manager_subject_id=? AND policy_version='bootstrap_admin.v1'", orgID, adminID).Scan(&adminCount); err != nil || adminCount != len(bootstrapAuthorities) {
		t.Fatalf("migrated bootstrap authorities=%d err=%v", adminCount, err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM delegation_authority WHERE org_id=? AND manager_subject_id=? AND policy_version='operator_policy.v1'", orgID, otherSubject).Scan(&unrelatedCount); err != nil || unrelatedCount != 1 {
		t.Fatalf("unrelated authority count=%d err=%v", unrelatedCount, err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT max(version) FROM schema_version").Scan(&version); err != nil || version != 19 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
}
