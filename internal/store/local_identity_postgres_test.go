package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func TestPostgresLocalBootstrapAndLogin(t *testing.T) {
	ctx := context.Background()
	baseDSN := os.Getenv("TEAMLEDGER_TEST_POSTGRES_DSN")
	if baseDSN == "" {
		t.Fatal("real PostgreSQL DSN is required; no skip/fallback")
	}
	base, err := store.Open(ctx, "postgres", baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dev019_" + strings.ReplaceAll(value.NewID(), "-", "")
	if _, err = base.DB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		base.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = base.DB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = base.Close()
	})
	u, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	repo, err := store.Open(ctx, "postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	keys := localKeys{key: []byte("01234567890123456789012345678901")}
	username, err := identity.LocalUsernameMAC(ctx, keys, "postgres.admin")
	if err != nil {
		t.Fatal(err)
	}
	phc, pepper, err := identity.NewPasswordCredential(ctx, keys, "postgres correct password")
	if err != nil {
		t.Fatal(err)
	}
	orgID, subjectID, accountID := value.NewID(), value.NewID(), value.NewID()
	binding := sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	now := time.Now().UTC().Truncate(time.Microsecond)
	inputDigest := sha256.Sum256([]byte("postgres-bootstrap"))
	_, err = repo.BootstrapLocal(ctx, store.LocalBootstrap{
		RequestID: value.NewID(), OrgID: orgID, SubjectID: subjectID, AccountID: accountID, Timezone: "Asia/Tokyo",
		InputDigest: inputDigest[:], UsernameDigest: username.Digest,
		UsernameKey:      sensitive.KeyReference{KeyID: username.KeyID, Version: username.Version},
		UsernameEnvelope: sensitive.Envelope{Context: binding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)},
		PepperKey:        pepper, PasswordPHC: phc, Now: now,
	})
	if err != nil {
		t.Fatal("PostgreSQL bootstrap failed", err)
	}
	service, err := identity.NewLocal(ctx, repo, repo, keys)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now.Add(time.Second) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "postgres.admin", Password: "postgres correct password", ReturnTo: "/", RequestID: value.NewID()}); err != nil {
		t.Fatal("PostgreSQL local login failed", err)
	}
	secondSubject, secondAccount := value.NewID(), value.NewID()
	if err = repo.CreateLocalSubject(ctx, orgID, secondSubject, value.NewID(), now.Add(2*time.Second)); err != nil {
		t.Fatal("PostgreSQL subject create failed", err)
	}
	secondUsername, err := identity.LocalUsernameMAC(ctx, keys, "postgres.operator")
	if err != nil {
		t.Fatal(err)
	}
	secondPHC, secondPepper, err := identity.NewPasswordCredential(ctx, keys, "postgres operator password")
	if err != nil {
		t.Fatal(err)
	}
	secondBinding := sensitive.Context{OrgID: orgID, RecordID: secondAccount, VersionID: secondAccount, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	if err = repo.CreateLocalAccount(ctx, store.LocalAccountProvision{
		RequestID: value.NewID(), OrgID: orgID, SubjectID: secondSubject, AccountID: secondAccount,
		UsernameDigest: secondUsername.Digest, UsernameKey: sensitive.KeyReference{KeyID: secondUsername.KeyID, Version: secondUsername.Version},
		UsernameEnvelope: sensitive.Envelope{Context: secondBinding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)},
		PepperKey:        secondPepper, PasswordPHC: secondPHC, Now: now.Add(3 * time.Second),
	}); err != nil {
		t.Fatal("PostgreSQL account create failed", err)
	}
	resetPHC, resetPepper, err := identity.NewPasswordCredential(ctx, keys, "postgres reset password")
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.ResetLocalAccount(ctx, orgID, secondSubject, secondUsername.Digest, resetPHC, resetPepper, value.NewID(), now.Add(4*time.Second)); err != nil {
		t.Fatal("PostgreSQL account reset failed", err)
	}
	if err = repo.DisableLocalAccount(ctx, orgID, secondSubject, secondUsername.Digest, value.NewID(), now.Add(5*time.Second)); err != nil {
		t.Fatal("PostgreSQL account disable failed", err)
	}
	const attempts = 8
	unknownDigest := sha256.Sum256([]byte("postgres-concurrent-unknown-account"))
	errs := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- repo.RecordLocalFailure(ctx, unknownDigest[:], value.NewID(), now.Add(6*time.Second))
		}()
	}
	wait.Wait()
	close(errs)
	for throttleErr := range errs {
		if throttleErr != nil {
			t.Fatal("concurrent PostgreSQL throttle failed", throttleErr)
		}
	}
	var failures int
	if err = repo.DB.QueryRowContext(ctx, "SELECT failures FROM local_login_throttle WHERE username_digest=$1", unknownDigest[:]).Scan(&failures); err != nil || failures != attempts {
		t.Fatal("concurrent PostgreSQL throttle lost an increment", failures, err)
	}
	if err = repo.SwitchIdentityMode(ctx, "oidc", value.NewID(), now.Add(6*time.Second)); err != nil {
		t.Fatal("PostgreSQL mode switch failed", err)
	}
	credential, err := repo.LookupLocalCredential(ctx, username.Digest)
	if err != nil {
		t.Fatal("PostgreSQL credential lookup after mode switch failed", err)
	}
	issueAt := now.Add(7 * time.Second)
	issue := identity.LocalSessionIssue{UsernameDigest: username.Digest, UsernameKeyID: username.KeyID, UsernameKeyVersion: username.Version, TokenHash: bytes.Repeat([]byte{93}, 32), CSRFHash: bytes.Repeat([]byte{94}, 32), CSRFKeyID: "00000000-0000-7000-8000-000000000001", CSRFVersion: 1, Now: issueAt, ExpiresAt: issueAt.Add(8 * time.Hour), IdleExpiresAt: issueAt.Add(30 * time.Minute), RequestID: value.NewID(), CredentialRevision: credential.CredentialRevision}
	if err = repo.IssueLocalSession(ctx, issue); !errors.Is(err, fault.Unauthenticated) {
		t.Fatal("PostgreSQL old-mode local session issued after mode switch", err)
	}
}
