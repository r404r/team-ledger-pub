package store_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

type localKeys struct{ key []byte }

func (k localKeys) MAC(_ context.Context, domain sensitive.KeyDomain, message []byte) (sensitive.MACValue, error) {
	mac := hmac.New(sha256.New, k.key)
	mac.Write([]byte(domain))
	mac.Write(message)
	return sensitive.MACValue{KeyID: "local-test-key", Version: 1, Digest: mac.Sum(nil)}, nil
}

func (k localKeys) Verify(ctx context.Context, domain sensitive.KeyDomain, reference sensitive.KeyReference, message, expected []byte) (bool, error) {
	if reference != (sensitive.KeyReference{KeyID: "local-test-key", Version: 1}) {
		return false, nil
	}
	value, err := k.MAC(ctx, domain, message)
	return err == nil && hmac.Equal(value.Digest, expected), err
}

type localWrapper struct{}

func (localWrapper) Wrap(_ context.Context, plain []byte) (sensitive.WrappedKey, error) {
	return sensitive.WrappedKey{KEKID: "00000000-0000-4000-8000-000000000001", Version: 1, Data: bytes.Clone(plain)}, nil
}

func (localWrapper) Unwrap(_ context.Context, wrapped sensitive.WrappedKey) ([]byte, error) {
	return bytes.Clone(wrapped.Data), nil
}

func TestLocalBootstrapLoginThrottleAndSession(t *testing.T) {
	ctx := context.Background()
	repo, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "local.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	keys := localKeys{key: []byte("01234567890123456789012345678901")}
	username, err := identity.LocalUsernameMAC(ctx, keys, "admin.user")
	if err != nil {
		t.Fatal(err)
	}
	phc, pepper, err := identity.NewPasswordCredential(ctx, keys, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	orgID, subjectID, accountID := value.NewID(), value.NewID(), value.NewID()
	binding := sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	now := time.Now().UTC().Truncate(time.Microsecond)
	inputDigest := sha256.Sum256([]byte("canonical-bootstrap-input"))
	bootstrap := store.LocalBootstrap{
		RequestID: value.NewID(), OrgID: orgID, SubjectID: subjectID, AccountID: accountID, Timezone: "Asia/Shanghai",
		InputDigest: inputDigest[:], UsernameDigest: username.Digest,
		UsernameKey:      sensitive.KeyReference{KeyID: username.KeyID, Version: username.Version},
		UsernameEnvelope: sensitive.Envelope{Context: binding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)},
		PepperKey:        pepper, PasswordPHC: phc, Now: now,
	}
	result, err := repo.BootstrapLocal(ctx, bootstrap)
	if err != nil || result.OrgID != orgID || result.SubjectID != subjectID || result.AccountID != accountID {
		t.Fatal("bootstrap failed", result, err)
	}
	replayed, err := repo.BootstrapLocal(ctx, bootstrap)
	if err != nil || replayed != result {
		t.Fatal("bootstrap replay did not return original IDs", replayed, err)
	}
	var policy string
	if err = repo.DB.QueryRowContext(ctx, "SELECT policy_version FROM local_bootstrap_receipt WHERE request_id=?", bootstrap.RequestID).Scan(&policy); err != nil || policy != "bootstrap_policy.v1" {
		t.Fatal("bootstrap policy version was not fixed", policy, err)
	}
	var approvedBy string
	if err = repo.DB.QueryRowContext(ctx, "SELECT approved_by FROM bootstrap_admin_policy WHERE org_id=?", orgID).Scan(&approvedBy); err != nil || approvedBy != subjectID {
		t.Fatal("bootstrap admin policy did not preserve the original self-approval", approvedBy, err)
	}
	var securityCapabilities int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM access_grant WHERE org_id=? AND subject_id=? AND capability IN('access_grant.manage','audit.read','identity.manage') AND category='audit' AND purpose='security_administration' AND mfa_required=1", orgID, subjectID).Scan(&securityCapabilities); err != nil || securityCapabilities != 3 {
		t.Fatal("bootstrap admin security capabilities missing", securityCapabilities, err)
	}
	service, err := identity.NewLocal(ctx, repo, repo, keys, sensitive.Cipher{Wrapper: localWrapper{}})
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now.Add(time.Minute) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "admin.user", Password: "wrong password value", ReturnTo: "/", RequestID: value.NewID()}); err == nil {
		t.Fatal("wrong password logged in")
	}
	var failures int
	if err = repo.DB.QueryRowContext(ctx, "SELECT failures FROM local_login_throttle WHERE username_digest=?", username.Digest).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("failed login did not atomically throttle", failures, err)
	}
	service.Now = func() time.Time { return now.Add(62 * time.Second) }
	login, err := service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "ADMIN.USER", Password: "correct horse battery staple", ReturnTo: "/", RequestID: value.NewID()})
	if err != nil {
		t.Fatal("correct password did not login", err)
	}
	if login.Next != "change_password" {
		t.Fatal("bootstrap password did not require first-login change", login.Next)
	}
	raw, err := base64.RawURLEncoding.DecodeString(login.SessionCookie)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	session, err := repo.IdentitySession(ctx, hash[:], now.Add(63*time.Second))
	if err != nil || session.OrgID != orgID || session.SubjectID != subjectID || session.AccessKind != "password_change" {
		t.Fatal("local session was not usable", session, err)
	}
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM local_login_throttle WHERE username_digest=?", username.Digest).Scan(&failures); err != nil || failures != 0 {
		t.Fatal("successful login did not reset throttle", failures, err)
	}
	service.Now = func() time.Time { return now.Add(64 * time.Second) }
	passwordRequestID := value.NewID()
	if err = service.ChangeLocalPassword(ctx, identity.LocalPasswordChangeRequest{SessionHash: hash[:], CurrentPassword: "correct horse battery staple", NewPassword: "replacement horse battery staple", RequestID: passwordRequestID}); err != nil {
		t.Fatal("self-service password change failed", err)
	}
	if _, err = repo.IdentitySession(ctx, hash[:], now.Add(65*time.Second)); err == nil {
		t.Fatal("password change did not revoke the current session")
	}
	var passwordAudits int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE request_id=? AND operation='AUTH-PASSWORD-CHANGE'", passwordRequestID).Scan(&passwordAudits); err != nil || passwordAudits != 1 {
		t.Fatal("password change audit missing", passwordAudits, err)
	}
	service.Now = func() time.Time { return now.Add(66 * time.Second) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "admin.user", Password: "replacement horse battery staple", ReturnTo: "/", RequestID: value.NewID()}); err != nil {
		t.Fatal("replacement password did not login", err)
	}
	nextSubject, nextAccount := value.NewID(), value.NewID()
	if err = repo.CreateLocalSubject(ctx, orgID, nextSubject, value.NewID(), now.Add(2*time.Minute)); err != nil {
		t.Fatal("local subject create failed", err)
	}
	nextUsername, err := identity.LocalUsernameMAC(ctx, keys, "operator.user")
	if err != nil {
		t.Fatal(err)
	}
	nextPHC, nextPepper, err := identity.NewPasswordCredential(ctx, keys, "operator initial password")
	if err != nil {
		t.Fatal(err)
	}
	nextBinding := sensitive.Context{OrgID: orgID, RecordID: nextAccount, VersionID: nextAccount, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	if err = repo.CreateLocalAccount(ctx, store.LocalAccountProvision{
		RequestID: value.NewID(), OrgID: orgID, SubjectID: nextSubject, AccountID: nextAccount,
		UsernameDigest: nextUsername.Digest, UsernameKey: sensitive.KeyReference{KeyID: nextUsername.KeyID, Version: nextUsername.Version},
		UsernameEnvelope: sensitive.Envelope{Context: nextBinding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)},
		PepperKey:        nextPepper, PasswordPHC: nextPHC, Now: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatal("local account create failed", err)
	}
	service.Now = func() time.Time { return now.Add(4 * time.Minute) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "operator.user", Password: "operator initial password", ReturnTo: "/", RequestID: value.NewID()}); err != nil {
		t.Fatal("created account did not login", err)
	}
	resetPHC, resetPepper, err := identity.NewPasswordCredential(ctx, keys, "operator reset password")
	if err != nil {
		t.Fatal(err)
	}
	resetRequestID := value.NewID()
	if err = repo.ResetLocalAccount(ctx, orgID, nextSubject, nextUsername.Digest, resetPHC, resetPepper, resetRequestID, now.Add(5*time.Minute)); err != nil {
		t.Fatal("local account reset failed", err)
	}
	var resetAudits int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE request_id=? AND operation='AUTH-ACCOUNT-RESET'", resetRequestID).Scan(&resetAudits); err != nil || resetAudits != 1 {
		t.Fatal("local account reset audit missing", resetAudits, err)
	}
	service.Now = func() time.Time { return now.Add(6 * time.Minute) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "operator.user", Password: "operator reset password", ReturnTo: "/", RequestID: value.NewID()}); err != nil {
		t.Fatal("reset account did not login", err)
	}
	if err = repo.DisableLocalAccount(ctx, orgID, nextSubject, nextUsername.Digest, value.NewID(), now.Add(7*time.Minute)); err != nil {
		t.Fatal("local account disable failed", err)
	}
	service.Now = func() time.Time { return now.Add(8 * time.Minute) }
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "operator.user", Password: "operator reset password", ReturnTo: "/", RequestID: value.NewID()}); err == nil {
		t.Fatal("disabled account logged in")
	}
	modeRequestID := value.NewID()
	if err = repo.SwitchIdentityMode(ctx, "oidc", modeRequestID, now.Add(9*time.Minute)); err != nil {
		t.Fatal("identity mode switch failed", err)
	}
	var modeAudits int
	if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE request_id=? AND operation='AUTH-MODE-SWITCH'", modeRequestID).Scan(&modeAudits); err != nil || modeAudits != 2 {
		t.Fatal("mode switch did not audit every affected subject", modeAudits, err)
	}
	if mode, modeErr := repo.IdentityMode(ctx); modeErr != nil || mode != "oidc" {
		t.Fatal("identity mode did not switch", mode, modeErr)
	}
	credential, err := repo.LookupLocalCredential(ctx, username.Digest)
	if err != nil {
		t.Fatal("lookup local credential after mode switch", err)
	}
	issueAt := now.Add(10 * time.Minute)
	issue := identity.LocalSessionIssue{UsernameDigest: username.Digest, UsernameKeyID: username.KeyID, UsernameKeyVersion: username.Version, TokenHash: bytes.Repeat([]byte{91}, 32), CSRFHash: bytes.Repeat([]byte{92}, 32), CSRFKeyID: "00000000-0000-7000-8000-000000000001", CSRFVersion: 1, AccessKind: "mfa_enrollment", Now: issueAt, ExpiresAt: issueAt.Add(10 * time.Minute), IdleExpiresAt: issueAt.Add(10 * time.Minute), MFAUntil: time.Unix(0, 0).UTC(), RequestID: value.NewID(), CredentialRevision: credential.CredentialRevision, FactorGeneration: credential.MFAGeneration}
	if err = repo.IssueLocalSession(ctx, issue); !errors.Is(err, fault.Unauthenticated) {
		t.Fatal("old-mode local session issued after mode switch", err)
	}
	if _, err = identity.NewLocal(ctx, repo, repo, keys, sensitive.Cipher{Wrapper: localWrapper{}}); err == nil {
		t.Fatal("local identity started after oidc mode switch")
	}
}
