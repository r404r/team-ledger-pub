package store_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func testTOTP(t *testing.T, encoded string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := (binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", value)
}

func cookieHash(t *testing.T, cookie string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	clear(raw)
	return hash[:]
}

func TestLocalMFAEnrollmentLoginStepUpAndRecovery(t *testing.T) {
	ctx := context.Background()
	repo, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "mfa.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	keys := localKeys{key: []byte("01234567890123456789012345678901")}
	username, _ := identity.LocalUsernameMAC(ctx, keys, "mfa.admin")
	phc, pepper, _ := identity.NewPasswordCredential(ctx, keys, "correct horse battery staple")
	orgID, subjectID, accountID := value.NewID(), value.NewID(), value.NewID()
	binding := sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	start := time.Date(2026, 10, 16, 3, 0, 1, 0, time.UTC)
	digest := sha256.Sum256([]byte("mfa-bootstrap"))
	_, err = repo.BootstrapLocal(ctx, store.LocalBootstrap{RequestID: value.NewID(), OrgID: orgID, SubjectID: subjectID, AccountID: accountID, Timezone: "UTC", InputDigest: digest[:], UsernameDigest: username.Digest, UsernameKey: sensitive.KeyReference{KeyID: username.KeyID, Version: username.Version}, UsernameEnvelope: sensitive.Envelope{Context: binding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE", DEKID: value.NewID(), Key: sensitive.WrappedKey{KEKID: value.NewID(), Version: 1, Data: []byte{1}}, SealedBytes: make([]byte, 39)}, PepperKey: pepper, PasswordPHC: phc, Now: start})
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewLocal(ctx, repo, repo, keys, sensitive.Cipher{Wrapper: localWrapper{}}, sensitive.Cipher{Wrapper: localWrapper{}})
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(time.Minute)
	service.Now = func() time.Time { return now }
	initial, err := service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "correct horse battery staple", ReturnTo: "/", RequestID: value.NewID()})
	if err != nil || initial.Next != "change_password" {
		t.Fatal("initial password did not create password-change session", initial, err)
	}
	if err = service.ChangeLocalPassword(ctx, identity.LocalPasswordChangeRequest{SessionHash: cookieHash(t, initial.SessionCookie), CurrentPassword: "correct horse battery staple", NewPassword: "updated horse battery staple", RequestID: value.NewID()}); err != nil {
		t.Fatal("initial password change failed", err)
	}
	login, err := service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", ReturnTo: "/", RequestID: value.NewID()})
	if err != nil || login.Next != "enroll" {
		t.Fatal("updated password did not create restricted enrollment", login, err)
	}
	restricted := cookieHash(t, login.SessionCookie)
	if _, err = repo.Security(ctx, restricted, "", ""); err != fault.Unauthenticated {
		t.Fatal("restricted session entered business authorization", err)
	}
	clockCalls := 0
	service.Now = func() time.Time {
		clockCalls++
		return now.Add(time.Duration(clockCalls) * time.Microsecond)
	}
	pending, err := service.LocalMFABegin(ctx, restricted, identity.LocalMFAReplaceRequest{SessionHash: restricted, RequestID: value.NewID()})
	if err != nil || pending.Mode != "initial" || pending.Secret == "" {
		t.Fatal("initial enrollment did not start", pending, err)
	}
	service.Now = func() time.Time { return now }
	confirmed, err := service.LocalMFAConfirm(ctx, restricted, testTOTP(t, pending.Secret, now), value.NewID())
	if err != nil || confirmed.RecoveryCode == "" {
		t.Fatal("initial TOTP confirmation failed", err)
	}
	manifest, err := repo.BackupManifest(ctx, now, 0, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal("MFA backup inventory failed", err)
	}
	mfaDependency := false
	for _, dependency := range manifest.KeyDependencies {
		if dependency.Domain == "identity_mfa" && dependency.KeyID == "00000000-0000-4000-8000-000000000001" && dependency.Version == 1 {
			mfaDependency = true
		}
	}
	if !mfaDependency {
		t.Fatal("MFA wrapper key missing from backup dependencies", manifest.KeyDependencies)
	}
	business := cookieHash(t, confirmed.SessionCookie)
	if _, err = repo.Security(ctx, business, "", ""); err != nil {
		t.Fatal("confirmed business session unavailable", err)
	}
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", TOTPCode: testTOTP(t, pending.Secret, now), ReturnTo: "/", RequestID: value.NewID()}); err != fault.Unauthenticated {
		t.Fatal("same TOTP step was replayed", err)
	}
	now = now.Add(31 * time.Second)
	type loginAttempt struct {
		result identity.LoginResult
		err    error
	}
	startLogin := make(chan struct{})
	attempts := make(chan loginAttempt, 2)
	for range 2 {
		go func() {
			<-startLogin
			result, loginErr := service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", TOTPCode: testTOTP(t, pending.Secret, now), ReturnTo: "/", RequestID: value.NewID()})
			attempts <- loginAttempt{result, loginErr}
		}()
	}
	close(startLogin)
	var freshLogin identity.LoginResult
	successes := 0
	for range 2 {
		attempt := <-attempts
		if attempt.err == nil {
			successes++
			freshLogin = attempt.result
		}
	}
	if successes != 1 || freshLogin.Next != "" {
		t.Fatalf("concurrent TOTP replay produced %d successful sessions", successes)
	}
	now = now.Add(31 * time.Second)
	stepped, err := service.LocalStepUp(ctx, identity.LocalMFAStepUpRequest{SessionHash: cookieHash(t, freshLogin.SessionCookie), Password: "updated horse battery staple", TOTPCode: testTOTP(t, pending.Secret, now), Action: "access_grant.manage", ReturnTo: "/security/grants", RequestID: value.NewID()})
	if err != nil || stepped.SessionCookie == freshLogin.SessionCookie {
		t.Fatal("local step-up did not rotate session", err)
	}
	now = now.Add(31 * time.Second)
	recoveryRequestID := value.NewID()
	recoveryRequest := identity.LocalMFARecoveryRequest{Username: "mfa.admin", Password: "updated horse battery staple", RecoveryCode: confirmed.RecoveryCode, ReturnTo: "/", RequestID: recoveryRequestID}
	recovered, err := service.LocalMFARecover(ctx, recoveryRequest)
	if err != nil || recovered.Next != "recover" {
		t.Fatal("recovery code did not create restricted recovery", err)
	}
	recoveryHash := cookieHash(t, recovered.SessionCookie)
	if _, err = repo.Security(ctx, recoveryHash, "", ""); err != fault.Unauthenticated {
		t.Fatal("recovery session entered business authorization", err)
	}
	firstPending, err := service.LocalMFAPending(ctx, recoveryHash)
	if err != nil || firstPending.Mode != "recovery" {
		t.Fatal("recovery enrollment unavailable", err)
	}
	replayedRecovery, err := service.LocalMFARecover(ctx, recoveryRequest)
	if err != nil || replayedRecovery.SessionCookie == recovered.SessionCookie {
		t.Fatal("response-loss retry did not rotate the restricted session", err)
	}
	recoveryHash = cookieHash(t, replayedRecovery.SessionCookie)
	recoveryPending, err := service.LocalMFAPending(ctx, recoveryHash)
	if err != nil || recoveryPending.Secret != firstPending.Secret {
		t.Fatal("response-loss retry did not preserve the pending factor", err)
	}
	now = now.Add(time.Second)
	newFactor, err := service.LocalMFAConfirm(ctx, recoveryHash, testTOTP(t, recoveryPending.Secret, now), value.NewID())
	if err != nil || newFactor.RecoveryCode == "" {
		t.Fatal("recovery factor confirmation failed", err)
	}
	now = now.Add(31 * time.Second)
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", TOTPCode: testTOTP(t, pending.Secret, now), ReturnTo: "/", RequestID: value.NewID()}); err != fault.Unauthenticated {
		t.Fatal("old factor survived recovery", err)
	}
	now = now.Add(2 * time.Second)
	if _, err = service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", TOTPCode: testTOTP(t, recoveryPending.Secret, now), ReturnTo: "/", RequestID: value.NewID()}); err != nil {
		t.Fatal("new factor could not login", err)
	}
	resetRequestID := value.NewID()
	if err = repo.ResetLocalMFA(ctx, orgID, subjectID, username.Digest, resetRequestID, now.Add(time.Minute)); err != nil {
		t.Fatal("offline MFA reset failed", err)
	}
	var resetGeneration int64
	if err = repo.DB.QueryRowContext(ctx, "SELECT generation FROM local_mfa_account WHERE account_id=?", accountID).Scan(&resetGeneration); err != nil {
		t.Fatal(err)
	}
	if err = repo.ResetLocalMFA(ctx, orgID, subjectID, username.Digest, resetRequestID, now.Add(2*time.Minute)); err != nil {
		t.Fatal("offline MFA reset retry was not idempotent", err)
	}
	var retriedGeneration int64
	if err = repo.DB.QueryRowContext(ctx, "SELECT generation FROM local_mfa_account WHERE account_id=?", accountID).Scan(&retriedGeneration); err != nil || retriedGeneration != resetGeneration {
		t.Fatal("offline MFA reset retry changed generation", resetGeneration, retriedGeneration, err)
	}
	resetLogin, err := service.LocalLogin(ctx, identity.LocalLoginRequest{Username: "mfa.admin", Password: "updated horse battery staple", ReturnTo: "/", RequestID: value.NewID()})
	if err != nil || resetLogin.Next != "enroll" {
		t.Fatal("offline MFA reset did not require fresh enrollment", resetLogin, err)
	}
	if err = repo.DisableLocalAccount(ctx, orgID, subjectID, username.Digest, value.NewID(), now.Add(time.Minute)); err != nil {
		t.Fatal("account disable failed", err)
	}
	for _, table := range []string{"local_mfa_factor", "local_mfa_enrollment", "local_mfa_recovery_code", "local_mfa_recovery_receipt", "local_mfa_reset_receipt"} {
		var count int
		if err = repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE account_id=?", accountID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s retained disabled account factors: count=%d err=%v", table, count, err)
		}
	}
}
