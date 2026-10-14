package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

type localTestKeys struct{ key []byte }

func (k localTestKeys) MAC(_ context.Context, domain sensitive.KeyDomain, message []byte) (sensitive.MACValue, error) {
	mac := hmac.New(sha256.New, k.key)
	mac.Write([]byte(domain))
	mac.Write(message)
	return sensitive.MACValue{KeyID: "local-test-key", Version: 1, Digest: mac.Sum(nil)}, nil
}

func (k localTestKeys) Verify(ctx context.Context, domain sensitive.KeyDomain, reference sensitive.KeyReference, message, expected []byte) (bool, error) {
	if reference != (sensitive.KeyReference{KeyID: "local-test-key", Version: 1}) {
		return false, nil
	}
	value, err := k.MAC(ctx, domain, message)
	return err == nil && hmac.Equal(value.Digest, expected), err
}

type rotatingLocalKeys struct {
	active uint32
	keys   map[uint32][]byte
}

func (k *rotatingLocalKeys) MAC(_ context.Context, domain sensitive.KeyDomain, message []byte) (sensitive.MACValue, error) {
	mac := hmac.New(sha256.New, k.keys[k.active])
	mac.Write([]byte(domain))
	mac.Write(message)
	return sensitive.MACValue{KeyID: fmt.Sprintf("local-test-key-%d", k.active), Version: k.active, Digest: mac.Sum(nil)}, nil
}

func (k *rotatingLocalKeys) Verify(_ context.Context, domain sensitive.KeyDomain, reference sensitive.KeyReference, message, expected []byte) (bool, error) {
	if reference.KeyID != fmt.Sprintf("local-test-key-%d", reference.Version) {
		return false, nil
	}
	mac := hmac.New(sha256.New, k.keys[reference.Version])
	mac.Write([]byte(domain))
	mac.Write(message)
	return hmac.Equal(mac.Sum(nil), expected), nil
}

func TestHistoricalPasswordPepperRemainsVerifiableAfterRotation(t *testing.T) {
	keys := &rotatingLocalKeys{active: 1, keys: map[uint32][]byte{1: bytes.Repeat([]byte{1}, 32), 2: bytes.Repeat([]byte{2}, 32)}}
	phc, reference, err := NewPasswordCredential(context.Background(), keys, "correct horse battery staple")
	if err != nil || reference.Version != 1 {
		t.Fatal("version 1 credential creation failed", err)
	}
	keys.active = 2
	if !verifyPHC(context.Background(), keys, phc, "correct horse battery staple", reference) {
		t.Fatal("historical pepper credential stopped verifying")
	}
	if verifyPHC(context.Background(), keys, phc, "correct horse battery staple", sensitive.KeyReference{KeyID: "wrong-key", Version: reference.Version}) {
		t.Fatal("credential accepted wrong pepper key ID with the correct version")
	}
	_, upgraded, err := NewPasswordCredential(context.Background(), keys, "correct horse battery staple")
	if err != nil || upgraded.Version != 2 || upgraded.KeyID == reference.KeyID {
		t.Fatal("active pepper credential was not upgraded", upgraded, err)
	}
}

func TestLocalUsernameAndPasswordCanonicalContracts(t *testing.T) {
	keys := localTestKeys{key: []byte("01234567890123456789012345678901")}
	canonical, err := CanonicalLocalUsername("Admin.User")
	if err != nil || canonical != "admin.user" {
		t.Fatalf("canonical username = %q, %v", canonical, err)
	}
	for _, value := range []string{" admin", "admin ", "a", "admin\x00user", "équipe", ".admin", "admin+user"} {
		if _, err = CanonicalLocalUsername(value); err == nil {
			t.Fatalf("unsafe username accepted: %q", value)
		}
	}
	phc, reference, err := NewPasswordCredential(context.Background(), keys, "correct horse battery staple")
	if err != nil || reference.Version != 1 || reference.KeyID == "" {
		t.Fatal("password credential was not created", err)
	}
	if !verifyPHC(context.Background(), keys, phc, "correct horse battery staple", reference) {
		t.Fatal("correct password does not verify")
	}
	if verifyPHC(context.Background(), keys, phc, "incorrect horse battery", reference) {
		t.Fatal("wrong password verified")
	}
	if _, _, err = NewPasswordCredential(context.Background(), keys, "too-short"); err == nil {
		t.Fatal("short password accepted")
	}
}
