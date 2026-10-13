package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	pepper, err := localPasswordMAC(context.Background(), keys, "correct horse battery staple")
	if err != nil || !verifyPHC(phc, pepper.Digest) {
		t.Fatal("correct password does not verify")
	}
	clear(pepper.Digest)
	wrong, err := localPasswordMAC(context.Background(), keys, "incorrect horse battery")
	if err != nil || verifyPHC(phc, wrong.Digest) {
		t.Fatal("wrong password verified")
	}
	clear(wrong.Digest)
	if _, _, err = NewPasswordCredential(context.Background(), keys, "too-short"); err == nil {
		t.Fatal("short password accepted")
	}
}
