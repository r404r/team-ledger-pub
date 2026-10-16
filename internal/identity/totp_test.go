package identity

import (
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238SHA1VectorsAndRejectsReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		step, ok := verifyTOTP(secret, tc.code, time.Unix(tc.unix, 0), -1)
		if !ok || step != tc.unix/30 {
			t.Fatalf("time %d: step=%d ok=%v", tc.unix, step, ok)
		}
		if _, replayed := verifyTOTP(secret, tc.code, time.Unix(tc.unix, 0), step); replayed {
			t.Fatalf("time %d accepted a replayed step", tc.unix)
		}
	}
}

func TestTOTPWindowAndRecoveryCodeCanonicalization(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	previous := hotp(secret, uint64(now.Unix()/30-1), 6)
	step, ok := verifyTOTP(secret, previous, now, -1)
	if !ok || step != now.Unix()/30-1 {
		t.Fatal("one-step clock drift was rejected")
	}
	tooOld := hotp(secret, uint64(now.Unix()/30-2), 6)
	if _, ok = verifyTOTP(secret, tooOld, now, -1); ok {
		t.Fatal("two-step clock drift was accepted")
	}
	for _, invalid := range []string{"", "12345", "1234567", "１２３４５６", "12345x"} {
		if _, ok = verifyTOTP(secret, invalid, now, -1); ok {
			t.Fatalf("invalid code %q was accepted", invalid)
		}
	}
	code, err := newRecoveryCode()
	if err != nil || len(code) != 39 {
		t.Fatal("invalid generated recovery code", code, err)
	}
	canonical, err := canonicalRecoveryCode(code)
	if err != nil || len(canonical) != 32 {
		t.Fatal("generated recovery code cannot be canonicalized", err)
	}
	if _, err = canonicalRecoveryCode(canonical[:31] + "0"); err == nil {
		t.Fatal("invalid base32 recovery code was accepted")
	}
}
