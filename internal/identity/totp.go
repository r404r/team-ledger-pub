package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	totpPeriod        = int64(30)
	totpSecretBytes   = 20
	totpDigits        = 6
	recoveryCodeBytes = 20
)

var ErrInvalidTOTP = errors.New("invalid TOTP")
var unpaddedBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func hotp(secret []byte, counter uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	value := binaryCode % modulus
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte(value%10) + '0'
		value /= 10
	}
	clear(digest)
	return string(out)
}

func newTOTPSecret() ([]byte, string, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		clear(secret)
		return nil, "", err
	}
	return secret, unpaddedBase32.EncodeToString(secret), nil
}

func decodeTOTPSecret(encoded string) ([]byte, error) {
	if len(encoded) != 32 || encoded != strings.ToUpper(encoded) {
		return nil, ErrInvalidTOTP
	}
	secret, err := unpaddedBase32.DecodeString(encoded)
	if err != nil || len(secret) != totpSecretBytes {
		clear(secret)
		return nil, ErrInvalidTOTP
	}
	return secret, nil
}

// verifyTOTP returns the accepted counter. A caller must persist it atomically
// and reject any value not greater than the factor's last accepted counter.
func verifyTOTP(secret []byte, code string, now time.Time, lastAccepted int64) (int64, bool) {
	if len(secret) != totpSecretBytes || len(code) != totpDigits || now.Unix() < 0 {
		return 0, false
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= lastAccepted || step < 0 {
			continue
		}
		candidate := hotp(secret, uint64(step), totpDigits)
		match := hmac.Equal([]byte(candidate), []byte(code))
		if match {
			return step, true
		}
	}
	return 0, false
}

func newRecoveryCode() (string, error) {
	raw := make([]byte, recoveryCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		clear(raw)
		return "", err
	}
	encoded := unpaddedBase32.EncodeToString(raw)
	clear(raw)
	var out strings.Builder
	out.Grow(len(encoded) + len(encoded)/4 - 1)
	for i := 0; i < len(encoded); i += 4 {
		if i != 0 {
			out.WriteByte('-')
		}
		out.WriteString(encoded[i : i+4])
	}
	return out.String(), nil
}

func canonicalRecoveryCode(value string) (string, error) {
	canonical := strings.ToUpper(strings.ReplaceAll(value, "-", ""))
	if len(canonical) != 32 {
		return "", ErrInvalidTOTP
	}
	raw, err := unpaddedBase32.DecodeString(canonical)
	if err != nil || len(raw) != recoveryCodeBytes {
		clear(raw)
		return "", ErrInvalidTOTP
	}
	clear(raw)
	return canonical, nil
}
