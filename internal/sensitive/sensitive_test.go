package sensitive_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

const profileLimit = 16 * 1024

var syntheticProfile = []byte(`{"display_name":"Synthetic employee","profile_summary":"SYNTHETIC-PII-ONLY"}`)

func profileContext() sensitive.Context {
	return sensitive.Context{
		OrgID:      "aaaaaaaa-1111-4111-8111-111111111111",
		EmployeeID: "bbbbbbbb-2222-4222-8222-222222222222",
		RecordID:   "cccccccc-3333-4333-8333-333333333333",
		VersionID:  "dddddddd-4444-4444-8444-444444444444",
		ObjectKind: "employee_profile", Purpose: "pii",
		SchemaType: "pii.profile.v1", SchemaVersion: 1,
	}
}

// Only the external key-service boundary is controlled. Both wrapping and
// payload authentication use real AES-GCM, never an echo or a fake cipher.
type controlledWrapper struct {
	wrapError         error
	unwrapError       error
	wrapResult        *sensitive.WrappedKey
	unwrapResult      []byte
	wrapCalls         int
	unwrapCalls       int
	wrappedPlaintexts [][]byte
}

func wrappingAEAD(version uint32) (cipher.AEAD, error) {
	if version != 1 && version != 2 {
		return nil, sensitive.ErrInvalid
	}
	key := bytes.Repeat([]byte{byte(0x30 + version)}, 32)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func wrapAAD(key sensitive.WrappedKey) []byte {
	b := []byte(key.KEKID)
	return binary.BigEndian.AppendUint32(b, key.Version)
}

func (w *controlledWrapper) Wrap(ctx context.Context, dek []byte) (sensitive.WrappedKey, error) {
	w.wrapCalls++
	if w.wrapError != nil {
		return sensitive.WrappedKey{}, w.wrapError
	}
	if err := ctx.Err(); err != nil {
		return sensitive.WrappedKey{}, err
	}
	w.wrappedPlaintexts = append(w.wrappedPlaintexts, bytes.Clone(dek))
	key := sensitive.WrappedKey{KEKID: "synthetic-pii-key", Version: 1}
	aead, err := wrappingAEAD(key.Version)
	if err != nil {
		return sensitive.WrappedKey{}, err
	}
	key.Data = aead.Seal(nil, nil, dek, wrapAAD(key))
	if w.wrapResult != nil {
		return *w.wrapResult, nil
	}
	return key, nil
}

func (w *controlledWrapper) Unwrap(ctx context.Context, key sensitive.WrappedKey) ([]byte, error) {
	w.unwrapCalls++
	if w.unwrapError != nil {
		return nil, w.unwrapError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key.KEKID != "synthetic-pii-key" {
		return nil, sensitive.ErrInvalid
	}
	aead, err := wrappingAEAD(key.Version)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, nil, key.Data, wrapAAD(key))
	if err != nil {
		return nil, sensitive.ErrInvalid
	}
	if w.unwrapResult != nil {
		clear(dek)
		return bytes.Clone(w.unwrapResult), nil
	}
	return dek, nil
}

// This independent encoder is the published wire contract, not a call to a
// production/private encoder. Interoperability catches mutually wrong Seal/Open.
func referenceAAD(t testing.TB, binding sensitive.Context) []byte {
	t.Helper()
	b := binary.BigEndian.AppendUint16([]byte("TEAMLEDGER-AAD"), 1)
	for _, id := range []string{binding.OrgID, binding.EmployeeID, binding.RecordID, binding.VersionID} {
		raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid synthetic UUID fixture")
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(raw)))
		b = append(b, raw...)
	}
	for _, field := range []string{binding.ObjectKind, binding.Purpose, binding.SchemaType} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
		b = append(b, field...)
	}
	b = binary.BigEndian.AppendUint32(b, 4)
	return binary.BigEndian.AppendUint32(b, binding.SchemaVersion)
}

func payloadAEAD(t testing.TB, dek []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal("constructing synthetic payload AES failed")
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal("constructing synthetic payload GCM failed")
	}
	return aead
}

func referenceEnvelope(t testing.TB, w *controlledWrapper) sensitive.Envelope {
	t.Helper()
	binding := profileContext()
	dek := bytes.Repeat([]byte{0x71}, 32)
	defer clear(dek)
	key, err := w.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatal("wrapping independent synthetic fixture failed")
	}
	return sensitive.Envelope{
		Context: binding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE",
		DEKID: "eeeeeeee-5555-4555-8555-555555555555", Key: key,
		SealedBytes: payloadAEAD(t, dek).Seal(nil, nil, syntheticProfile, referenceAAD(t, binding)),
	}
}

func cloneEnvelope(e sensitive.Envelope) sensitive.Envelope {
	e.Key.Data = bytes.Clone(e.Key.Data)
	e.SealedBytes = bytes.Clone(e.SealedBytes)
	return e
}

func requireOpenRejected(t testing.TB, c sensitive.Cipher, binding sensitive.Context, e sensitive.Envelope, want error) {
	t.Helper()
	plaintext, err := c.Open(context.Background(), binding, e)
	if !errors.Is(err, want) {
		t.Errorf("Open must reject with the declared error category; got category match=%t", errors.Is(err, want))
	}
	if len(plaintext) != 0 {
		t.Error("rejected Open released plaintext")
	}
}

func requireSealRejected(t testing.TB, c sensitive.Cipher, binding sensitive.Context, plaintext []byte, want error) {
	t.Helper()
	e, err := c.Seal(context.Background(), binding, plaintext)
	if !errors.Is(err, want) {
		t.Errorf("Seal must reject with the declared error category; got category match=%t", errors.Is(err, want))
	}
	if e.Context != (sensitive.Context{}) || e.FormatVersion != 0 || e.Algorithm != "" || e.DEKID != "" || e.Key.KEKID != "" || e.Key.Version != 0 || len(e.Key.Data) != 0 || len(e.SealedBytes) != 0 {
		t.Error("failed Seal returned a usable or partially populated envelope")
	}
}

func TestEnvelopeRoundTripUsesCanonicalAADAndFreshVersionKeys(t *testing.T) {
	w := &controlledWrapper{}
	c := sensitive.Cipher{Wrapper: w}
	binding := profileContext()
	first, err := c.Seal(context.Background(), binding, syntheticProfile)
	if err != nil {
		t.Fatal("valid Seal must succeed before envelope roundtrip assertions")
	}
	if first.Context != binding || first.FormatVersion != 1 || first.Algorithm != "A256GCM-RANDOMNONCE" {
		t.Fatal("Seal did not preserve the declared context and envelope format")
	}
	dekID := first.DEKID
	if len(dekID) != 36 || dekID != strings.ToLower(dekID) || dekID[8] != '-' || dekID[13] != '-' || dekID[18] != '-' || dekID[23] != '-' {
		t.Fatal("Seal must return a canonical lowercase DEK UUID")
	}
	if raw, err := hex.DecodeString(strings.ReplaceAll(dekID, "-", "")); err != nil || len(raw) != 16 {
		t.Fatal("Seal returned an invalid DEK UUID")
	}
	if len(first.SealedBytes) != len(syntheticProfile)+28 {
		t.Fatal("sealed envelope must contain exactly nonce, ciphertext and tag")
	}
	if bytes.Contains(first.SealedBytes, syntheticProfile) || bytes.Contains(first.Key.Data, syntheticProfile) {
		t.Error("envelope exposes the synthetic profile plaintext")
	}
	dek, err := w.Unwrap(context.Background(), first.Key)
	if err != nil || len(dek) != 32 {
		t.Fatal("Seal must wrap a real 256-bit DEK")
	}
	defer clear(dek)
	decoded, err := payloadAEAD(t, dek).Open(nil, nil, first.SealedBytes, referenceAAD(t, binding))
	if err != nil || !bytes.Equal(decoded, syntheticProfile) {
		t.Fatal("Seal is not interoperable with the exact canonical AAD frame")
	}
	opened, err := c.Open(context.Background(), binding, first)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("valid envelope must open to the original bytes")
	}
	binding.VersionID = "ffffffff-6666-4666-8666-666666666666"
	second, err := c.Seal(context.Background(), binding, syntheticProfile)
	if err != nil {
		t.Fatal("new immutable version must seal successfully")
	}
	if second.Context != binding || second.DEKID == first.DEKID || second.DEKID == "" {
		t.Error("new version must carry its new binding and a fresh DEK identifier")
	}
	if len(w.wrappedPlaintexts) != 2 || len(w.wrappedPlaintexts[0]) != 32 || len(w.wrappedPlaintexts[1]) != 32 {
		t.Fatal("each version must send an independent 256-bit DEK to the key service")
	}
	if bytes.Equal(w.wrappedPlaintexts[0], w.wrappedPlaintexts[1]) || bytes.Equal(first.SealedBytes, second.SealedBytes) {
		t.Error("immutable version reused its predecessor's DEK or sealed bytes")
	}
	opened, err = c.Open(context.Background(), binding, second)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("new version must open under its own binding")
	}
	requireOpenRejected(t, c, binding, first, sensitive.ErrInvalid)
	requireOpenRejected(t, c, profileContext(), second, sensitive.ErrInvalid)
}

func TestOpenAcceptsIndependentCanonicalEnvelope(t *testing.T) {
	w := &controlledWrapper{}
	e := referenceEnvelope(t, w)
	opened, err := (sensitive.Cipher{Wrapper: w}).Open(context.Background(), profileContext(), e)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("Open must authenticate the independent canonical-format envelope")
	}
}

func contextChanges() []struct {
	name   string
	change func(*sensitive.Context)
} {
	return []struct {
		name   string
		change func(*sensitive.Context)
	}{
		{"org", func(c *sensitive.Context) { c.OrgID = "12345678-1111-4111-8111-111111111111" }},
		{"employee", func(c *sensitive.Context) { c.EmployeeID = "12345678-2222-4222-8222-222222222222" }},
		{"record", func(c *sensitive.Context) { c.RecordID = "12345678-3333-4333-8333-333333333333" }},
		{"version", func(c *sensitive.Context) { c.VersionID = "12345678-4444-4444-8444-444444444444" }},
		{"object_kind", func(c *sensitive.Context) { c.ObjectKind = "interview_note" }},
		{"purpose", func(c *sensitive.Context) { c.Purpose = "compensation" }},
		{"schema_type", func(c *sensitive.Context) { c.SchemaType = "pii.profile.v2" }},
		{"schema_version", func(c *sensitive.Context) { c.SchemaVersion = 2 }},
	}
}

func TestOpenRejectsEveryContextDimensionAndForgedEnvelopeOwner(t *testing.T) {
	for _, tc := range contextChanges() {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			c := sensitive.Cipher{Wrapper: w}
			wrong := profileContext()
			tc.change(&wrong)
			requireOpenRejected(t, c, wrong, e, sensitive.ErrInvalid)
			if w.unwrapCalls != 0 {
				t.Error("binding mismatch reached the external key service")
			}
			forged := cloneEnvelope(e)
			forged.Context = wrong
			requireOpenRejected(t, c, profileContext(), forged, sensitive.ErrInvalid)
			if w.unwrapCalls != 0 {
				t.Error("envelope metadata mismatch reached the external key service")
			}
			// Matching forged owner metadata cannot rebind authenticated payload.
			requireOpenRejected(t, c, wrong, forged, sensitive.ErrInvalid)
		})
	}
}

func TestOpenRejectsTamperedPayloadAndWrappedKey(t *testing.T) {
	cases := []struct {
		name   string
		change func(*sensitive.Envelope)
	}{
		{"nonce", func(e *sensitive.Envelope) { e.SealedBytes[0] ^= 1 }},
		{"ciphertext", func(e *sensitive.Envelope) { e.SealedBytes[12] ^= 1 }},
		{"tag", func(e *sensitive.Envelope) { e.SealedBytes[len(e.SealedBytes)-1] ^= 1 }},
		{"wrapped_nonce", func(e *sensitive.Envelope) { e.Key.Data[0] ^= 1 }},
		{"wrapped_dek", func(e *sensitive.Envelope) { e.Key.Data[12] ^= 1 }},
		{"wrapped_tag", func(e *sensitive.Envelope) { e.Key.Data[len(e.Key.Data)-1] ^= 1 }},
		{"wrapped_truncation", func(e *sensitive.Envelope) { e.Key.Data = e.Key.Data[:len(e.Key.Data)-1] }},
		{"unknown_kek", func(e *sensitive.Envelope) { e.Key.KEKID = "unknown-synthetic-key" }},
		{"unknown_key_version", func(e *sensitive.Envelope) { e.Key.Version = 99 }},
		{"mismatched_key_version", func(e *sensitive.Envelope) { e.Key.Version = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			tc.change(&e)
			requireOpenRejected(t, sensitive.Cipher{Wrapper: w}, profileContext(), e, sensitive.ErrInvalid)
		})
	}
}

func TestOpenRejectsMalformedEnvelopeBeforeKeyIO(t *testing.T) {
	cases := []struct {
		name   string
		change func(*sensitive.Envelope)
	}{
		{"zero_format", func(e *sensitive.Envelope) { e.FormatVersion = 0 }},
		{"unknown_format", func(e *sensitive.Envelope) { e.FormatVersion = 2 }},
		{"empty_algorithm", func(e *sensitive.Envelope) { e.Algorithm = "" }},
		{"unknown_algorithm", func(e *sensitive.Envelope) { e.Algorithm = "A128GCM" }},
		{"missing_dek_id", func(e *sensitive.Envelope) { e.DEKID = "" }},
		{"malformed_dek_id", func(e *sensitive.Envelope) { e.DEKID = "not-a-uuid" }},
		{"noncanonical_dek_id", func(e *sensitive.Envelope) { e.DEKID = strings.ToUpper(e.DEKID) }},
		{"missing_kek_id", func(e *sensitive.Envelope) { e.Key.KEKID = "" }},
		{"zero_key_version", func(e *sensitive.Envelope) { e.Key.Version = 0 }},
		{"empty_wrapped_dek", func(e *sensitive.Envelope) { e.Key.Data = nil }},
		{"empty_sealed_bytes", func(e *sensitive.Envelope) { e.SealedBytes = nil }},
		{"missing_tag", func(e *sensitive.Envelope) { e.SealedBytes = e.SealedBytes[:27] }},
		{"oversized_payload", func(e *sensitive.Envelope) { e.SealedBytes = make([]byte, profileLimit+29) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			tc.change(&e)
			requireOpenRejected(t, sensitive.Cipher{Wrapper: w}, profileContext(), e, sensitive.ErrInvalid)
			if w.unwrapCalls != 0 {
				t.Error("malformed envelope metadata reached the external key service")
			}
		})
	}
}

func TestSealAndOpenRejectMalformedBindingBeforeKeyIO(t *testing.T) {
	setters := []struct {
		name string
		set  func(*sensitive.Context, string)
	}{
		{"org", func(c *sensitive.Context, v string) { c.OrgID = v }},
		{"employee", func(c *sensitive.Context, v string) { c.EmployeeID = v }},
		{"record", func(c *sensitive.Context, v string) { c.RecordID = v }},
		{"version", func(c *sensitive.Context, v string) { c.VersionID = v }},
	}
	for _, field := range setters {
		for _, malformed := range []struct{ name, value string }{
			{"empty", ""}, {"nonhex", "zzzzzzzz-1111-4111-8111-111111111111"},
			{"uppercase", "AAAAAAAA-1111-4111-8111-111111111111"},
			{"unhyphenated", "aaaaaaaa111141118111111111111111"},
			{"trailing_bytes", "aaaaaaaa-1111-4111-8111-111111111111\x00"},
		} {
			t.Run(field.name+"/"+malformed.name, func(t *testing.T) {
				w := &controlledWrapper{}
				e := referenceEnvelope(t, w)
				w.wrapCalls = 0
				binding := profileContext()
				field.set(&binding, malformed.value)
				e.Context = binding
				c := sensitive.Cipher{Wrapper: w}
				requireSealRejected(t, c, binding, syntheticProfile, sensitive.ErrInvalid)
				requireOpenRejected(t, c, binding, e, sensitive.ErrInvalid)
				if w.wrapCalls != 0 || w.unwrapCalls != 0 {
					t.Error("malformed UUID binding reached external key I/O")
				}
			})
		}
	}
	for _, tc := range contextChanges()[4:] {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			w.wrapCalls = 0
			binding := profileContext()
			tc.change(&binding)
			e.Context = binding
			c := sensitive.Cipher{Wrapper: w}
			requireSealRejected(t, c, binding, syntheticProfile, sensitive.ErrInvalid)
			requireOpenRejected(t, c, binding, e, sensitive.ErrInvalid)
			if w.wrapCalls != 0 || w.unwrapCalls != 0 {
				t.Error("unregistered context reached external key I/O")
			}
		})
	}
}

func TestProfileByteLimitIsEnforcedWithoutKeyIO(t *testing.T) {
	w := &controlledWrapper{}
	c := sensitive.Cipher{Wrapper: w}
	// Exactly 16 KiB of already-approved bytes. Schema validation belongs to
	// the organization service rather than the cryptographic package.
	atLimit := bytes.Repeat([]byte{'x'}, profileLimit)
	e, err := c.Seal(context.Background(), profileContext(), atLimit)
	if err != nil {
		t.Fatal("the declared maximum approved payload must seal successfully")
	}
	opened, err := c.Open(context.Background(), profileContext(), e)
	if err != nil || !bytes.Equal(opened, atLimit) {
		t.Fatal("maximum approved payload must roundtrip without truncation")
	}
	w.wrapCalls = 0
	requireSealRejected(t, c, profileContext(), make([]byte, profileLimit+1), sensitive.ErrInvalid)
	if w.wrapCalls != 0 {
		t.Error("over-limit plaintext reached external wrapping I/O")
	}
}

func TestKeyServiceErrorsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
	}{
		{"unavailable", sensitive.ErrUnavailable},
		{"transport", errors.New("synthetic external transport failure")},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			w.wrapError = tc.failure
			w.unwrapError = tc.failure
			c := sensitive.Cipher{Wrapper: w}
			requireSealRejected(t, c, profileContext(), syntheticProfile, sensitive.ErrUnavailable)
			requireOpenRejected(t, c, profileContext(), e, sensitive.ErrUnavailable)
		})
	}
	w := &controlledWrapper{}
	e := referenceEnvelope(t, w)
	// Missing key infrastructure must never become a plaintext fallback.
	requireSealRejected(t, sensitive.Cipher{}, profileContext(), syntheticProfile, sensitive.ErrUnavailable)
	requireOpenRejected(t, sensitive.Cipher{}, profileContext(), e, sensitive.ErrUnavailable)
}

func TestMalformedKeyServiceResultsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  sensitive.WrappedKey
	}{
		{"missing_kek", sensitive.WrappedKey{Version: 1, Data: []byte{1}}},
		{"zero_version", sensitive.WrappedKey{KEKID: "synthetic-pii-key", Data: []byte{1}}},
		{"missing_wrapped_key", sensitive.WrappedKey{KEKID: "synthetic-pii-key", Version: 1}},
	} {
		t.Run("wrap/"+tc.name, func(t *testing.T) {
			w := &controlledWrapper{wrapResult: &tc.key}
			requireSealRejected(t, sensitive.Cipher{Wrapper: w}, profileContext(), syntheticProfile, sensitive.ErrInvalid)
		})
	}
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		t.Run("unwrap/bytes_"+strconv.Itoa(size), func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			w.unwrapResult = make([]byte, size)
			requireOpenRejected(t, sensitive.Cipher{Wrapper: w}, profileContext(), e, sensitive.ErrInvalid)
		})
	}
}

func TestKEKRewrapPreservesAuthenticatedPayload(t *testing.T) {
	w := &controlledWrapper{}
	e := referenceEnvelope(t, w)
	dek, err := w.Unwrap(context.Background(), e.Key)
	if err != nil {
		t.Fatal("synthetic original key must unwrap")
	}
	defer clear(dek)
	rewrapped := cloneEnvelope(e)
	rewrapped.Key.Version = 2
	aead, err := wrappingAEAD(2)
	if err != nil {
		t.Fatal("synthetic rotation key unavailable")
	}
	rewrapped.Key.Data = aead.Seal(nil, nil, dek, wrapAAD(rewrapped.Key))
	opened, err := (sensitive.Cipher{Wrapper: w}).Open(context.Background(), profileContext(), rewrapped)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("valid KEK rewrap must open unchanged payload without rebinding AAD")
	}
}

func TestOpenRejectsAuthenticatedWrongDEK(t *testing.T) {
	w := &controlledWrapper{}
	e := referenceEnvelope(t, w)
	unrelatedDEK := bytes.Repeat([]byte{0x72}, 32)
	defer clear(unrelatedDEK)
	key, err := w.Wrap(context.Background(), unrelatedDEK)
	if err != nil {
		t.Fatal("independent synthetic replacement DEK must wrap")
	}
	e.Key = key
	requireOpenRejected(t, sensitive.Cipher{Wrapper: w}, profileContext(), e, sensitive.ErrInvalid)
}

func TestSealAndOpenRejectEmptyContextRegistryFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*sensitive.Context)
	}{
		{"object_kind", func(c *sensitive.Context) { c.ObjectKind = "" }},
		{"purpose", func(c *sensitive.Context) { c.Purpose = "" }},
		{"schema_type", func(c *sensitive.Context) { c.SchemaType = "" }},
		{"schema_version", func(c *sensitive.Context) { c.SchemaVersion = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &controlledWrapper{}
			e := referenceEnvelope(t, w)
			w.wrapCalls = 0
			binding := profileContext()
			tc.change(&binding)
			e.Context = binding
			c := sensitive.Cipher{Wrapper: w}
			requireSealRejected(t, c, binding, syntheticProfile, sensitive.ErrInvalid)
			requireOpenRejected(t, c, binding, e, sensitive.ErrInvalid)
			if w.wrapCalls != 0 || w.unwrapCalls != 0 {
				t.Error("empty context registry field reached external key I/O")
			}
		})
	}
}
