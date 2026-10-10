package sensitive_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func FuzzEnvelopeBindingsAndMalformedInput(f *testing.F) {
	fixture := referenceEnvelope(f, &controlledWrapper{})
	opened, err := (sensitive.Cipher{Wrapper: &controlledWrapper{}}).Open(context.Background(), profileContext(), fixture)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		f.Fatal("fuzz prerequisite: real Open must accept the independent canonical envelope")
	}
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0, 255, 0, 128}, uint8(1))
	f.Add([]byte("not-a-uuid"), uint8(2))
	f.Add([]byte("A256GCM-RANDOMNONCE"), uint8(3))
	f.Add(bytes.Clone(fixture.SealedBytes[:27]), uint8(4))
	f.Add(bytes.Clone(fixture.Key.Data), uint8(5))
	f.Add([]byte("pii.profile.v1\x00"), uint8(6))
	f.Add([]byte("aaaaaaaa-1111-4111-8111-111111111111"), uint8(7))
	f.Fuzz(func(t *testing.T, raw []byte, selector uint8) {
		// Bound every exercised string/blob and all crypto work independently
		// of the engine's generated input size. Panics fail the fuzz case.
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		c := sensitive.Cipher{Wrapper: &controlledWrapper{}}
		wrong := profileContext()
		changes := contextChanges()
		changes[int(selector)%len(changes)].change(&wrong)
		requireOpenRejected(t, c, wrong, cloneEnvelope(fixture), sensitive.ErrInvalid)
		forged := cloneEnvelope(fixture)
		forged.Context = wrong
		requireOpenRejected(t, c, wrong, forged, sensitive.ErrInvalid)

		malformedBinding := profileContext()
		malformedBinding.OrgID = "!" + string(raw)
		requireSealRejected(t, c, malformedBinding, raw, sensitive.ErrInvalid)
		malformed := cloneEnvelope(fixture)
		malformed.Context = malformedBinding
		requireOpenRejected(t, c, malformedBinding, malformed, sensitive.ErrInvalid)

		arbitrary := cloneEnvelope(fixture)
		switch selector % 12 {
		case 0:
			arbitrary.SealedBytes = bytes.Clone(raw)
		case 1:
			arbitrary.Key.Data = bytes.Clone(raw)
		case 2:
			arbitrary.Key.KEKID = string(raw)
		case 3:
			arbitrary.Algorithm = string(raw)
		case 4:
			arbitrary.DEKID = string(raw)
		case 5:
			arbitrary.Context.OrgID = string(raw)
		case 6:
			arbitrary.Context.SchemaType = string(raw)
		case 7:
			arbitrary.Context.Purpose = string(raw)
		case 8:
			arbitrary.Context.ObjectKind = string(raw)
		case 9:
			arbitrary.FormatVersion = uint16(selector)
			if len(raw) >= 2 {
				arbitrary.FormatVersion = binary.BigEndian.Uint16(raw[:2])
			}
		case 10:
			arbitrary.Key.Version = uint32(selector)
			if len(raw) >= 4 {
				arbitrary.Key.Version = binary.BigEndian.Uint32(raw[:4])
			}
		case 11:
			arbitrary.Context.SchemaVersion = uint32(selector)
			if len(raw) >= 4 {
				arbitrary.Context.SchemaVersion = binary.BigEndian.Uint32(raw[:4])
			}
		}
		plaintext, err := c.Open(context.Background(), profileContext(), arbitrary)
		if err != nil && len(plaintext) != 0 {
			t.Fatal("malformed envelope released plaintext while reporting failure")
		}
		if err == nil && !bytes.Equal(plaintext, syntheticProfile) {
			t.Fatal("arbitrary envelope released unauthenticated or altered plaintext")
		}
		if arbitrary.Context != profileContext() && (!errors.Is(err, sensitive.ErrInvalid) || len(plaintext) != 0) {
			t.Fatal("arbitrary context mismatch was not rejected without plaintext")
		}
	})
}
