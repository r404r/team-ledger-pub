package sensitive_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func organizationContexts() []sensitive.Context {
	team := profileContext()
	team.EmployeeID = ""
	team.ObjectKind = "team_label"
	team.SchemaType = "org.team.label.v1"
	position := profileContext()
	position.ObjectKind = "position_assignment"
	position.SchemaType = "org.position.v1"
	change := profileContext()
	change.EmployeeID = ""
	change.ObjectKind = "structure_change"
	change.SchemaType = "org.structure.reason.v1"
	return []sensitive.Context{team, position, change}
}

// Encode the published frames independently, including the zero-length owner
// frame for organization objects rather than a substituted employee UUID.
func organizationReferenceAAD(t testing.TB, binding sensitive.Context) []byte {
	t.Helper()
	b := binary.BigEndian.AppendUint16([]byte("TEAMLEDGER-AAD"), 1)
	for i, id := range []string{binding.OrgID, binding.EmployeeID, binding.RecordID, binding.VersionID} {
		if i == 1 && id == "" {
			b = binary.BigEndian.AppendUint32(b, 0)
			continue
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(raw) != 16 {
			t.Fatal("invalid synthetic UUID fixture")
		}
		b = binary.BigEndian.AppendUint32(b, 16)
		b = append(b, raw...)
	}
	for _, field := range []string{binding.ObjectKind, binding.Purpose, binding.SchemaType} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
		b = append(b, field...)
	}
	b = binary.BigEndian.AppendUint32(b, 4)
	return binary.BigEndian.AppendUint32(b, binding.SchemaVersion)
}

func independentOrganizationEnvelope(t testing.TB, w *controlledWrapper, binding sensitive.Context, plaintext, aad []byte) sensitive.Envelope {
	t.Helper()
	dek := bytes.Repeat([]byte{0x71}, 32)
	defer clear(dek)
	key, err := w.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatal("wrapping independent synthetic fixture failed")
	}
	return sensitive.Envelope{
		Context: binding, FormatVersion: 1, Algorithm: "A256GCM-RANDOMNONCE",
		DEKID: "eeeeeeee-5555-4555-8555-555555555555", Key: key,
		SealedBytes: payloadAEAD(t, dek).Seal(nil, nil, plaintext, aad),
	}
}

func TestOrganizationCipherRoundTripAndIndependentAAD(t *testing.T) {
	payloads := [][]byte{
		[]byte(`"SYNTHETIC-TEAM-LABEL"`),
		[]byte(`{"title":"SYNTHETIC-POSITION","description":"SYNTHETIC-DESCRIPTION"}`),
		[]byte(`"SYNTHETIC-STRUCTURE-REASON"`),
	}
	for i, binding := range organizationContexts() {
		t.Run(binding.ObjectKind, func(t *testing.T) {
			w := &controlledWrapper{}
			c := sensitive.Cipher{Wrapper: w}
			plaintext := payloads[i]
			aad := organizationReferenceAAD(t, binding)
			envelope, err := c.Seal(context.Background(), binding, plaintext)
			if err != nil {
				t.Fatal("valid organization payload must seal")
			}
			if envelope.Context != binding || envelope.FormatVersion != 1 || envelope.Algorithm != "A256GCM-RANDOMNONCE" {
				t.Fatal("organization envelope did not retain exact binding and format")
			}
			if len(envelope.SealedBytes) != len(plaintext)+28 || bytes.Contains(envelope.SealedBytes, plaintext) || bytes.Contains(envelope.Key.Data, plaintext) {
				t.Fatal("organization envelope must contain real authenticated ciphertext without plaintext")
			}
			opened, err := c.Open(context.Background(), binding, envelope)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("valid organization payload must open to original bytes")
			}
			clear(opened)
			dek, err := w.Unwrap(context.Background(), envelope.Key)
			if err != nil {
				t.Fatal("organization envelope must wrap a real DEK")
			}
			defer clear(dek)
			opened, err = payloadAEAD(t, dek).Open(nil, nil, envelope.SealedBytes, aad)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("Seal must use independently encoded organization AAD")
			}
			clear(opened)
			external := independentOrganizationEnvelope(t, w, binding, plaintext, aad)
			opened, err = c.Open(context.Background(), binding, external)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("Open must authenticate independently encrypted organization payload")
			}
			clear(opened)
			second, err := c.Seal(context.Background(), binding, plaintext)
			if err != nil || second.DEKID == envelope.DEKID || bytes.Equal(second.SealedBytes, envelope.SealedBytes) {
				t.Fatal("each organization payload must use a fresh DEK and ciphertext")
			}
			if len(w.wrappedPlaintexts) != 3 || bytes.Equal(w.wrappedPlaintexts[0], w.wrappedPlaintexts[2]) {
				t.Fatal("organization Seal must generate fresh key material")
			}
			if binding.EmployeeID == "" {
				// The employee frame follows magic, format, and the org frame.
				ownerOffset := len("TEAMLEDGER-AAD") + 2 + 4 + 16
				if binary.BigEndian.Uint32(aad[ownerOffset:ownerOffset+4]) != 0 {
					t.Fatal("organization-owned AAD must have an empty employee frame")
				}
				fakeOwner := binding
				fakeOwner.EmployeeID = profileContext().EmployeeID
				wrongAAD := organizationReferenceAAD(t, fakeOwner)
				if decoded, err := payloadAEAD(t, dek).Open(nil, nil, envelope.SealedBytes, wrongAAD); err == nil || len(decoded) != 0 {
					t.Fatal("organization ciphertext must not authenticate a fake employee frame")
				}
			}
		})
	}
}

func TestEmployeeProfileVersionTwoAADBytesRemainStable(t *testing.T) {
	// Frozen v2 bytes, not computed from production metadata.
	golden, err := hex.DecodeString("5445414d4c45444745522d4141440001" +
		"00000010aaaaaaaa111141118111111111111111" +
		"00000010bbbbbbbb222242228222222222222222" +
		"00000010cccccccc333343338333333333333333" +
		"00000010dddddddd444444448444444444444444" +
		"00000010656d706c6f7965655f70726f66696c65" +
		"00000003706969" +
		"0000000e7069692e70726f66696c652e7632" +
		"0000000400000001")
	if err != nil {
		t.Fatal("invalid frozen profile AAD fixture")
	}
	w := &controlledWrapper{}
	c := sensitive.Cipher{Wrapper: w}
	binding := profileContext()
	legacy := independentOrganizationEnvelope(t, w, binding, syntheticProfile, golden)
	opened, err := c.Open(context.Background(), binding, legacy)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("profile v2 ciphertext must authenticate exact AAD")
	}
	clear(opened)
	current, err := c.Seal(context.Background(), binding, syntheticProfile)
	if err != nil {
		t.Fatal("profile Seal must accept the v2 context")
	}
	dek, err := w.Unwrap(context.Background(), current.Key)
	if err != nil {
		t.Fatal("profile key must unwrap")
	}
	defer clear(dek)
	opened, err = payloadAEAD(t, dek).Open(nil, nil, current.SealedBytes, golden)
	if err != nil || !bytes.Equal(opened, syntheticProfile) {
		t.Fatal("profile Seal changed the exact frozen v2 AAD bytes")
	}
	clear(opened)
}

func TestOrganizationCipherRejectsEveryTamperedContextDimension(t *testing.T) {
	for _, binding := range organizationContexts() {
		for _, mutation := range contextChanges() {
			t.Run(binding.ObjectKind+"/"+mutation.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, syntheticProfile)
				if err != nil {
					t.Fatal("valid organization fixture must seal")
				}
				wrong := binding
				mutation.change(&wrong)
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				forged := cloneEnvelope(envelope)
				forged.Context = wrong
				requireOpenRejected(t, c, binding, forged, sensitive.ErrInvalid)
				if w.unwrapCalls != 0 {
					t.Fatal("ownership or metadata mismatch reached the external key service")
				}
				// Even matching forged metadata cannot rebind authenticated bytes.
				requireOpenRejected(t, c, wrong, forged, sensitive.ErrInvalid)
				validChangedContext := mutation.name == "org" || mutation.name == "record" || mutation.name == "version" || (mutation.name == "employee" && binding.ObjectKind == "position_assignment")
				if validChangedContext && w.unwrapCalls != 1 {
					t.Error("valid-shaped forged metadata must be rejected by real payload authentication")
				}
				if !validChangedContext && w.unwrapCalls != 0 {
					t.Error("invalid organization metadata must fail before key I/O")
				}
			})
		}
	}
}

func TestOrganizationCipherRejectsCrossTypeCiphertextSwaps(t *testing.T) {
	bindings := append(organizationContexts(), profileContext())
	for _, source := range bindings {
		for _, target := range bindings {
			if source.ObjectKind == target.ObjectKind {
				continue
			}
			t.Run(source.ObjectKind+"_to_"+target.ObjectKind, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), source, syntheticProfile)
				if err != nil {
					t.Fatal("cross-type source must seal")
				}
				requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 0 {
					t.Fatal("cross-type metadata mismatch reached the external key service")
				}
				// Carry the actual original key and ciphertext together, so a
				// wrong DEK cannot mask a failure to authenticate the object type.
				envelope.Context = target
				requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 1 {
					t.Error("forged valid target must fail real cross-type payload authentication")
				}
			})
		}
	}
}

func TestOrganizationCipherRejectsInvalidContextsBeforeKeyIO(t *testing.T) {
	type mutation struct {
		name   string
		change func(*sensitive.Context)
	}
	for _, binding := range append(organizationContexts(), profileContext()) {
		invalid := []mutation{
			{"blank_org", func(c *sensitive.Context) { c.OrgID = "" }},
			{"blank_record", func(c *sensitive.Context) { c.RecordID = "" }},
			{"blank_version", func(c *sensitive.Context) { c.VersionID = "" }},
			{"uppercase_org", func(c *sensitive.Context) { c.OrgID = strings.ToUpper(c.OrgID) }},
			{"uppercase_record", func(c *sensitive.Context) { c.RecordID = strings.ToUpper(c.RecordID) }},
			{"uppercase_version", func(c *sensitive.Context) { c.VersionID = strings.ToUpper(c.VersionID) }},
			{"malformed_org", func(c *sensitive.Context) { c.OrgID = "not-a-uuid" }},
			{"malformed_record", func(c *sensitive.Context) { c.RecordID = "not-a-uuid" }},
			{"malformed_version", func(c *sensitive.Context) { c.VersionID = "not-a-uuid" }},
			{"unknown_kind", func(c *sensitive.Context) { c.ObjectKind = "team" }},
			{"blank_kind", func(c *sensitive.Context) { c.ObjectKind = "" }},
			{"unknown_schema", func(c *sensitive.Context) { c.SchemaType = "org.unknown.v1" }},
			{"blank_schema", func(c *sensitive.Context) { c.SchemaType = "" }},
			{"schema_version_zero", func(c *sensitive.Context) { c.SchemaVersion = 0 }},
			{"schema_version_two", func(c *sensitive.Context) { c.SchemaVersion = 2 }},
			{"blank_purpose", func(c *sensitive.Context) { c.Purpose = "" }},
			{"wrong_purpose", func(c *sensitive.Context) { c.Purpose = "metadata" }},
		}
		if binding.EmployeeID == "" {
			invalid = append(invalid,
				mutation{"fake_employee_owner", func(c *sensitive.Context) { c.EmployeeID = profileContext().EmployeeID }},
				mutation{"nil_uuid_employee_owner", func(c *sensitive.Context) { c.EmployeeID = "00000000-0000-0000-0000-000000000000" }},
				mutation{"whitespace_owner", func(c *sensitive.Context) { c.EmployeeID = " " }},
			)
		} else {
			invalid = append(invalid,
				mutation{"blank_employee_owner", func(c *sensitive.Context) { c.EmployeeID = "" }},
				mutation{"uppercase_employee_owner", func(c *sensitive.Context) { c.EmployeeID = strings.ToUpper(c.EmployeeID) }},
				mutation{"malformed_employee_owner", func(c *sensitive.Context) { c.EmployeeID = "not-a-uuid" }},
			)
		}
		for _, other := range append(organizationContexts(), profileContext()) {
			if binding.SchemaType != other.SchemaType {
				invalid = append(invalid, mutation{"wrong_schema_" + other.ObjectKind, func(c *sensitive.Context) { c.SchemaType = other.SchemaType }})
			}
		}
		for _, tc := range invalid {
			t.Run(binding.ObjectKind+"/"+tc.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, syntheticProfile)
				if err != nil {
					t.Fatal("valid fixture must seal before malformed context assertions")
				}
				w.wrapCalls = 0
				wrong := binding
				tc.change(&wrong)
				envelope.Context = wrong
				requireSealRejected(t, c, wrong, syntheticProfile, sensitive.ErrInvalid)
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				if w.wrapCalls != 0 || w.unwrapCalls != 0 {
					t.Error("invalid ownership, UUID, or finite schema context reached external key I/O")
				}
			})
		}
	}
}
