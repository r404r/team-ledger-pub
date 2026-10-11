package sensitive_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func interviewContexts() []sensitive.Context {
	kinds := []struct {
		kind, schema string
	}{
		{"interview_note_shared", "interview.note.v1"},
		{"interview_note_manager_private", "interview.note.v1"},
		{"interview_note_hr_confidential", "interview.note.v1"},
		{"interview_action", "interview.action.v1"},
		{"interview_reason", "interview.reason.v1"},
	}
	bindings := make([]sensitive.Context, len(kinds))
	for i, kind := range kinds {
		bindings[i] = profileContext()
		bindings[i].ObjectKind = kind.kind
		bindings[i].Purpose = "interview"
		bindings[i].SchemaType = kind.schema
	}
	return bindings
}

func TestInterviewCipherRoundTripAndIndependentAAD(t *testing.T) {
	plaintext := []byte(`{"text":"SYNTHETIC-INTERVIEW-CONTENT","edit_reason":"SYNTHETIC-CORRECTION"}`)
	for _, binding := range interviewContexts() {
		t.Run(binding.ObjectKind, func(t *testing.T) {
			w := &controlledWrapper{}
			c := sensitive.Cipher{Wrapper: w}
			aad := referenceAAD(t, binding)
			envelope, err := c.Seal(context.Background(), binding, plaintext)
			if err != nil {
				t.Fatal("valid employee-owned interview payload must seal")
			}
			if envelope.Context != binding || envelope.FormatVersion != 1 || envelope.Algorithm != "A256GCM-RANDOMNONCE" {
				t.Fatal("interview envelope must retain exact ownership, category and schema")
			}
			if len(envelope.SealedBytes) != len(plaintext)+28 || bytes.Contains(envelope.SealedBytes, plaintext) || bytes.Contains(envelope.Key.Data, plaintext) {
				t.Fatal("interview payload must use authenticated ciphertext without exposing plaintext")
			}
			opened, err := c.Open(context.Background(), binding, envelope)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("valid interview payload must open to original bytes")
			}
			clear(opened)
			dek, err := w.Unwrap(context.Background(), envelope.Key)
			if err != nil || len(dek) != 32 {
				t.Fatal("interview envelope must wrap a real 256-bit DEK")
			}
			defer clear(dek)
			opened, err = payloadAEAD(t, dek).Open(nil, nil, envelope.SealedBytes, aad)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("Seal must use the independently encoded canonical interview AAD")
			}
			clear(opened)
			external := independentOrganizationEnvelope(t, w, binding, plaintext, aad)
			opened, err = c.Open(context.Background(), binding, external)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("Open must authenticate independently encrypted interview ciphertext")
			}
			clear(opened)
			binding.VersionID = "ffffffff-6666-4666-8666-666666666666"
			second, err := c.Seal(context.Background(), binding, plaintext)
			if err != nil || second.DEKID == envelope.DEKID || bytes.Equal(second.SealedBytes, envelope.SealedBytes) {
				t.Fatal("new immutable interview payload must have fresh key identity and ciphertext")
			}
			if len(w.wrappedPlaintexts) != 3 || bytes.Equal(w.wrappedPlaintexts[0], w.wrappedPlaintexts[2]) {
				t.Fatal("new interview payload must not reuse its predecessor's DEK")
			}
			opened, err = c.Open(context.Background(), binding, second)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("new immutable interview payload must open under its own version")
			}
			clear(opened)
		})
	}
}

func TestInterviewCipherRejectsSwappedContextBeforeUnwrap(t *testing.T) {
	for _, binding := range interviewContexts() {
		for _, mutation := range contextChanges() {
			t.Run(binding.ObjectKind+"/"+mutation.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, []byte("SYNTHETIC-INTERVIEW-CONTENT"))
				if err != nil {
					t.Fatal("valid interview fixture must seal before tamper assertions")
				}
				wrong := binding
				mutation.change(&wrong)
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				forged := cloneEnvelope(envelope)
				forged.Context = wrong
				requireOpenRejected(t, c, binding, forged, sensitive.ErrInvalid)
				if w.unwrapCalls != 0 {
					t.Fatal("swapped org, employee, head, version, kind, purpose or schema reached key service")
				}
				// Matching forged UUID metadata is syntactically valid but cannot
				// rebind the original authenticated payload to another object.
				requireOpenRejected(t, c, wrong, forged, sensitive.ErrInvalid)
				validChangedContext := mutation.name == "org" || mutation.name == "employee" || mutation.name == "record" || mutation.name == "version"
				if validChangedContext && w.unwrapCalls != 1 {
					t.Error("valid-shaped forged ownership must fail real payload authentication")
				}
				if !validChangedContext && w.unwrapCalls != 0 {
					t.Error("invalid interview kind, purpose or schema must fail before unwrap")
				}
			})
		}
	}
}

func TestInterviewCipherRejectsCategoryAndLegacyCiphertextSwaps(t *testing.T) {
	bindings := append(interviewContexts(), organizationContexts()...)
	bindings = append(bindings, profileContext())
	for _, source := range bindings {
		for _, target := range bindings {
			if source.ObjectKind == target.ObjectKind || (source.Purpose == "pii" && target.Purpose == "pii") {
				continue
			}
			t.Run(source.ObjectKind+"_to_"+target.ObjectKind, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), source, []byte("SYNTHETIC-CROSS-CATEGORY-CONTENT"))
				if err != nil {
					t.Fatal("valid category fixture must seal before ciphertext swap")
				}
				requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 0 {
					t.Fatal("category or legacy/interview context swap reached unwrap")
				}
				// Swap the original key and ciphertext together, so a wrong DEK
				// cannot hide a missing category or purpose AAD binding.
				envelope.Context = target
				requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 1 {
					t.Error("matching valid forged category must fail actual AEAD authentication")
				}
			})
		}
	}
}

func TestInterviewCipherRejectsInvalidFiniteContextsBeforeKeyIO(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*sensitive.Context)
	}{
		{"blank_org", func(c *sensitive.Context) { c.OrgID = "" }},
		{"blank_employee", func(c *sensitive.Context) { c.EmployeeID = "" }},
		{"blank_head", func(c *sensitive.Context) { c.RecordID = "" }},
		{"blank_version", func(c *sensitive.Context) { c.VersionID = "" }},
		{"uppercase_org", func(c *sensitive.Context) { c.OrgID = strings.ToUpper(c.OrgID) }},
		{"uppercase_employee", func(c *sensitive.Context) { c.EmployeeID = strings.ToUpper(c.EmployeeID) }},
		{"uppercase_head", func(c *sensitive.Context) { c.RecordID = strings.ToUpper(c.RecordID) }},
		{"uppercase_version", func(c *sensitive.Context) { c.VersionID = strings.ToUpper(c.VersionID) }},
		{"malformed_employee", func(c *sensitive.Context) { c.EmployeeID = "not-a-uuid" }},
		{"blank_kind", func(c *sensitive.Context) { c.ObjectKind = "" }},
		{"generic_note_kind", func(c *sensitive.Context) { c.ObjectKind = "interview_note" }},
		{"unknown_category", func(c *sensitive.Context) { c.ObjectKind = "interview_note_financial" }},
		{"blank_purpose", func(c *sensitive.Context) { c.Purpose = "" }},
		{"legacy_purpose", func(c *sensitive.Context) { c.Purpose = "pii" }},
		{"authorization_purpose", func(c *sensitive.Context) { c.Purpose = "interview_followup" }},
		{"blank_schema", func(c *sensitive.Context) { c.SchemaType = "" }},
		{"legacy_schema", func(c *sensitive.Context) { c.SchemaType = "pii.profile.v1" }},
		{"unknown_schema", func(c *sensitive.Context) { c.SchemaType = "interview.unknown.v1" }},
		{"schema_version_zero", func(c *sensitive.Context) { c.SchemaVersion = 0 }},
		{"schema_version_two", func(c *sensitive.Context) { c.SchemaVersion = 2 }},
	}
	for _, binding := range interviewContexts() {
		for _, mutation := range mutations {
			t.Run(binding.ObjectKind+"/"+mutation.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, []byte("SYNTHETIC-INTERVIEW-CONTENT"))
				if err != nil {
					t.Fatal("valid interview fixture must seal before invalid context assertion")
				}
				wrong := binding
				mutation.change(&wrong)
				requireSealRejected(t, c, wrong, []byte("SYNTHETIC-INTERVIEW-CONTENT"), sensitive.ErrInvalid)
				envelope.Context = wrong
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				if w.wrapCalls != 1 || w.unwrapCalls != 0 {
					t.Error("invalid finite interview context must not perform key I/O")
				}
			})
		}
		for _, schema := range []string{"interview.note.v1", "interview.action.v1", "interview.reason.v1"} {
			if schema == binding.SchemaType {
				continue
			}
			t.Run(binding.ObjectKind+"/wrong_"+schema, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				wrong := binding
				wrong.SchemaType = schema
				envelope := independentOrganizationEnvelope(t, w, wrong, []byte("SYNTHETIC-INTERVIEW-CONTENT"), referenceAAD(t, wrong))
				requireSealRejected(t, c, wrong, []byte("SYNTHETIC-INTERVIEW-CONTENT"), sensitive.ErrInvalid)
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				if w.wrapCalls != 1 || w.unwrapCalls != 0 {
					t.Error("wrong interview family/schema pair must be rejected before key I/O")
				}
			})
		}
	}
	for _, binding := range append(organizationContexts(), profileContext()) {
		t.Run(binding.ObjectKind+"/interview_purpose", func(t *testing.T) {
			w := &controlledWrapper{}
			c := sensitive.Cipher{Wrapper: w}
			binding.Purpose = "interview"
			envelope := independentOrganizationEnvelope(t, w, binding, syntheticProfile, organizationReferenceAAD(t, binding))
			requireSealRejected(t, c, binding, syntheticProfile, sensitive.ErrInvalid)
			requireOpenRejected(t, c, binding, envelope, sensitive.ErrInvalid)
			if w.wrapCalls != 1 || w.unwrapCalls != 0 {
				t.Error("interview purpose must not broaden any legacy PII family")
			}
		})
	}
}

func TestInterviewCipherRejectsPayloadAndWrappedKeyTampering(t *testing.T) {
	mutations := []struct {
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
		{"wrong_kek", func(e *sensitive.Envelope) { e.Key.KEKID = "unknown-interview-key" }},
		{"wrong_kek_version", func(e *sensitive.Envelope) { e.Key.Version = 2 }},
	}
	for _, binding := range interviewContexts() {
		for _, mutation := range mutations {
			t.Run(binding.ObjectKind+"/"+mutation.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, []byte("SYNTHETIC-INTERVIEW-CONTENT"))
				if err != nil {
					t.Fatal("valid interview fixture must seal before cryptographic tampering")
				}
				mutation.change(&envelope)
				requireOpenRejected(t, c, binding, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 1 {
					t.Error("tamper test must exercise real AES payload or wrapper authentication")
				}
			})
		}
	}
}
