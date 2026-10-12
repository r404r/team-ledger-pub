package sensitive_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func compensationContexts() []sensitive.Context {
	var result []sensitive.Context
	for _, pair := range []struct{ kind, schema string }{
		{"compensation_proposal", "compensation.proposal.v1"},
		{"compensation_terms", "compensation.terms.v1"},
		{"compensation_decision", "compensation.decision.v1"},
	} {
		binding := profileContext()
		binding.ObjectKind, binding.Purpose, binding.SchemaType = pair.kind, "financial", pair.schema
		result = append(result, binding)
	}
	return result
}

func TestCompensationCipherUsesIndependentCanonicalAAD(t *testing.T) {
	plaintext := []byte(`{"reason":"SYNTHETIC_FINANCIAL_REASON","amount_minor":"9007199254740993"}`)
	for _, binding := range compensationContexts() {
		t.Run(binding.ObjectKind, func(t *testing.T) {
			w := &controlledWrapper{}
			c := sensitive.Cipher{Wrapper: w}
			aad := referenceAAD(t, binding)
			envelope, err := c.Seal(context.Background(), binding, plaintext)
			if err != nil || envelope.Context != binding || bytes.Contains(envelope.SealedBytes, plaintext) {
				t.Fatal("finite financial payload failed to seal with its employee owner")
			}
			dek, err := w.Unwrap(context.Background(), envelope.Key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(dek)
			opened, err := payloadAEAD(t, dek).Open(nil, nil, envelope.SealedBytes, aad)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("financial Seal used incompatible canonical AAD")
			}
			clear(opened)
			external := independentOrganizationEnvelope(t, w, binding, plaintext, aad)
			opened, err = c.Open(context.Background(), binding, external)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatal("financial Open rejected independently encoded legacy-format AAD")
			}
			clear(opened)
		})
	}
}

func TestCompensationCipherRejectsOwnerPurposeAndSchemaMutation(t *testing.T) {
	for _, binding := range compensationContexts() {
		for _, mutation := range contextChanges() {
			t.Run(binding.ObjectKind+"/"+mutation.name, func(t *testing.T) {
				w := &controlledWrapper{}
				c := sensitive.Cipher{Wrapper: w}
				envelope, err := c.Seal(context.Background(), binding, []byte("SYNTHETIC_FINANCIAL_PAYLOAD"))
				if err != nil {
					t.Fatal(err)
				}
				wrong := binding
				mutation.change(&wrong)
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				if w.unwrapCalls != 0 {
					t.Fatal("context mismatch reached financial key service")
				}
				envelope.Context = wrong
				requireOpenRejected(t, c, wrong, envelope, sensitive.ErrInvalid)
				ownerMutation := mutation.name == "org" || mutation.name == "employee" || mutation.name == "record" || mutation.name == "version"
				if ownerMutation && w.unwrapCalls != 1 || !ownerMutation && w.unwrapCalls != 0 {
					t.Fatal("forged valid owner must fail AEAD; invalid kind/purpose/schema must fail before key I/O")
				}
			})
		}
	}
}

func TestCompensationCipherFiniteSchemasAndCrossPurposeIsolation(t *testing.T) {
	for _, source := range compensationContexts() {
		for _, mutate := range []func(*sensitive.Context){
			func(c *sensitive.Context) { c.EmployeeID = "" },
			func(c *sensitive.Context) { c.ObjectKind = "compensation_event" },
			func(c *sensitive.Context) { c.ObjectKind = "compensation_term" },
			func(c *sensitive.Context) { c.ObjectKind = "bonus_award" },
			func(c *sensitive.Context) { c.Purpose = "compensation_management" },
			func(c *sensitive.Context) { c.Purpose = "interview" },
			func(c *sensitive.Context) { c.SchemaType = "compensation.memo.v1" },
			func(c *sensitive.Context) { c.SchemaVersion = 2 },
		} {
			w := &controlledWrapper{}
			wrong := source
			mutate(&wrong)
			requireSealRejected(t, sensitive.Cipher{Wrapper: w}, wrong, []byte("SYNTHETIC_FINANCIAL_PAYLOAD"), sensitive.ErrInvalid)
			if w.wrapCalls != 0 {
				t.Fatal("unsupported finite financial binding reached wrap")
			}
		}
		for _, other := range compensationContexts() {
			if other.SchemaType == source.SchemaType {
				continue
			}
			w := &controlledWrapper{}
			wrong := source
			wrong.SchemaType = other.SchemaType
			requireSealRejected(t, sensitive.Cipher{Wrapper: w}, wrong, []byte("SYNTHETIC_FINANCIAL_PAYLOAD"), sensitive.ErrInvalid)
			if w.wrapCalls != 0 {
				t.Fatal("financial kind/schema mismatch reached wrap")
			}
		}
		for _, target := range append(append(compensationContexts(), interviewContexts()...), profileContext()) {
			if source == target {
				continue
			}
			w := &controlledWrapper{}
			c := sensitive.Cipher{Wrapper: w}
			envelope, err := c.Seal(context.Background(), source, []byte("SYNTHETIC_FINANCIAL_PAYLOAD"))
			if err != nil {
				t.Fatal(err)
			}
			requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
			if w.unwrapCalls != 0 {
				t.Fatal("financial/interview/PII context swap reached unwrap")
			}
			envelope.Context = target
			requireOpenRejected(t, c, target, envelope, sensitive.ErrInvalid)
			if w.unwrapCalls != 1 {
				t.Fatal("valid forged category binding did not reach authenticated payload rejection")
			}
		}
	}
}
