package testsupport_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestFinancialTransitUsesIndependentKeyCredentialTrustAndAvailability(t *testing.T) {
	financial, err := testsupport.NewVaultFixture("dev009-financial")
	if err != nil {
		t.Fatal(err)
	}
	defer financial.Close()
	pii, err := testsupport.NewVaultFixture("dev002-pii")
	if err != nil {
		t.Fatal(err)
	}
	defer pii.Close()
	ctx := context.Background()
	dek := bytes.Repeat([]byte{31}, 32)
	defer clear(dek)
	financeWrapper, err := financial.Wrapper()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := financeWrapper.Wrap(ctx, dek)
	if err != nil {
		t.Fatal("real financial TLS Transit wrap failed:", err)
	}
	unwrapped, err := financeWrapper.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(unwrapped, dek) {
		clear(unwrapped)
		t.Fatal("financial Transit must preserve the exact data key:", err)
	}
	clear(unwrapped)
	wrongCredential, err := sensitive.NewVaultWrapper(financial.Server.URL, financial.KeyName, pii.Token, financial.Server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongCredential.Wrap(ctx, dek); !errors.Is(err, sensitive.ErrUnavailable) {
		t.Fatal("PII credentials cannot access financial Transit:", err)
	}
	wrongTrust, err := sensitive.NewVaultWrapper(financial.Server.URL, financial.KeyName, financial.Token, pii.Server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongTrust.Wrap(ctx, dek); !errors.Is(err, sensitive.ErrUnavailable) {
		t.Fatal("PII fixture trust must not validate the independent financial server:", err)
	}
	financial.Fail.Store(true)
	if _, err := financeWrapper.Wrap(ctx, dek); !errors.Is(err, sensitive.ErrUnavailable) {
		t.Fatal("financial Transit outage must fail closed:", err)
	}
	piiWrapper, err := pii.Wrapper()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := piiWrapper.Wrap(ctx, dek); err != nil {
		t.Fatal("independent PII Transit must remain available:", err)
	}
	financial.Fail.Store(false)
	unwrapped, err = financeWrapper.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(unwrapped, dek) {
		clear(unwrapped)
		t.Fatal("recovering the same financial key must recover the prior wrap:", err)
	}
	clear(unwrapped)
}
