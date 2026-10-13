package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func cryptoState(generation uint64, digest byte, pii uint32, pending *sensitive.KeyReference, write bool) sensitive.ReadyState {
	active, activeKeys := map[sensitive.KeyDomain]uint32{}, map[sensitive.KeyDomain]sensitive.KeyReference{}
	for _, domain := range []sensitive.KeyDomain{
		sensitive.DomainPIIPayload, sensitive.DomainInterviewPayload, sensitive.DomainAssessmentPayload,
		sensitive.DomainFinancialPayload, sensitive.DomainIdentityTransaction, sensitive.DomainIdentityMapping,
		sensitive.DomainBackupArchive, sensitive.DomainStaffCodeLookup, sensitive.DomainBonusPaymentLookup,
		sensitive.DomainIdentitySubjectLookup, sensitive.DomainCommandReceipt, sensitive.DomainAssessmentGeneration,
		sensitive.DomainCSRFToken, sensitive.DomainCursorToken, sensitive.DomainLocalUsernameLookup,
		sensitive.DomainLocalPasswordPepper,
	} {
		active[domain] = 1
		activeKeys[domain] = sensitive.KeyReference{KeyID: "00000000-0000-4000-8000-000000000001", Version: 1}
	}
	active[sensitive.DomainPIIPayload] = pii
	activeKeys[sensitive.DomainPIIPayload] = sensitive.KeyReference{KeyID: "00000000-0000-4000-8000-00000000000" + string(rune('0'+pii)), Version: pii}
	staged := map[sensitive.KeyDomain]sensitive.KeyReference{}
	if pending != nil {
		staged[sensitive.DomainPIIPayload] = *pending
	}
	return sensitive.ReadyState{MaterialGeneration: generation, Digest: strings.Repeat(string(digest), 64), Active: active, ActiveKeys: activeKeys, Staged: staged, WriteEnabled: write}
}
func TestCryptoMaterialGenerationRequiresA1A2AndFinalAcknowledgement(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
			initial := cryptoState(1, 'a', 1, nil, true)
			if err := f.Repo.VerifyOrInitializeCryptoState(ctx, initial, now); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.VerifyCryptoState(ctx, initial); err != nil {
				t.Fatal(err)
			}
			mismatch := cryptoState(2, 'b', 1, nil, true)
			if err := f.Repo.VerifyCryptoState(ctx, mismatch); err == nil {
				t.Fatal("unacknowledged keyring generation matched database")
			}
			manifest := bytes.Repeat([]byte{0x5a}, 32)
			target := sensitive.KeyReference{KeyID: "00000000-0000-4000-8000-000000000002", Version: 2}
			staged := cryptoState(2, 'b', 1, &target, false)
			if err := f.Repo.BeginCryptoStage(ctx, staged, sensitive.DomainPIIPayload, manifest, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.BeginCryptoStage(ctx, staged, sensitive.DomainPIIPayload, manifest, now.Add(time.Second)); err != nil {
				t.Fatal("idempotent A1 retry failed", err)
			}
			if err := f.Repo.VerifyCryptoState(ctx, staged); err == nil {
				t.Fatal("staged generation enabled application traffic")
			}
			activated := cryptoState(3, 'c', 2, &target, false)
			if err := f.Repo.RecordCryptoActivation(ctx, activated, sensitive.DomainPIIPayload, manifest, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.RecordCryptoActivation(ctx, activated, sensitive.DomainPIIPayload, manifest, now.Add(2*time.Second)); err != nil {
				t.Fatal("idempotent A2 retry failed", err)
			}
			acknowledged := cryptoState(4, 'd', 2, nil, true)
			if err := f.Repo.CompleteCryptoActivation(ctx, acknowledged, sensitive.DomainPIIPayload, manifest, now.Add(3*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.VerifyCryptoState(ctx, acknowledged); err != nil {
				t.Fatal("acknowledged generation unavailable", err)
			}
			for _, kind := range []string{"A1", "A2"} {
				var count int
				query := "SELECT count(*) FROM crypto_material_receipt WHERE kind=? AND manifest_digest=?"
				if backend == "postgres" {
					query = "SELECT count(*) FROM crypto_material_receipt WHERE kind=$1 AND manifest_digest=$2"
				}
				if err := f.Repo.DB.QueryRowContext(ctx, query, kind, manifest).Scan(&count); err != nil || count != 1 {
					t.Fatalf("%s receipt missing: count=%d err=%v", kind, count, err)
				}
			}
			old, proof, needed, err := f.Repo.PrepareCryptoRetirement(ctx, sensitive.DomainPIIPayload, manifest, now.Add(4*time.Second))
			if err != nil || !needed || old != initial.ActiveKeys[sensitive.DomainPIIPayload] || len(proof) != 32 {
				t.Fatal("retirement dependency proof failed", old, needed, err)
			}
			if err = f.Repo.VerifyCryptoState(ctx, acknowledged); err == nil {
				t.Fatal("retirement intent did not fence application traffic")
			}
			retired := cryptoState(5, 'e', 2, nil, true)
			if err = f.Repo.CompleteCryptoRetirement(ctx, retired, sensitive.DomainPIIPayload, old, proof, now.Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.VerifyCryptoState(ctx, retired); err != nil {
				t.Fatal("retired generation unavailable", err)
			}
		})
	}
}
