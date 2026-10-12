package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func privateFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func commandRequest(who testsupport.Credential) compensation.Request {
	return compensation.Request{TokenHash: who.Hash, Purpose: "compensation_management", Key: value.NewID(), RequestID: value.NewID()}
}

func approvalFiles(t *testing.T, org string, version int64, keyID, approver string) (string, []byte, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := value.NewID()
	payload := maintenanceApprovalPayload{OrgID: org, TargetVersion: version, TargetKeyID: keyID, ApprovedBySubjectID: approver, RequestID: requestID, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	document := maintenanceApprovalDocument{OrgID: payload.OrgID, TargetVersion: payload.TargetVersion, TargetKeyID: payload.TargetKeyID, ApprovedBySubjectID: payload.ApprovedBySubjectID, RequestID: payload.RequestID, ExpiresAt: payload.ExpiresAt, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := json.Marshal(maintenanceApprovalTrust{Authorities: []maintenanceApprovalAuthority{{SubjectID: approver, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}}})
	if err != nil {
		t.Fatal(err)
	}
	return privateFile(t, "approval.json", raw), trust, requestID
}

func TestBonusHMACCLIReindexesExistingEncryptedPayment(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	created, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_BONUS_CLI"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	employeeID := created.ID
	award, err := f.Compensation.CreateBonusAward(ctx, commandRequest(f.BonusW), employeeID, compensation.BonusAwardCommand{BonusRevision: "0", Award: compensation.BonusAwardPayload{PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Category: "spot", Reason: "SYNTHETIC", Amount: compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: "100"}}})
	if err != nil {
		t.Fatal(err)
	}
	award, err = f.Compensation.TransitionBonusAward(ctx, commandRequest(f.BonusW), award.ID, compensation.BonusAwardTransition{Action: "submit", Revision: award.Revision, BonusRevision: award.BonusRevision})
	if err != nil {
		t.Fatal(err)
	}
	award, err = f.Compensation.TransitionBonusAward(ctx, commandRequest(f.BonusApprover), award.ID, compensation.BonusAwardTransition{Action: "approve", Revision: award.Revision, BonusRevision: award.BonusRevision, DecisionReason: "SYNTHETIC"})
	if err != nil {
		t.Fatal(err)
	}
	payment, err := f.Compensation.RecordBonusPayment(ctx, commandRequest(f.BonusPayW), employeeID, compensation.BonusPaymentCommand{BonusRevision: "3", BusinessSource: "fixture_payroll", ExternalFactID: "cli-stable", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt", Reason: "SYNTHETIC", Amount: compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: "40"}, AwardID: &award.ID})
	if err != nil {
		t.Fatal(err)
	}
	key2 := []byte("23456789012345678901234567890123")
	approvalFile, approvalTrust, approvalRequestID := approvalFiles(t, f.OrgID, 2, "bonus-payment-v2", f.BonusApprover.SubjectID)
	args := []string{"reindex", "-backend", "sqlite", "-dsn-file", privateFile(t, "dsn", []byte(f.DSN)), "-vault-endpoint", f.FinancialKMS.Server.URL, "-vault-key", f.FinancialKMS.KeyName, "-vault-token-file", privateFile(t, "token", []byte(f.FinancialKMS.Token)), "-hmac-key-file", privateFile(t, "hmac", key2), "-approval-file", approvalFile, "-org-id", f.OrgID, "-target-version", "2", "-target-key-id", "bonus-payment-v2"}
	if err = runWithTrust(args, f.FinancialKMS.Server.Client(), approvalTrust); err != nil {
		t.Fatal("real CLI reindex", err)
	}
	var approvedBy string
	var actorUID int64
	if err = f.Repo.DB.QueryRow("SELECT approved_by_subject_id,actor_uid FROM bonus_hmac_maintenance_audit WHERE org_id=? AND request_id=?", f.OrgID, approvalRequestID).Scan(&approvedBy, &actorUID); err != nil || approvedBy != f.BonusApprover.SubjectID || actorUID != int64(os.Geteuid()) {
		t.Fatal("maintenance approval and kernel operator were not audited separately", err)
	}
	f.Compensation.BonusHMACKeys[2] = key2
	f.Compensation.BonusHMACKeyIDs[2] = "bonus-payment-v2"
	f.Compensation.BonusHMACActive = 2
	replayed, err := f.Compensation.RecordBonusPayment(ctx, commandRequest(f.BonusPayW), employeeID, compensation.BonusPaymentCommand{BonusRevision: "3", BusinessSource: "fixture_payroll", ExternalFactID: "cli-stable", Kind: "payment", PaidDate: "2026-02-01", EvidenceReference: "receipt", Reason: "SYNTHETIC", Amount: compensation.BonusMoney{Currency: "USD", Scale: 2, AmountMinor: "40"}, AwardID: &award.ID})
	if err != nil || replayed.ID != payment.ID {
		t.Fatal("reindexed business replay", replayed, err)
	}
}

func TestBonusHMACApprovalRejectsTamperingAndUntrustedSigner(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	org, approver, requestID := value.NewID(), value.NewID(), value.NewID()
	payload := maintenanceApprovalPayload{OrgID: org, TargetVersion: 2, TargetKeyID: "bonus-payment-v2", ApprovedBySubjectID: approver, RequestID: requestID, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	canonical, _ := json.Marshal(payload)
	valid := maintenanceApprovalDocument{OrgID: org, TargetVersion: 2, TargetKeyID: payload.TargetKeyID, ApprovedBySubjectID: approver, RequestID: requestID, ExpiresAt: payload.ExpiresAt, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
	trust, _ := json.Marshal(maintenanceApprovalTrust{Authorities: []maintenanceApprovalAuthority{{SubjectID: approver, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}}})
	tampered := valid
	tampered.TargetVersion = 3
	raw, _ := json.Marshal(tampered)
	if _, err = verifyMaintenanceApproval(raw, trust, time.Now(), org, 3, payload.TargetKeyID); err == nil {
		t.Fatal("tampered approved target version accepted")
	}
	replacement, _, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatal(genErr)
	}
	untrusted, _ := json.Marshal(maintenanceApprovalTrust{Authorities: []maintenanceApprovalAuthority{{SubjectID: approver, PublicKey: base64.RawURLEncoding.EncodeToString(replacement)}}})
	raw, _ = json.Marshal(valid)
	if _, err = verifyMaintenanceApproval(raw, untrusted, time.Now(), org, 2, payload.TargetKeyID); err == nil {
		t.Fatal("signature from a key not pinned to the approved subject was accepted")
	}
}
