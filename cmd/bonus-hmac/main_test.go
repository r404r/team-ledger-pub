package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

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
