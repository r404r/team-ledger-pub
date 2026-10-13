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

func TestVerifyRequiresCanonicalTrustedBoundedApproval(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	subject, org, request := value.NewID(), value.NewID(), value.NewID()
	expires := now.Add(time.Hour).Format(time.RFC3339)
	body := payload{org, "interview", "interview-kek-v2", 2, subject, request, expires}
	encoded, _ := json.Marshal(body)
	doc := document{org, "interview", "interview-kek-v2", 2, subject, request, expires, base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, encoded))}
	raw, _ := json.Marshal(doc)
	registry, _ := json.Marshal(trust{Authorities: []authority{{subject, base64.RawURLEncoding.EncodeToString(public)}}})
	plan, err := verify(raw, registry, now)
	if err != nil || plan.OrgID != org || plan.Domain != "interview" || plan.KEKID != "interview-kek-v2" || plan.Version != 2 || len(plan.ManifestDigest) != 32 {
		t.Fatal(plan, err)
	}
	doc.TargetVersion = 3
	tampered, _ := json.Marshal(doc)
	if _, err = verify(tampered, registry, now); err == nil {
		t.Fatal("tampered approval accepted")
	}
	if _, err = verify(raw, registry, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired approval accepted")
	}
}
