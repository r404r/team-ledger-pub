package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestRunRewrapsRealEnvelopeThroughVaultEndpoints(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	if _, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "CLI_REWRAP"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := value.NewID()
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	body := payload{f.OrgID, "pii", f.FinancialKMS.KeyName, 1, f.Owner.SubjectID, request, expires}
	encoded, _ := json.Marshal(body)
	approval, _ := json.Marshal(document{f.OrgID, "pii", f.FinancialKMS.KeyName, 1, f.Owner.SubjectID, request, expires, base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, encoded))})
	registry, _ := json.Marshal(trust{Authorities: []authority{{f.Owner.SubjectID, base64.RawURLEncoding.EncodeToString(public)}}})
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	dsnFile := write("dsn", []byte(f.DSN))
	sourceToken := write("source.token", []byte(f.KMS.Token))
	targetToken := write("target.token", []byte(f.FinancialKMS.Token))
	approvalFile := write("approval.json", approval)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 15 * time.Second}
	args := []string{"-backend", "sqlite", "-dsn-file", dsnFile, "-source-vault-endpoint", f.KMS.Server.URL, "-source-vault-key", f.KMS.KeyName, "-source-vault-token-file", sourceToken, "-target-vault-endpoint", f.FinancialKMS.Server.URL, "-target-vault-key", f.FinancialKMS.KeyName, "-target-vault-token-file", targetToken, "-approval-file", approvalFile, "-limit", "100"}
	if err = run(args, client, registry); err != nil {
		t.Fatal(err)
	}
	var old int
	if err = f.Repo.DB.QueryRow("SELECT count(*) FROM encrypted_payload WHERE org_id=? AND kek_id<>?", f.OrgID, f.FinancialKMS.KeyName).Scan(&old); err != nil || old != 0 {
		t.Fatal("old wrapper remained", old, err)
	}
}
