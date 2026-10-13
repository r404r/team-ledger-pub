package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func main() {
	if err := runWithTrust(os.Args[1:], nil); err != nil {
		fmt.Fprintln(os.Stderr, "Bonus HMAC maintenance failed")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Bonus HMAC maintenance committed")
}

type maintenanceApprovalDocument struct {
	OrgID               string `json:"org_id"`
	TargetVersion       int64  `json:"target_version"`
	TargetKeyID         string `json:"target_key_id"`
	ApprovedBySubjectID string `json:"approved_by_subject_id"`
	RequestID           string `json:"request_id"`
	ExpiresAt           string `json:"expires_at"`
	Signature           string `json:"signature"`
}

var approvalTrustFile = "/etc/teamledger/bonus-hmac-approval-authorities.json"

type maintenanceApprovalAuthority struct {
	SubjectID string `json:"subject_id"`
	PublicKey string `json:"public_key"`
}

type maintenanceApprovalTrust struct {
	Authorities []maintenanceApprovalAuthority `json:"authorities"`
}

type maintenanceApprovalPayload struct {
	OrgID               string `json:"org_id"`
	TargetVersion       int64  `json:"target_version"`
	TargetKeyID         string `json:"target_key_id"`
	ApprovedBySubjectID string `json:"approved_by_subject_id"`
	RequestID           string `json:"request_id"`
	ExpiresAt           string `json:"expires_at"`
}

func decodeStrictObject(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fault.Invalid
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return fault.Invalid
	}
	return nil
}

func approvalPublicKey(raw []byte, subject string) ([]byte, error) {
	var trust maintenanceApprovalTrust
	if decodeStrictObject(raw, &trust) != nil || len(trust.Authorities) == 0 || len(trust.Authorities) > 100 {
		return nil, fault.Unavailable
	}
	seen := make(map[string]bool, len(trust.Authorities))
	var found []byte
	for _, authority := range trust.Authorities {
		key, err := base64.RawURLEncoding.DecodeString(authority.PublicKey)
		if err != nil || !value.ValidID(authority.SubjectID) || len(key) != ed25519.PublicKeySize || seen[authority.SubjectID] {
			return nil, fault.Unavailable
		}
		seen[authority.SubjectID] = true
		if authority.SubjectID == subject {
			found = key
		}
	}
	if len(found) != ed25519.PublicKeySize {
		return nil, fault.Forbidden
	}
	return found, nil
}

func verifyMaintenanceApproval(raw, trust []byte, now time.Time, org string, version int64, keyID string) (compensation.BonusHMACMaintenanceApproval, error) {
	var document maintenanceApprovalDocument
	if decodeStrictObject(raw, &document) != nil || document.OrgID != org || document.TargetVersion != version || document.TargetKeyID != keyID || !value.ValidID(document.ApprovedBySubjectID) || !value.ValidID(document.RequestID) {
		return compensation.BonusHMACMaintenanceApproval{}, fault.Invalid
	}
	publicKey, err := approvalPublicKey(trust, document.ApprovedBySubjectID)
	if err != nil {
		return compensation.BonusHMACMaintenanceApproval{}, err
	}
	expires, err := time.Parse(time.RFC3339, document.ExpiresAt)
	if err != nil || !now.Before(expires) || expires.After(now.Add(24*time.Hour)) {
		return compensation.BonusHMACMaintenanceApproval{}, fault.Invalid
	}
	payload, err := json.Marshal(maintenanceApprovalPayload{OrgID: document.OrgID, TargetVersion: document.TargetVersion, TargetKeyID: document.TargetKeyID, ApprovedBySubjectID: document.ApprovedBySubjectID, RequestID: document.RequestID, ExpiresAt: document.ExpiresAt})
	if err != nil {
		return compensation.BonusHMACMaintenanceApproval{}, fault.Invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return compensation.BonusHMACMaintenanceApproval{}, fault.Forbidden
	}
	digest := sha256.Sum256(raw)
	return compensation.BonusHMACMaintenanceApproval{ApprovedBySubjectID: document.ApprovedBySubjectID, RequestID: document.RequestID, ApprovalDigest: digest[:]}, nil
}

func runWithTrust(args []string, trustOverride []byte) error {
	if len(args) == 0 || args[0] != "reindex" {
		return fault.Invalid
	}
	flags := flag.NewFlagSet("bonus-hmac reindex", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backend := flags.String("backend", "", "sqlite or postgres")
	dsnFile := flags.String("dsn-file", "", "protected DSN file")
	caFile := flags.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	keydSocket := flags.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	approvalFile := flags.String("approval-file", "", "protected signed maintenance approval")
	// The signer trust registry is fixed deployment configuration, never a CLI argument.
	org := flags.String("org-id", "", "organization UUID")
	targetVersion := flags.String("target-version", "", "monotonic target key version")
	targetKeyID := flags.String("target-key-id", "", "operator-visible key identifier")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !value.ValidID(*org) || *keydSocket == "" {
		return fault.Invalid
	}
	version, err := strconv.ParseInt(*targetVersion, 10, 64)
	if err != nil || version < 1 || strings.TrimSpace(*targetKeyID) == "" || len(*targetKeyID) > 128 {
		return fault.Invalid
	}
	dsnBytes, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(dsnBytes)
	dsn := strings.TrimSpace(string(dsnBytes))
	var postgresCA []byte
	if *backend == "postgres" {
		u, parseErr := url.Parse(dsn)
		if parseErr != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || *caFile == "" || u.Query().Get("sslmode") != "verify-full" || u.Query().Get("sslrootcert") != *caFile {
			return fault.Unavailable
		}
		postgresCA, err = configfile.Read(*caFile, 1<<20, false)
		if err != nil {
			return fault.Unavailable
		}
	} else if *backend != "sqlite" || *caFile != "" {
		return fault.Invalid
	}
	approvalRaw, err := configfile.Read(*approvalFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(approvalRaw)
	trust := trustOverride
	if trust == nil {
		trust, err = configfile.ReadRootTrust(approvalTrustFile, 64<<10)
		if err != nil {
			return fault.Unavailable
		}
		defer clear(trust)
	}
	approval, err := verifyMaintenanceApproval(approvalRaw, trust, time.Now(), *org, version, *targetKeyID)
	if err != nil {
		return err
	}
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 10 * time.Second}
	hmacValue, err := keys.MACStaging(context.Background(), sensitive.DomainBonusPaymentLookup, approval.ApprovalDigest, []byte("TEAMLEDGER-PROCESS-KEY\x00bonus-payment-v1"))
	if err != nil || int64(hmacValue.Version) != version || hmacValue.KeyID != *targetKeyID {
		clear(hmacValue.Digest)
		return fault.Unavailable
	}
	defer clear(hmacValue.Digest)
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainFinancialPayload)
	if err != nil {
		return fault.Unavailable
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var repo *store.Repository
	if *backend == "postgres" {
		repo, err = store.OpenPostgresWithCheckedCA(ctx, dsn, postgresCA)
	} else {
		repo, err = store.Open(ctx, *backend, dsn)
	}
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	service := compensation.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, BonusHMACKeys: map[int64][]byte{version: hmacValue.Digest}}
	return service.ReindexBonusPaymentHMAC(ctx, *org, version, *targetKeyID, 0, approval)
}
