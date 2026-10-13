package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/maintenance"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

var approvalTrustFile = "/etc/teamledger/key-rewrap-approval-authorities.json"

type document struct {
	OrgID         string `json:"org_id"`
	Domain        string `json:"domain"`
	TargetKEKID   string `json:"target_kek_id"`
	TargetVersion uint32 `json:"target_version"`
	ApprovedBy    string `json:"approved_by_subject_id"`
	RequestID     string `json:"request_id"`
	ExpiresAt     string `json:"expires_at"`
	Signature     string `json:"signature"`
}
type payload struct {
	OrgID         string `json:"org_id"`
	Domain        string `json:"domain"`
	TargetKEKID   string `json:"target_kek_id"`
	TargetVersion uint32 `json:"target_version"`
	ApprovedBy    string `json:"approved_by_subject_id"`
	RequestID     string `json:"request_id"`
	ExpiresAt     string `json:"expires_at"`
}
type authority struct {
	SubjectID string `json:"subject_id"`
	PublicKey string `json:"public_key"`
}
type trust struct {
	Authorities []authority `json:"authorities"`
}

func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errors.New("invalid approval")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("invalid approval")
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical approval")
	}
	return nil
}
func verify(raw, registry []byte, now time.Time) (maintenance.Target, error) {
	var doc document
	if strict(raw, &doc) != nil || !value.ValidID(doc.OrgID) || !value.ValidID(doc.ApprovedBy) || !value.ValidID(doc.RequestID) || (doc.Domain != "pii" && doc.Domain != "interview" && doc.Domain != "assessment" && doc.Domain != "financial") || doc.TargetKEKID == "" || len(doc.TargetKEKID) > 128 || doc.TargetVersion == 0 {
		return maintenance.Target{}, errors.New("invalid approval")
	}
	expires, e := time.Parse(time.RFC3339, doc.ExpiresAt)
	if e != nil || !now.Before(expires) || expires.After(now.Add(24*time.Hour)) {
		return maintenance.Target{}, errors.New("expired approval")
	}
	var trusted trust
	if strict(registry, &trusted) != nil || len(trusted.Authorities) < 1 || len(trusted.Authorities) > 100 {
		return maintenance.Target{}, errors.New("invalid trust")
	}
	var public []byte
	seen := map[string]bool{}
	for _, entry := range trusted.Authorities {
		key, e := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if e != nil || !value.ValidID(entry.SubjectID) || len(key) != ed25519.PublicKeySize || seen[entry.SubjectID] {
			return maintenance.Target{}, errors.New("invalid trust")
		}
		seen[entry.SubjectID] = true
		if entry.SubjectID == doc.ApprovedBy {
			public = key
		}
	}
	body, _ := json.Marshal(payload{doc.OrgID, doc.Domain, doc.TargetKEKID, doc.TargetVersion, doc.ApprovedBy, doc.RequestID, doc.ExpiresAt})
	signature, e := base64.RawURLEncoding.DecodeString(doc.Signature)
	if e != nil || !ed25519.Verify(public, body, signature) {
		return maintenance.Target{}, errors.New("untrusted approval")
	}
	digest := sha256.Sum256(raw)
	return maintenance.Target{OrgID: doc.OrgID, Domain: doc.Domain, KEKID: doc.TargetKEKID, Version: doc.TargetVersion, ManifestDigest: digest[:]}, nil
}
func protected(path string, limit int) ([]byte, error) {
	raw, e := configfile.Read(path, limit, true)
	if e != nil {
		return nil, e
	}
	return raw, nil
}
func run(args []string, trustOverride []byte) error {
	flags := flag.NewFlagSet("key-rewrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backend := flags.String("backend", "", "")
	dsnFile := flags.String("dsn-file", "", "")
	dbCA := flags.String("postgres-ca-file", "", "")
	keydSocket := flags.String("keyd-socket", "", "")
	approvalFile := flags.String("approval-file", "", "")
	limitRaw := flags.String("limit", "100", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *keydSocket == "" {
		return errors.New("invalid arguments")
	}
	limit, e := strconv.Atoi(*limitRaw)
	if e != nil || limit < 1 || limit > 1000 {
		return errors.New("invalid limit")
	}
	dsnRaw, e := protected(*dsnFile, 16<<10)
	if e != nil {
		return e
	}
	defer clear(dsnRaw)
	dsn := strings.TrimSpace(string(dsnRaw))
	var repo *store.Repository
	if *backend == "postgres" {
		u, parse := url.Parse(dsn)
		if parse != nil || u.Query().Get("sslmode") != "verify-full" || u.Query().Get("sslrootcert") != *dbCA {
			return errors.New("invalid database TLS")
		}
		ca, read := configfile.Read(*dbCA, 1<<20, false)
		if read != nil {
			return read
		}
		defer clear(ca)
		repo, e = store.OpenPostgresWithCheckedCA(context.Background(), dsn, ca)
	} else if *backend == "sqlite" && *dbCA == "" {
		repo, e = store.Open(context.Background(), *backend, dsn)
	} else {
		return errors.New("invalid backend")
	}
	if e != nil {
		return e
	}
	defer repo.Close()
	if e = repo.CheckSchema(context.Background()); e != nil {
		return e
	}
	approval, e := protected(*approvalFile, 16<<10)
	if e != nil {
		return e
	}
	defer clear(approval)
	registry := trustOverride
	if registry == nil {
		registry, e = configfile.ReadRootTrust(approvalTrustFile, 64<<10)
		if e != nil {
			return e
		}
		defer clear(registry)
	}
	plan, e := verify(approval, registry, time.Now().UTC())
	if e != nil {
		return e
	}
	host, e := os.Hostname()
	if e != nil || host == "" {
		return errors.New("invalid host")
	}
	hostDigest := sha256.Sum256([]byte("TEAMLEDGER-MAINTENANCE-HOST\x00\x01" + host))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	keyDomain := map[string]sensitive.KeyDomain{"pii": sensitive.DomainPIIPayload, "interview": sensitive.DomainInterviewPayload, "assessment": sensitive.DomainAssessmentPayload, "financial": sensitive.DomainFinancialPayload}[plan.Domain]
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 10 * time.Second}
	ready, readyErr := keys.Ready(ctx)
	if readyErr != nil {
		return errors.New("local key service unavailable")
	}
	target := sensitive.KeyReference{KeyID: plan.KEKID, Version: plan.Version}
	control, controlErr := repo.CryptoControl(ctx)
	if controlErr != nil {
		return errors.New("database key material control unavailable")
	}
	retire := func() error {
		old, proof, needed, retireErr := repo.PrepareCryptoRetirement(ctx, keyDomain, plan.ManifestDigest, time.Now().UTC())
		if retireErr != nil {
			return retireErr
		}
		if !needed {
			return nil
		}
		retired, retireErr := keys.Retire(ctx, keyDomain, old, proof)
		if retireErr != nil {
			return errors.New("key retirement failed")
		}
		return repo.CompleteCryptoRetirement(ctx, retired, keyDomain, old, proof, time.Now().UTC())
	}
	if ready.WriteEnabled {
		if control.Phase == "activated" && ready.Active[keyDomain] == plan.Version {
			if e = repo.CompleteCryptoActivation(ctx, ready, keyDomain, plan.ManifestDigest, time.Now().UTC()); e != nil {
				return e
			}
			control.Phase = "stable"
		}
		if (control.Phase == "stable" || control.Phase == "retiring") && ready.Active[keyDomain] == plan.Version {
			return retire()
		}
		return errors.New("approved key is not staged")
	}
	if ready.Staged[keyDomain] != target || len(ready.Staged) != 1 {
		return errors.New("staged key does not match approval")
	}
	if control.Phase == "stable" {
		if e = repo.BeginCryptoStage(ctx, ready, keyDomain, plan.ManifestDigest, time.Now().UTC()); e != nil {
			return e
		}
	} else if control.Phase != "staged" && control.Phase != "activated" {
		return errors.New("invalid database key material phase")
	}
	if control.Phase != "activated" {
		_, done, e := maintenance.RunKeyRewrapWith(ctx, repo, func(callContext context.Context, current sensitive.WrappedKey) (sensitive.WrappedKey, error) {
			return keys.Rewrap(callContext, keyDomain, current)
		}, plan, maintenance.Actor{UID: int64(os.Geteuid()), HostDigest: hostDigest[:]}, limit, time.Now().UTC().Truncate(time.Microsecond))
		if e != nil {
			return e
		}
		if !done {
			return errors.New("bounded batch complete; re-run same approval")
		}
		if ready.Active[keyDomain] != plan.Version {
			ready, e = keys.Activate(ctx, keyDomain, plan.ManifestDigest)
			if e != nil {
				return errors.New("key activation failed")
			}
		}
		if e = repo.RecordCryptoActivation(ctx, ready, keyDomain, plan.ManifestDigest, time.Now().UTC()); e != nil {
			return e
		}
	}
	ready, e = keys.Acknowledge(ctx, keyDomain, plan.ManifestDigest)
	if e != nil {
		return errors.New("key acknowledgement failed")
	}
	if e = repo.CompleteCryptoActivation(ctx, ready, keyDomain, plan.ManifestDigest, time.Now().UTC()); e != nil {
		return e
	}
	return retire()
}
func main() {
	if e := run(os.Args[1:], nil); e != nil {
		fmt.Fprintln(os.Stderr, "KEK rewrap failed")
		os.Exit(1)
	}
	fmt.Println("KEK rewrap committed")
}
