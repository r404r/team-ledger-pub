package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/maintenance"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	if strict(raw, &doc) != nil || !value.ValidID(doc.OrgID) || !value.ValidID(doc.ApprovedBy) || !value.ValidID(doc.RequestID) || (doc.Domain != "pii" && doc.Domain != "interview" && doc.Domain != "financial") || doc.TargetKEKID == "" || len(doc.TargetKEKID) > 128 || doc.TargetVersion == 0 {
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
func run(args []string, client *http.Client, trustOverride []byte) error {
	flags := flag.NewFlagSet("key-rewrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backend := flags.String("backend", "", "")
	dsnFile := flags.String("dsn-file", "", "")
	dbCA := flags.String("postgres-ca-file", "", "")
	sourceURL := flags.String("source-vault-endpoint", "", "")
	sourceKey := flags.String("source-vault-key", "", "")
	sourceTokenFile := flags.String("source-vault-token-file", "", "")
	targetURL := flags.String("target-vault-endpoint", "", "")
	targetKey := flags.String("target-vault-key", "", "")
	targetTokenFile := flags.String("target-vault-token-file", "", "")
	approvalFile := flags.String("approval-file", "", "")
	limitRaw := flags.String("limit", "100", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || client == nil {
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
	sourceToken, e := protected(*sourceTokenFile, 16<<10)
	if e != nil {
		return e
	}
	defer clear(sourceToken)
	if strings.ContainsAny(string(sourceToken), "\x00\r\n") {
		return errors.New("invalid source token")
	}
	targetToken, e := protected(*targetTokenFile, 16<<10)
	if e != nil {
		return e
	}
	defer clear(targetToken)
	if strings.ContainsAny(string(targetToken), "\x00\r\n") {
		return errors.New("invalid target token")
	}
	source, e := sensitive.NewVaultWrapper(*sourceURL, *sourceKey, string(sourceToken), client)
	if e != nil {
		return e
	}
	target, e := sensitive.NewVaultWrapper(*targetURL, *targetKey, string(targetToken), client)
	if e != nil {
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
	_, done, e := maintenance.RunKeyRewrap(ctx, repo, source, target, plan, maintenance.Actor{UID: int64(os.Geteuid()), HostDigest: hostDigest[:]}, limit, time.Now().UTC().Truncate(time.Microsecond))
	if e != nil {
		return e
	}
	if !done {
		return errors.New("bounded batch complete; re-run same approval")
	}
	return nil
}
func main() {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	if e := run(os.Args[1:], client, nil); e != nil {
		fmt.Fprintln(os.Stderr, "KEK rewrap failed")
		os.Exit(1)
	}
	fmt.Println("KEK rewrap committed")
}
