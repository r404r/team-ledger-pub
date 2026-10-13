package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "API startup or runtime failed:", err)
		os.Exit(1)
	}
}
func required(name string) (string, error) {
	s := os.Getenv("TEAMLEDGER_" + name)
	if strings.TrimSpace(s) == "" {
		return "", errors.New("missing configuration")
	}
	return s, nil
}
func validListener(address, scope string) bool {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return false
	}
	switch scope {
	case "":
		return ip.IsLoopback()
	case "container":
		return ip.IsUnspecified()
	default:
		return false
	}
}

func secret(name string, size int) ([]byte, error) {
	path, e := required(name)
	if e != nil {
		return nil, e
	}
	b, e := configfile.Read(path, size, true)
	if e != nil {
		return nil, e
	}
	if len(b) != size {
		clear(b)
		return nil, errors.New("invalid secret size")
	}
	return b, nil
}

type identityModeReader interface {
	IdentityMode(context.Context) (string, error)
}

func identityModeMatches(ctx context.Context, reader identityModeReader, configured string) bool {
	current, err := reader.IdentityMode(ctx)
	return err == nil && current == configured
}

func run() error {
	names := []string{"BACKEND", "DSN", "LISTEN", "PUBLIC_ORIGIN", "TLS_CERT_FILE", "TLS_KEY_FILE", "KEYD_SOCKET", "WEB_DIR", "DEPLOYMENT_ID"}
	cfg := map[string]string{}
	for _, name := range names {
		v, e := required(name)
		if e != nil {
			return e
		}
		cfg[name] = v
	}
	if !validListener(cfg["LISTEN"], os.Getenv("TEAMLEDGER_LISTEN_SCOPE")) {
		return errors.New("invalid listener")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	keys := &sensitive.KeydClient{Socket: cfg["KEYD_SOCKET"], Timeout: 5 * time.Second}
	ready, e := keys.Ready(startup)
	if e != nil || ready.MaterialGeneration == 0 {
		return errors.New("key service unavailable")
	}
	csrf, e := keys.ProcessKey(startup, sensitive.DomainCSRFToken, "csrf-v1")
	if e != nil {
		return errors.New("key service unavailable")
	}
	defer clear(csrf)
	digest, e := keys.ProcessKey(startup, sensitive.DomainCommandReceipt, "command-receipt-v1")
	if e != nil {
		return errors.New("key service unavailable")
	}
	defer clear(digest)
	cursor, e := keys.ProcessKey(startup, sensitive.DomainCursorToken, "cursor-v1")
	if e != nil {
		return errors.New("key service unavailable")
	}
	defer clear(cursor)
	identityKey, e := keys.ProcessKey(startup, sensitive.DomainIdentitySubjectLookup, "identity-subject-v1")
	if e != nil {
		return errors.New("key service unavailable")
	}
	defer clear(identityKey)
	transactionKey, e := keys.ProcessKey(startup, sensitive.DomainCommandReceipt, "identity-transaction-v1")
	if e != nil {
		return errors.New("key service unavailable")
	}
	defer clear(transactionKey)
	wrapper, e := sensitive.NewKeydWrapper(keys, sensitive.DomainPIIPayload)
	if e != nil {
		return errors.New("invalid key service configuration")
	}
	interviewWrapper, e := sensitive.NewKeydWrapper(keys, sensitive.DomainInterviewPayload)
	if e != nil {
		return errors.New("invalid key service configuration")
	}
	assessmentWrapper, e := sensitive.NewKeydWrapper(keys, sensitive.DomainAssessmentPayload)
	if e != nil {
		return errors.New("invalid key service configuration")
	}
	financialWrapper, e := sensitive.NewKeydWrapper(keys, sensitive.DomainFinancialPayload)
	if e != nil {
		return errors.New("invalid key service configuration")
	}
	policy, e := compensationPolicy()
	if e != nil {
		return e
	}
	var bonusHMACKeys map[int64][]byte
	var bonusHMACKeyIDs map[int64]string
	var bonusHMACActive int64
	if len(policy.ControlledBonusSources) != 0 {
		value, err := keys.MAC(startup, sensitive.DomainBonusPaymentLookup, []byte("TEAMLEDGER-PROCESS-KEY\x00bonus-payment-v1"))
		if err != nil {
			return errors.New("key service unavailable")
		}
		bonusHMACActive = int64(value.Version)
		bonusHMACKeys = map[int64][]byte{bonusHMACActive: value.Digest}
		bonusHMACKeyIDs = map[int64]string{bonusHMACActive: value.KeyID}
		defer clear(value.Digest)
	}
	keyPEM, e := configfile.Read(cfg["TLS_KEY_FILE"], 64<<10, true)
	if e != nil {
		return e
	}
	defer clear(keyPEM)
	certFile, e := os.Open(cfg["TLS_CERT_FILE"])
	if e != nil {
		return errors.New("invalid TLS configuration")
	}
	certInfo, e := certFile.Stat()
	if e != nil || !certInfo.Mode().IsRegular() {
		certFile.Close()
		return errors.New("invalid TLS configuration")
	}
	certPEM, e := io.ReadAll(io.LimitReader(certFile, (1<<20)+1))
	certFile.Close()
	if e != nil || len(certPEM) > 1<<20 {
		return errors.New("invalid TLS configuration")
	}
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		return errors.New("invalid TLS configuration")
	}
	assessmentProviders, assessmentWorkers, assessmentServices, workerRoots, e := assessmentConfiguration()
	if e != nil {
		return e
	}
	repo, e := store.Open(startup, cfg["BACKEND"], cfg["DSN"])
	if e != nil {
		return errors.New("database unavailable")
	}
	defer repo.Close()
	if repo.CheckSchema(startup) != nil {
		return errors.New("invalid database schema")
	}
	if repo.VerifyOrInitializeCryptoState(startup, ready, time.Now().UTC()) != nil {
		return errors.New("key material does not match database")
	}
	service := &organization.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	interviews := &interview.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: interviewWrapper}, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	assessments := &assessment.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: assessmentWrapper}, DigestKey: digest, ProviderPolicies: assessmentProviders, Workers: assessmentWorkers, ServiceSubjects: assessmentServices, Now: time.Now}
	schedulerFailed := make(chan struct{}, 1)
	go func() {
		if runAssessmentScheduler(ctx, assessments) != nil {
			schedulerFailed <- struct{}{}
		}
	}()
	finance := &compensation.Service{Store: repo, Batches: repo, Cipher: sensitive.Cipher{Wrapper: financialWrapper}, DigestKey: digest, CursorKey: cursor, BonusHMACKeys: bonusHMACKeys, BonusHMACKeyIDs: bonusHMACKeyIDs, BonusHMACActive: bonusHMACActive, Policy: policy, Now: time.Now}
	grants := &authz.Service{Store: repo, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	identityMode, oidcConfig, closeIdentity, e := identityConfiguration(cfg["PUBLIC_ORIGIN"], csrf, digest, cursor, identityKey, transactionKey)
	if e != nil {
		return e
	}
	if repo.EnsureIdentityMode(startup, identityMode, time.Now().UTC()) != nil {
		return errors.New("identity mode does not match database")
	}
	if closeIdentity != nil {
		defer closeIdentity()
	}
	var identities *identity.Service
	if identityMode == "local" {
		identities, e = identity.NewLocal(startup, repo, repo, csrf, keys)
	} else {
		identities, e = identity.New(startup, repo, csrf, oidcConfig)
	}
	if e != nil {
		return errors.New("identity unavailable")
	}
	handler, e := httpapi.New(service, interviews, assessments, finance, grants, identities, csrf, cfg["PUBLIC_ORIGIN"], cfg["WEB_DIR"], cfg["DEPLOYMENT_ID"])
	if e != nil {
		return e
	}
	verifiedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			handler.ServeHTTP(w, r)
			return
		}
		state, err := keys.Ready(r.Context())
		if err != nil || repo.VerifyCryptoState(r.Context(), state) != nil || !identityModeMatches(r.Context(), repo, identityMode) {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if workerRoots != nil {
		serverTLS.ClientAuth = tls.VerifyClientCertIfGiven
		serverTLS.ClientCAs = workerRoots
	}
	server := &http.Server{Addr: cfg["LISTEN"], Handler: verifiedHandler, TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	listener, e := net.Listen("tcp", cfg["LISTEN"])
	if e != nil {
		return errors.New("listener unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("server failed")
		}
	case <-schedulerFailed:
		server.Close()
		<-done
		return errors.New("assessment scheduler failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			server.Close()
			return errors.New("shutdown failed")
		}
		e = <-done
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("server failed")
		}
	}
	return nil
}

func validConfigurationKeyID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
