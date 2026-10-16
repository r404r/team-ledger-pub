package main

import (
	"context"
	"crypto/rand"
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
	leaseKey := make([]byte, 32)
	if _, e = rand.Read(leaseKey); e != nil {
		return errors.New("random source unavailable")
	}
	defer clear(leaseKey)
	transactionKey, e := keys.ProcessKey(startup, sensitive.DomainIdentityTransaction, "identity-transaction-v1")
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
	mfaWrapper, e := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMFA)
	if e != nil {
		return errors.New("invalid key service configuration")
	}
	policy, e := compensationPolicy()
	if e != nil {
		return e
	}
	var bonusHMACKeyIDs map[int64]string
	var bonusHMACActive int64
	if len(policy.ControlledBonusSources) != 0 {
		reference := ready.ActiveKeys[sensitive.DomainBonusPaymentLookup]
		if reference.Version == 0 || reference.KeyID == "" {
			return errors.New("key service unavailable")
		}
		bonusHMACActive = int64(reference.Version)
		bonusHMACKeyIDs = map[int64]string{bonusHMACActive: reference.KeyID}
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
	repo.CommandMACKey = ready.ActiveKeys[sensitive.DomainCommandReceipt]
	repo.GenerationMACKey = ready.ActiveKeys[sensitive.DomainAssessmentGeneration]
	if repo.CommandMACKey.KeyID == "" || repo.CommandMACKey.Version == 0 || repo.GenerationMACKey.KeyID == "" || repo.GenerationMACKey.Version == 0 {
		return errors.New("key material does not match persistent MAC contracts")
	}
	commandMAC := func(frame []byte) ([]byte, error) {
		value, err := keys.MAC(ctx, sensitive.DomainCommandReceipt, frame)
		return value.Digest, err
	}
	generationMAC := func(frame []byte) ([]byte, error) {
		value, err := keys.MAC(ctx, sensitive.DomainAssessmentGeneration, frame)
		return value.Digest, err
	}
	cursorMAC := func(frame []byte) ([]byte, error) {
		value, err := keys.MAC(ctx, sensitive.DomainCursorToken, frame)
		return value.Digest, err
	}
	service := &organization.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, CommandMAC: commandMAC, CursorMAC: cursorMAC, StaffCodeMAC: func(ctx context.Context, frame []byte) (sensitive.MACValue, error) {
		return keys.MAC(ctx, sensitive.DomainStaffCodeLookup, frame)
	}, Now: time.Now}
	interviews := &interview.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: interviewWrapper}, CommandMAC: commandMAC, CursorMAC: cursorMAC, Now: time.Now}
	assessments := &assessment.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: assessmentWrapper}, DigestKey: leaseKey, CommandMAC: commandMAC, GenerationMAC: generationMAC, ProviderPolicies: assessmentProviders, Workers: assessmentWorkers, ServiceSubjects: assessmentServices, Now: time.Now}
	schedulerFailed := make(chan struct{}, 1)
	go func() {
		if runAssessmentScheduler(ctx, assessments) != nil {
			schedulerFailed <- struct{}{}
		}
	}()
	finance := &compensation.Service{Store: repo, Batches: repo, Cipher: sensitive.Cipher{Wrapper: financialWrapper}, CommandMAC: commandMAC, CursorMAC: cursorMAC, BonusHMACKeyIDs: bonusHMACKeyIDs, BonusHMACActive: bonusHMACActive, BonusMAC: func(ctx context.Context, frame []byte) (sensitive.MACValue, error) {
		return keys.MAC(ctx, sensitive.DomainBonusPaymentLookup, frame)
	}, StaffCodeMAC: func(ctx context.Context, frame []byte) (sensitive.MACValue, error) {
		return keys.MAC(ctx, sensitive.DomainStaffCodeLookup, frame)
	}, Policy: policy, Now: time.Now}
	grants := &authz.Service{Store: repo, CommandMAC: commandMAC, CursorMAC: cursorMAC, Now: time.Now}
	identityMode, oidcConfig, closeIdentity, e := identityConfiguration(cfg["PUBLIC_ORIGIN"], transactionKey)
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
		identities, e = identity.NewLocal(startup, repo, repo, keys, sensitive.Cipher{Wrapper: mfaWrapper})
	} else {
		identities, e = identity.New(startup, repo, keys, oidcConfig)
	}
	if e != nil {
		return errors.New("identity unavailable")
	}
	handler, e := httpapi.New(service, interviews, assessments, finance, grants, identities, keys, cfg["PUBLIC_ORIGIN"], cfg["WEB_DIR"], cfg["DEPLOYMENT_ID"])
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
