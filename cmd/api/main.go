package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	if run() != nil {
		fmt.Fprintln(os.Stderr, "API startup or runtime failed")
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

func run() error {
	names := []string{"BACKEND", "DSN", "LISTEN", "PUBLIC_ORIGIN", "TLS_CERT_FILE", "TLS_KEY_FILE", "KMS_URL", "KMS_KEY", "INTERVIEW_KMS_URL", "INTERVIEW_KMS_KEY", "WEB_DIR"}
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
	csrf, e := secret("CSRF_KEY_FILE", 32)
	if e != nil {
		return e
	}
	defer clear(csrf)
	digest, e := secret("DIGEST_KEY_FILE", 32)
	if e != nil {
		return e
	}
	defer clear(digest)
	cursor, e := secret("CURSOR_KEY_FILE", 32)
	if e != nil {
		return e
	}
	defer clear(cursor)
	if bytes.Equal(csrf, digest) || bytes.Equal(cursor, csrf) || bytes.Equal(cursor, digest) {
		return errors.New("keys must be distinct")
	}
	tokenPath, e := required("KMS_TOKEN_FILE")
	if e != nil {
		return e
	}
	token, e := configfile.Read(tokenPath, 4096, true)
	if e != nil {
		return e
	}
	defer clear(token)
	tokenText := strings.TrimSpace(string(token))
	if tokenText == "" || strings.ContainsAny(tokenText, "\r\n") {
		return errors.New("invalid token")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		return errors.New("invalid trust store")
	}
	if ca := os.Getenv("TEAMLEDGER_KMS_CA_FILE"); ca != "" {
		pem, e := configfile.Read(ca, 1<<20, false)
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid KMS CA")
		}
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 8, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	wrapper, e := sensitive.NewVaultWrapper(cfg["KMS_URL"], cfg["KMS_KEY"], tokenText, client)
	if e != nil {
		return errors.New("invalid KMS configuration")
	}
	interviewWrapper, closeInterviewKeys, e := interviewKeyService(cfg, tokenText)
	if e != nil {
		return e
	}
	defer closeInterviewKeys()
	policy, e := compensationPolicy()
	if e != nil {
		return e
	}
	var bonusHMACKeys map[int64][]byte
	var bonusHMACKeyIDs map[int64]string
	var bonusHMACActive int64
	if len(policy.ControlledBonusSources) != 0 {
		activeText, activeKeyID := os.Getenv("TEAMLEDGER_BONUS_HMAC_ACTIVE_VERSION"), os.Getenv("TEAMLEDGER_BONUS_HMAC_ACTIVE_KEY_ID")
		active, parseErr := strconv.ParseInt(activeText, 10, 64)
		if parseErr != nil || active < 1 || strconv.FormatInt(active, 10) != activeText || !validConfigurationKeyID(activeKeyID) {
			return errors.New("invalid bonus HMAC configuration")
		}
		bonusKey, err := secret("BONUS_HMAC_ACTIVE_KEY_FILE", 32)
		if err != nil {
			return err
		}
		defer clear(bonusKey)
		if bytes.Equal(bonusKey, csrf) || bytes.Equal(bonusKey, digest) || bytes.Equal(bonusKey, cursor) {
			return errors.New("keys must be distinct")
		}
		bonusHMACActive = active
		bonusHMACKeys = map[int64][]byte{active: bonusKey}
		bonusHMACKeyIDs = map[int64]string{active: activeKeyID}
	}
	var financialWrapper sensitive.Wrapper
	if policy.Enabled {
		var closeFinancialKeys func()
		financialWrapper, closeFinancialKeys, e = financialKeyService(cfg, tokenText)
		if e != nil {
			return e
		}
		defer closeFinancialKeys()
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	repo, e := store.Open(startup, cfg["BACKEND"], cfg["DSN"])
	if e != nil {
		return errors.New("database unavailable")
	}
	defer repo.Close()
	if repo.CheckSchema(startup) != nil {
		return errors.New("invalid database schema")
	}
	service := &organization.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	interviews := &interview.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: interviewWrapper}, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	assessments := &assessment.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: interviewWrapper}, DigestKey: digest, ProviderPolicies: assessmentProviders, Workers: assessmentWorkers, ServiceSubjects: assessmentServices, Now: time.Now}
	schedulerFailed := make(chan struct{}, 1)
	go func() {
		if runAssessmentScheduler(ctx, assessments) != nil {
			schedulerFailed <- struct{}{}
		}
	}()
	finance := &compensation.Service{Store: repo, Batches: repo, Cipher: sensitive.Cipher{Wrapper: financialWrapper}, DigestKey: digest, CursorKey: cursor, BonusHMACKeys: bonusHMACKeys, BonusHMACKeyIDs: bonusHMACKeyIDs, BonusHMACActive: bonusHMACActive, Policy: policy, Now: time.Now}
	grants := &authz.Service{Store: repo, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	oidcConfig, closeIdentity, e := identityConfiguration(cfg["PUBLIC_ORIGIN"], csrf, digest, cursor)
	if e != nil {
		return e
	}
	if closeIdentity != nil {
		defer closeIdentity()
	}
	identities, e := identity.New(startup, repo, csrf, oidcConfig)
	if e != nil {
		return errors.New("identity unavailable")
	}
	handler, e := httpapi.New(service, interviews, assessments, finance, grants, identities, csrf, cfg["PUBLIC_ORIGIN"], cfg["WEB_DIR"])
	if e != nil {
		return e
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if workerRoots != nil {
		serverTLS.ClientAuth = tls.VerifyClientCertIfGiven
		serverTLS.ClientCAs = workerRoots
	}
	server := &http.Server{Addr: cfg["LISTEN"], Handler: handler, TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
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
