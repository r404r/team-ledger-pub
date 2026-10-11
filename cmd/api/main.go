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
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/httpapi"
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
func secret(name string, size int) ([]byte, error) {
	path, e := required(name)
	if e != nil {
		return nil, e
	}
	b, e := protectedFile(path, size, true)
	if e != nil {
		return nil, e
	}
	if len(b) != size {
		clear(b)
		return nil, errors.New("invalid secret size")
	}
	return b, nil
}

// Linux secret policy requires service-owned 0400/0600 regular files.
// Public trust anchors allow root/service ownership, but no group/other writes.
// Read the checked descriptor, not a subsequently reopened path.
func protectedFile(path string, limit int, confidential bool) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("invalid protected file")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid protected file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode().Perm()
	if !ok {
		return nil, errors.New("invalid protected file")
	}
	if confidential {
		if stat.Uid != uint32(os.Geteuid()) || (mode != 0400 && mode != 0600) {
			return nil, errors.New("invalid protected file")
		}
	} else if (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) || mode&0022 != 0 {
		return nil, errors.New("invalid trust file")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) == 0 || len(b) > limit {
		clear(b)
		return nil, errors.New("invalid protected file size")
	}
	return b, nil
}
func run() error {
	names := []string{"BACKEND", "DSN", "LISTEN", "PUBLIC_ORIGIN", "TLS_CERT_FILE", "TLS_KEY_FILE", "KMS_URL", "KMS_KEY", "WEB_DIR"}
	cfg := map[string]string{}
	for _, name := range names {
		v, e := required(name)
		if e != nil {
			return e
		}
		cfg[name] = v
	}
	host, _, e := net.SplitHostPort(cfg["LISTEN"])
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsLoopback() {
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
	token, e := protectedFile(tokenPath, 4096, true)
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
		pem, e := protectedFile(ca, 1<<20, false)
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
	keyPEM, e := protectedFile(cfg["TLS_KEY_FILE"], 64<<10, true)
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
	service := &organization.Service{Store: repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, DigestKey: digest, Now: time.Now}
	grants := &authz.Service{Store: repo, DigestKey: digest, CursorKey: cursor, Now: time.Now}
	handler, e := httpapi.New(service, grants, csrf, cfg["PUBLIC_ORIGIN"], cfg["WEB_DIR"])
	if e != nil {
		return e
	}
	server := &http.Server{Addr: cfg["LISTEN"], Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
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
