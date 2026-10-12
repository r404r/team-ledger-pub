package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/store"
)

func required(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("missing configuration")
	}
	return value, nil
}
func run(ctx context.Context) error {
	backend, err := required("TEAMLEDGER_DB_BACKEND")
	if err != nil {
		return err
	}
	dsn, err := required("TEAMLEDGER_DB_DSN")
	if err != nil {
		return err
	}
	var repository *store.Repository
	if backend == "postgres" {
		caPath, e := required("TEAMLEDGER_DB_CA_FILE")
		if e != nil {
			return e
		}
		ca, e := configfile.Read(caPath, 1<<20, false)
		if e != nil {
			return e
		}
		defer clear(ca)
		repository, e = store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
		if e != nil {
			return e
		}
	} else if backend == "sqlite" {
		repository, err = store.Open(ctx, backend, dsn)
		if err != nil {
			return err
		}
	} else {
		return errors.New("unsupported backend")
	}
	defer repository.Close()
	endpoint, err := required("TEAMLEDGER_AUDIT_ENDPOINT")
	if err != nil {
		return err
	}
	caPath, err := required("TEAMLEDGER_AUDIT_CA_FILE")
	if err != nil {
		return err
	}
	caPEM, err := configfile.ReadRootTrust(caPath, 1<<20)
	if err != nil {
		return err
	}
	defer clear(caPEM)
	certPath, err := required("TEAMLEDGER_AUDIT_CLIENT_CERT_FILE")
	if err != nil {
		return err
	}
	certPEM, err := configfile.Read(certPath, 1<<20, false)
	if err != nil {
		return err
	}
	defer clear(certPEM)
	keyPath, err := required("TEAMLEDGER_AUDIT_CLIENT_KEY_FILE")
	if err != nil {
		return err
	}
	keyPEM, err := configfile.Read(keyPath, 1<<20, true)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("invalid audit client identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid audit CA")
	}
	publicPath, err := required("TEAMLEDGER_AUDIT_RECEIPT_KEY_FILE")
	if err != nil {
		return err
	}
	encoded, err := configfile.ReadRootTrust(publicPath, 256)
	if err != nil {
		return err
	}
	defer clear(encoded)
	public, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid audit receipt key")
	}
	defer clear(public)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	for delivered := 0; delivered < 100; delivered++ {
		found, e := audit.DeliverOne(ctx, repository, client, endpoint, ed25519.PublicKey(public), time.Now().UTC().Truncate(time.Microsecond))
		if e != nil {
			return e
		}
		if !found {
			return nil
		}
	}
	return errors.New("audit backlog remains after bounded batch")
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal("audit forwarder unavailable")
	}
}
