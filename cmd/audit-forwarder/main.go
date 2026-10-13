package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	deployment, err := required("TEAMLEDGER_DEPLOYMENT_ID")
	if err != nil {
		return err
	}
	endpoint, err := required("TEAMLEDGER_AUDIT_ENDPOINT")
	if err != nil {
		return err
	}
	caPath, err := required("TEAMLEDGER_AUDIT_CA_FILE")
	if err != nil {
		return err
	}
	caPEM, err := configfile.Read(caPath, 1<<20, false)
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
	encoded, err := configfile.Read(publicPath, 16<<10, false)
	if err != nil {
		return err
	}
	defer clear(encoded)
	receiptKeys, err := audit.ParseReceiptKeys(encoded)
	if err != nil {
		return errors.New("invalid audit receipt trust")
	}
	defer func() {
		for _, key := range receiptKeys {
			clear(key)
		}
	}()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	once := os.Getenv("TEAMLEDGER_AUDIT_ONCE") == "1"
	var nextProbe time.Time
	for {
		now := time.Now().UTC().Truncate(time.Microsecond)
		var deliveryErr error
		if !now.Before(nextProbe) {
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			probeErr := audit.ProbeReceiver(probeCtx, client, endpoint)
			cancel()
			statusCtx, statusCancel := context.WithTimeout(ctx, 5*time.Second)
			statusErr := repository.RecordAuditReceiverStatus(statusCtx, deployment, probeErr == nil, now)
			statusCancel()
			if statusErr != nil {
				deliveryErr = statusErr
			}
			nextProbe = now.Add(5 * time.Second)
		}
		found := false
		if deliveryErr == nil {
			found, deliveryErr = audit.DeliverOne(ctx, repository, client, endpoint, deployment, receiptKeys, now)
		}
		if deliveryErr != nil && once {
			return deliveryErr
		}
		if once && !found {
			return nil
		}
		if deliveryErr == nil && found {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal("audit forwarder unavailable")
	}
}
