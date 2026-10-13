package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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

func readCertificate(certName, keyName string) (tls.Certificate, error) {
	certPath, err := required(certName)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPath, err := required(keyName)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err := configfile.Read(certPath, 1<<20, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(certPEM)
	keyPEM, err := configfile.Read(keyPath, 1<<20, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, errors.New("invalid audit TLS identity")
	}
	return certificate, nil
}

func readTrust(name string) (*x509.CertPool, error) {
	path, err := required(name)
	if err != nil {
		return nil, err
	}
	encoded, err := configfile.Read(path, 1<<20, false)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		return nil, errors.New("invalid audit CA")
	}
	return pool, nil
}

func openRepository(ctx context.Context) (*store.Repository, error) {
	backend, err := required("TEAMLEDGER_DB_BACKEND")
	if err != nil {
		return nil, err
	}
	dsn, err := required("TEAMLEDGER_DB_DSN")
	if err != nil {
		return nil, err
	}
	if backend == "sqlite" {
		return store.Open(ctx, backend, dsn)
	}
	if backend != "postgres" {
		return nil, errors.New("unsupported backend")
	}
	caPath, err := required("TEAMLEDGER_DB_CA_FILE")
	if err != nil {
		return nil, err
	}
	ca, err := configfile.Read(caPath, 1<<20, false)
	if err != nil {
		return nil, err
	}
	defer clear(ca)
	return store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
}

func handler(repository *store.Repository, receiver *audit.Receiver, private ed25519.PrivateKey) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		probe := []byte("TEAMLEDGER-AUDIT-RECEIVER-READY")
		signature := ed25519.Sign(private, probe)
		public, ok := private.Public().(ed25519.PublicKey)
		if !ok || !ed25519.Verify(public, probe, signature) || repository.AuditReceiverReady(r.Context()) != nil {
			clear(signature)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		clear(signature)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
		if err != nil || len(body) > 16<<10 {
			clear(body)
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		defer clear(body)
		receipt, err := receiver.Receive(r.Context(), r.Header.Get("Idempotency-Key"), body)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, audit.ErrInvalidAuditDelivery) {
				status = http.StatusBadRequest
			} else if errors.Is(err, audit.ErrAuditEventConflict) {
				status = http.StatusConflict
			}
			http.Error(w, "rejected", status)
			return
		}
		defer clear(receipt)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(receipt)
	})
	return mux
}

func serve(ctx context.Context) error {
	listen, err := required("TEAMLEDGER_AUDIT_LISTEN")
	if err != nil {
		return err
	}
	deployment, err := required("TEAMLEDGER_DEPLOYMENT_ID")
	if err != nil {
		return err
	}
	repository, err := openRepository(ctx)
	if err != nil {
		return err
	}
	defer repository.Close()
	serverCertificate, err := readCertificate("TEAMLEDGER_AUDIT_SERVER_CERT_FILE", "TEAMLEDGER_AUDIT_SERVER_KEY_FILE")
	if err != nil {
		return err
	}
	clientRoots, err := readTrust("TEAMLEDGER_AUDIT_CA_FILE")
	if err != nil {
		return err
	}
	signerPath, err := required("TEAMLEDGER_AUDIT_SIGNER_FILE")
	if err != nil {
		return err
	}
	keyID, private, err := audit.LoadSigner(signerPath)
	if err != nil {
		return err
	}
	defer clear(private)
	receiver, err := audit.NewReceiver(repository, deployment, keyID, private, func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots})
	server := &http.Server{Handler: handler(repository, receiver, private), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tlsListener) }()
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func healthcheck(ctx context.Context) error {
	endpoint, err := required("TEAMLEDGER_AUDIT_HEALTH_ENDPOINT")
	if err != nil {
		return err
	}
	certificate, err := readCertificate("TEAMLEDGER_AUDIT_HEALTH_CERT_FILE", "TEAMLEDGER_AUDIT_HEALTH_KEY_FILE")
	if err != nil {
		return err
	}
	roots, err := readTrust("TEAMLEDGER_AUDIT_CA_FILE")
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("audit receiver not ready")
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := healthcheck(ctx); err != nil {
			log.Fatal("audit receiver unavailable")
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		log.Fatal("audit receiver unavailable")
	}
}
