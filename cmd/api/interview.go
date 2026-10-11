package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/sensitive"
)

func interviewKeyService(cfg map[string]string, piiToken string) (sensitive.Wrapper, func(), error) {
	path, err := required("INTERVIEW_KMS_TOKEN_FILE")
	if err != nil {
		return nil, nil, err
	}
	token, err := configfile.Read(path, 4096, true)
	if err != nil {
		return nil, nil, err
	}
	defer clear(token)
	tokenText := strings.TrimSpace(string(token))
	if tokenText == "" || strings.ContainsAny(tokenText, "\r\n") || tokenText == piiToken || cfg["INTERVIEW_KMS_KEY"] == cfg["KMS_KEY"] {
		return nil, nil, errors.New("invalid purpose-separated KMS configuration")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, errors.New("invalid interview trust store")
	}
	if ca := os.Getenv("TEAMLEDGER_INTERVIEW_KMS_CA_FILE"); ca != "" {
		pem, err := configfile.Read(ca, 1<<20, false)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, nil, errors.New("invalid interview KMS CA")
		}
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 8, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	wrapper, err := sensitive.NewVaultWrapper(cfg["INTERVIEW_KMS_URL"], cfg["INTERVIEW_KMS_KEY"], tokenText, client)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("invalid interview KMS configuration")
	}
	return wrapper, transport.CloseIdleConnections, nil
}
