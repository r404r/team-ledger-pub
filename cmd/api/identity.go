package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/identity"
)

func identityConfiguration(origin string, csrf, digest, cursor, idKey, txKey []byte) (*identity.OIDCConfig, func(), error) {
	names := []string{"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET_FILE", "OIDC_MFA_ACR", "OIDC_MFA_AMR", "OIDC_CA_FILE"}
	mode := os.Getenv("TEAMLEDGER_OIDC_MODE")
	if mode != "" && mode != "disabled" && mode != "oidc" {
		return nil, nil, errors.New("invalid OIDC mode")
	}
	if mode != "oidc" {
		for _, name := range names {
			if os.Getenv("TEAMLEDGER_"+name) != "" {
				return nil, nil, errors.New("incomplete OIDC configuration")
			}
		}
		return nil, nil, nil
	}
	values := make(map[string]string, len(names)-1)
	for _, name := range names[:len(names)-1] {
		value, e := required(name)
		if e != nil {
			return nil, nil, e
		}
		values[name] = value
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, errors.New("invalid identity origin")
	}
	if len(idKey) != 32 || len(txKey) != 32 || bytes.Equal(idKey, txKey) || bytes.Equal(idKey, csrf) || bytes.Equal(idKey, digest) || bytes.Equal(idKey, cursor) || bytes.Equal(txKey, csrf) || bytes.Equal(txKey, digest) || bytes.Equal(txKey, cursor) {
		return nil, nil, errors.New("keys must be distinct")
	}
	secretBytes, e := configfile.Read(values["OIDC_CLIENT_SECRET_FILE"], 4096, true)
	if e != nil {
		return nil, nil, e
	}
	clientSecret := strings.TrimSpace(string(secretBytes))
	clear(secretBytes)
	if clientSecret == "" || strings.ContainsAny(clientSecret, "\r\n") {
		return nil, nil, errors.New("invalid OIDC credential")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		return nil, nil, errors.New("invalid identity trust store")
	}
	if ca := os.Getenv("TEAMLEDGER_OIDC_CA_FILE"); ca != "" {
		pem, e := configfile.Read(ca, 1<<20, false)
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, nil, errors.New("invalid OIDC CA")
		}
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 8, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	config := &identity.OIDCConfig{Issuer: values["OIDC_ISSUER"], ClientID: values["OIDC_CLIENT_ID"], ClientSecret: clientSecret, RedirectURI: strings.TrimSuffix(origin, "/") + "/api/v1/auth/callback", HTTPClient: client, IdentityKey: idKey, TransactionKey: txKey, MFAACR: values["OIDC_MFA_ACR"], MFAAMR: strings.Split(values["OIDC_MFA_AMR"], ",")}
	return config, transport.CloseIdleConnections, nil
}
