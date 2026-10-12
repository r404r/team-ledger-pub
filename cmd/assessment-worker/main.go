package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/providerapproval"
	"github.com/r404r/team-ledger/internal/value"
)

type config struct {
	workerID, apiURL, providerURL, providerPolicyID, providerAudience string
	providerApprovalExpires                                           time.Time
	apiClient, providerClient                                         *http.Client
}
type providerRequest struct {
	Input    assessment.StructuredInput `json:"input"`
	Audience string                     `json:"audience"`
}
type resultCommand struct {
	Lease    assessment.Lease          `json:"lease"`
	Document assessment.ResultDocument `json:"document"`
}
type failCommand struct {
	Lease assessment.Lease `json:"lease"`
	Code  string           `json:"code"`
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "assessment worker failed")
		os.Exit(1)
	}
}
func required(name string) (string, error) {
	v := os.Getenv("TEAMLEDGER_" + name)
	if strings.TrimSpace(v) == "" {
		return "", errors.New("missing configuration")
	}
	return v, nil
}
func endpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("invalid endpoint")
	}
	return strings.TrimSuffix(raw, "/"), nil
}
func load() (config, error) {
	var c config
	var err error
	if c.workerID, err = required("ASSESSMENT_WORKER_ID"); err != nil || len(c.workerID) > 128 {
		return c, errors.New("invalid worker")
	}
	if c.apiURL, err = required("ASSESSMENT_API_URL"); err != nil {
		return c, err
	}
	if c.apiURL, err = endpoint(c.apiURL); err != nil {
		return c, err
	}
	if c.providerURL, err = required("ASSESSMENT_PROVIDER_URL"); err != nil {
		return c, err
	}
	if c.providerURL, err = endpoint(c.providerURL); err != nil {
		return c, err
	}
	if c.providerPolicyID, err = required("ASSESSMENT_PROVIDER_POLICY_ID"); err != nil {
		return c, err
	}
	approvalPath, err := required("ASSESSMENT_PROVIDER_APPROVAL_FILE")
	if err != nil {
		return c, err
	}
	approval, err := providerapproval.Load(approvalPath, time.Now())
	if err != nil || approval.PolicyID != c.providerPolicyID || approval.Endpoint != c.providerURL {
		return c, errors.New("provider processing is not approved")
	}
	c.providerAudience, c.providerApprovalExpires = approval.Audience, approval.Expiry
	caPath, err := required("ASSESSMENT_TLS_CA_FILE")
	if err != nil {
		return c, err
	}
	ca, err := configfile.Read(caPath, 1<<20, false)
	if err != nil {
		return c, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return c, errors.New("invalid CA")
	}
	certPath, err := required("ASSESSMENT_TLS_CERT_FILE")
	if err != nil {
		return c, err
	}
	keyPath, err := required("ASSESSMENT_TLS_KEY_FILE")
	if err != nil {
		return c, err
	}
	certPEM, err := configfile.Read(certPath, 1<<20, false)
	if err != nil {
		return c, err
	}
	keyPEM, err := configfile.Read(keyPath, 64<<10, true)
	if err != nil {
		return c, err
	}
	defer clear(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return c, errors.New("invalid client certificate")
	}
	apiTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	c.apiClient = &http.Client{Transport: apiTransport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	providerCAPath, err := required("ASSESSMENT_PROVIDER_CA_FILE")
	if err != nil {
		return c, err
	}
	providerCA, err := configfile.Read(providerCAPath, 1<<20, false)
	if err != nil {
		return c, errors.New("invalid provider CA")
	}
	providerRoots := x509.NewCertPool()
	if !providerRoots.AppendCertsFromPEM(providerCA) {
		return c, errors.New("invalid provider CA")
	}
	providerTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: providerRoots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	c.providerClient = &http.Client{Transport: providerTransport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	return c, nil
}
func strictResponse(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("remote rejection")
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return errors.New("invalid content type")
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing response")
	}
	return nil
}
func (c config) post(ctx context.Context, path, key string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-TeamLedger-Worker-ID", c.workerID)
	req.Header.Set("Idempotency-Key", key)
	resp, err := c.apiClient.Do(req)
	if err != nil {
		return err
	}
	if out == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errors.New("API rejection")
		}
		return nil
	}
	return strictResponse(resp, out)
}
func (c config) claim(ctx context.Context) (assessment.Lease, error) {
	var lease assessment.Lease
	err := c.post(ctx, "/internal/v1/assessment/jobs/claim", value.NewID(), struct{}{}, &lease)
	return lease, err
}
func (c config) provider(ctx context.Context, lease assessment.Lease) (assessment.ResultDocument, error) {
	if lease.ProviderPolicyID != c.providerPolicyID || lease.Audience != c.providerAudience || !time.Now().Before(c.providerApprovalExpires) {
		return assessment.ResultDocument{}, errors.New("unapproved provider policy")
	}
	raw, err := json.Marshal(providerRequest{Input: lease.Input, Audience: lease.Audience})
	if err != nil {
		return assessment.ResultDocument{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL+"/v1/assessment", bytes.NewReader(raw))
	if err != nil {
		return assessment.ResultDocument{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.providerClient.Do(req)
	if err != nil {
		return assessment.ResultDocument{}, err
	}
	var out assessment.ResultDocument
	err = strictResponse(resp, &out)
	return out, err
}
func (c config) cycle(ctx context.Context) error {
	lease, err := c.claim(ctx)
	if err != nil {
		return err
	}
	document, err := c.provider(ctx, lease)
	if err != nil {
		_ = c.post(ctx, "/internal/v1/assessment/jobs/fail", value.NewID(), failCommand{Lease: lease, Code: "provider_unavailable"}, nil)
		return err
	}
	key := value.NewID()
	err = c.post(ctx, "/internal/v1/assessment/jobs/result", key, resultCommand{Lease: lease, Document: document}, nil)
	if err != nil {
		return c.post(ctx, "/internal/v1/assessment/jobs/result", key, resultCommand{Lease: lease, Document: document}, nil)
	}
	return nil
}
func run() error {
	c, err := load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	once := os.Getenv("TEAMLEDGER_ASSESSMENT_WORKER_ONCE") == "1"
	for {
		err = c.cycle(ctx)
		if once {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}
