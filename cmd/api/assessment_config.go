package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/providerapproval"
	"github.com/r404r/team-ledger/internal/value"
)

func assessmentConfiguration() (map[string]assessment.ProviderPolicy, map[string]assessment.WorkerIdentity, map[string]assessment.ServiceIdentity, *x509.CertPool, error) {
	providers := map[string]assessment.ProviderPolicy{}
	workers := map[string]assessment.WorkerIdentity{}
	services := map[string]assessment.ServiceIdentity{}
	workerNames := []string{"ASSESSMENT_PROVIDER_POLICY_ID", "ASSESSMENT_PROVIDER_AUDIENCE", "ASSESSMENT_PROVIDER_URL", "ASSESSMENT_PROVIDER_APPROVAL_FILE", "ASSESSMENT_WORKER_ID", "ASSESSMENT_WORKER_ORG_ID", "ASSESSMENT_WORKER_CA_FILE", "ASSESSMENT_WORKER_CERT_FILE"}
	values, configured := map[string]string{}, 0
	for _, name := range workerNames {
		values[name] = os.Getenv("TEAMLEDGER_" + name)
		if values[name] != "" {
			configured++
		}
	}
	var pool *x509.CertPool
	if configured != 0 {
		if configured != len(workerNames) || !value.ValidID(values["ASSESSMENT_PROVIDER_POLICY_ID"]) || !value.ValidID(values["ASSESSMENT_WORKER_ORG_ID"]) || values["ASSESSMENT_WORKER_ID"] == "" || len(values["ASSESSMENT_WORKER_ID"]) > 128 || values["ASSESSMENT_PROVIDER_AUDIENCE"] != "employee_followup" && values["ASSESSMENT_PROVIDER_AUDIENCE"] != "manager_followup" {
			return nil, nil, nil, nil, errors.New("invalid assessment worker configuration")
		}
		caPEM, err := configfile.Read(values["ASSESSMENT_WORKER_CA_FILE"], 1<<20, false)
		if err != nil {
			return nil, nil, nil, nil, errors.New("invalid assessment worker CA")
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, nil, nil, errors.New("invalid assessment worker CA")
		}
		certPEM, err := configfile.Read(values["ASSESSMENT_WORKER_CERT_FILE"], 1<<20, false)
		if err != nil {
			return nil, nil, nil, nil, errors.New("invalid assessment worker certificate")
		}
		block, rest := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return nil, nil, nil, nil, errors.New("invalid assessment worker certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, nil, nil, errors.New("invalid assessment worker certificate")
		}
		digest := sha256.Sum256(cert.Raw)
		providerID, workerID := values["ASSESSMENT_PROVIDER_POLICY_ID"], values["ASSESSMENT_WORKER_ID"]
		approval, approvalErr := providerapproval.Load(values["ASSESSMENT_PROVIDER_APPROVAL_FILE"], time.Now())
		if approvalErr != nil || approval.PolicyID != providerID || approval.Audience != values["ASSESSMENT_PROVIDER_AUDIENCE"] || approval.Endpoint != values["ASSESSMENT_PROVIDER_URL"] {
			return nil, nil, nil, nil, errors.New("provider processing is not approved")
		}
		providers[providerID] = assessment.ProviderPolicy{ID: providerID, Audience: approval.Audience, Enabled: true, ExpiresAt: approval.Expiry}
		workers[workerID] = assessment.WorkerIdentity{OrgID: values["ASSESSMENT_WORKER_ORG_ID"], CertDigest: digest[:]}
	}
	serviceSubject, serviceKeyFile := os.Getenv("TEAMLEDGER_ASSESSMENT_SERVICE_SUBJECT_ID"), os.Getenv("TEAMLEDGER_ASSESSMENT_SERVICE_TOKEN_HASH_FILE")
	if (serviceSubject == "") != (serviceKeyFile == "") || serviceSubject != "" && !value.ValidID(serviceSubject) {
		return nil, nil, nil, nil, errors.New("invalid assessment service identity")
	}
	if serviceSubject != "" {
		tokenHash, err := configfile.Read(serviceKeyFile, sha256.Size, true)
		if err != nil || len(tokenHash) != sha256.Size {
			return nil, nil, nil, nil, errors.New("invalid assessment service identity")
		}
		services[serviceSubject] = assessment.ServiceIdentity{TokenHash: tokenHash}
	}
	return providers, workers, services, pool, nil
}

func runAssessmentScheduler(ctx context.Context, service *assessment.Service) error {
	run := func() error {
		scan, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, err := service.ScanDue(scan)
		return err
	}
	if err := run(); err != nil {
		return err
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := run(); err != nil {
				return err
			}
		}
	}
}
