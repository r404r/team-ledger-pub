package httpapi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestHealthSeparatesProcessLivenessFromSchemaKeysAndAuditReadiness(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			fixture := testsupport.NewHarness(t, backend)
			request := func(path string) int {
				req, err := http.NewRequest(http.MethodGet, fixture.Server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := fixture.Server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				return response.StatusCode
			}
			if status := request("/health/live"); status != 200 {
				t.Fatal("live", status)
			}
			if status := request("/health/ready"); status != 200 {
				t.Fatal("ready", status)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			if err := fixture.Repo.AuditDenied(context.Background(), organization.Audit{ID: value.NewID(), OrgID: fixture.OrgID, SubjectID: fixture.Owner.SubjectID, Operation: "OP-SEC-04", Purpose: "security_administration", RequestID: value.NewID(), At: now.Add(-6 * time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if status := request("/health/ready"); status != 503 {
				t.Fatal("stale independent audit backlog did not close readiness", status)
			}
			if status := request("/health/live"); status != 200 {
				t.Fatal("audit dependency changed process liveness", status)
			}
		})
	}
}
