package httpapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func seedAuditHTTPAccess(t *testing.T, f *testsupport.Fixture) {
	t.Helper()
	ctx := context.Background()
	if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'audit.read','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'audit.read','org',$3)", f.OrgID, f.Owner.SubjectID, f.OrgID); err != nil {
		t.Fatal(err)
	}
	if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,'audit.read','audit','org',?,'security_administration',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,'audit.read','audit','org',$4,'security_administration',$5,$6,true)", value.NewID(), f.OrgID, f.Owner.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
}

func TestAPIAuditEventsRequireIndependentAuditReadAndStrictFilters(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			seedAuditHTTPAccess(t, f)
			var page audit.Page
			apiSend(t, f, grantRequest(t, f, f.Owner, "GET", "/api/v1/audit-events?operation=OP-SEC-01&limit=10", "", ""), 200, &page)
			if page.Items == nil || page.Consistency != "current" {
				t.Fatal("audit API did not return explicit current safe page", page)
			}
			apiSend(t, f, grantRequest(t, f, f.Observer, "GET", "/api/v1/audit-events?limit=10", "", ""), 403, nil)
			apiSend(t, f, grantRequest(t, f, f.Owner, "GET", "/api/v1/audit-events?limit=01", "", ""), 422, nil)
			apiSend(t, f, grantRequest(t, f, f.Owner, "GET", "/api/v1/audit-events?unknown=x", "", ""), 422, nil)
		})
	}
}
