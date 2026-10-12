package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func auditBackends(t *testing.T, run func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, testsupport.NewHarness(t, backend)) })
	}
}

func grantAuditRead(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	ctx := context.Background()
	if err := f.Exec(ctx,
		"INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'audit.read','org',?)",
		"INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'audit.read','org',$3)", f.OrgID, f.Owner.SubjectID, f.OrgID); err != nil {
		t.Fatal(err)
	}
	id := value.NewID()
	if err := f.Exec(ctx,
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,'audit.read','audit','org',?,'security_administration',?,?,1)",
		"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,'audit.read','audit','org',$4,'security_administration',$5,$6,true)", id, f.OrgID, f.Owner.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedAuditEvent(t *testing.T, f *testsupport.Fixture, at time.Time) string {
	t.Helper()
	id := value.NewID()
	if err := f.Exec(context.Background(),
		"INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at) VALUES(?,?,?,'OP-SEC-04','security_administration',?,'allowed',?)",
		"INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at) VALUES($1,$2,$3,'OP-SEC-04','security_administration',$4,'allowed',$5)", id, f.OrgID, f.Manager.SubjectID, value.NewID(), f.Repo.BindTime(at)); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAuditReadIsIndependentBoundSanitizedAndFailSafe(t *testing.T) {
	auditBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		grant := grantAuditRead(t, f)
		older := seedAuditEvent(t, f, f.Now.Add(-2*time.Minute))
		newer := seedAuditEvent(t, f, f.Now.Add(-time.Minute))
		service := &audit.Service{Store: f.Repo, CursorKey: f.CursorKey, Now: func() time.Time { return f.Now }}
		request := audit.Request{TokenHash: f.Owner.Hash, Purpose: audit.Purpose, RequestID: value.NewID()}
		filter := audit.Filter{Operation: "OP-SEC-04", Limit: 1}
		page, err := service.List(ctx, request, filter)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != newer || page.NextCursor == nil || page.Consistency != "current" {
			t.Fatal("first sanitized audit page:", page, err)
		}
		raw, err := json.Marshal(page)
		if err != nil || strings.Contains(string(raw), "amount") || strings.Contains(string(raw), "note") || strings.Contains(string(raw), "prompt") || strings.Contains(string(raw), "identity_digest") {
			t.Fatal("audit DTO exposed sensitive content fields", string(raw), err)
		}
		filter.Cursor = *page.NextCursor
		request.RequestID = value.NewID()
		page, err = service.List(ctx, request, filter)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != older {
			t.Fatal("bound second audit page:", page, err)
		}
		if err = f.Exec(ctx, "UPDATE access_grant SET revoked=1,revision=revision+1,revoked_by=?,revoked_at=?,revoke_reason='policy_change' WHERE org_id=? AND id=?", "UPDATE access_grant SET revoked=true,revision=revision+1,revoked_by=$1,revoked_at=$2,revoke_reason='policy_change' WHERE org_id=$3 AND id=$4", f.Manager.SubjectID, f.Repo.BindTime(f.Now), f.OrgID, grant); err != nil {
			t.Fatal(err)
		}
		request.RequestID = value.NewID()
		if _, err = service.List(ctx, request, filter); !errors.Is(err, fault.Forbidden) {
			t.Fatal("revoked audit reader reused cursor:", err)
		}
		if err = f.Exec(ctx, "DELETE FROM audit_outbox", "DELETE FROM audit_outbox"); err != nil {
			t.Fatal(err)
		}
		if err = f.DisableAudit(ctx); err != nil {
			t.Fatal(err)
		}
		request.TokenHash, request.RequestID = f.Observer.Hash, value.NewID()
		if _, err = service.List(ctx, request, audit.Filter{Limit: 10}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("deny audit outage must preserve original safe authorization error:", err)
		}
	})
}
func TestAuditReadRechecksExpiryAfterSubjectLock(t *testing.T) {
	auditBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		grantAuditRead(t, f)
		calls := 0
		service := &audit.Service{Store: f.Repo, CursorKey: f.CursorKey, Now: func() time.Time {
			calls++
			if calls == 1 {
				return f.Now
			}
			return f.Now.Add(2 * time.Hour)
		}}
		request := audit.Request{TokenHash: f.Owner.Hash, Purpose: audit.Purpose, RequestID: value.NewID()}
		if _, err := service.List(context.Background(), request, audit.Filter{Limit: 10}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("audit read survived authorization expiry while acquiring lock:", err)
		}
	})
}
