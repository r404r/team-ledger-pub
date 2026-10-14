package store_test

import (
	"context"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func csrfSQL(backend, sqlite, postgres string) string {
	if backend == "sqlite" {
		return sqlite
	}
	return postgres
}

func TestCSRFVersionRevocationIsAtomicAndAdvancesEpochs(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			defer f.Close()
			ctx := context.Background()
			var subjectBefore, orgBefore int64
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2"), f.OrgID, f.Owner.SubjectID).Scan(&subjectBefore); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT auth_epoch FROM authorization_guard WHERE org_id=?", "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"), f.OrgID).Scan(&orgBefore); err != nil {
				t.Fatal(err)
			}
			requestID := value.NewID()
			var oldKey sensitive.KeyReference
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT csrf_key_id,csrf_version FROM session WHERE org_id=? AND subject_id=? AND revoked=0 LIMIT 1", "SELECT csrf_key_id,csrf_version FROM session WHERE org_id=$1 AND subject_id=$2 AND revoked=false LIMIT 1"), f.OrgID, f.Owner.SubjectID).Scan(&oldKey.KeyID, &oldKey.Version); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.RevokeCSRFVersion(ctx, oldKey, requestID, f.Now); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Service.Session(ctx, f.Request(f.Owner), ""); err == nil || err == fault.Unavailable {
				t.Fatal("old CSRF session remained usable", err)
			}
			var subjectAfter, orgAfter, audits int64
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2"), f.OrgID, f.Owner.SubjectID).Scan(&subjectAfter); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT auth_epoch FROM authorization_guard WHERE org_id=?", "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"), f.OrgID).Scan(&orgAfter); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRowContext(ctx, csrfSQL(backend, "SELECT count(*) FROM audit_event WHERE request_id=?", "SELECT count(*) FROM audit_event WHERE request_id=$1"), requestID).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if subjectAfter != subjectBefore+1 || orgAfter != orgBefore+1 || audits == 0 {
				t.Fatalf("revocation facts subject=%d/%d org=%d/%d audits=%d", subjectBefore, subjectAfter, orgBefore, orgAfter, audits)
			}
		})
	}
}
