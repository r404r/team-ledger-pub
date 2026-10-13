package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func employeeBindArgs(t *testing.T, f *testsupport.Fixture, subject, employee, sub, request string) []string {
	t.Helper()
	args := []string{"bind", "-backend", f.Backend, "-dsn-file", maintenanceFile(t, "dsn", []byte(f.DSN), 0600), "-issuer", "https://approved-synthetic.invalid", "-identity-key-file", maintenanceFile(t, "key", bytes.Repeat([]byte{91}, 32), 0600), "-sub-file", maintenanceFile(t, "sub", []byte(sub), 0600), "-org-id", f.OrgID, "-subject-id", subject, "-request-id", request}
	if employee != "" {
		args = append(args, "-employee-id", employee)
	}
	if f.Backend == "postgres" {
		u, err := url.Parse(f.DSN)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "-postgres-ca-file", u.Query().Get("sslrootcert"))
	}
	return args
}

func createCorrespondenceEmployee(t *testing.T, f *testsupport.Fixture, otherOrg bool) string {
	t.Helper()
	owner, org := f.Owner, f.OrgID
	if otherOrg {
		owner, org = f.OtherOwner, f.OtherOrgID
	}
	made, err := f.Service.Create(context.Background(), f.Request(owner), org, organization.CreateCommand{Profile: organization.Profile{LocalName: "SYNTHETIC_CORRESPONDENCE_EMPLOYEE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	return made.ID
}

func TestIdentityCLIExplicitEmployeeLinkIsImmutableTypedAndAuditedWithoutAutoAuthority(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			employee := createCorrespondenceEmployee(t, f, false)
			otherEmployee := createCorrespondenceEmployee(t, f, false)
			foreignEmployee := createCorrespondenceEmployee(t, f, true)
			grants, subjects := f.Count(t, "access_grant"), f.Count(t, "subject")
			requestID := value.NewID()
			if err := run(employeeBindArgs(t, f, f.Reader.SubjectID, employee, "synthetic-approved-employee", requestID)); err != nil {
				t.Fatal("explicit approved subject/employee CLI link failed:", err)
			}
			query := "SELECT org_id,subject_id,employee_id FROM subject_employee"
			var gotOrg, gotSubject, gotEmployee string
			if err := f.Repo.DB.QueryRow(query).Scan(&gotOrg, &gotSubject, &gotEmployee); err != nil || gotOrg != f.OrgID || gotSubject != f.Reader.SubjectID || gotEmployee != employee {
				t.Fatal("CLI must persist exact same-org approved correspondence:", err)
			}
			query = "SELECT subject_id,actor_kind,actor_uid,target_subject_id,target_employee_id FROM audit_event WHERE request_id=? AND operation='AUTH-BIND'"
			if backend == "postgres" {
				query = "SELECT subject_id,actor_kind,actor_uid,target_subject_id,target_employee_id FROM audit_event WHERE request_id=$1 AND operation='AUTH-BIND'"
			}
			var actor sql.NullString
			var kind, targetSubject, targetEmployee string
			var uid int64
			if err := f.Repo.DB.QueryRow(query, requestID).Scan(&actor, &kind, &uid, &targetSubject, &targetEmployee); err != nil || actor.Valid || kind != "local_maintenance" || uid != int64(os.Geteuid()) || targetSubject != f.Reader.SubjectID || targetEmployee != employee {
				t.Fatal("maintenance must audit native actor separately from exact approved subject/employee target:", err)
			}
			for _, invalid := range []struct{ subject, employee, sub string }{
				{f.Reader.SubjectID, otherEmployee, "synthetic-forbidden-rebind"},
				{f.Observer.SubjectID, employee, "synthetic-forbidden-shared-employee"},
				{f.Observer.SubjectID, foreignEmployee, "synthetic-forbidden-foreign-employee"},
			} {
				identities, audits := f.Count(t, "subject_identity"), f.Count(t, "audit_event")
				if err := run(employeeBindArgs(t, f, invalid.subject, invalid.employee, invalid.sub, value.NewID())); err == nil {
					t.Fatal("wrong existing/occupied/foreign correspondence must fail")
				}
				if f.Count(t, "subject_identity") != identities || f.Count(t, "audit_event") != audits || f.Count(t, "subject_employee") != 1 {
					t.Fatal("failed correspondence cannot leave an identity, link, or successful audit")
				}
			}
			if err := run(employeeBindArgs(t, f, f.Reader.SubjectID, "", "synthetic-approved-alias-no-employee-flag", value.NewID())); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRow("SELECT employee_id FROM subject_employee").Scan(&gotEmployee); err != nil || gotEmployee != employee {
				t.Fatal("omitting employee flag cannot clear or alter previously approved correspondence:", err)
			}
			if f.Count(t, "access_grant") != grants || f.Count(t, "subject") != subjects {
				t.Fatal("employment correspondence must not provision subject or grant authority")
			}
			if _, err := f.Service.Read(context.Background(), f.Request(f.Reader), employee, "2026-10-11", true); err == nil {
				t.Fatal("explicit correspondence alone cannot release employee PII")
			}
		})
	}
}

func TestApprovedEmployeeLinkAndEpochRollBackWhenMaintenanceAuditCannotCommit(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			employee := createCorrespondenceEmployee(t, f, false)
			var before, after int64
			query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
			if backend == "postgres" {
				query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
			}
			if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Repo.DB.Exec("ALTER TABLE audit_event RENAME TO audit_event_unavailable"); err != nil {
				t.Fatal(err)
			}
			digest, err := identity.IdentityDigest(bytes.Repeat([]byte{91}, 32), "https://approved-synthetic.invalid", "synthetic-audit-failed-correspondence")
			if err != nil {
				t.Fatal(err)
			}
			mapping := identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Reader.SubjectID, EmployeeID: employee}
			if err := f.Repo.BindIdentity(context.Background(), mapping, value.NewID(), f.Now); !errors.Is(err, fault.AuditUnavailable) {
				t.Fatal("actual maintenance transaction must reach failed audit and reject employment binding:", err)
			}
			if _, err := f.Repo.DB.Exec("ALTER TABLE audit_event_unavailable RENAME TO audit_event"); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&after); err != nil || after != before || f.Count(t, "subject_employee") != 0 || f.Count(t, "subject_identity") != 0 {
				t.Fatal("failed maintenance audit must roll back link, identity and authority context epoch together:", err)
			}
		})
	}
}
