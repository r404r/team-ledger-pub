package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

func relationSnapshot(at time.Time, kind string) authz.Snapshot {
	s := authz.Snapshot{OrgID: "org", SubjectID: "subject", Timezone: "America/Los_Angeles", SubjectEmployeeID: "actor", Active: true, SessionEpoch: 1, SubjectEpoch: 1, ExpiresAt: at.Add(48 * time.Hour), IdleExpiresAt: at.Add(48 * time.Hour), MFAUntil: at.Add(48 * time.Hour)}
	scopeKind, scopeID := "employee", "employee"
	t := authz.Tenure{Kind: kind, ID: "original", EmployeeID: "employee", ManagerEmployeeID: "actor", ValidFrom: "2026-10-01", EmployeeFrom: "2026-01-01", ManagerFrom: "2026-01-01"}
	if kind == "job_assignment" {
		scopeKind, scopeID = "department", "department"
		t.EmployeeID, t.DepartmentID, t.DepartmentFrom = "actor", "department", "2026-01-01"
	}
	s.Assignments = []authz.Assignment{{Capability: "pii.read", ScopeKind: scopeKind, ScopeID: scopeID}}
	s.Grants = []authz.Grant{{Capability: "pii.read", Category: "pii", Purpose: "organization_management", ScopeKind: scopeKind, ScopeID: scopeID, ValidFrom: at.Add(-time.Hour), ExpiresAt: at.Add(48 * time.Hour), MFARequired: true, RelationBound: true, RelationRef: &authz.RelationReference{Kind: kind, ID: "original"}, RelationActorEmployeeID: "actor"}}
	s.Relations = []authz.Tenure{t}
	return s
}

func TestImmutableRelationTenureUsesOrganizationDateAndExactReference(t *testing.T) {
	// UTC October 12 is still October 11 in the organization's persisted zone.
	at := time.Date(2026, 10, 12, 6, 59, 0, 0, time.UTC)
	for _, kind := range []string{"reporting_line", "job_assignment"} {
		t.Run(kind, func(t *testing.T) {
			s := relationSnapshot(at, kind)
			allows := func(s authz.Snapshot, now time.Time) bool {
				if kind == "job_assignment" {
					return s.AllowsDepartment("pii.read", "pii", "department", "organization_management", now)
				}
				return s.Allows("pii.read", "pii", "employee", "organization_management", now)
			}
			end := "2026-10-12"
			s.Relations[0].EffectiveTo = &end
			if !allows(s, at) {
				t.Fatal("scheduled future end revoked before organization date boundary")
			}
			if allows(s, at.Add(time.Minute)) {
				t.Fatal("current end boundary must fail without a background job")
			}
			if s.Relations[0].ValidTo != nil {
				t.Fatal("effective end rewrote immutable nominal interval")
			}
			s.Relations[0].EffectiveTo = nil
			s.Relations[0].Superseded = true
			replacement := s.Relations[0]
			replacement.ID, replacement.Superseded = "replacement", false
			s.Relations = append(s.Relations, replacement)
			if allows(s, at) {
				t.Fatal("same endpoint replacement revived original bound reference")
			}
			s.Relations[0].Superseded = false
			s.SubjectEmployeeID = "other"
			if allows(s, at) {
				t.Fatal("unapproved actor correspondence qualified bound grant")
			}
			s.SubjectEmployeeID = "actor"
			s.Timezone = "not/a/timezone"
			if allows(s, at) {
				t.Fatal("invalid timezone qualified relation")
			}
		})
	}
}

func TestDepartmentScopeUsesCurrentJobAssignmentWithoutInheritedRights(t *testing.T) {
	at := time.Date(2026, 10, 12, 6, 59, 0, 0, time.UTC)
	s := relationSnapshot(at, "job_assignment")
	s.Grants[0].RelationBound, s.Grants[0].RelationRef, s.Grants[0].RelationActorEmployeeID = false, nil, ""
	end := "2026-10-12"
	s.JobAssignments = []authz.Tenure{{ID: "assignment", Kind: "job_assignment", EmployeeID: "employee", DepartmentID: "department", ValidFrom: "2026-10-01", EffectiveTo: &end, EmployeeFrom: "2026-01-01", DepartmentFrom: "2026-01-01"}}
	if !s.Allows("pii.read", "pii", "employee", "organization_management", at) {
		t.Fatal("current exact job assignment did not cover employee")
	}
	if s.Allows("pii.read", "pii", "employee", "organization_management", at.Add(time.Minute)) {
		t.Fatal("historical job assignment retained authority")
	}
	if s.AllowsDepartment("pii.read", "pii", "descendant", "organization_management", at) {
		t.Fatal("department scope granted inherited rights")
	}
	if s.AllowsDepartment("payroll.read", "financial", "department", "organization_management", at) {
		t.Fatal("unimplemented finance capability escaped default deny")
	}
	s.Grants[0].Category = "metadata"
	if s.Allows("pii.read", "pii", "employee", "organization_management", at) {
		t.Fatal("job assignment replaced required explicit grant category")
	}
}
