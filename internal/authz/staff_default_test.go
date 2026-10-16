package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

func staffDefaultSnapshot(now time.Time) authz.Snapshot {
	ended := "2026-10-16"
	return authz.Snapshot{
		SubjectID: "subject", OrgID: "org", Timezone: "UTC", Active: true,
		SessionEpoch: 1, SubjectEpoch: 1, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		StaffDefaultEmployeeID: "manager", StaffDefaultEmployeeFrom: "2025-01-01",
		StaffDefaultReports: []authz.Tenure{
			{ID: "current", Kind: "reporting_line", EmployeeID: "report", ManagerEmployeeID: "manager", ValidFrom: "2026-01-01", EmployeeFrom: "2025-01-01", ManagerFrom: "2025-01-01"},
			{ID: "ended", Kind: "reporting_line", EmployeeID: "former", ManagerEmployeeID: "manager", ValidFrom: "2026-01-01", EffectiveTo: &ended, EmployeeFrom: "2025-01-01", ManagerFrom: "2025-01-01"},
			{ID: "grandchild", Kind: "reporting_line", EmployeeID: "grandchild", ManagerEmployeeID: "report", ValidFrom: "2026-01-01", EmployeeFrom: "2025-01-01", ManagerFrom: "2025-01-01"},
		},
	}
}

func TestStaffDefaultAllowsOnlyOwnAndCurrentDirectReportEmployeeReads(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	snapshot := staffDefaultSnapshot(now)
	for _, employee := range []string{"manager", "report"} {
		if !snapshot.Allows("organization.read", "metadata", employee, "organization_management", now) || !snapshot.Allows("pii.read", "pii", employee, "organization_management", now) || !snapshot.Allows("interview.read", "metadata", employee, "interview_followup", now) || !snapshot.StaffDefaultCanCreateInterview(employee, now) {
			t.Fatalf("staff default did not allow employee and interview reads/create for %s", employee)
		}
	}
	for _, employee := range []string{"", "peer", "former", "grandchild"} {
		if snapshot.Allows("organization.read", "metadata", employee, "organization_management", now) || snapshot.Allows("pii.read", "pii", employee, "organization_management", now) || snapshot.Allows("interview.read", "metadata", employee, "interview_followup", now) || snapshot.StaffDefaultCanCreateInterview(employee, now) {
			t.Fatalf("staff default escaped one-hop current scope for %q", employee)
		}
	}
	if snapshot.Allows("organization.write", "metadata", "manager", "organization_management", now) || snapshot.Allows("sensitive.export", "pii", "manager", "organization_management", now) || snapshot.Allows("interview.write", "metadata", "manager", "interview_followup", now) {
		t.Fatal("staff default granted an employee write, export, or general interview write capability")
	}
	scope := snapshot.StaffDefaultScope(now)
	if len(scope) != 2 || scope[0] != "manager" || scope[1] != "report" {
		t.Fatalf("staff default directory scope = %#v", scope)
	}
}

func TestStaffDefaultRequiresCurrentEmployeeAndValidSession(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	snapshot := staffDefaultSnapshot(now)
	ended := "2026-10-16"
	snapshot.StaffDefaultEmployeeTo = &ended
	if snapshot.Allows("organization.read", "metadata", "manager", "organization_management", now) || len(snapshot.StaffDefaultScope(now)) != 0 {
		t.Fatal("ended staff employment retained default access")
	}
	snapshot = staffDefaultSnapshot(now)
	snapshot.SessionRevoked = true
	if snapshot.Allows("organization.read", "metadata", "manager", "organization_management", now) || snapshot.StaffDefaultCanCreateInterview("manager", now) {
		t.Fatal("revoked session retained staff default access")
	}
}
