package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

func TestAuditReadIsIndependentAndRequiresRecentMFA(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	grant := authz.Grant{Capability: "audit.read", Category: "audit", ScopeKind: "org", ScopeID: "10000000-0000-4000-8000-000000000001", Purpose: "security_administration", ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MFARequired: true}
	snapshot := authz.Snapshot{OrgID: grant.ScopeID, Active: true, Timezone: "UTC", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), MFAUntil: now.Add(time.Minute), Assignments: []authz.Assignment{{Capability: "audit.read", ScopeKind: "org", ScopeID: grant.ScopeID}}, Grants: []authz.Grant{grant}}
	if !authz.SupportedPair("audit.read", "audit", "security_administration") || !snapshot.Allows("audit.read", "audit", "", "security_administration", now) {
		t.Fatal("approved independent audit grant was not usable")
	}
	for _, tuple := range [][3]string{{"audit.read", "pii", "security_administration"}, {"audit.read", "audit", "organization_management"}} {
		if authz.SupportedPair(tuple[0], tuple[1], tuple[2]) {
			t.Fatal("unapproved audit tuple accepted", tuple)
		}
	}
	snapshot.MFAUntil = now
	if snapshot.Allows("audit.read", "audit", "", "security_administration", now) {
		t.Fatal("audit read remained usable after the recent-MFA boundary")
	}
}

func TestIdentityManagementRequiresDedicatedGrantAndRecentMFA(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	org := "10000000-0000-4000-8000-000000000001"
	grant := authz.Grant{Capability: "identity.manage", Category: "audit", ScopeKind: "org", ScopeID: org, Purpose: authz.ManagementPurpose, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MFARequired: true}
	snapshot := authz.Snapshot{OrgID: org, Active: true, Timezone: "UTC", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), MFAUntil: now.Add(time.Minute), Assignments: []authz.Assignment{{Capability: "identity.manage", ScopeKind: "org", ScopeID: org}}, Grants: []authz.Grant{grant}}
	if !authz.SupportedPair("identity.manage", "audit", authz.ManagementPurpose) || !snapshot.Allows("identity.manage", "audit", "", authz.ManagementPurpose, now) {
		t.Fatal("dedicated identity administration grant was not usable")
	}
	if snapshot.Allows("access_grant.manage", "audit", "", authz.ManagementPurpose, now) || snapshot.Allows("audit.read", "audit", "", authz.ManagementPurpose, now) {
		t.Fatal("identity administration implied an independent security capability")
	}
	snapshot.MFAUntil = now
	if snapshot.Allows("identity.manage", "audit", "", authz.ManagementPurpose, now) {
		t.Fatal("identity administration remained usable after the recent-MFA boundary")
	}
}
