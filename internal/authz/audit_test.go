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
