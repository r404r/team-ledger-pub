package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

func TestCurrentManagementGrantRequiresPurposeScopeAndMFA(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	const org = "22222222-2222-4222-8222-222222222222"
	const employee = "33333333-3333-4333-8333-333333333333"
	for _, tc := range []struct {
		name, scope, requestedEmployee, purpose string
		mfaUntil, validFrom, expiresAt          time.Time
		revoked                                 bool
		want                                    bool
	}{
		{"approved employee management", employee, employee, "security_administration", at.Add(time.Minute), at.Add(-time.Hour), at.Add(time.Hour), false, true},
		{"different employee", employee, "44444444-4444-4444-8444-444444444444", "security_administration", at.Add(time.Minute), at.Add(-time.Hour), at.Add(time.Hour), false, false},
		{"employee cannot manage whole org", employee, "", "security_administration", at.Add(time.Minute), at.Add(-time.Hour), at.Add(time.Hour), false, false},
		{"business purpose cannot manage grants", employee, employee, "organization_management", at.Add(time.Minute), at.Add(-time.Hour), at.Add(time.Hour), false, false},
		{"MFA expiry boundary", employee, employee, "security_administration", at, at.Add(-time.Hour), at.Add(time.Hour), false, false},
		{"future management grant", employee, employee, "security_administration", at.Add(time.Minute), at.Add(time.Microsecond), at.Add(time.Hour), false, false},
		{"grant expiry boundary", employee, employee, "security_administration", at.Add(time.Minute), at.Add(-time.Hour), at, false, false},
		{"revoked management grant", employee, employee, "security_administration", at.Add(time.Minute), at.Add(-time.Hour), at.Add(time.Hour), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := authz.Snapshot{
				SubjectID: "11111111-1111-4111-8111-111111111111", OrgID: org,
				Active: true, SessionEpoch: 1, SubjectEpoch: 1,
				ExpiresAt: at.Add(time.Hour), IdleExpiresAt: at.Add(time.Minute), MFAUntil: tc.mfaUntil,
				Assignments: []authz.Assignment{{Capability: "access_grant.manage", ScopeKind: "employee", ScopeID: tc.scope}},
				Grants: []authz.Grant{{Capability: "access_grant.manage", Category: "audit", ScopeKind: "employee", ScopeID: tc.scope,
					Purpose: "security_administration", ValidFrom: tc.validFrom, ExpiresAt: tc.expiresAt, Revoked: tc.revoked, MFARequired: true}},
			}
			if got := s.Allows("access_grant.manage", "audit", tc.requestedEmployee, tc.purpose, at); got != tc.want {
				t.Fatalf("current management permission=%v; want %v", got, tc.want)
			}
		})
	}
}
