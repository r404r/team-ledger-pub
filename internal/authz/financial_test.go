package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

func financialSnapshot(at time.Time, capability string, ref *authz.ObjectReference) authz.Snapshot {
	s := objectSnapshot(at, capability, "financial", ref)
	s.Grants[0].Purpose = "compensation_management"
	return s
}

func TestFinancialCapabilitiesRemainIndependentAndExact(t *testing.T) {
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	refs := []authz.ObjectReference{
		{Kind: "compensation_proposal", ID: "44444444-4444-4444-8444-444444444444"},
		{Kind: "compensation_event", ID: "55555555-5555-4555-8555-555555555555"},
		{Kind: "compensation_term", ID: "66666666-6666-4666-8666-666666666666"},
	}
	for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
		for _, ref := range refs {
			t.Run(capability+"/"+ref.Kind, func(t *testing.T) {
				want := capability == "compensation.read" || capability == "sensitive.export" || ref.Kind == "compensation_proposal"
				if !authz.SupportedPair(capability, "financial", "compensation_management") || authz.ObjectPair(capability, "financial", ref.Kind) != want || !authz.CanonicalLineage(ref) {
					t.Fatal("finite financial family rejected or immutable write admitted")
				}
				s := financialSnapshot(at, capability, &ref)
				if s.AllowsObject(capability, "financial", objectEmployee, "compensation_management", at, ref) != want {
					t.Fatal("exact financial permission differs from its capability family")
				}
				other := ref
				other.ID = "77777777-7777-4777-8777-777777777777"
				if s.Allows(capability, "financial", objectEmployee, "compensation_management", at) || s.AllowsObject(capability, "financial", objectEmployee, "compensation_management", at, other) || s.AllowsObject(capability, "financial", "88888888-8888-4888-8888-888888888888", "compensation_management", at, ref) {
					t.Fatal("exact financial authority elevated to aggregate, another object, or another owner")
				}
				for _, otherCapability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
					if otherCapability != capability && s.AllowsObject(otherCapability, "financial", objectEmployee, "compensation_management", at, ref) {
						t.Fatal("financial capability implicitly granted another operation")
					}
				}
				s.Grants[0].ObjectRef = nil
				if s.AllowsObject(capability, "financial", objectEmployee, "compensation_management", at, ref) != want {
					t.Fatal("broad approved scope changed finite immutable write policy")
				}
			})
		}
	}
	for _, lineage := range [][]authz.ObjectReference{{refs[0], refs[1]}, {refs[1], refs[2]}, {objectLineage()[0], refs[0]}, {{Kind: "compensation_aggregate", ID: refs[0].ID}}, {{Kind: "compensation_term", ID: "invalid"}}} {
		if authz.CanonicalLineage(lineage...) {
			t.Fatal("financial lineage must be a singleton exact typed object")
		}
	}
	for _, pair := range []struct{ capability, category, purpose string }{
		{"compensation.write", "financial", "compensation_management"},
		{"compensation.read", "metadata", "compensation_management"},
		{"compensation.approve", "financial", "interview_followup"},
		{"bonus.read", "financial", "compensation_management"},
		{"sensitive.export", "financial", "organization_management"},
	} {
		if authz.SupportedPair(pair.capability, pair.category, pair.purpose) {
			t.Fatal("unsupported capability/category/purpose admitted")
		}
	}
}

func TestFinancialRequiresCurrentMFAAndNeverRelationAuthority(t *testing.T) {
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	ref := authz.ObjectReference{Kind: "compensation_proposal", ID: "44444444-4444-4444-8444-444444444444"}
	for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
		for _, mutate := range []func(*authz.Snapshot){
			func(s *authz.Snapshot) { s.MFAUntil = at },
			func(s *authz.Snapshot) { s.Grants[0].ExpiresAt = at },
			func(s *authz.Snapshot) { s.Grants[0].ValidFrom = at.Add(time.Microsecond) },
			func(s *authz.Snapshot) { s.Grants[0].Revoked = true },
			func(s *authz.Snapshot) { s.Assignments = nil },
			func(s *authz.Snapshot) { s.SubjectEpoch++ },
			func(s *authz.Snapshot) { s.Grants[0].Purpose = "interview_followup" },
			func(s *authz.Snapshot) {
				s.SubjectEmployeeID = "88888888-8888-4888-8888-888888888888"
				s.Grants[0].RelationBound = true
				s.Grants[0].RelationRef = &authz.RelationReference{Kind: "reporting_line", ID: "99999999-9999-4999-8999-999999999999"}
				s.Grants[0].RelationActorEmployeeID = s.SubjectEmployeeID
				s.Relations = []authz.Tenure{{ID: s.Grants[0].RelationRef.ID, Kind: "reporting_line", EmployeeID: objectEmployee, ManagerEmployeeID: s.SubjectEmployeeID, ValidFrom: "2026-01-01", EmployeeFrom: "2026-01-01", ManagerFrom: "2026-01-01"}}
			},
		} {
			s := financialSnapshot(at, capability, &ref)
			if !s.AllowsObject(capability, "financial", objectEmployee, "compensation_management", at, ref) {
				t.Fatal("valid financial exact fixture denied")
			}
			mutate(&s)
			if s.AllowsObject(capability, "financial", objectEmployee, "compensation_management", at, ref) {
				t.Fatal("financial exact grant bypassed current MFA, scope, session or relation prohibition")
			}
			s.Grants[0].ObjectRef = nil
			if s.Allows(capability, "financial", objectEmployee, "compensation_management", at) {
				t.Fatal("broad financial grant bypassed current authorization")
			}
		}
	}
}
