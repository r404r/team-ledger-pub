package authz_test

import (
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
)

const objectOrg = "22222222-2222-4222-8222-222222222222"
const objectEmployee = "33333333-3333-4333-8333-333333333333"

func objectSnapshot(at time.Time, capability, category string, ref *authz.ObjectReference) authz.Snapshot {
	return authz.Snapshot{OrgID: objectOrg, Timezone: "UTC", Active: true, SessionEpoch: 1, SubjectEpoch: 1, ExpiresAt: at.Add(time.Hour), IdleExpiresAt: at.Add(time.Hour), MFAUntil: at.Add(time.Minute),
		Assignments: []authz.Assignment{{Capability: capability, ScopeKind: "org", ScopeID: objectOrg}},
		Grants:      []authz.Grant{{Capability: capability, Category: category, ScopeKind: "employee", ScopeID: objectEmployee, Purpose: "interview_followup", ValidFrom: at.Add(-time.Hour), ExpiresAt: at.Add(time.Hour), ObjectRef: ref}}}
}

func objectLineage() []authz.ObjectReference {
	return []authz.ObjectReference{{Kind: "interview", ID: "44444444-4444-4444-8444-444444444444"}, {Kind: "note_head", ID: "55555555-5555-4555-8555-555555555555"}, {Kind: "note_version", ID: "66666666-6666-4666-8666-666666666666"}}
}

func TestObjectGrantNeverFallsBackToScopeOrHead(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	lineage := objectLineage()
	s := objectSnapshot(at, "note.read", "shared", &lineage[2])
	if !s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, lineage...) {
		t.Fatal("exact approved historical version denied")
	}
	if s.Allows("note.read", "shared", objectEmployee, "interview_followup", at) || s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, lineage[:2]...) || s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, lineage[:1]...) {
		t.Fatal("version-only authority escaped into whole employee/head/interview")
	}
	other := append([]authz.ObjectReference(nil), lineage...)
	other[2].ID = "77777777-7777-4777-8777-777777777777"
	if s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, other...) || s.AllowsObject("note.read", "manager_private", objectEmployee, "interview_followup", at, lineage...) || s.AllowsObject("note.read", "shared", "88888888-8888-4888-8888-888888888888", "interview_followup", at, lineage...) {
		t.Fatal("object grant crossed immutable version/category/employee")
	}
	s.Grants[0].ObjectRef = nil
	if !s.Allows("note.read", "shared", objectEmployee, "interview_followup", at) || !s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, other...) {
		t.Fatal("explicit NULL scope grant ceased to cover owned versions")
	}
	s.Grants[0].ObjectRef = &lineage[1]
	if !s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, lineage...) || !s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, other...) {
		t.Fatal("explicit head grant must cover its canonical immutable versions")
	}
}

func TestCanonicalObjectLineageAndFiniteFamilies(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	lineage := objectLineage()
	s := objectSnapshot(at, "note.read", "shared", nil)
	for _, bad := range [][]authz.ObjectReference{nil, {lineage[2]}, {lineage[0], lineage[2]}, {lineage[2], lineage[1], lineage[0]}, {lineage[0], {Kind: "note_head", ID: lineage[0].ID}}, {lineage[0], {Kind: "action_item", ID: lineage[1].ID}, lineage[2]}, {{Kind: "interview", ID: "not-a-uuid"}}} {
		if authz.CanonicalLineage(bad...) || s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, bad...) {
			t.Fatalf("malformed lineage accepted: %+v", bad)
		}
	}
	for _, pair := range []struct {
		capability, category, kind string
		want                       bool
	}{
		{"interview.read", "metadata", "interview", true}, {"interview.read", "metadata", "note_version", false},
		{"note.read", "shared", "note_version", true}, {"note.write", "shared", "note_version", false}, {"note.publish", "hr_confidential", "note_head", true},
		{"note.read", "shared", "action_item", false}, {"action.write", "shared", "action_item", true}, {"action.read", "manager_private", "action_item", false},
		{"sensitive.export", "metadata", "note_version", false}, {"sensitive.export", "shared", "action_item", true}, {"sensitive.export", "hr_confidential", "action_item", false},
	} {
		if authz.ObjectPair(pair.capability, pair.category, pair.kind) != pair.want {
			t.Fatalf("wrong finite object family policy: %+v", pair)
		}
	}
	management := objectSnapshot(at, "access_grant.manage", "audit", &lineage[0])
	management.Grants[0].Purpose = authz.ManagementPurpose
	if management.Allows("access_grant.manage", "audit", objectEmployee, authz.ManagementPurpose, at) || len(management.ManagedScopes(at)) != 0 {
		t.Fatal("object restriction became whole-scope management authority")
	}
	management.Grants[0].ScopeKind, management.Grants[0].ScopeID = "department", lineage[0].ID
	management.Assignments[0].ScopeKind, management.Assignments[0].ScopeID = "department", lineage[0].ID
	if management.AllowsDepartment("access_grant.manage", "audit", lineage[0].ID, authz.ManagementPurpose, at) {
		t.Fatal("department checks lost object restriction")
	}
}

func TestObjectAuthorityCurrentValidityAndMandatorySessionMFA(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	lineage := objectLineage()
	for _, capability := range []string{"note.publish", "sensitive.export"} {
		s := objectSnapshot(at, capability, "shared", nil)
		if !s.AllowsObject(capability, "shared", objectEmployee, "interview_followup", at, lineage[:2]...) {
			t.Fatal("current MFA permission denied", capability)
		}
		s.MFAUntil = at
		if s.AllowsObject(capability, "shared", objectEmployee, "interview_followup", at, lineage[:2]...) || s.Allows(capability, "shared", objectEmployee, "interview_followup", at) {
			t.Fatal("mandatory current-session MFA bypassed by optional grant flag", capability)
		}
	}
	for _, mutate := range []func(*authz.Snapshot){
		func(s *authz.Snapshot) { s.Grants[0].Revoked = true },
		func(s *authz.Snapshot) { s.Grants[0].ExpiresAt = at },
		func(s *authz.Snapshot) { s.Grants[0].ValidFrom = at.Add(time.Microsecond) },
		func(s *authz.Snapshot) { s.Assignments = nil },
		func(s *authz.Snapshot) { s.SessionRevoked = true },
		func(s *authz.Snapshot) { s.SubjectEpoch++ },
	} {
		s := objectSnapshot(at, "note.read", "shared", &lineage[2])
		mutate(&s)
		if s.AllowsObject("note.read", "shared", objectEmployee, "interview_followup", at, lineage...) {
			t.Fatal("object grant bypassed current validity/assignment/session")
		}
	}
}

func TestSourceApprovalIsExactVersionEmployeeAndActiveTargetGrant(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	lineage := objectLineage()
	source := authz.ObjectReference{Kind: "note_version", ID: "77777777-7777-4777-8777-777777777777"}
	s := objectSnapshot(at, "note.publish", "shared", &lineage[1])
	s.Grants[0].ApprovedSourceRefs = []authz.ObjectReference{source}
	s.Grants[0].ApprovedSourceEmployees = map[string]string{source.ID: objectEmployee}
	if !s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", at, source, lineage[:2]...) {
		t.Fatal("active explicit target source approval denied")
	}
	if s.AllowsObject("note.read", "manager_private", objectEmployee, "interview_followup", at, lineage...) {
		t.Fatal("target approval manufactured independent private source read")
	}
	other := source
	other.ID = "88888888-8888-4888-8888-888888888888"
	if s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", at, other, lineage[:2]...) || s.AllowsApprovedSource("note.publish", "hr_confidential", objectEmployee, "interview_followup", at, source, lineage[:2]...) {
		t.Fatal("approval escaped source version/target category")
	}
	s.Grants[0].ApprovedSourceEmployees[source.ID] = "99999999-9999-4999-8999-999999999999"
	if s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", at, source, lineage[:2]...) {
		t.Fatal("source approval crossed employee despite broad assignment")
	}
	s.Grants[0].ApprovedSourceEmployees[source.ID] = objectEmployee
	for _, revoke := range []bool{false, true} {
		s.Grants[0].Revoked = revoke
		if !revoke {
			s.MFAUntil = at
		} else {
			s.MFAUntil = at.Add(time.Minute)
		}
		if s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", at, source, lineage[:2]...) {
			t.Fatal("expired MFA/revoked target revived approval")
		}
	}
}

func TestObjectAndSourceApprovalUseExactCurrentOrganizationDayRelation(t *testing.T) {
	before := time.Date(2026, 10, 11, 14, 59, 0, 0, time.UTC)
	lineage := objectLineage()
	s := objectSnapshot(before, "note.publish", "shared", &lineage[1])
	s.Timezone = "Asia/Tokyo"
	s.SubjectEmployeeID = "88888888-8888-4888-8888-888888888888"
	end := "2026-10-12"
	relationID := "99999999-9999-4999-8999-999999999999"
	s.Grants[0].RelationBound = true
	s.Grants[0].RelationRef = &authz.RelationReference{Kind: "reporting_line", ID: relationID}
	s.Grants[0].RelationActorEmployeeID = s.SubjectEmployeeID
	s.Relations = []authz.Tenure{{ID: relationID, Kind: "reporting_line", EmployeeID: objectEmployee, ManagerEmployeeID: s.SubjectEmployeeID, ValidFrom: "2026-01-01", ValidTo: &end, EmployeeFrom: "2026-01-01", ManagerFrom: "2026-01-01"}}
	source := authz.ObjectReference{Kind: "note_version", ID: "77777777-7777-4777-8777-777777777777"}
	s.Grants[0].ApprovedSourceRefs = []authz.ObjectReference{source}
	s.Grants[0].ApprovedSourceEmployees = map[string]string{source.ID: objectEmployee}
	s.MFAUntil = before.Add(time.Hour)
	if !s.AllowsObject("note.publish", "shared", objectEmployee, "interview_followup", before, lineage[:2]...) || !s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", before, source, lineage[:2]...) {
		t.Fatal("current exact original manager tenure denied")
	}
	boundary := before.Add(time.Minute)
	if s.AllowsObject("note.publish", "shared", objectEmployee, "interview_followup", boundary, lineage[:2]...) || s.AllowsApprovedSource("note.publish", "shared", objectEmployee, "interview_followup", boundary, source, lineage[:2]...) {
		t.Fatal("historical objects/sources revived ended local-day manager relation")
	}
	s.Relations[0].ID, s.Relations[0].ValidTo = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", nil
	if s.AllowsObject("note.publish", "shared", objectEmployee, "interview_followup", boundary, lineage[:2]...) {
		t.Fatal("replacement tenure requalified original immutable relation ID")
	}
}
