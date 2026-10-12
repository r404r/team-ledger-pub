package authz

import "time"

type Assignment struct{ Capability, ScopeKind, ScopeID string }
type Grant struct {
	Capability, Category, ScopeKind, ScopeID, Purpose string
	ValidFrom, ExpiresAt                              time.Time
	Revoked, RelationBound, MFARequired               bool
	RelationRef                                       *RelationReference
	RelationActorEmployeeID                           string
	ObjectRef                                         *ObjectReference
	ApprovedSourceRefs                                []ObjectReference
	ApprovedSourceEmployees                           map[string]string
}

// Tenure retains the approved interval separately from its effective projection.
// A replacement never qualifies the old immutable reference again.
type Tenure struct {
	ID, Kind, EmployeeID, TeamID, ManagerEmployeeID string
	ValidFrom                                       string
	ValidTo, EffectiveTo                            *string
	Superseded                                      bool
	EmployeeFrom, TeamFrom, ManagerFrom             string
	EmployeeTo, TeamTo, ManagerTo                   *string
}

func within(day, from string, to *string) bool {
	return from != "" && day >= from && (to == nil || day < *to)
}

func (t Tenure) Current(day string) bool {
	if t.Superseded || !within(day, t.ValidFrom, t.ValidTo) || t.EffectiveTo != nil && day >= *t.EffectiveTo || !within(day, t.EmployeeFrom, t.EmployeeTo) {
		return false
	}
	switch t.Kind {
	case "team_membership":
		return within(day, t.TeamFrom, t.TeamTo)
	case "reporting_line":
		return within(day, t.ManagerFrom, t.ManagerTo)
	}
	return false
}

type Snapshot struct {
	SubjectID, OrgID, Timezone            string
	Active, SessionRevoked                bool
	SessionEpoch, SubjectEpoch, AuthEpoch int64
	ExpiresAt, IdleExpiresAt, MFAUntil    time.Time
	CSRFHash                              []byte
	CSRFVersion                           uint32
	Assignments                           []Assignment
	Grants                                []Grant
	SubjectEmployeeID                     string
	Memberships                           []Tenure
	Relations                             []Tenure
}

func (s Snapshot) Valid(now time.Time) bool {
	return s.Active && !s.SessionRevoked && s.SessionEpoch == s.SubjectEpoch && now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

func (s Snapshot) day(now time.Time) (string, bool) {
	zone, err := time.LoadLocation(s.Timezone)
	if err != nil || s.Timezone == "" {
		return "", false
	}
	return now.In(zone).Format("2006-01-02"), true
}

func (s Snapshot) scopeMatches(kind, id, employee, team string, now time.Time) bool {
	if kind == "org" {
		return id == s.OrgID
	}
	if team != "" {
		_, validZone := s.day(now)
		return validZone && kind == "team" && id == team
	}
	if kind == "employee" {
		return employee != "" && id == employee
	}
	if kind != "team" || employee == "" {
		return false
	}
	day, ok := s.day(now)
	if !ok {
		return false
	}
	for _, m := range s.Memberships {
		if m.EmployeeID == employee && m.TeamID == id && m.Current(day) {
			return true
		}
	}
	return false
}

func (s Snapshot) relationQualified(g Grant, now time.Time) bool {
	if g.Category == "financial" && g.RelationBound {
		return false
	}
	if !g.RelationBound {
		return g.RelationRef == nil && g.RelationActorEmployeeID == ""
	}
	if g.RelationRef == nil || s.SubjectEmployeeID == "" || g.RelationActorEmployeeID != s.SubjectEmployeeID {
		return false
	}
	day, ok := s.day(now)
	if !ok {
		return false
	}
	for _, t := range s.Relations {
		if t.ID != g.RelationRef.ID || t.Kind != g.RelationRef.Kind || !t.Current(day) {
			continue
		}
		switch t.Kind {
		case "reporting_line":
			return g.ScopeKind == "employee" && g.ScopeID == t.EmployeeID && s.SubjectEmployeeID == t.ManagerEmployeeID
		case "team_membership":
			return g.ScopeKind == "team" && g.ScopeID == t.TeamID && s.SubjectEmployeeID == t.EmployeeID
		}
	}
	return false
}

func (s Snapshot) Allows(capability, category, employee, purpose string, now time.Time) bool {
	return s.allows(capability, category, employee, "", purpose, now, nil, nil)
}

func (s Snapshot) AllowsTeam(capability, category, team, purpose string, now time.Time) bool {
	if team == "" {
		return false
	}
	if _, ok := s.day(now); !ok {
		return false
	}
	return s.allows(capability, category, "", team, purpose, now, nil, nil)
}

func (s Snapshot) allows(capability, category, employee, team, purpose string, now time.Time, lineage []ObjectReference, source *ObjectReference) bool {
	if !s.Valid(now) || !SupportedPair(capability, category, purpose) || requiresMFA(capability) && !now.Before(s.MFAUntil) {
		return false
	}
	assigned := false
	for _, a := range s.Assignments {
		if a.Capability == capability && s.scopeMatches(a.ScopeKind, a.ScopeID, employee, team, now) {
			assigned = true
			break
		}
	}
	if !assigned {
		return false
	}
	for _, g := range s.Grants {
		if g.Capability == capability && g.Category == category && g.Purpose == purpose && !g.Revoked && !now.Before(g.ValidFrom) && now.Before(g.ExpiresAt) && (!g.MFARequired || now.Before(s.MFAUntil)) && s.scopeMatches(g.ScopeKind, g.ScopeID, employee, team, now) && s.relationQualified(g, now) && objectMatches(g.ObjectRef, capability, category, lineage) && sourceMatches(g, employee, source) {
			return true
		}
	}
	return false
}

func SupportedPair(capability, category, purpose string) bool {
	switch capability {
	case "organization.read", "organization.write":
		return category == "metadata" && purpose == "organization_management"
	case "pii.read", "pii.write":
		return category == "pii" && purpose == "organization_management"
	case "access_grant.manage":
		return category == "audit" && purpose == ManagementPurpose
	case "interview.read", "interview.write":
		return category == "metadata" && purpose == "interview_followup"
	case "note.read", "note.write", "note.publish":
		return noteCategory(category) && purpose == "interview_followup"
	case "action.read", "action.write":
		return category == "shared" && purpose == "interview_followup"
	case "compensation.read", "compensation.propose", "compensation.approve", "bonus.target.manage", "bonus.propose", "bonus.approve", "bonus.payment.record", "compensation.extension.manage":
		return category == "financial" && purpose == "compensation_management"
	case "sensitive.export":
		return (category == "metadata" || noteCategory(category)) && purpose == "interview_followup" || category == "financial" && purpose == "compensation_management"
	}
	return false
}

func Covers(outer Scope, inner Scope, org string) bool {
	return outer.Kind == "org" && outer.ID == org && (inner.Kind == "org" && inner.ID == org || inner.Kind == "employee" || inner.Kind == "team") ||
		(outer.Kind == "employee" || outer.Kind == "team") && outer.Kind == inner.Kind && outer.ID == inner.ID
}

func (s Snapshot) ManagedScopes(now time.Time) []Scope {
	result := make([]Scope, 0)
	if !s.Valid(now) || !now.Before(s.MFAUntil) {
		return result
	}
	seen := map[Scope]bool{}
	for _, a := range s.Assignments {
		if a.Capability != "access_grant.manage" {
			continue
		}
		for _, g := range s.Grants {
			if g.ObjectRef != nil || g.Capability != "access_grant.manage" || g.Category != "audit" || g.Purpose != ManagementPurpose || g.Revoked || now.Before(g.ValidFrom) || !now.Before(g.ExpiresAt) || !s.relationQualified(g, now) {
				continue
			}
			scope, other := Scope{a.ScopeKind, a.ScopeID}, Scope{g.ScopeKind, g.ScopeID}
			if Covers(scope, other, s.OrgID) || scope.Kind == "team" && other.Kind == "employee" && s.scopeMatches("team", scope.ID, other.ID, "", now) {
				scope = other
			} else if !Covers(other, scope, s.OrgID) && !(other.Kind == "team" && scope.Kind == "employee" && s.scopeMatches("team", other.ID, scope.ID, "", now)) {
				continue
			}
			if scope.Kind == "team" {
				if _, ok := s.day(now); !ok {
					continue
				}
			}
			if !seen[scope] {
				seen[scope] = true
				result = append(result, scope)
			}
		}
	}
	return result
}
