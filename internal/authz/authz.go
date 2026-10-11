package authz

import "time"

type Assignment struct{ Capability, ScopeKind, ScopeID string }
type Grant struct {
	Capability, Category, ScopeKind, ScopeID, Purpose string
	ValidFrom, ExpiresAt                              time.Time
	Revoked, RelationBound, MFARequired               bool
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
}

func (s Snapshot) Valid(now time.Time) bool {
	return s.Active && !s.SessionRevoked && s.SessionEpoch == s.SubjectEpoch && now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

func ScopeMatches(kind, id, org, employee string) bool {
	return kind == "org" && id == org || kind == "employee" && employee != "" && id == employee
}

func (s Snapshot) Allows(capability, category, employee, purpose string, now time.Time) bool {
	if !s.Valid(now) || !SupportedPair(capability, category, purpose) || (capability == "access_grant.manage" && !now.Before(s.MFAUntil)) {
		return false
	}
	assigned := false
	for _, a := range s.Assignments {
		if a.Capability == capability && ScopeMatches(a.ScopeKind, a.ScopeID, s.OrgID, employee) {
			assigned = true
			break
		}
	}
	if !assigned {
		return false
	}
	for _, g := range s.Grants {
		if g.Capability == capability && g.Category == category && g.Purpose == purpose && !g.Revoked && !g.RelationBound && !now.Before(g.ValidFrom) && now.Before(g.ExpiresAt) && (!g.MFARequired || now.Before(s.MFAUntil)) && ScopeMatches(g.ScopeKind, g.ScopeID, s.OrgID, employee) {
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
	}
	return false
}

func Covers(outer Scope, inner Scope, org string) bool {
	return outer.Kind == "org" && outer.ID == org && (inner.Kind == "org" && inner.ID == org || inner.Kind == "employee") ||
		outer.Kind == "employee" && inner.Kind == "employee" && outer.ID == inner.ID
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
			if g.Capability != "access_grant.manage" || g.Category != "audit" || g.Purpose != ManagementPurpose ||
				g.Revoked || g.RelationBound || now.Before(g.ValidFrom) || !now.Before(g.ExpiresAt) {
				continue
			}
			scope := Scope{a.ScopeKind, a.ScopeID}
			other := Scope{g.ScopeKind, g.ScopeID}
			if Covers(scope, other, s.OrgID) {
				scope = other
			} else if !Covers(other, scope, s.OrgID) {
				continue
			}
			if !seen[scope] {
				seen[scope] = true
				result = append(result, scope)
			}
		}
	}
	return result
}
