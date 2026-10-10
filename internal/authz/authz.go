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
	if !s.Valid(now) || purpose != "organization_management" {
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
