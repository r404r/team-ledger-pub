package organization

import (
	"context"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
)

func withoutTeamScopes(s authz.Snapshot) authz.Snapshot {
	// Team-to-employee coverage requires a membership witness. Removing that
	// witness from this local value tests only approved org/employee scopes
	// without copying either authority collection or altering stored facts.
	s.Memberships = nil
	return s
}

// Store the explicit approved scope that covered each permission at commit.
// Receipt confirmation rechecks those scopes, not the command's ended tenure or
// the employee's new team. It never manufactures current graph qualification.
func (s *Service) itemAuthority(ctx context.Context, reader Reader, req Request, snap authz.Snapshot, g Graph, items []StructureItem, reason bool) ([]StructureAuthorityTarget, error) {
	now := s.clock()
	relations := map[string]Relation{}
	for _, r := range g.Relations {
		relations[r.ID] = r
	}
	targets := []StructureAuthorityTarget{}
	seen := map[StructureAuthorityTarget]bool{}
	employeeSnapshots := make(map[string]authz.Snapshot)
	save := func(cap, cat, kind, id string) {
		t := StructureAuthorityTarget{Capability: cap, Category: cat, Kind: kind, ID: id}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	permissionError := func(cap string) error {
		if cap == "organization.read" {
			return fault.NotFound
		}
		return fault.Forbidden
	}
	teamPermission := func(id, cap, cat string) error {
		if snap.Allows(cap, cat, "", req.Purpose, now) {
			save(cap, cat, "org", snap.OrgID)
			return nil
		}
		if snap.AllowsTeam(cap, cat, id, req.Purpose, now) {
			save(cap, cat, "team", id)
			return nil
		}
		return permissionError(cap)
	}
	employeePermission := func(id, cap, cat string) error {
		current, loaded := employeeSnapshots[id]
		if !loaded {
			var err error
			current, err = reader.Security(ctx, req.TokenHash, snap.OrgID, id)
			if err != nil {
				return err
			}
			if current.AuthEpoch != snap.AuthEpoch {
				return fault.Forbidden
			}
			employeeSnapshots[id] = current
		}
		if current.Allows(cap, cat, "", req.Purpose, now) {
			save(cap, cat, "org", snap.OrgID)
			return nil
		}
		explicit := withoutTeamScopes(current)
		if explicit.Allows(cap, cat, id, req.Purpose, now) {
			save(cap, cat, "employee", id)
			return nil
		}
		day, err := s.authorizationDay(current)
		if err != nil {
			return err
		}
		for _, m := range current.Memberships {
			if m.EmployeeID == id && m.Current(day) && current.AllowsTeam(cap, cat, m.TeamID, req.Purpose, now) {
				save(cap, cat, "team", m.TeamID)
				return nil
			}
		}
		return permissionError(cap)
	}
	team := func(id string, write bool) error {
		if err := teamPermission(id, "organization.read", "metadata"); err != nil {
			return err
		}
		if write {
			return teamPermission(id, "organization.write", "metadata")
		}
		return nil
	}
	employee := func(id string, write bool) error {
		if err := employeePermission(id, "organization.read", "metadata"); err != nil {
			return err
		}
		if write {
			return employeePermission(id, "organization.write", "metadata")
		}
		return nil
	}
	authorize := func(r Relation) error {
		switch r.Kind {
		case "team_parent":
			if err := team(r.TeamID, true); err != nil {
				return err
			}
			return team(r.ParentTeamID, false)
		case "membership", "position":
			if err := employee(r.EmployeeID, true); err != nil {
				return err
			}
			if r.TeamID != "" {
				return team(r.TeamID, false)
			}
			return nil
		case "reporting_line":
			if err := employee(r.EmployeeID, true); err != nil {
				return err
			}
			return employee(r.ManagerEmployeeID, false)
		}
		return fault.Invalid
	}
	for _, item := range items {
		if item.Action == "lifecycle" {
			if item.Kind == "team_lifecycle" {
				if err := team(*item.TeamID, true); err != nil {
					return nil, err
				}
			} else {
				if err := employee(*item.EmployeeID, true); err != nil {
					return nil, err
				}
			}
			continue
		}
		if item.Ref != nil {
			r, ok := relations[*item.Ref]
			if !ok || r.Kind != item.Kind {
				return nil, fault.NotFound
			}
			if err := authorize(r); err != nil {
				return nil, err
			}
			if item.Action == "end" {
				continue
			}
		}
		r := Relation{Kind: item.Kind, EmployeeID: ptrValue(item.EmployeeID), TeamID: ptrValue(item.TeamID), ParentTeamID: ptrValue(item.ParentTeamID), ManagerEmployeeID: ptrValue(item.ManagerEmployeeID)}
		if err := authorize(r); err != nil {
			return nil, err
		}
		if item.Position != nil {
			for _, cap := range []string{"pii.read", "pii.write"} {
				if err := employeePermission(*item.EmployeeID, cap, "pii"); err != nil {
					return nil, err
				}
			}
		}
	}
	if reason {
		for _, cap := range []string{"pii.read", "pii.write"} {
			if !snap.Allows(cap, "pii", "", req.Purpose, now) {
				return nil, fault.Forbidden
			}
			save(cap, "pii", "org", snap.OrgID)
		}
	}
	return targets, nil
}
func (s *Service) receiptAuthority(ctx context.Context, reader Reader, req Request, snap authz.Snapshot, targets []StructureAuthorityTarget) error {
	if len(targets) == 0 {
		return fault.Unavailable
	}
	now := s.clock()
	for _, t := range targets {
		allowed := false
		switch t.Kind {
		case "org":
			allowed = t.ID == snap.OrgID && snap.Allows(t.Capability, t.Category, "", req.Purpose, now)
		case "team":
			allowed = snap.AllowsTeam(t.Capability, t.Category, t.ID, req.Purpose, now)
		case "employee":
			current, err := reader.Security(ctx, req.TokenHash, snap.OrgID, t.ID)
			if err != nil {
				return err
			}
			explicit := withoutTeamScopes(current)
			allowed = current.AuthEpoch == snap.AuthEpoch && explicit.Allows(t.Capability, t.Category, t.ID, req.Purpose, now)
		}
		if !allowed {
			if t.Capability == "organization.read" {
				return fault.NotFound
			}
			return fault.Forbidden
		}
	}
	return nil
}
func teamReceiptTargets(org string, label bool) []StructureAuthorityTarget {
	targets := []StructureAuthorityTarget{{Capability: "organization.read", Category: "metadata", Kind: "org", ID: org}, {Capability: "organization.write", Category: "metadata", Kind: "org", ID: org}}
	if label {
		targets = append(targets, StructureAuthorityTarget{Capability: "pii.read", Category: "pii", Kind: "org", ID: org}, StructureAuthorityTarget{Capability: "pii.write", Category: "pii", Kind: "org", ID: org})
	}
	return targets
}
