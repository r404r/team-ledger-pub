package organization

import (
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"sort"
)

func active(l Lifecycle, day string) bool {
	return day >= l.ValidFrom && (l.ValidTo == nil || day < *l.ValidTo)
}
func effective(r Relation) Lifecycle {
	l := r.Lifecycle
	if r.EffectiveTo != nil && (l.ValidTo == nil || *r.EffectiveTo < *l.ValidTo) {
		l.ValidTo = r.EffectiveTo
	}
	return l
}
func relationActive(r Relation, day string) bool { return !r.Superseded && active(effective(r), day) }
func contains(owner, child Lifecycle) bool {
	return child.ValidFrom >= owner.ValidFrom && (owner.ValidTo == nil || child.ValidTo != nil && *child.ValidTo <= *owner.ValidTo)
}

// ValidateGraph checks every interval boundary, including the final unbounded
// segment. Immutable superseded facts remain in Graph but never revive.
func ValidateGraph(g Graph) error {
	teams := make(map[string]Lifecycle, len(g.Teams))
	employees := make(map[string]Lifecycle, len(g.Employees))
	boundaries := make(map[string]struct{})
	add := func(l Lifecycle) {
		boundaries[l.ValidFrom] = struct{}{}
		if l.ValidTo != nil {
			boundaries[*l.ValidTo] = struct{}{}
		}
	}
	for _, t := range g.Teams {
		if t.OrgID != g.OrgID || !value.ValidID(t.ID) || !validLifecycle(t.Lifecycle) {
			return fault.Invalid
		}
		if _, ok := teams[t.ID]; ok {
			return fault.Invalid
		}
		teams[t.ID] = t.Lifecycle
		add(t.Lifecycle)
	}
	for _, e := range g.Employees {
		if e.OrgID != g.OrgID || !value.ValidID(e.ID) || !validLifecycle(e.Lifecycle) {
			return fault.Invalid
		}
		if _, ok := employees[e.ID]; ok {
			return fault.Invalid
		}
		employees[e.ID] = e.Lifecycle
		add(e.Lifecycle)
	}
	ids := make(map[string]struct{}, len(g.Relations))
	for _, r := range g.Relations {
		if r.OrgID != g.OrgID || !value.ValidID(r.ID) || !validLifecycle(r.Lifecycle) {
			return fault.Invalid
		}
		if _, ok := ids[r.ID]; ok {
			return fault.Invalid
		}
		ids[r.ID] = struct{}{}
		if r.Superseded {
			continue
		}
		l := effective(r)
		if !validLifecycle(l) {
			return fault.Invalid
		}
		add(l)
		team := func(id string) bool { o, ok := teams[id]; return ok && contains(o, l) }
		employee := func(id string) bool { o, ok := employees[id]; return ok && contains(o, l) }
		switch r.Kind {
		case "team_parent":
			if r.TeamID == r.ParentTeamID || !team(r.TeamID) || !team(r.ParentTeamID) {
				return fault.Invalid
			}
		case "membership":
			if !r.IsPrimary || !employee(r.EmployeeID) || !team(r.TeamID) {
				return fault.Invalid
			}
		case "position":
			if !r.IsPrimary || !employee(r.EmployeeID) || r.TeamID != "" && !team(r.TeamID) {
				return fault.Invalid
			}
		case "reporting_line":
			if r.EmployeeID == r.ManagerEmployeeID || !employee(r.EmployeeID) || !employee(r.ManagerEmployeeID) || (r.ReportingKind != "administrative" && r.ReportingKind != "dotted") {
				return fault.Invalid
			}
		default:
			return fault.Invalid
		}
	}
	days := make([]string, 0, len(boundaries))
	for day := range boundaries {
		days = append(days, day)
	}
	sort.Strings(days)
	parents := map[string]string{}
	managers := map[string]string{}
	members := map[string]bool{}
	positions := map[string]bool{}
	cycleState := map[string]uint8{}
	for _, day := range days {
		clear(parents)
		clear(managers)
		clear(members)
		clear(positions)
		for _, r := range g.Relations {
			if !relationActive(r, day) {
				continue
			}
			switch r.Kind {
			case "team_parent":
				if _, ok := parents[r.TeamID]; ok {
					return fault.Invalid
				}
				parents[r.TeamID] = r.ParentTeamID
			case "membership":
				if members[r.EmployeeID] {
					return fault.Invalid
				}
				members[r.EmployeeID] = true
			case "position":
				if positions[r.EmployeeID] {
					return fault.Invalid
				}
				positions[r.EmployeeID] = true
			case "reporting_line":
				if r.ReportingKind == "administrative" {
					if _, ok := managers[r.EmployeeID]; ok {
						return fault.Invalid
					}
					managers[r.EmployeeID] = r.ManagerEmployeeID
				}
			}
		}
		if cyclic(parents, cycleState) || cyclic(managers, cycleState) {
			return fault.Invalid
		}
	}
	return nil
}
func cyclic(edges map[string]string, state map[string]uint8) bool {
	clear(state)
	for start := range edges {
		if state[start] == 2 {
			continue
		}
		node := start
		for node != "" && state[node] == 0 {
			state[node] = 1
			node = edges[node]
		}
		if node != "" && state[node] == 1 {
			return true
		}
		node = start
		for node != "" && state[node] == 1 {
			state[node] = 2
			node = edges[node]
		}
	}
	return false
}
