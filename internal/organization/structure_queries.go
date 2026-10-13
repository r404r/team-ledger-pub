package organization

import (
	"context"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func (s *Service) authorizationDay(snap authz.Snapshot) (string, error) {
	zone, err := time.LoadLocation(snap.Timezone)
	if err != nil || snap.Timezone == "" {
		return "", fault.Unavailable
	}
	return s.clock().In(zone).Format("2006-01-02"), nil
}
func (s *Service) openOrganization(ctx context.Context, org, employee, record, id, kind, schema string, target any) error {
	p, err := s.Store.OrganizationPayload(ctx, org, id)
	if err != nil {
		return err
	}
	binding := sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: record, VersionID: id, ObjectKind: kind, Purpose: "pii", SchemaType: schema, SchemaVersion: 1}
	plain, err := s.Cipher.Open(ctx, binding, p.Envelope)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(plain)
	if json.Unmarshal(plain, target) != nil {
		return fault.Unavailable
	}
	return nil
}
func (s *Service) prepareView(ctx context.Context, req Request, snap authz.Snapshot, e Employee, asOf string, includeProfile bool, g Graph) (View, error) {
	day, err := s.authorizationDay(snap)
	if err != nil {
		return View{}, err
	}
	v := View{ID: e.ID, OrgID: e.OrgID, Lifecycle: e.Lifecycle, AsOf: asOf, AuthorizationDate: day, GraphRevision: strconv.FormatInt(g.Revision, 10)}
	relations, err := s.Store.EmployeeRelations(ctx, e.OrgID, e.ID, asOf)
	if err != nil {
		return View{}, err
	}
	pii := includeProfile && snap.Allows("pii.read", "pii", e.ID, req.Purpose, s.clock())
	for _, r := range relations {
		if !relationActive(r, asOf) {
			continue
		}
		l := effective(r)
		switch r.Kind {
		case "membership":
			v.Memberships = append(v.Memberships, MembershipView{ID: r.ID, EmployeeID: r.EmployeeID, TeamID: r.TeamID, IsPrimary: r.IsPrimary, ValidFrom: l.ValidFrom, ValidTo: l.ValidTo})
		case "position":
			p := PositionView{ID: r.ID, EmployeeID: r.EmployeeID, TeamID: r.TeamID, IsPrimary: r.IsPrimary, ValidFrom: l.ValidFrom, ValidTo: l.ValidTo}
			if pii {
				var payload PositionPayload
				if err = s.openOrganization(ctx, e.OrgID, e.ID, r.ID, r.PayloadID, "position_assignment", "org.position.v1", &payload); err != nil {
					return View{}, err
				}
				if !positionValid(payload) {
					return View{}, fault.Unavailable
				}
				p.Position = &payload
			}
			v.Positions = append(v.Positions, p)
		case "reporting_line":
			v.ReportingLines = append(v.ReportingLines, ReportingView{ID: r.ID, EmployeeID: r.EmployeeID, ManagerEmployeeID: r.ManagerEmployeeID, Kind: r.ReportingKind, ValidFrom: l.ValidFrom, ValidTo: l.ValidTo})
		}
	}
	if pii {
		version, err := s.Store.Version(ctx, e.OrgID, e.ID, e.HeadID)
		if err != nil {
			return View{}, err
		}
		plain, err := s.Cipher.Open(ctx, profileBinding(e, version.ID), version.Envelope)
		if err != nil {
			return View{}, fault.Unavailable
		}
		defer clear(plain)
		var payload ProfilePayload
		if json.Unmarshal(plain, &payload) != nil || !validProfile(payload.Profile) || !utf8.ValidString(payload.EditReason) || len(payload.EditReason) > 4096 {
			return View{}, fault.Unavailable
		}
		v.Profile = &payload.Profile
		v.Revision = strconv.FormatInt(e.Revision, 10)
	}
	return v, nil
}
func positionValid(p PositionPayload) bool {
	return utf8.ValidString(p.Title) && strings.TrimSpace(p.Title) != "" && len(p.Title) <= 256 && textValid(p.PositionCode, 64, true) && textValid(p.Description, 4096, false)
}
func (s *Service) releaseQuery(ctx context.Context, req Request, snap authz.Snapshot, g Graph, day, op string, employees []Employee, teams, piiTeams []string, piiEmployees []string, orgPII bool) error {
	return s.Store.WithTx(ctx, snap.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, snap.OrgID, []string{snap.SubjectID}); err != nil {
			return err
		}
		current, err := s.structureAuthority(ctx, tx, req, snap.OrgID, op, false)
		if err != nil {
			return err
		}
		if current.AuthEpoch != snap.AuthEpoch {
			return fault.Forbidden
		}
		currentDay, err := s.authorizationDay(current)
		if err != nil {
			return err
		}
		if currentDay != day {
			return fault.Conflict
		}
		latest, err := tx.GraphState(ctx, snap.OrgID)
		if err != nil {
			return err
		}
		if latest.Revision != g.Revision {
			return fault.Conflict
		}
		now := s.clock()
		if len(employees) == 0 && len(teams) == 0 && !current.Allows("organization.read", "metadata", "", req.Purpose, now) {
			return fault.NotFound
		}
		for _, team := range teams {
			if !current.AllowsTeam("organization.read", "metadata", team, req.Purpose, now) {
				return fault.NotFound
			}
		}
		for _, team := range piiTeams {
			if !current.AllowsTeam("pii.read", "pii", team, req.Purpose, now) {
				return fault.Forbidden
			}
		}
		if orgPII && !current.Allows("pii.read", "pii", "", req.Purpose, now) {
			return fault.Forbidden
		}
		for _, e := range employees {
			employeeSnap, err := tx.Security(ctx, req.TokenHash, snap.OrgID, e.ID)
			if err != nil {
				return err
			}
			if !employeeSnap.Allows("organization.read", "metadata", e.ID, req.Purpose, now) {
				return fault.NotFound
			}
			if e.HeadID != "" {
				currentEmployee, err := tx.Employee(ctx, e.ID)
				if err != nil {
					return err
				}
				if currentEmployee.OrgID != e.OrgID || currentEmployee.HeadID != e.HeadID || currentEmployee.Revision != e.Revision {
					return fault.Conflict
				}
			}
		}
		for _, id := range piiEmployees {
			employeeSnap, err := tx.Security(ctx, req.TokenHash, snap.OrgID, id)
			if err != nil {
				return err
			}
			if !employeeSnap.Allows("pii.read", "pii", id, req.Purpose, now) {
				return fault.Forbidden
			}
		}
		employee := ""
		if len(employees) == 1 && (op == "OP-ORG-06" || op == "OP-ORG-07") {
			employee = employees[0].ID
		}
		return tx.Audit(ctx, s.audit(req, current, employee, op, "allowed"))
	})
}
func (s *Service) Tree(ctx context.Context, req Request, org string, q TreeQuery) (TreeView, error) {
	const op = "OP-ORG-01"
	snap, err := s.structureAuthority(ctx, s.Store, req, org, op, false)
	if err != nil {
		return TreeView{}, s.denied(ctx, req, snap, op, err)
	}
	if !value.ValidID(org) || !value.ValidDate(q.AsOf) || q.RootTeamID != "" && !value.ValidID(q.RootTeamID) || q.Depth < 0 || q.Depth > 10 || q.Limit < 0 || q.Limit > 100 {
		return TreeView{}, fault.Invalid
	}
	if q.Depth == 0 {
		q.Depth = 10
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	day, err := s.authorizationDay(snap)
	if err != nil {
		return TreeView{}, err
	}
	g, err := s.Store.Graph(ctx, org)
	if err != nil {
		return TreeView{}, err
	}
	now := s.clock()
	permitted := map[string]Team{}
	allowed := snap.Allows("organization.read", "metadata", "", req.Purpose, now)
	rootAllowed := q.RootTeamID == ""
	witnessTeam := ""
	for _, t := range g.Teams {
		if !snap.AllowsTeam("organization.read", "metadata", t.ID, req.Purpose, now) {
			continue
		}
		allowed = true
		if witnessTeam == "" {
			witnessTeam = t.ID
		}
		if t.ID == q.RootTeamID {
			rootAllowed = true
			witnessTeam = t.ID
		}
		if active(t.Lifecycle, q.AsOf) {
			permitted[t.ID] = t
		}
	}
	if !allowed || !rootAllowed {
		return TreeView{}, s.denied(ctx, req, snap, op, fault.NotFound)
	}
	selected := map[string]bool{}
	if q.RootTeamID == "" {
		for id := range permitted {
			selected[id] = true
		}
	} else {
		distance := map[string]int{q.RootTeamID: 0}
		for depth := range q.Depth {
			for _, r := range g.Relations {
				if r.Kind != "team_parent" || !relationActive(r, q.AsOf) {
					continue
				}
				if d, ok := distance[r.ParentTeamID]; ok && d == depth {
					if _, seen := distance[r.TeamID]; !seen {
						distance[r.TeamID] = depth + 1
					}
				}
			}
		}
		for id := range distance {
			if _, ok := permitted[id]; ok {
				selected[id] = true
			}
		}
	}
	v := TreeView{OrgID: org, AsOf: q.AsOf, AuthorizationDate: day, GraphRevision: strconv.FormatInt(g.Revision, 10), AuthEpoch: strconv.FormatInt(snap.AuthEpoch, 10), Nodes: []TreeNode{}, Edges: []TreeEdge{}, Employees: []TreeEmployee{}}
	teams := []string{}
	piiTeams := []string{}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > q.Limit {
		return TreeView{}, fault.Invalid
	}
	snapshotSize := len(ids)
	released := []Employee{}
	for _, r := range g.Relations {
		if !relationActive(r, q.AsOf) {
			continue
		}
		l := effective(r)
		if r.Kind == "team_parent" && selected[r.TeamID] && selected[r.ParentTeamID] {
			if snapshotSize >= q.Limit {
				return TreeView{}, fault.Invalid
			}
			v.Edges = append(v.Edges, TreeEdge{ID: r.ID, ChildTeamID: r.TeamID, ParentTeamID: r.ParentTeamID, ValidFrom: l.ValidFrom, ValidTo: l.ValidTo})
			snapshotSize++
		}
		if r.Kind == "membership" && selected[r.TeamID] && snap.Allows("organization.read", "metadata", r.EmployeeID, req.Purpose, now) {
			if snapshotSize >= q.Limit {
				return TreeView{}, fault.Invalid
			}
			v.Employees = append(v.Employees, TreeEmployee{ID: r.EmployeeID, TeamID: r.TeamID})
			snapshotSize++
			released = append(released, Employee{ID: r.EmployeeID, OrgID: org})
		}
	}
	for _, id := range ids {
		t := permitted[id]
		n := TreeNode{ID: id, Code: t.Code, Lifecycle: t.Lifecycle}
		teams = append(teams, id)
		if q.IncludeLabels && t.LabelPayloadID != "" && snap.AllowsTeam("pii.read", "pii", id, req.Purpose, now) {
			var payload struct {
				Label string `json:"label"`
			}
			if err = s.openOrganization(ctx, org, "", id, t.LabelPayloadID, "team_label", "org.team.label.v1", &payload); err != nil {
				return TreeView{}, err
			}
			if !utf8.ValidString(payload.Label) || len(payload.Label) > 256 {
				return TreeView{}, fault.Unavailable
			}
			n.Label = &payload.Label
			piiTeams = append(piiTeams, id)
		}
		v.Nodes = append(v.Nodes, n)
	}
	if len(teams) == 0 && witnessTeam != "" {
		teams = append(teams, witnessTeam)
	}
	if err = s.releaseQuery(ctx, req, snap, g, day, op, released, teams, piiTeams, nil, false); err != nil {
		return TreeView{}, s.denied(ctx, req, snap, op, err)
	}
	return v, nil
}
func (s *Service) directoryScope(snap authz.Snapshot, req Request, q DirectoryQuery, day string) DirectoryScope {
	now := s.clock()
	scope := DirectoryScope{AuthorizationDate: day}
	scope.Org = snap.Allows("organization.read", "metadata", "", req.Purpose, now) && (q.Q == "" || snap.Allows("pii.read", "pii", "", req.Purpose, now))
	employees, teams := map[string]bool{}, map[string]bool{}
	for _, a := range snap.Assignments {
		if a.ScopeKind == "employee" {
			employees[a.ScopeID] = true
		}
		if a.ScopeKind == "team" {
			teams[a.ScopeID] = true
		}
	}
	for _, a := range snap.Grants {
		if a.ScopeKind == "employee" {
			employees[a.ScopeID] = true
		}
		if a.ScopeKind == "team" {
			teams[a.ScopeID] = true
		}
	}
	for _, m := range snap.Memberships {
		employees[m.EmployeeID] = true
	}
	for id := range employees {
		if snap.Allows("organization.read", "metadata", id, req.Purpose, now) && (q.Q == "" || snap.Allows("pii.read", "pii", id, req.Purpose, now)) {
			scope.Employees = append(scope.Employees, id)
		}
	}
	for id := range teams {
		if snap.AllowsTeam("organization.read", "metadata", id, req.Purpose, now) && (q.Q == "" || snap.AllowsTeam("pii.read", "pii", id, req.Purpose, now)) {
			scope.Teams = append(scope.Teams, id)
		}
	}
	sort.Strings(scope.Employees)
	sort.Strings(scope.Teams)
	return scope
}
func (s *Service) Directory(ctx context.Context, req Request, org string, q DirectoryQuery) (DirectoryPage, error) {
	const op = "OP-ORG-04"
	snap, err := s.structureAuthority(ctx, s.Store, req, org, op, false)
	if err != nil {
		return DirectoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	if !value.ValidID(org) || !value.ValidDate(q.AsOf) || q.TeamID != "" && !value.ValidID(q.TeamID) || q.EmployeeID != "" && !value.ValidID(q.EmployeeID) || !utf8.ValidString(q.Q) || len(q.Q) > 256 || q.Q != "" && !q.IncludeProfile || q.Limit < 0 || q.Limit > 100 || (q.Lifecycle != "" && q.Lifecycle != "active" && q.Lifecycle != "inactive" && q.Lifecycle != "all") {
		return DirectoryPage{}, fault.Invalid
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Lifecycle == "" {
		q.Lifecycle = "active"
	}
	day, err := s.authorizationDay(snap)
	if err != nil {
		return DirectoryPage{}, err
	}
	scope := s.directoryScope(snap, req, q, day)
	if !scope.Org && len(scope.Employees) == 0 && len(scope.Teams) == 0 {
		return DirectoryPage{}, s.denied(ctx, req, snap, op, fault.Forbidden)
	}
	g, err := s.Store.GraphState(ctx, org)
	if err != nil {
		return DirectoryPage{}, err
	}
	filterQuery := q
	filterQuery.Cursor = ""
	filterQuery.Q = ""
	digest, err := s.queryDigest("directory", filterQuery, q.Q)
	if err != nil {
		return DirectoryPage{}, err
	}
	last := ""
	if q.Cursor != "" {
		last, err = s.openQueryCursor(q.Cursor, "directory", snap, g, day, digest)
		if err != nil {
			return DirectoryPage{}, err
		}
		if !value.ValidID(last) {
			return DirectoryPage{}, fault.Invalid
		}
	}
	candidates, err := s.Store.DirectoryCandidates(ctx, org, last, q, scope, 501)
	if err != nil {
		return DirectoryPage{}, err
	}
	page := DirectoryPage{Items: []View{}, AsOf: q.AsOf, Consistency: "current", AuthorizationDate: day, GraphRevision: strconv.FormatInt(g.Revision, 10), AuthEpoch: strconv.FormatInt(snap.AuthEpoch, 10)}
	scanned := 0
	released := []Employee{}
	piiIDs := []string{}
	more := false
	needle := strings.ToLower(q.Q)
	for i, e := range candidates {
		if scanned >= 500 || len(page.Items) >= q.Limit {
			more = true
			break
		}
		scanned++
		last = e.ID
		employeeSnap, err := s.Store.Security(ctx, req.TokenHash, org, e.ID)
		if err != nil {
			return DirectoryPage{}, err
		}
		if employeeSnap.AuthEpoch != snap.AuthEpoch {
			return DirectoryPage{}, fault.Forbidden
		}
		if !employeeSnap.Allows("organization.read", "metadata", e.ID, req.Purpose, s.clock()) {
			return DirectoryPage{}, fault.Forbidden
		}
		if q.Q != "" && !employeeSnap.Allows("pii.read", "pii", e.ID, req.Purpose, s.clock()) {
			return DirectoryPage{}, fault.Forbidden
		}
		v, err := s.prepareView(ctx, req, employeeSnap, e, q.AsOf, q.IncludeProfile, g)
		if err != nil {
			return DirectoryPage{}, err
		}
		released = append(released, e)
		if v.Profile != nil {
			piiIDs = append(piiIDs, e.ID)
		}
		if q.Q == "" || v.Profile != nil && (strings.Contains(strings.ToLower(v.Profile.LocalName), needle) || strings.Contains(strings.ToLower(v.Profile.EnglishName), needle)) {
			page.Items = append(page.Items, v)
		}
		if i+1 < len(candidates) {
			more = true
		} else {
			more = false
		}
	}
	if more && last != "" {
		token, err := s.sealQueryCursor("directory", snap, g, day, digest, last)
		if err != nil {
			return DirectoryPage{}, err
		}
		page.NextCursor = &token
	}
	page.SearchIncomplete = q.Q != "" && scanned == 500 && more
	var witnessTeams, witnessPIITeams []string
	orgPII := false
	if len(released) == 0 {
		switch {
		case scope.Org:
			orgPII = q.Q != ""
		case len(scope.Teams) != 0:
			witnessTeams = append(witnessTeams, scope.Teams[0])
			if q.Q != "" {
				witnessPIITeams = append(witnessPIITeams, scope.Teams[0])
			}
		case len(scope.Employees) != 0:
			id := scope.Employees[0]
			released = append(released, Employee{ID: id, OrgID: org})
			if q.Q != "" {
				piiIDs = append(piiIDs, id)
			}
		}
	}
	if err = s.releaseQuery(ctx, req, snap, g, day, op, released, witnessTeams, witnessPIITeams, piiIDs, orgPII); err != nil {
		return DirectoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	return page, nil
}
func (s *Service) History(ctx context.Context, req Request, employee string, q HistoryQuery) (HistoryPage, error) {
	const op = "OP-ORG-07"
	if _, err := s.Session(ctx, req, ""); err != nil {
		return HistoryPage{}, err
	}
	if !value.ValidID(employee) || q.Limit < 0 || q.Limit > 100 || (q.From == "") != (q.To == "") || q.From != "" && (!value.ValidDate(q.From) || !value.ValidDate(q.To) || q.From >= q.To) {
		return HistoryPage{}, fault.Invalid
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	e, err := s.Store.Employee(ctx, employee)
	if err != nil {
		return HistoryPage{}, err
	}
	snap, err := s.authorize(ctx, s.Store, req, e.OrgID, employee, "OP-ORG-06")
	if err != nil {
		return HistoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	day, err := s.authorizationDay(snap)
	if err != nil {
		return HistoryPage{}, err
	}
	g, err := s.Store.GraphState(ctx, e.OrgID)
	if err != nil {
		return HistoryPage{}, err
	}
	filter := struct {
		Employee, From, To string
		Limit              int
	}{employee, q.From, q.To, q.Limit}
	digest, err := s.queryDigest("history", filter, "")
	if err != nil {
		return HistoryPage{}, err
	}
	after, lastID := time.Time{}, ""
	if q.Cursor != "" {
		last, err := s.openQueryCursor(q.Cursor, "history", snap, g, day, digest)
		if err != nil {
			return HistoryPage{}, err
		}
		parts := strings.Split(last, "|")
		if len(parts) != 2 || !value.ValidID(parts[1]) {
			return HistoryPage{}, fault.Invalid
		}
		after, err = time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return HistoryPage{}, fault.Invalid
		}
		lastID = parts[1]
	}
	changes, err := s.Store.StructureHistory(ctx, e.OrgID, employee, q, after, lastID, q.Limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	page := HistoryPage{Items: []HistoryItem{}, From: q.From, To: q.To, Consistency: "current", AuthorizationDate: day, GraphRevision: strconv.FormatInt(g.Revision, 10), AuthEpoch: strconv.FormatInt(snap.AuthEpoch, 10)}
	if q.From == "" {
		page.AsOf = day
	}
	more := len(changes) > q.Limit
	if more {
		changes = changes[:q.Limit]
	}
	orgSnap, err := s.Store.Security(ctx, req.TokenHash, e.OrgID, "")
	if err != nil {
		return HistoryPage{}, err
	}
	orgPII := orgSnap.Allows("pii.read", "pii", "", req.Purpose, s.clock())
	employeePII := snap.Allows("pii.read", "pii", employee, req.Purpose, s.clock())
	reasonReleased, positionReleased := false, false
	for _, c := range changes {
		h := HistoryItem{ID: c.ID, ActorSubjectID: c.SubjectID, RecordedAt: c.RecordedAt.UTC(), GraphBefore: strconv.FormatInt(c.GraphBefore, 10), GraphAfter: strconv.FormatInt(c.GraphAfter, 10), Items: []HistoryRelation{}}
		for _, item := range c.Items {
			if item.EmployeeID != employee {
				continue
			}
			if item.Kind == "position" && employeePII {
				var payload PositionPayload
				if err = s.openOrganization(ctx, e.OrgID, employee, item.ID, item.PayloadID, "position_assignment", "org.position.v1", &payload); err != nil {
					return HistoryPage{}, err
				}
				if !positionValid(payload) {
					return HistoryPage{}, fault.Unavailable
				}
				item.Position = &payload
				positionReleased = true
			}
			h.Items = append(h.Items, item)
		}
		if len(h.Items) == 0 {
			continue
		}
		if orgPII && c.ReasonPayloadID != "" {
			var payload struct {
				Reason string `json:"reason"`
			}
			if err = s.openOrganization(ctx, e.OrgID, "", c.ID, c.ReasonPayloadID, "structure_change", "org.structure.reason.v1", &payload); err != nil {
				return HistoryPage{}, err
			}
			if !utf8.ValidString(payload.Reason) || len(payload.Reason) > 4096 {
				return HistoryPage{}, fault.Unavailable
			}
			h.Reason = &payload.Reason
			reasonReleased = true
		}
		page.Items = append(page.Items, h)
	}
	if more && len(changes) > 0 {
		c := changes[len(changes)-1]
		token, err := s.sealQueryCursor("history", snap, g, day, digest, c.RecordedAt.UTC().Format(time.RFC3339Nano)+"|"+c.ID)
		if err != nil {
			return HistoryPage{}, err
		}
		page.NextCursor = &token
	}
	var piiIDs []string
	if positionReleased {
		piiIDs = append(piiIDs, employee)
	}
	if err = s.releaseQuery(ctx, req, snap, g, day, op, []Employee{e}, nil, nil, piiIDs, reasonReleased); err != nil {
		return HistoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	return page, nil
}
