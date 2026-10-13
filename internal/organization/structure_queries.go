package organization

import (
	"context"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
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
func (s *Service) prepareView(ctx context.Context, req Request, snap authz.Snapshot, e Employee, asOf string, includeProfile bool, g Graph) (View, error) {
	day, err := s.authorizationDay(snap)
	if err != nil {
		return View{}, err
	}
	v := View{ID: e.ID, OrgID: e.OrgID, Lifecycle: e.Lifecycle, AsOf: asOf, AuthorizationDate: day, GraphRevision: strconv.FormatInt(g.Revision, 10)}
	facts, err := s.Store.EmployeeWorkforceFacts(ctx, e.OrgID, e.ID, asOf)
	if err != nil {
		return View{}, err
	}
	pii := includeProfile && snap.Allows("pii.read", "pii", e.ID, req.Purpose, s.clock())
	v.Employment, v.JobAssignments, v.ReportingLines = facts.Employment, facts.JobAssignments, facts.ReportingLines
	if pii {
		v.Identifiers, v.Education = facts.Identifiers, facts.Education
		for i := range v.Identifiers {
			var payload struct {
				StaffCode string `json:"staff_code"`
			}
			if err = s.openWorkforcePayload(ctx, e.OrgID, e.ID, v.Identifiers[i].ID, v.Identifiers[i].PayloadID, "employee_identifier", "pii.employee_identifier.v1", &payload); err != nil {
				return View{}, err
			}
			v.Identifiers[i].StaffCode = payload.StaffCode
			v.Identifiers[i].PayloadID = ""
		}
		for i := range v.Education {
			var payload struct {
				Institution *string `json:"institution,omitempty"`
				Field       *string `json:"field,omitempty"`
				AwardDate   *string `json:"award_date,omitempty"`
			}
			if err = s.openWorkforcePayload(ctx, e.OrgID, e.ID, v.Education[i].ID, v.Education[i].PayloadID, "education_record", "pii.education.v1", &payload); err != nil {
				return View{}, err
			}
			v.Education[i].Institution, v.Education[i].Field, v.Education[i].AwardDate = payload.Institution, payload.Field, payload.AwardDate
			v.Education[i].PayloadID = ""
		}
		for i := range v.JobAssignments {
			if v.JobAssignments[i].PayloadID == "" {
				continue
			}
			var payload PositionPayload
			if err = s.openWorkforcePayload(ctx, e.OrgID, e.ID, v.JobAssignments[i].ID, v.JobAssignments[i].PayloadID, "job_assignment", "pii.job_assignment_position.v1", &payload); err != nil || !positionValid(payload) {
				return View{}, fault.Unavailable
			}
			v.JobAssignments[i].Position = &payload
			v.JobAssignments[i].PayloadID = ""
		}
	} else {
		v.Identifiers, v.Education = []IdentifierView{}, []EducationView{}
		for i := range v.JobAssignments {
			v.JobAssignments[i].PayloadID = ""
		}
	}
	for i := range v.ReportingLines {
		if v.ReportingLines[i].Kind == "administrative" {
			v.DirectManager, v.HOD = &v.ReportingLines[i], &v.ReportingLines[i]
			break
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
func (s *Service) releaseQuery(ctx context.Context, req Request, snap authz.Snapshot, g Graph, day, op string, employees []Employee, piiEmployees []string, orgPII bool) error {
	return s.Store.WithTx(ctx, snap.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, snap.OrgID, []string{snap.SubjectID}); err != nil {
			return err
		}
		var current authz.Snapshot
		var err error
		if len(employees) == 1 && (op == "OP-ORG-06" || op == "OP-ORG-07") {
			current, err = s.authorize(ctx, tx, req, snap.OrgID, employees[0].ID, op)
		} else {
			current, err = s.structureAuthority(ctx, tx, req, snap.OrgID, op, false)
		}
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
		if len(employees) == 0 && !current.Allows("organization.read", "metadata", "", req.Purpose, now) {
			return fault.NotFound
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
	if !value.ValidID(org) || !value.ValidDate(q.AsOf) || q.RootDepartmentID != "" && !value.ValidID(q.RootDepartmentID) || q.Depth < 0 || q.Depth > 3 || q.Limit < 0 || q.Limit > 100 {
		return TreeView{}, fault.Invalid
	}
	if !snap.Allows("organization.read", "metadata", "", req.Purpose, s.clock()) {
		return TreeView{}, s.denied(ctx, req, snap, op, fault.Forbidden)
	}
	if q.IncludeLabels && !snap.Allows("pii.read", "pii", "", req.Purpose, s.clock()) {
		return TreeView{}, s.denied(ctx, req, snap, op, fault.Forbidden)
	}
	if q.Depth == 0 {
		q.Depth = 3
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	day, err := s.authorizationDay(snap)
	if err != nil {
		return TreeView{}, err
	}
	catalogs, err := s.Catalogs(ctx, req, org, WorkforceCatalogQuery{AsOf: q.AsOf, Limit: 100})
	if err != nil {
		return TreeView{}, err
	}
	g, err := s.Store.GraphState(ctx, org)
	if err != nil {
		return TreeView{}, err
	}
	employees, err := s.Store.DirectoryCandidates(ctx, org, "", DirectoryQuery{AsOf: q.AsOf, Lifecycle: "active"}, DirectoryScope{Org: true, AuthorizationDate: day}, 501)
	if err != nil {
		return TreeView{}, err
	}
	selected, depths := map[string]bool{}, map[string]int{}
	if q.RootDepartmentID != "" {
		for _, unit := range catalogs.OrgUnits {
			if unit.ID == q.RootDepartmentID && unit.Kind == "department" {
				selected[unit.ID], depths[unit.ID] = true, 0
			}
		}
		if !selected[q.RootDepartmentID] {
			return TreeView{}, fault.NotFound
		}
	} else {
		for _, unit := range catalogs.OrgUnits {
			if unit.Kind == "business_group" {
				selected[unit.ID], depths[unit.ID] = true, 0
			}
		}
		for depth := 1; depth < q.Depth; depth++ {
			for _, edge := range catalogs.OrgUnitParents {
				if parentDepth, ok := depths[edge.ParentUnitID]; ok && parentDepth == depth-1 {
					selected[edge.ChildUnitID], depths[edge.ChildUnitID] = true, depth
				}
			}
		}
	}
	if len(selected) > q.Limit {
		return TreeView{}, fault.Invalid
	}
	out := TreeView{OrgID: org, AsOf: q.AsOf, AuthorizationDate: day, GraphRevision: catalogs.GraphRevision, AuthEpoch: strconv.FormatInt(snap.AuthEpoch, 10), Nodes: []TreeNode{}, Edges: []TreeEdge{}, Employees: []TreeEmployee{}}
	for _, unit := range catalogs.OrgUnits {
		if !selected[unit.ID] {
			continue
		}
		node := TreeNode{ID: unit.ID, Code: unit.Code, Kind: unit.Kind, Lifecycle: Lifecycle{ValidFrom: unit.ValidFrom, ValidTo: unit.ValidTo}}
		if q.IncludeLabels {
			node.Label = &unit.Label
		}
		out.Nodes = append(out.Nodes, node)
	}
	for _, edge := range catalogs.OrgUnitParents {
		if selected[edge.ChildUnitID] && selected[edge.ParentUnitID] {
			out.Edges = append(out.Edges, TreeEdge{ID: edge.ID, ChildUnitID: edge.ChildUnitID, ParentUnitID: edge.ParentUnitID, ValidFrom: edge.ValidFrom, ValidTo: edge.ValidTo})
		}
	}
	released, piiEmployees := []Employee{}, []string{}
	for _, employee := range employees {
		facts, factErr := s.Store.EmployeeWorkforceFacts(ctx, org, employee.ID, q.AsOf)
		if factErr != nil {
			return TreeView{}, factErr
		}
		for _, assignment := range facts.JobAssignments {
			if !selected[assignment.DepartmentID] {
				continue
			}
			item := TreeEmployee{ID: employee.ID, DepartmentID: assignment.DepartmentID}
			if q.IncludeLabels {
				view, viewErr := s.prepareView(ctx, req, snap, employee, q.AsOf, true, g)
				if viewErr != nil {
					return TreeView{}, viewErr
				}
				item.Profile = view.Profile
				piiEmployees = append(piiEmployees, employee.ID)
			}
			out.Employees = append(out.Employees, item)
			released = append(released, employee)
			break
		}
	}
	if len(out.Employees) > 500 {
		return TreeView{}, fault.Invalid
	}
	if err = s.releaseQuery(ctx, req, snap, g, day, op, released, piiEmployees, q.IncludeLabels); err != nil {
		return TreeView{}, s.denied(ctx, req, snap, op, err)
	}
	return out, nil
}
func (s *Service) directoryScope(ctx context.Context, snap authz.Snapshot, req Request, q DirectoryQuery, day string) (DirectoryScope, error) {
	now := s.clock()
	scope := DirectoryScope{AuthorizationDate: day}
	scope.Org = snap.Allows("organization.read", "metadata", "", req.Purpose, now) && (q.Q == "" || snap.Allows("pii.read", "pii", "", req.Purpose, now))
	employees, departments := map[string]bool{}, map[string]bool{}
	for _, a := range snap.Assignments {
		if a.ScopeKind == "employee" {
			employees[a.ScopeID] = true
		} else if a.ScopeKind == "department" {
			departments[a.ScopeID] = true
		}
	}
	for _, a := range snap.Grants {
		if a.ScopeKind == "employee" {
			employees[a.ScopeID] = true
		} else if a.ScopeKind == "department" {
			departments[a.ScopeID] = true
		}
	}
	for id := range employees {
		employeeSnap, err := s.Store.Security(ctx, req.TokenHash, snap.OrgID, id)
		if err != nil {
			return DirectoryScope{}, err
		}
		if employeeSnap.AuthEpoch != snap.AuthEpoch {
			return DirectoryScope{}, fault.Forbidden
		}
		if employeeSnap.Allows("organization.read", "metadata", id, req.Purpose, now) && (q.Q == "" || employeeSnap.Allows("pii.read", "pii", id, req.Purpose, now)) {
			scope.Employees = append(scope.Employees, id)
		}
	}
	for id := range departments {
		if snap.AllowsDepartment("organization.read", "metadata", id, req.Purpose, now) && (q.Q == "" || snap.AllowsDepartment("pii.read", "pii", id, req.Purpose, now)) {
			scope.Departments = append(scope.Departments, id)
		}
	}
	sort.Strings(scope.Employees)
	sort.Strings(scope.Departments)
	return scope, nil
}

func directoryProfileMatch(view View, needle string) bool {
	if view.Profile != nil && (strings.Contains(strings.ToLower(view.Profile.LocalName), needle) || strings.Contains(strings.ToLower(view.Profile.EnglishName), needle)) {
		return true
	}
	for _, identifier := range view.Identifiers {
		if strings.Contains(strings.ToLower(identifier.StaffCode), needle) {
			return true
		}
	}
	return false
}
func (s *Service) Directory(ctx context.Context, req Request, org string, q DirectoryQuery) (DirectoryPage, error) {
	const op = "OP-ORG-04"
	snap, err := s.structureAuthority(ctx, s.Store, req, org, op, false)
	if err != nil {
		return DirectoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	if !value.ValidID(org) || !value.ValidDate(q.AsOf) || q.DepartmentID != "" && !value.ValidID(q.DepartmentID) || q.EmployeeID != "" && !value.ValidID(q.EmployeeID) || !utf8.ValidString(q.Q) || len(q.Q) > 256 || q.Q != "" && !q.IncludeProfile || q.Limit < 0 || q.Limit > 100 || (q.Lifecycle != "" && q.Lifecycle != "active" && q.Lifecycle != "inactive" && q.Lifecycle != "all") {
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
	scope, err := s.directoryScope(ctx, snap, req, q, day)
	if err != nil {
		return DirectoryPage{}, err
	}
	if !scope.Org && len(scope.Employees) == 0 && len(scope.Departments) == 0 {
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
		if q.Q == "" || directoryProfileMatch(v, needle) {
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
	orgPII := false
	if len(released) == 0 {
		switch {
		case scope.Org:
			orgPII = q.Q != ""
		case len(scope.Employees) != 0:
			id := scope.Employees[0]
			released = append(released, Employee{ID: id, OrgID: org})
			if q.Q != "" {
				piiIDs = append(piiIDs, id)
			}
		}
	}
	if err = s.releaseQuery(ctx, req, snap, g, day, op, released, piiIDs, orgPII); err != nil {
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
			if item.Kind == "job_assignment" && employeePII && item.PayloadID != "" {
				var payload PositionPayload
				if err = s.openWorkforcePayload(ctx, e.OrgID, employee, item.ID, item.PayloadID, "job_assignment", "pii.job_assignment_position.v1", &payload); err != nil {
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
			if err = s.openWorkforcePayload(ctx, e.OrgID, "", c.ID, c.ReasonPayloadID, "structure_change", "org.structure.reason.v1", &payload); err != nil {
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
	if err = s.releaseQuery(ctx, req, snap, g, day, op, []Employee{e}, piiIDs, reasonReleased); err != nil {
		return HistoryPage{}, s.denied(ctx, req, snap, op, err)
	}
	return page, nil
}
