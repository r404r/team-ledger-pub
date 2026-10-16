package interview

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

// scope resolves object restrictions against canonical stored ownership before
// passing IDs to SQL. An exact immutable-version grant never widens to its head.
func (s *Service) scope(ctx context.Context, r Reader, a authz.Snapshot, cap, cat, employee, interviewID string) (Scope, error) {
	out := Scope{Broad: a.Allows(cap, cat, employee, "interview_followup", s.clock())}
	if out.Broad {
		return out, nil
	}
	seen := make(map[authz.ObjectReference]bool)
	for _, g := range a.Grants {
		if g.Capability != cap || g.Category != cat || g.ObjectRef == nil || seen[*g.ObjectRef] {
			continue
		}
		obj := *g.ObjectRef
		seen[obj] = true
		var line []authz.ObjectReference
		var owner, parent, storedCategory string
		switch obj.Kind {
		case "interview":
			i, e := r.Interview(ctx, a.OrgID, obj.ID)
			if errors.Is(e, fault.NotFound) {
				continue
			}
			if e != nil {
				return out, e
			}
			owner, parent, line = i.EmployeeID, i.ID, interviewLine(i)
		case "note_head":
			if !category(cat) {
				continue
			}
			// A head restriction is usable only within the requested canonical
			// interview/category; never infer its parent from caller-supplied IDs.
			if interviewID == "" {
				continue
			}
			h, ok, e := r.InterviewHead(ctx, a.OrgID, interviewID, cat)
			if e != nil {
				return out, e
			}
			if !ok || h.ID != obj.ID {
				continue
			}
			owner, parent, storedCategory, line = h.EmployeeID, h.InterviewID, h.Category, headLine(h)
		case "note_version":
			v, e := r.InterviewVersion(ctx, a.OrgID, obj.ID)
			if errors.Is(e, fault.NotFound) {
				continue
			}
			if e != nil {
				return out, e
			}
			owner, parent, storedCategory, line = v.EmployeeID, v.InterviewID, v.Category, versionLine(v)
		case "action_item":
			v, e := r.InterviewAction(ctx, a.OrgID, obj.ID)
			if errors.Is(e, fault.NotFound) {
				continue
			}
			if e != nil {
				return out, e
			}
			owner, parent, storedCategory, line = v.EmployeeID, v.InterviewID, "shared", actionLine(v)
		default:
			continue
		}
		if owner != employee || interviewID != "" && parent != interviewID || storedCategory != "" && storedCategory != cat || !s.allows(a, cap, cat, employee, line) {
			continue
		}
		switch obj.Kind {
		case "interview":
			out.Interviews = append(out.Interviews, obj.ID)
		case "note_head":
			out.Heads = append(out.Heads, obj.ID)
		case "note_version":
			out.Versions = append(out.Versions, obj.ID)
		case "action_item":
			out.Actions = append(out.Actions, obj.ID)
		}
	}
	sort.Strings(out.Interviews)
	sort.Strings(out.Heads)
	sort.Strings(out.Versions)
	sort.Strings(out.Actions)
	return out, nil
}

func scopeEmpty(v Scope) bool {
	return !v.Broad && len(v.Interviews)+len(v.Heads)+len(v.Versions)+len(v.Actions) == 0
}

// release is the only plaintext release gate. No KMS work belongs in this Tx.
func (s *Service) release(ctx context.Context, q Request, a authz.Snapshot, employee, op string, validate func(Tx, authz.Snapshot) error) error {
	d, e := day(a, s.clock())
	if e != nil {
		return e
	}
	g, e := s.Store.GraphState(ctx, a.OrgID)
	if e != nil {
		return e
	}
	return s.Store.WithInterviewTx(ctx, a.OrgID, func(tx Tx) error {
		if e := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); e != nil {
			return e
		}
		if e := tx.LockInterviewEmployee(ctx, a.OrgID, employee); e != nil {
			return e
		}
		current, e := s.session(ctx, tx, q, a.OrgID, employee)
		if e != nil {
			return e
		}
		if current.OrgID != a.OrgID || current.SubjectID != a.SubjectID || current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch || current.SessionEpoch != a.SessionEpoch || current.Timezone != a.Timezone {
			return fault.Forbidden
		}
		today, e := day(current, s.clock())
		if e != nil {
			return e
		}
		if today != d {
			return fault.Conflict
		}
		graph, e := tx.GraphState(ctx, a.OrgID)
		if e != nil {
			return e
		}
		if graph.Revision != g.Revision {
			return fault.Conflict
		}
		if e = validate(tx, current); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, current, employee, op, "allowed"))
	})
}

func (s *Service) validateCursor(ctx context.Context, tx Tx, a authz.Snapshot, c cursor) error {
	d, e := day(a, s.clock())
	if e != nil {
		return e
	}
	g, e := tx.GraphState(ctx, a.OrgID)
	if e != nil {
		return e
	}
	if c.Org != a.OrgID || c.Subject != a.SubjectID || c.Auth != a.AuthEpoch || c.SubjectEpoch != a.SubjectEpoch {
		return fault.Forbidden
	}
	if c.Day != d || c.Graph != g.Revision {
		return fault.Conflict
	}
	return nil
}

func (s *Service) projectSources(ctx context.Context, r Reader, a authz.Snapshot, employee string, owners ...string) ([]SourceRef, error) {
	facts := make([]SourceFact, 0, 10)
	for _, owner := range owners {
		rows, e := r.InterviewSources(ctx, a.OrgID, owner)
		if e != nil {
			return nil, e
		}
		facts = append(facts, rows...)
	}
	if len(facts) > 10 {
		return nil, fault.Unavailable
	}
	out := make([]SourceRef, 0, len(facts))
	seen := make(map[string]bool, len(facts))
	for _, fact := range facts {
		src := fact.SourceRef
		if src.Kind != "note_version" || !value.ValidID(src.ID) || seen[src.ID] || fact.EmployeeID != employee {
			return nil, fault.Unavailable
		}
		seen[src.ID] = true
		v, e := r.InterviewVersion(ctx, a.OrgID, src.ID)
		if errors.Is(e, fault.NotFound) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if v.EmployeeID != employee || v.Category != fact.Category || v.Status != "published" || v.VersionNo != src.ExpectedVersion {
			return nil, fault.Unavailable
		}
		if s.allows(a, "note.read", v.Category, employee, versionLine(v)) {
			if v.SourceEpoch != fact.Epoch {
				return nil, fault.Conflict
			}
			out = append(out, src)
		}
	}
	return out, nil
}

func (s *Service) projectSupersedes(ctx context.Context, r Reader, a authz.Snapshot, v Version) (*string, error) {
	if v.SupersedesVersionID == nil {
		return nil, nil
	}
	old, e := r.InterviewVersion(ctx, a.OrgID, *v.SupersedesVersionID)
	if errors.Is(e, fault.NotFound) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if old.HeadID != v.HeadID || old.EmployeeID != v.EmployeeID || old.Category != v.Category {
		return nil, fault.Unavailable
	}
	if !s.allows(a, "note.read", old.Category, old.EmployeeID, versionLine(old)) {
		return nil, nil
	}
	return new(old.ID), nil
}

func (s *Service) prepareNote(ctx context.Context, r Reader, a authz.Snapshot, v Version) (NoteView, error) {
	if v.OrgID != a.OrgID || !category(v.Category) {
		return NoteView{}, fault.NotFound
	}
	if e := s.require(a, v.EmployeeID, v.Category, versionLine(v), "note.read"); e != nil {
		return NoteView{}, e
	}
	refs, e := s.projectSources(ctx, r, a, v.EmployeeID, v.ID)
	if e != nil {
		return NoteView{}, e
	}
	supersedes, e := s.projectSupersedes(ctx, r, a, v)
	if e != nil {
		return NoteView{}, e
	}
	var p struct {
		Text       string `json:"text"`
		EditReason string `json:"edit_reason"`
	}
	if e = s.open(ctx, r, a.OrgID, v.PayloadID, binding(a.OrgID, v.EmployeeID, v.HeadID, v.ID, "interview_note_"+v.Category, "interview.note.v1"), &p); e != nil {
		return NoteView{}, e
	}
	if !text(p.Text, 12288, true) || !text(p.EditReason, 4096, false) {
		return NoteView{}, fault.Unavailable
	}
	out := v.NoteView
	out.HeadID = ""
	if s.allows(a, "note.read", v.Category, v.EmployeeID, headLine(Head{ID: v.HeadID, InterviewID: v.InterviewID})) {
		out.HeadID = v.HeadID
	}
	out.Text = p.Text
	out.EditReason = p.EditReason
	out.SourceRefs = refs
	out.SupersedesVersionID = supersedes
	return out, nil
}

func validActionHistory(a ActionRecord) bool {
	if len(a.EventRecords) < 1 || len(a.EventRecords) > 3 || int64(len(a.EventRecords)) != a.Number {
		return false
	}
	status := "todo"
	for n, event := range a.EventRecords {
		if event.OrgID != a.OrgID || event.ActionID != a.ID || event.InterviewID != a.InterviewID || event.EmployeeID != a.EmployeeID || event.Number != int64(n+1) || event.Revision != number(event.Number) {
			return false
		}
		if n == 0 {
			if event.Status != "todo" {
				return false
			}
		} else {
			action := ""
			switch event.Status {
			case "in_progress":
				action = "start"
			case "done":
				action = "complete"
			case "cancelled":
				action = "cancel"
			default:
				return false
			}
			next, e := nextActionStatus(status, action)
			if e != nil || next != event.Status {
				return false
			}
			status = next
		}
	}
	last := a.EventRecords[len(a.EventRecords)-1]
	return last.Status == a.Status && last.PayloadID == a.PayloadID
}

func actionSourceOwners(record ActionRecord) []string {
	owners := make([]string, 0, len(record.EventRecords))
	for _, event := range record.EventRecords {
		owners = append(owners, event.ID)
	}
	return owners
}

func (s *Service) prepareAction(ctx context.Context, r Reader, a authz.Snapshot, record ActionRecord) (ActionView, error) {
	if record.OrgID != a.OrgID {
		return ActionView{}, fault.NotFound
	}
	if e := s.require(a, record.EmployeeID, "shared", actionLine(record), "action.read"); e != nil {
		return ActionView{}, e
	}
	if !validActionHistory(record) {
		return ActionView{}, fault.Unavailable
	}
	refs, e := s.projectSources(ctx, r, a, record.EmployeeID, actionSourceOwners(record)...)
	if e != nil {
		return ActionView{}, e
	}
	d, e := day(a, s.clock())
	if e != nil {
		return ActionView{}, e
	}
	out := record.ActionView
	out.SourceRefs = refs
	out.Events = make([]ActionEventView, 0, len(record.EventRecords))
	for _, event := range record.EventRecords {
		var p struct {
			Text    string `json:"minimal_shared_text"`
			Blocker string `json:"safe_blocker_text"`
		}
		if e = s.open(ctx, r, a.OrgID, event.PayloadID, binding(a.OrgID, record.EmployeeID, record.ID, event.PayloadID, "interview_action", "interview.action.v1"), &p); e != nil {
			return ActionView{}, e
		}
		if !text(p.Blocker, 4096, false) {
			return ActionView{}, fault.Unavailable
		}
		if event.Number == 1 {
			if !text(p.Text, 12288, true) {
				return ActionView{}, fault.Unavailable
			}
			out.MinimalSharedText = p.Text
		}
		v := event.ActionEventView
		v.SafeBlockerText = p.Blocker
		out.Events = append(out.Events, v)
		if event.PayloadID == record.PayloadID {
			out.SafeBlockerText = p.Blocker
		}
	}
	out.Overdue = record.DueDate != nil && *record.DueDate < d && record.Status != "done" && record.Status != "cancelled"
	return out, nil
}

// Callers pass the prepared projection in NoteView/ActionView; raw stored
// source facts must not be mistaken for the set of references being released.
func (s *Service) validateVersion(ctx context.Context, tx Tx, a authz.Snapshot, v Version) error {
	latest, e := tx.InterviewVersion(ctx, a.OrgID, v.ID)
	if e != nil {
		return e
	}
	if e = s.require(a, v.EmployeeID, v.Category, versionLine(latest), "note.read"); e != nil {
		return e
	}
	if latest.OrgID != v.OrgID || latest.EmployeeID != v.EmployeeID || latest.InterviewID != v.InterviewID || latest.HeadID != v.HeadID || latest.Category != v.Category || latest.Number != v.Number || latest.PayloadID != v.PayloadID || latest.SourceEpoch != v.SourceEpoch {
		return fault.Conflict
	}
	headID := ""
	if s.allows(a, "note.read", latest.Category, latest.EmployeeID, headLine(Head{ID: latest.HeadID, InterviewID: latest.InterviewID})) {
		headID = latest.HeadID
	}
	if v.NoteView.HeadID != headID {
		return fault.Forbidden
	}
	refs, e := s.projectSources(ctx, tx, a, latest.EmployeeID, latest.ID)
	if e != nil {
		return e
	}
	supersedes, e := s.projectSupersedes(ctx, tx, a, latest)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(refs, v.SourceRefs) || !reflect.DeepEqual(supersedes, v.SupersedesVersionID) {
		return fault.Forbidden
	}
	return nil
}

func (s *Service) validateAction(ctx context.Context, tx Tx, a authz.Snapshot, record ActionRecord) error {
	latest, e := tx.InterviewAction(ctx, a.OrgID, record.ID)
	if e != nil {
		return e
	}
	if e = s.require(a, record.EmployeeID, "shared", actionLine(latest), "action.read"); e != nil {
		return e
	}
	if latest.OrgID != record.OrgID || latest.EmployeeID != record.EmployeeID || latest.InterviewID != record.InterviewID || latest.Number != record.Number || latest.PayloadID != record.PayloadID || !reflect.DeepEqual(latest.EventRecords, record.EventRecords) {
		return fault.Conflict
	}
	refs, e := s.projectSources(ctx, tx, a, latest.EmployeeID, actionSourceOwners(latest)...)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(refs, record.SourceRefs) {
		return fault.Forbidden
	}
	return nil
}

func (s *Service) NoteVersion(ctx context.Context, q Request, id string) (NoteView, error) {
	const op = "OP-INT-06"
	a, e := s.session(ctx, s.Store, q, "", "")
	if e != nil {
		return NoteView{}, e
	}
	if !value.ValidID(id) {
		return NoteView{}, fault.Invalid
	}
	v, e := s.Store.InterviewVersion(ctx, a.OrgID, id)
	if e != nil {
		return NoteView{}, s.denied(ctx, q, a, op, e)
	}
	a, e = s.session(ctx, s.Store, q, a.OrgID, v.EmployeeID)
	if e != nil {
		return NoteView{}, e
	}
	if e = s.require(a, v.EmployeeID, v.Category, versionLine(v), "note.read"); e != nil {
		return NoteView{}, s.denied(ctx, q, a, op, e)
	}
	c, e := s.cursor(ctx, a, "version:"+id, "")
	if e != nil {
		return NoteView{}, e
	}
	out, e := s.prepareNote(ctx, s.Store, a, v)
	if e != nil {
		return NoteView{}, s.denied(ctx, q, a, op, e)
	}
	v.NoteView = out
	e = s.release(ctx, q, a, v.EmployeeID, op, func(tx Tx, current authz.Snapshot) error {
		if e := s.validateCursor(ctx, tx, current, c); e != nil {
			return e
		}
		return s.validateVersion(ctx, tx, current, v)
	})
	if e != nil {
		return NoteView{}, s.denied(ctx, q, a, op, e)
	}
	return out, nil
}

func (s *Service) List(ctx context.Context, q Request, employee string, query ListQuery) (ListView, error) {
	const op = "OP-INT-01"
	a, e := s.employee(ctx, q, employee)
	if e != nil {
		return ListView{}, e
	}
	n, e := limit(query.Limit, 20)
	if e != nil {
		return ListView{}, e
	}
	if query.Status != "" && query.Status != "scheduled" && query.Status != "in_progress" && query.Status != "completed" && query.Status != "cancelled" {
		return ListView{}, fault.Invalid
	}
	zone, e := time.LoadLocation(a.Timezone)
	if e != nil || a.Timezone == "" {
		return ListView{}, fault.Unavailable
	}
	var from, to time.Time
	if query.From != "" {
		if !value.ValidDate(query.From) {
			return ListView{}, fault.Invalid
		}
		from, e = time.ParseInLocation("2006-01-02", query.From, zone)
		if e != nil {
			return ListView{}, fault.Invalid
		}
	}
	if query.To != "" {
		if !value.ValidDate(query.To) {
			return ListView{}, fault.Invalid
		}
		to, e = time.ParseInLocation("2006-01-02", query.To, zone)
		if e != nil {
			return ListView{}, fault.Invalid
		}
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return ListView{}, fault.Invalid
	}
	sc, e := s.scope(ctx, s.Store, a, "interview.read", "metadata", employee, "")
	if e != nil {
		return ListView{}, e
	}
	if scopeEmpty(sc) {
		return ListView{}, s.denied(ctx, q, a, op, fault.NotFound)
	}
	bound, _ := json.Marshal(struct {
		Employee, From, To, Status string
		Limit                      int
	}{employee, query.From, query.To, query.Status, n})
	c, e := s.cursor(ctx, a, string(bound), query.Cursor)
	if e != nil {
		return ListView{}, e
	}
	if c.Last != "" && !value.ValidID(c.Last) {
		return ListView{}, fault.Invalid
	}
	records, e := s.Store.InterviewList(ctx, a.OrgID, employee, query, sc, from, to, c.Last, n+1)
	if e != nil {
		return ListView{}, e
	}
	out := ListView{Items: make([]InterviewView, 0, n), AsOf: c.Day, Consistency: "current", Permissions: []Permission{{"interview.read", "metadata"}}}
	write := sc.Broad && a.Allows("interview.write", "metadata", employee, "interview_followup", s.clock())
	create := write || a.StaffDefaultCanCreateInterview(employee, s.clock())
	if write {
		out.Permissions = append(out.Permissions, Permission{"interview.write", "metadata"})
	} else if create {
		out.Permissions = append(out.Permissions, Permission{"interview.create", "metadata"})
	}
	if len(records) > n {
		records = records[:n]
		out.NextCursor, e = s.encodeCursor(c, records[n-1].ID)
		if e != nil {
			return ListView{}, e
		}
	}
	for _, i := range records {
		if e = s.require(a, employee, "metadata", interviewLine(i), "interview.read"); e != nil {
			return ListView{}, s.denied(ctx, q, a, op, e)
		}
		out.Items = append(out.Items, i.InterviewView)
	}
	e = s.release(ctx, q, a, employee, op, func(tx Tx, current authz.Snapshot) error {
		if e := s.validateCursor(ctx, tx, current, c); e != nil {
			return e
		}
		now, e := s.scope(ctx, tx, current, "interview.read", "metadata", employee, "")
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(now, sc) {
			return fault.Forbidden
		}
		if write && !current.Allows("interview.write", "metadata", employee, "interview_followup", s.clock()) {
			return fault.Forbidden
		}
		if create && !write && !current.StaffDefaultCanCreateInterview(employee, s.clock()) {
			return fault.Forbidden
		}
		for _, i := range records {
			latest, e := tx.Interview(ctx, a.OrgID, i.ID)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(latest, i) {
				return fault.Conflict
			}
			if e = s.require(current, employee, "metadata", interviewLine(latest), "interview.read"); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return ListView{}, s.denied(ctx, q, a, op, e)
	}
	return out, nil
}

// State events are independent of action-induced aggregate revision bumps.
// Their ciphertext references never enter the metadata response.
func (s *Service) prepareInterviewEvents(ctx context.Context, r Reader, a authz.Snapshot, i Record) ([]TransitionEvent, []InterviewEventView, error) {
	events, e := r.InterviewEvents(ctx, a.OrgID, i.ID)
	if e != nil {
		return nil, nil, e
	}
	if len(events) < 1 || len(events) > 3 {
		return nil, nil, fault.Unavailable
	}
	out := make([]InterviewEventView, 0, len(events))
	reasonRead := s.allows(a, "note.read", "shared", i.EmployeeID, interviewLine(i))
	previousRevision := int64(0)
	for _, event := range events {
		if event.OrgID != i.OrgID || event.InterviewID != i.ID || event.EmployeeID != i.EmployeeID || !value.ValidID(event.ID) || event.Revision <= previousRevision || event.Revision > i.Number {
			return nil, nil, fault.Unavailable
		}
		switch event.Status {
		case "scheduled", "in_progress", "completed", "cancelled":
		default:
			return nil, nil, fault.Unavailable
		}
		previousRevision = event.Revision
		view := InterviewEventView{ID: event.ID, Status: event.Status, Revision: number(event.Revision), AuthorSubjectID: event.AuthorSubjectID, RecordedAt: event.RecordedAt, ActualStartedAt: event.ActualStartedAt, ActualEndedAt: event.ActualEndedAt, Backfilled: event.Backfilled}
		if event.PayloadID != "" && reasonRead {
			var payload struct {
				Reason string `json:"reason"`
			}
			if e = s.open(ctx, r, a.OrgID, event.PayloadID, binding(a.OrgID, i.EmployeeID, i.ID, event.PayloadID, "interview_reason", "interview.reason.v1"), &payload); e != nil {
				return nil, nil, e
			}
			if !text(payload.Reason, 4096, true) {
				return nil, nil, fault.Unavailable
			}
			view.Reason = new(payload.Reason)
		}
		out = append(out, view)
	}
	latest := events[len(events)-1]
	if latest.Status != i.Status || latest.Backfilled != i.Backfilled || !reflect.DeepEqual(latest.ActualStartedAt, i.ActualStartedAt) || !reflect.DeepEqual(latest.ActualEndedAt, i.ActualEndedAt) {
		return nil, nil, fault.Unavailable
	}
	return events, out, nil
}

// Detail uses one combined, bounded stream: shared, manager_private,
// hr_confidential, then actions. A category filter selects just that stream.
func (s *Service) Detail(ctx context.Context, q Request, id string, query DetailQuery) (DetailView, error) {
	const op = "OP-INT-04"
	a, i, e := s.objectInterview(ctx, q, id)
	if e != nil {
		return DetailView{}, e
	}
	if e = s.require(a, i.EmployeeID, "metadata", interviewLine(i), "interview.read"); e != nil {
		return DetailView{}, s.denied(ctx, q, a, op, e)
	}
	n, e := limit(query.Limit, 100)
	if e != nil {
		return DetailView{}, e
	}
	requested := map[string]bool{}
	for _, cat := range query.IncludeSections {
		if !category(cat) || requested[cat] {
			return DetailView{}, fault.Invalid
		}
		requested[cat] = true
	}
	if query.Category != "" && !category(query.Category) && query.Category != "actions" {
		return DetailView{}, fault.Invalid
	}
	if category(query.Category) && !requested[query.Category] || query.Category == "actions" && !query.IncludeActions {
		return DetailView{}, fault.Invalid
	}
	streams := make([]string, 0, 4)
	for _, cat := range []string{"shared", "manager_private", "hr_confidential"} {
		if requested[cat] && (query.Category == "" || query.Category == cat) {
			streams = append(streams, cat)
		}
	}
	if query.IncludeActions && (query.Category == "" || query.Category == "actions") {
		streams = append(streams, "actions")
	}
	included := make([]string, 0, 3)
	for _, cat := range []string{"shared", "manager_private", "hr_confidential"} {
		if requested[cat] {
			included = append(included, cat)
		}
	}
	bound, _ := json.Marshal(struct {
		ID       string
		Sections []string
		Actions  bool
		Category string
		Limit    int
	}{id, included, query.IncludeActions, query.Category, n})
	c, e := s.cursor(ctx, a, string(bound), query.Cursor)
	if e != nil {
		return DetailView{}, e
	}
	start, after := 0, ""
	if c.Last != "" {
		parts := strings.Split(c.Last, ":")
		if len(parts) != 2 || !value.ValidID(parts[1]) {
			return DetailView{}, fault.Invalid
		}
		start = -1
		for k, cat := range streams {
			if cat == parts[0] {
				start = k
			}
		}
		if start < 0 {
			return DetailView{}, fault.Invalid
		}
		after = parts[1]
	}
	out := DetailView{Interview: i.InterviewView, Sections: []SectionView{}, ActionItems: []ActionView{}, Permissions: []Permission{}}
	history, eventViews, e := s.prepareInterviewEvents(ctx, s.Store, a, i)
	if e != nil {
		return DetailView{}, s.denied(ctx, q, a, op, e)
	}
	out.InterviewEvents = eventViews
	heads := map[string]Head{}
	exists := map[string]bool{}
	for _, cat := range []string{"shared", "manager_private", "hr_confidential"} {
		h, ok, e := s.Store.InterviewHead(ctx, a.OrgID, id, cat)
		if e != nil {
			return DetailView{}, e
		}
		heads[cat] = h
		exists[cat] = ok
	}
	var versions []Version
	var actions []ActionRecord
	scopes := map[string]Scope{}
	remaining := n
	last := ""
	more := false
	for k := start; k < len(streams); k++ {
		cat := streams[k]
		cap := "note.read"
		scopeCat := cat
		if cat == "actions" {
			cap = "action.read"
			scopeCat = "shared"
		}
		sc, e := s.scope(ctx, s.Store, a, cap, scopeCat, i.EmployeeID, id)
		if e != nil {
			return DetailView{}, e
		}
		scopes[cat] = sc
		cursorAfter := ""
		if k == start {
			cursorAfter = after
		}
		if cat == "actions" {
			rows, e := s.Store.InterviewActions(ctx, a.OrgID, id, sc, cursorAfter, remaining+1)
			if e != nil {
				return DetailView{}, e
			}
			for _, row := range rows {
				if remaining == 0 {
					more = true
					break
				}
				view, e := s.prepareAction(ctx, s.Store, a, row)
				if e != nil {
					return DetailView{}, s.denied(ctx, q, a, op, e)
				}
				row.ActionView = view
				actions = append(actions, row)
				out.ActionItems = append(out.ActionItems, view)
				remaining--
				last = cat + ":" + row.ID
			}
		} else {
			rows, e := s.Store.InterviewVersions(ctx, a.OrgID, id, cat, sc, cursorAfter, remaining+1)
			if e != nil {
				return DetailView{}, e
			}
			for _, row := range rows {
				if remaining == 0 {
					more = true
					break
				}
				view, e := s.prepareNote(ctx, s.Store, a, row)
				if e != nil {
					return DetailView{}, s.denied(ctx, q, a, op, e)
				}
				row.NoteView = view
				versions = append(versions, row)
				remaining--
				last = cat + ":" + row.ID
			}
		}
		if more {
			break
		}
	}
	if more {
		out.NextCursor, e = s.encodeCursor(c, last)
		if e != nil {
			return DetailView{}, e
		}
	}
	// Heads and permission hints are bounded by the finite category registry;
	// exact historical readers receive no unrelated current revision or pointer.
	var pointers []Version
	for _, cat := range []string{"shared", "manager_private", "hr_confidential"} {
		h := heads[cat]
		line := interviewLine(i)
		if exists[cat] {
			line = headLine(h)
		}
		read := s.allows(a, "note.read", cat, i.EmployeeID, line)
		edit := s.allows(a, "note.write", cat, i.EmployeeID, line)
		write := read && edit
		publish := write && s.allows(a, "note.publish", cat, i.EmployeeID, line)
		sc, ok := scopes[cat]
		if !ok {
			sc, e = s.scope(ctx, s.Store, a, "note.read", cat, i.EmployeeID, id)
			if e != nil {
				return DetailView{}, e
			}
			scopes[cat] = sc
		}
		visible := make([]NoteView, 0)
		for _, v := range versions {
			if v.Category == cat {
				visible = append(visible, v.NoteView)
			}
		}
		if !scopeEmpty(sc) {
			out.Permissions = append(out.Permissions, Permission{"note.read", cat})
		}
		if write {
			out.Permissions = append(out.Permissions, Permission{"note.write", cat})
		}
		if publish {
			out.Permissions = append(out.Permissions, Permission{"note.publish", cat})
		}
		if !requested[cat] || query.Category != "" && query.Category != cat || !exists[cat] || len(visible) == 0 && !read {
			continue
		}
		section := SectionView{Category: cat, Versions: visible}
		if read {
			section.HeadID = h.ID
			section.HeadRevision = new(number(h.Revision))
		}
		for _, ptr := range []struct {
			id   string
			dest **string
		}{{h.DraftID, &section.DraftVersionID}, {h.PublishedID, &section.PublishedVersionID}} {
			if ptr.id == "" || !read {
				continue
			}
			v, e := s.Store.InterviewVersion(ctx, a.OrgID, ptr.id)
			if e != nil {
				return DetailView{}, e
			}
			if v.HeadID != h.ID || v.EmployeeID != i.EmployeeID || v.Category != cat {
				return DetailView{}, fault.Unavailable
			}
			if s.allows(a, "note.read", cat, i.EmployeeID, versionLine(v)) {
				*ptr.dest = new(v.ID)
				pointers = append(pointers, v)
			}
		}
		out.Sections = append(out.Sections, section)
	}
	out.Permissions = append(out.Permissions, Permission{"interview.read", "metadata"})
	if s.allows(a, "interview.write", "metadata", i.EmployeeID, interviewLine(i)) {
		out.Permissions = append(out.Permissions, Permission{"interview.write", "metadata"})
	}
	actionRead := s.allows(a, "action.read", "shared", i.EmployeeID, interviewLine(i))
	actionScope, ok := scopes["actions"]
	if !ok {
		actionScope, e = s.scope(ctx, s.Store, a, "action.read", "shared", i.EmployeeID, id)
		if e != nil {
			return DetailView{}, e
		}
		scopes["actions"] = actionScope
	}
	if !scopeEmpty(actionScope) {
		out.Permissions = append(out.Permissions, Permission{"action.read", "shared"})
	}
	if actionRead && s.allows(a, "action.write", "shared", i.EmployeeID, interviewLine(i)) {
		out.Permissions = append(out.Permissions, Permission{"action.write", "shared"})
	}
	// Export hints apply only to already visible objects. An exact-version grant
	// must offer that version without requiring or revealing a current head.
	exportAllowed := func(current authz.Snapshot, cat string) bool {
		if cat == "metadata" {
			return s.allows(current, "sensitive.export", cat, i.EmployeeID, interviewLine(i))
		}
		for _, v := range versions {
			if v.Category == cat && s.allows(current, "sensitive.export", cat, i.EmployeeID, versionLine(v)) {
				return true
			}
		}
		if cat == "shared" {
			for _, action := range actions {
				if s.allows(current, "sensitive.export", cat, i.EmployeeID, actionLine(action)) {
					return true
				}
			}
		}
		return false
	}
	for _, cat := range []string{"metadata", "shared", "manager_private", "hr_confidential"} {
		if exportAllowed(a, cat) {
			out.Permissions = append(out.Permissions, Permission{"sensitive.export", cat})
		}
	}
	e = s.release(ctx, q, a, i.EmployeeID, op, func(tx Tx, current authz.Snapshot) error {
		if e := s.validateCursor(ctx, tx, current, c); e != nil {
			return e
		}
		latest, e := tx.Interview(ctx, a.OrgID, id)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(latest, i) {
			return fault.Conflict
		}
		if e = s.require(current, i.EmployeeID, "metadata", interviewLine(latest), "interview.read"); e != nil {
			return e
		}
		currentHistory, e := tx.InterviewEvents(ctx, a.OrgID, id)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(currentHistory, history) {
			return fault.Conflict
		}
		for _, event := range out.InterviewEvents {
			if event.Reason != nil {
				if e = s.require(current, i.EmployeeID, "shared", interviewLine(latest), "note.read"); e != nil {
					return e
				}
				break
			}
		}
		for cat, sc := range scopes {
			cap, scopeCat := "note.read", cat
			if cat == "actions" {
				cap, scopeCat = "action.read", "shared"
			}
			now, e := s.scope(ctx, tx, current, cap, scopeCat, i.EmployeeID, id)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(now, sc) {
				return fault.Forbidden
			}
		}
		for _, v := range versions {
			if e = s.validateVersion(ctx, tx, current, v); e != nil {
				return e
			}
		}
		for _, v := range actions {
			if e = s.validateAction(ctx, tx, current, v); e != nil {
				return e
			}
		}
		for _, section := range out.Sections {
			h, ok, e := tx.InterviewHead(ctx, a.OrgID, id, section.Category)
			if e != nil {
				return e
			}
			if !ok || !reflect.DeepEqual(h, heads[section.Category]) {
				return fault.Conflict
			}
			if section.HeadRevision != nil && !s.allows(current, "note.read", h.Category, i.EmployeeID, headLine(h)) && !s.allows(current, "note.write", h.Category, i.EmployeeID, headLine(h)) {
				return fault.Forbidden
			}
		}
		for _, v := range pointers {
			now, e := tx.InterviewVersion(ctx, a.OrgID, v.ID)
			if e != nil {
				return e
			}
			if now.Number != v.Number || now.HeadID != v.HeadID {
				return fault.Conflict
			}
			if e = s.require(current, i.EmployeeID, v.Category, versionLine(now), "note.read"); e != nil {
				return e
			}
		}
		for _, p := range out.Permissions {
			if p.Capability == "sensitive.export" {
				if !exportAllowed(current, p.Category) {
					return fault.Forbidden
				}
				continue
			}
			line := interviewLine(i)
			if category(p.Category) && strings.HasPrefix(p.Capability, "note.") && exists[p.Category] {
				line = headLine(heads[p.Category])
			}
			if s.allows(current, p.Capability, p.Category, i.EmployeeID, line) {
				continue
			}
			allowed := p.Capability == "note.read" && !scopeEmpty(scopes[p.Category]) || p.Capability == "action.read" && !scopeEmpty(scopes["actions"])
			if !allowed {
				return fault.Forbidden
			}
		}
		return nil
	})
	if e != nil {
		return DetailView{}, s.denied(ctx, q, a, op, e)
	}
	return out, nil
}
