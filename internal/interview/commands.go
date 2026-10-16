package interview

import (
	"context"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"strings"
)

func (s *Service) Create(ctx context.Context, q Request, employee string, c CreateCommand) (Result, error) {
	a, e := s.employee(ctx, q, employee)
	if e != nil {
		return Result{}, e
	}
	if e = s.requireInterviewCreate(a, employee, nil); e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-02", e)
	}
	scheduled, e := timestamp(c.ScheduledAt)
	if e != nil || len(c.Participants) > 20 {
		return Result{}, fault.Invalid
	}
	start, e := actual(c.ActualStartedAt, s.clock())
	if e != nil {
		return Result{}, e
	}
	end, e := actual(c.ActualEndedAt, s.clock())
	if e != nil {
		return Result{}, e
	}
	if c.Backfilled {
		if start == nil || end == nil || end.Before(*start) {
			return Result{}, fault.Invalid
		}
	} else if start != nil || end != nil {
		return Result{}, fault.Invalid
	}
	dday, e := day(a, s.clock())
	if e != nil {
		return Result{}, e
	}
	seen := map[Party]bool{}
	for _, p := range c.Participants {
		if seen[p] || !value.ValidID(p.ID) || (p.Kind != "subject" && p.Kind != "employee") {
			return Result{}, fault.Invalid
		}
		seen[p] = true
		ok, e := s.Store.InterviewParty(ctx, a.OrgID, p, false, dday)
		if e != nil {
			return Result{}, e
		}
		if !ok {
			return Result{}, fault.Invalid
		}
	}
	if c.Participants == nil {
		c.Participants = []Party{}
	}
	digest, e := s.digest(q, a, "OP-INT-02", employee, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, "OP-INT-02", digest); ok || e != nil {
		return r, e
	}
	status := "scheduled"
	if c.Backfilled {
		status = "completed"
	}
	i := Record{OrgID: a.OrgID, Number: 1, InterviewView: InterviewView{ID: value.NewID(), EmployeeID: employee, Status: status, Revision: "1", ScheduledAt: scheduled, ActualStartedAt: start, ActualEndedAt: end, Backfilled: c.Backfilled, RecordedAt: s.clock(), AuthorSubjectID: a.SubjectID, Participants: c.Participants}}
	event := TransitionEvent{OrgID: a.OrgID, ID: value.NewID(), InterviewID: i.ID, EmployeeID: employee, Status: status, Revision: 1, ActualStartedAt: start, ActualEndedAt: end, Backfilled: c.Backfilled, AuthorSubjectID: a.SubjectID, RecordedAt: i.RecordedAt}
	return s.commit(ctx, q, a, employee, "OP-INT-02", digest, Write{Interview: &i, Transition: &event}, Result{ID: i.ID, Status: status, Revision: "1"}, func(tx Tx, current authz.Snapshot) error {
		if e := s.requireInterviewCreate(current, employee, interviewLine(i)); e != nil {
			return e
		}
		for _, p := range c.Participants {
			ok, e := tx.InterviewParty(ctx, a.OrgID, p, false, dday)
			if e != nil {
				return e
			}
			if !ok {
				return fault.Invalid
			}
		}
		return nil
	})
}

func (s *Service) Transition(ctx context.Context, q Request, id string, c TransitionCommand) (Result, error) {
	a, i, e := s.objectInterview(ctx, q, id)
	if e != nil {
		return Result{}, e
	}
	line := interviewLine(i)
	if e = s.require(a, i.EmployeeID, "metadata", line, "interview.read", "interview.write"); e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-03", e)
	}
	expected, e := revision(c.ExpectedRevision, false)
	if e != nil || !text(c.Reason, 4096, false) || (c.Action != "start" && c.Action != "complete" && c.Action != "cancel") {
		return Result{}, fault.Invalid
	}
	start, e := actual(c.ActualStartedAt, s.clock())
	if e != nil {
		return Result{}, e
	}
	end, e := actual(c.ActualEndedAt, s.clock())
	if e != nil {
		return Result{}, e
	}
	digest, e := s.digest(q, a, "OP-INT-03", id, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, "OP-INT-03", digest); ok || e != nil {
		return r, e
	}
	if i.Number != expected {
		return Result{}, fault.Conflict
	}
	mode := c.Action
	if c.Backfilled {
		if c.Action != "complete" {
			return Result{}, fault.Invalid
		}
		mode = backfilledCompletion
	}
	status, e := nextInterviewStatus(i.Status, mode)
	if e != nil {
		return Result{}, e
	}
	switch c.Action {
	case "start":
		if start == nil || end != nil {
			return Result{}, fault.Invalid
		}
		i.ActualStartedAt = start
	case "complete":
		if c.Backfilled {
			if start == nil || end == nil || end.Before(*start) {
				return Result{}, fault.Invalid
			}
			i.ActualStartedAt = start
			i.Backfilled = true
		} else if start != nil || end == nil || i.ActualStartedAt == nil || end.Before(*i.ActualStartedAt) {
			return Result{}, fault.Invalid
		}
		i.ActualEndedAt = end
	case "cancel":
		if start != nil || end != nil || strings.TrimSpace(c.Reason) == "" {
			return Result{}, fault.Invalid
		}
	}
	i.Status = status
	i.Number++
	i.Revision = number(i.Number)
	event := TransitionEvent{OrgID: a.OrgID, ID: value.NewID(), InterviewID: id, EmployeeID: i.EmployeeID, Status: status, Revision: i.Number, ActualStartedAt: i.ActualStartedAt, ActualEndedAt: i.ActualEndedAt, Backfilled: i.Backfilled, AuthorSubjectID: a.SubjectID, RecordedAt: s.clock()}
	w := Write{Interview: &i, ExpectedInterviewRevision: expected, Transition: &event}
	if c.Reason != "" {
		pid := value.NewID()
		p, e := s.seal(ctx, binding(a.OrgID, i.EmployeeID, id, pid, "interview_reason", "interview.reason.v1"), struct {
			Reason string `json:"reason"`
		}{c.Reason})
		if e != nil {
			return Result{}, e
		}
		event.PayloadID = pid
		w.Payloads = []Payload{p}
	}
	return s.commit(ctx, q, a, i.EmployeeID, "OP-INT-03", digest, w, Result{ID: id, Status: status, Revision: i.Revision}, func(tx Tx, current authz.Snapshot) error {
		return s.require(current, i.EmployeeID, "metadata", line, "interview.read", "interview.write")
	})
}

func (s *Service) sources(ctx context.Context, r Reader, a authz.Snapshot, employee, cat, cap string, line []authz.ObjectReference, refs []SourceRef, minimized bool) ([]SourceFact, error) {
	if len(refs) > 10 {
		return nil, fault.Invalid
	}
	out := make([]SourceFact, 0, len(refs))
	seen := map[string]bool{}
	for _, src := range refs {
		if src.Kind != "note_version" || !value.ValidID(src.ID) || seen[src.ID] {
			return nil, fault.Invalid
		}
		seen[src.ID] = true
		n, e := revision(src.ExpectedVersion, false)
		if e != nil {
			return nil, e
		}
		v, e := r.InterviewVersion(ctx, a.OrgID, src.ID)
		if e != nil {
			return nil, fault.NotFound
		}
		if v.EmployeeID != employee || v.Number != n || v.Status != "published" {
			return nil, fault.Invalid
		}
		if e = s.require(a, employee, v.Category, versionLine(v), "note.read"); e != nil {
			return nil, e
		}
		if v.Category != cat && (!minimized || !a.AllowsApprovedSource(cap, cat, employee, "interview_followup", s.clock(), ref("note_version", v.ID), line...)) {
			return nil, fault.Forbidden
		}
		out = append(out, SourceFact{SourceRef: src, EmployeeID: employee, Category: v.Category, Epoch: v.SourceEpoch})
	}
	return out, nil
}

func (s *Service) SaveNote(ctx context.Context, q Request, id string, c NoteCommand) (Result, error) {
	a, i, e := s.objectInterview(ctx, q, id)
	if e != nil {
		return Result{}, e
	}
	if !category(c.Category) {
		return Result{}, fault.Invalid
	}
	h, exists, e := s.Store.InterviewHead(ctx, a.OrgID, id, c.Category)
	if e != nil {
		return Result{}, e
	}
	line := interviewLine(i)
	if exists {
		line = headLine(h)
	}
	caps := []string{"note.read", "note.write"}
	if c.Action == "publish" {
		caps = append(caps, "note.publish")
	} else if c.Action != "save_draft" {
		return Result{}, fault.Invalid
	}
	if e = s.require(a, i.EmployeeID, c.Category, line, caps...); e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-05", e)
	}
	expected, e := revision(c.ExpectedHeadRevision, true)
	if e != nil || !text(c.Text, 12288, true) || !text(c.EditReason, 4096, false) {
		return Result{}, fault.Invalid
	}
	if c.HeadID != nil && !value.ValidID(*c.HeadID) || c.SupersedesVersionID != nil && !value.ValidID(*c.SupersedesVersionID) {
		return Result{}, fault.Invalid
	}
	if c.HeadID != nil && (!exists || *c.HeadID != h.ID) {
		return Result{}, fault.Invalid
	}
	if c.SupersedesVersionID != nil {
		old, e := s.Store.InterviewVersion(ctx, a.OrgID, *c.SupersedesVersionID)
		if e != nil {
			return Result{}, fault.Invalid
		}
		if !exists || old.HeadID != h.ID || old.Category != c.Category {
			return Result{}, fault.Invalid
		}
		if e = s.require(a, i.EmployeeID, c.Category, versionLine(old), "note.read"); e != nil {
			return Result{}, s.denied(ctx, q, a, "OP-INT-05", e)
		}
	}
	source, e := s.sources(ctx, s.Store, a, i.EmployeeID, c.Category, "note.publish", line, c.SourceRefs, c.ConfirmMinimized)
	if e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-05", e)
	}
	if c.SourceRefs == nil {
		c.SourceRefs = []SourceRef{}
	}
	digest, e := s.digest(q, a, "OP-INT-05", id, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, "OP-INT-05", digest); ok || e != nil {
		return r, e
	}
	if exists && (c.HeadID == nil || expected == 0) {
		return Result{}, fault.Conflict
	}
	if !exists && (c.HeadID != nil || c.SupersedesVersionID != nil || expected != 0) {
		return Result{}, fault.Conflict
	}
	if i.Status == "cancelled" {
		return Result{}, fault.Conflict
	}
	if (i.Status == "completed" || exists) && strings.TrimSpace(c.EditReason) == "" {
		return Result{}, fault.Invalid
	}
	if exists && h.Revision != expected {
		return Result{}, fault.Conflict
	}
	if !exists {
		h = Head{OrgID: a.OrgID, ID: value.NewID(), InterviewID: id, EmployeeID: i.EmployeeID, Category: c.Category, ACLEpoch: 1}
	} else if c.SupersedesVersionID == nil {
		return Result{}, fault.Invalid
	}
	h.Revision++
	h.ACLEpoch++
	vid := value.NewID()
	status := "draft"
	if c.Action == "publish" {
		status = "published"
		h.PublishedID = vid
	} else {
		h.DraftID = vid
	}
	p, e := s.seal(ctx, binding(a.OrgID, i.EmployeeID, h.ID, vid, "interview_note_"+c.Category, "interview.note.v1"), struct {
		Text       string `json:"text"`
		EditReason string `json:"edit_reason"`
	}{c.Text, c.EditReason})
	if e != nil {
		return Result{}, e
	}
	content, e := s.digest(q, a, "interview.note.content", h.ID, struct {
		Text       string
		EditReason string
	}{c.Text, c.EditReason})
	if e != nil {
		return Result{}, e
	}
	v := Version{OrgID: a.OrgID, HeadID: h.ID, PayloadID: vid, Number: h.Revision, SourceEpoch: 1, ContentDigest: content, NoteView: NoteView{ID: vid, InterviewID: id, EmployeeID: i.EmployeeID, Category: c.Category, Status: status, VersionNo: number(h.Revision), AuthorSubjectID: a.SubjectID, RecordedAt: p.RecordedAt, SupersedesVersionID: c.SupersedesVersionID}}
	result := Result{ID: vid, Status: status, Revision: number(v.Number), HeadID: new(h.ID), HeadRevision: new(number(h.Revision)), VersionNo: new(number(v.Number))}
	return s.commit(ctx, q, a, i.EmployeeID, "OP-INT-05", digest, Write{Head: &h, ExpectedHeadRevision: expected, Version: &v, Payloads: []Payload{p}, Sources: source}, result, func(tx Tx, current authz.Snapshot) error {
		if e := s.require(current, i.EmployeeID, c.Category, line, caps...); e != nil {
			return e
		}
		_, e := s.sources(ctx, tx, current, i.EmployeeID, c.Category, "note.publish", line, c.SourceRefs, c.ConfirmMinimized)
		if e != nil {
			return e
		}
		latest, e := tx.Interview(ctx, a.OrgID, id)
		if e != nil {
			return e
		}
		if latest.Status == "cancelled" {
			return fault.Conflict
		}
		if latest.Status == "completed" && strings.TrimSpace(c.EditReason) == "" {
			return fault.Invalid
		}
		return nil
	})
}

func (s *Service) CreateAction(ctx context.Context, q Request, id string, c ActionCommand) (Result, error) {
	a, i, e := s.objectInterview(ctx, q, id)
	if e != nil {
		return Result{}, e
	}
	line := interviewLine(i)
	if e = s.require(a, i.EmployeeID, "shared", line, "action.read", "action.write"); e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-07", e)
	}
	expected, e := revision(c.ExpectedRevision, false)
	if e != nil || !text(c.MinimalSharedText, 12288, true) || c.DueDate != nil && !value.ValidDate(*c.DueDate) || !value.ValidID(c.Owner.ID) || (c.Owner.Kind != "subject" && c.Owner.Kind != "employee") {
		return Result{}, fault.Invalid
	}
	dday, e := day(a, s.clock())
	if e != nil {
		return Result{}, e
	}
	ok, e := s.Store.InterviewParty(ctx, a.OrgID, c.Owner, true, dday)
	if e != nil {
		return Result{}, e
	}
	if !ok {
		return Result{}, fault.Invalid
	}
	sources, e := s.sources(ctx, s.Store, a, i.EmployeeID, "shared", "action.write", line, c.SourceRefs, c.ConfirmMinimized)
	if e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-07", e)
	}
	if c.SourceRefs == nil {
		c.SourceRefs = []SourceRef{}
	}
	digest, e := s.digest(q, a, "OP-INT-07", id, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, "OP-INT-07", digest); ok || e != nil {
		return r, e
	}
	if i.Number != expected || i.Status == "completed" || i.Status == "cancelled" {
		return Result{}, fault.Conflict
	}
	aid, pid := value.NewID(), value.NewID()
	p, e := s.seal(ctx, binding(a.OrgID, i.EmployeeID, aid, pid, "interview_action", "interview.action.v1"), struct {
		Text    string `json:"minimal_shared_text"`
		Blocker string `json:"safe_blocker_text"`
	}{c.MinimalSharedText, ""})
	if e != nil {
		return Result{}, e
	}
	action := ActionRecord{OrgID: a.OrgID, PayloadID: pid, Number: 1, ActionView: ActionView{ID: aid, InterviewID: id, EmployeeID: i.EmployeeID, Revision: "1", Status: "todo", Owner: c.Owner, DueDate: c.DueDate, RecordedAt: p.RecordedAt}}
	event := Event{OrgID: a.OrgID, ActionID: aid, InterviewID: id, EmployeeID: i.EmployeeID, PayloadID: pid, Number: 1, ActionEventView: ActionEventView{ID: value.NewID(), Status: "todo", Revision: "1", AuthorSubjectID: a.SubjectID, RecordedAt: p.RecordedAt}}
	i.Number++
	i.Revision = number(i.Number)
	return s.commit(ctx, q, a, i.EmployeeID, "OP-INT-07", digest, Write{Interview: &i, ExpectedInterviewRevision: expected, Action: &action, Event: &event, Payloads: []Payload{p}, Sources: sources}, Result{ID: aid, Status: "todo", Revision: "1", InterviewRevision: new(i.Revision)}, func(tx Tx, current authz.Snapshot) error {
		if e := s.require(current, i.EmployeeID, "shared", line, "action.read", "action.write"); e != nil {
			return e
		}
		ok, e := tx.InterviewParty(ctx, a.OrgID, c.Owner, true, dday)
		if e != nil {
			return e
		}
		if !ok {
			return fault.Invalid
		}
		_, e = s.sources(ctx, tx, current, i.EmployeeID, "shared", "action.write", line, c.SourceRefs, c.ConfirmMinimized)
		return e
	})
}

func (s *Service) TransitionAction(ctx context.Context, q Request, id string, c ActionTransitionCommand) (Result, error) {
	a, e := s.session(ctx, s.Store, q, "", "")
	if e != nil {
		return Result{}, e
	}
	if !value.ValidID(id) {
		return Result{}, fault.Invalid
	}
	action, e := s.Store.InterviewAction(ctx, a.OrgID, id)
	if e != nil {
		return Result{}, e
	}
	a, e = s.session(ctx, s.Store, q, a.OrgID, action.EmployeeID)
	if e != nil {
		return Result{}, e
	}
	line := actionLine(action)
	if e = s.require(a, action.EmployeeID, "shared", line, "action.read", "action.write"); e != nil {
		return Result{}, s.denied(ctx, q, a, "OP-INT-08", e)
	}
	expected, e := revision(c.ExpectedRevision, false)
	if e != nil || !text(c.SafeBlockerText, 4096, false) {
		return Result{}, fault.Invalid
	}
	digest, e := s.digest(q, a, "OP-INT-08", id, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, "OP-INT-08", digest); ok || e != nil {
		return r, e
	}
	if action.Number != expected {
		return Result{}, fault.Conflict
	}
	status, e := nextActionStatus(action.Status, c.Action)
	if e != nil {
		return Result{}, e
	}
	pid := value.NewID()
	p, e := s.seal(ctx, binding(a.OrgID, action.EmployeeID, id, pid, "interview_action", "interview.action.v1"), struct {
		Blocker string `json:"safe_blocker_text"`
	}{c.SafeBlockerText})
	if e != nil {
		return Result{}, e
	}
	action.Number++
	action.Revision = number(action.Number)
	action.Status = status
	action.PayloadID = pid
	event := Event{OrgID: a.OrgID, ActionID: id, InterviewID: action.InterviewID, EmployeeID: action.EmployeeID, PayloadID: pid, Number: action.Number, ActionEventView: ActionEventView{ID: value.NewID(), Status: status, Revision: action.Revision, AuthorSubjectID: a.SubjectID, RecordedAt: p.RecordedAt}}
	return s.commit(ctx, q, a, action.EmployeeID, "OP-INT-08", digest, Write{Action: &action, ExpectedActionRevision: expected, Event: &event, Payloads: []Payload{p}}, Result{ID: id, Status: status, Revision: action.Revision}, func(tx Tx, current authz.Snapshot) error {
		return s.require(current, action.EmployeeID, "shared", line, "action.read", "action.write")
	})
}
