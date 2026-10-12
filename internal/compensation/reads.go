package compensation

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

// Scope is resolved from canonical owners before the store applies LIMIT.
func (s *Service) financialScope(ctx context.Context, r Reader, a authz.Snapshot, employee string) (Scope, error) {
	out := Scope{Broad: s.allows(a, "compensation.read", employee), Proposals: []string{}, Events: []string{}, Terms: []string{}}
	if out.Broad {
		return out, nil
	}
	seen := map[authz.ObjectReference]bool{}
	for _, g := range a.Grants {
		if g.ObjectRef == nil || seen[*g.ObjectRef] || !s.allows(a, "compensation.read", employee, *g.ObjectRef) {
			continue
		}
		x := *g.ObjectRef
		seen[x] = true
		var org, owner string
		var e error
		switch x.Kind {
		case "compensation_proposal":
			var p ProposalRecord
			p, e = r.CompensationProposal(ctx, a.OrgID, x.ID)
			org, owner = p.OrgID, p.EmployeeID
		case "compensation_event":
			var p EventRecord
			p, e = r.CompensationEvent(ctx, a.OrgID, x.ID)
			org, owner = p.OrgID, p.EmployeeID
		case "compensation_term":
			var p TermRecord
			p, e = r.CompensationTerm(ctx, a.OrgID, x.ID)
			org, owner = p.OrgID, p.EmployeeID
		default:
			continue
		}
		if errors.Is(e, fault.NotFound) {
			continue
		}
		if e != nil {
			return out, e
		}
		if org != a.OrgID || owner != employee {
			continue
		}
		switch x.Kind {
		case "compensation_proposal":
			out.Proposals = append(out.Proposals, x.ID)
		case "compensation_event":
			out.Events = append(out.Events, x.ID)
		case "compensation_term":
			out.Terms = append(out.Terms, x.ID)
		}
	}
	sort.Strings(out.Proposals)
	sort.Strings(out.Events)
	sort.Strings(out.Terms)
	return out, nil
}
func (s *Service) projectTerm(ctx context.Context, t TermRecord) (TermView, error) {
	var terms Terms
	e := s.open(ctx, s.Store, t.OrgID, t.PayloadID, binding(t.OrgID, t.EmployeeID, t.ID, t.ID, "compensation_terms", "compensation.terms.v1"), &terms)
	if e != nil {
		return TermView{}, e
	}
	if e = s.Policy.terms(&terms); e != nil {
		return TermView{}, fault.Unavailable
	}
	if terms.Components == nil {
		terms.Components = []Component{}
	}
	return TermView{ID: t.ID, Revision: number(t.Version), EmployeeID: t.EmployeeID, EffectiveDate: t.EffectiveDate, EventID: t.EventID, Terms: terms}, nil
}
func (s *Service) projectProposal(ctx context.Context, a authz.Snapshot, p ProposalRecord) (ProposalView, error) {
	if p.OrgID != a.OrgID {
		return ProposalView{}, fault.NotFound
	}
	if e := s.require(a, p.EmployeeID, []authz.ObjectReference{ref("compensation_proposal", p.ID)}); e != nil {
		return ProposalView{}, e
	}
	payload, e := s.loadCommand(ctx, p)
	if e != nil {
		return ProposalView{}, e
	}
	c := payload.Command
	if c.Members == nil {
		c.Members = []CorrectionMember{}
	}
	out := ProposalView{ID: p.ID, EmployeeID: p.EmployeeID, Kind: p.Kind, Status: p.Status, Revision: number(p.Revision), CompRevision: number(p.BasisRevision), AuthorSubjectID: p.AuthorSubjectID, RecordedAt: p.RecordedAt.UTC().Format(time.RFC3339Nano), EffectiveDate: c.EffectiveDate, BeforeTermID: c.BeforeTermID, After: c.After, Reason: c.Reason, Members: c.Members, DecisionReason: payload.DecisionReason, ApprovalID: p.ApprovalID}
	out.Permissions = []Permission{}
	for _, cap := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
		if s.allows(a, cap, p.EmployeeID, ref("compensation_proposal", p.ID)) {
			out.Permissions = append(out.Permissions, Permission{cap, "financial"})
		}
	}
	return out, nil
}
func (s *Service) projectEvent(ctx context.Context, a authz.Snapshot, e EventRecord, exporting bool) (ApprovalEventView, error) {
	if e.OrgID != a.OrgID {
		return ApprovalEventView{}, fault.NotFound
	}
	if err := s.require(a, e.EmployeeID, []authz.ObjectReference{ref("compensation_event", e.ID)}); err != nil {
		return ApprovalEventView{}, err
	}
	out := ApprovalEventView{ID: e.ID, Revision: number(e.Sequence), Kind: e.Kind, EffectiveDate: e.EffectiveDate, BeforeTermID: e.BeforeTermID, AfterTermID: e.AfterTermID, CorrectsEventID: e.CorrectsEventID, MemberKey: e.MemberKey}
	if !s.allows(a, "compensation.read", e.EmployeeID) {
		out.MemberKey = ""
	}
	for i, id := range []*string{e.BeforeTermID, e.AfterTermID} {
		if id == nil || !s.allows(a, "compensation.read", e.EmployeeID, ref("compensation_term", *id)) || exporting && !s.allows(a, "sensitive.export", e.EmployeeID, ref("compensation_term", *id)) {
			continue
		}
		t, err := s.Store.CompensationTerm(ctx, e.OrgID, *id)
		if err != nil {
			return ApprovalEventView{}, err
		}
		if t.OrgID != e.OrgID || t.EmployeeID != e.EmployeeID {
			return ApprovalEventView{}, fault.Unavailable
		}
		v, err := s.projectTerm(ctx, t)
		if err != nil {
			return ApprovalEventView{}, err
		}
		if i == 0 {
			out.Before = &v
		} else {
			out.After = &v
		}
	}
	return out, nil
}
func recheckProposal(ctx context.Context, r Reader, p ProposalRecord) error {
	v, e := r.CompensationProposal(ctx, p.OrgID, p.ID)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(v, p) {
		return fault.Conflict
	}
	return nil
}
func recheckTerm(ctx context.Context, r Reader, t TermRecord) error {
	v, e := r.CompensationTerm(ctx, t.OrgID, t.ID)
	if e != nil {
		return e
	}
	if v != t {
		return fault.Conflict
	}
	return nil
}
func recheckEvent(ctx context.Context, r Reader, t EventRecord) error {
	v, e := r.CompensationEvent(ctx, t.OrgID, t.ID)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(v, t) {
		return fault.Conflict
	}
	return nil
}

func (s *Service) Current(ctx context.Context, q Request, employee string, query CurrentQuery) (CurrentView, error) {
	out := CurrentView{}
	if !value.ValidDate(query.AsOf) {
		return out, fault.Invalid
	}
	if query.FutureLimit == 0 {
		query.FutureLimit = 100
	}
	if query.FutureLimit < 1 || query.FutureLimit > 100 {
		return out, fault.Invalid
	}
	a, e := s.employee(ctx, q, employee)
	if e != nil {
		return out, s.denied(ctx, q, a, "OP-COMP-01", e)
	}
	if e = s.require(a, employee, nil); e != nil {
		return out, s.denied(ctx, q, a, "OP-COMP-01", e)
	}
	b, e := s.basis(ctx, a, employee)
	if e != nil {
		return out, e
	}
	schedule, e := s.Store.CompensationSchedule(ctx, a.OrgID, employee, query)
	if e != nil {
		return out, e
	}
	out = CurrentView{EmployeeID: employee, AsOf: query.AsOf, CompRevision: number(b.Aggregate), AuthorizationUntil: s.authorizationUntil(a), FutureTerms: []TermView{}, Permissions: []Permission{}}
	terms := []TermRecord{}
	for _, row := range schedule {
		if row.OrgID != a.OrgID || row.EmployeeID != employee || row.Revision != b.Aggregate {
			return CurrentView{}, fault.Conflict
		}
		current := row.EffectiveDate <= query.AsOf && (row.ValidTo == nil || query.AsOf < *row.ValidTo)
		future := row.EffectiveDate > query.AsOf && len(out.FutureTerms) < query.FutureLimit
		if !current && !future {
			continue
		}
		if err := s.require(a, employee, nil); err != nil {
			return CurrentView{}, s.denied(ctx, q, a, "OP-COMP-01", err)
		}
		t, err := s.Store.CompensationTerm(ctx, a.OrgID, row.TermID)
		if err != nil {
			return CurrentView{}, err
		}
		if t.OrgID != a.OrgID || t.EmployeeID != employee || t.EventID != row.EventID || t.EffectiveDate != row.EffectiveDate {
			return CurrentView{}, fault.Unavailable
		}
		if err = s.require(a, employee, nil); err != nil {
			return CurrentView{}, s.denied(ctx, q, a, "OP-COMP-01", err)
		}
		v, err := s.projectTerm(ctx, t)
		if err != nil {
			return CurrentView{}, err
		}
		terms = append(terms, t)
		v.ValidTo = row.ValidTo
		if current {
			if out.CurrentTerm != nil {
				return CurrentView{}, fault.Unavailable
			}
			out.CurrentTerm = &v
		} else {
			out.FutureTerms = append(out.FutureTerms, v)
		}
	}
	for _, cap := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
		if s.allows(a, cap, employee) {
			out.Permissions = append(out.Permissions, Permission{cap, "financial"})
		}
	}
	e = s.release(ctx, q, a, employee, "OP-COMP-01", b, func(tx Tx, current authz.Snapshot) error {
		if err := s.require(current, employee, nil); err != nil {
			return err
		}
		rows, err := tx.CompensationSchedule(ctx, a.OrgID, employee, query)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(rows, schedule) {
			return fault.Conflict
		}
		for _, t := range terms {
			if err = recheckTerm(ctx, tx, t); err != nil {
				return err
			}
		}
		for _, p := range out.Permissions {
			if !s.allows(current, p.Capability, employee) {
				return fault.Forbidden
			}
		}
		return nil
	})
	if e != nil {
		return CurrentView{}, s.denied(ctx, q, a, "OP-COMP-01", e)
	}
	return out, nil
}

func parseChangesTime(v string) (time.Time, error) {
	if len(v) < 20 || len(v) > 27 || !strings.HasSuffix(v, "Z") || v[:4] == "0000" || v[10] != 'T' || v[13] != ':' || v[16] != ':' {
		return time.Time{}, fault.Invalid
	}
	if len(v) != 20 {
		if v[19] != '.' || len(v) < 22 {
			return time.Time{}, fault.Invalid
		}
		for _, c := range v[20 : len(v)-1] {
			if c < '0' || c > '9' {
				return time.Time{}, fault.Invalid
			}
		}
	}
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil {
		return time.Time{}, fault.Invalid
	}
	return t, nil
}
func normalizeChanges(q ChangesQuery) (ChangesQuery, time.Time, time.Time, error) {
	if q.RecordKind == "" {
		q.RecordKind = "approvals"
	}
	if q.RecordKind == "proposal_revisions" {
		if !value.ValidID(q.ProposalID) || q.From != "" || q.To != "" || q.Status != "" {
			return q, time.Time{}, time.Time{}, fault.Invalid
		}
		if q.Limit == 0 {
			q.Limit = 20
		}
		if q.Limit < 1 || q.Limit > 100 {
			return q, time.Time{}, time.Time{}, fault.Invalid
		}
		return q, time.Time{}, time.Time{}, nil
	}
	if q.RecordKind != "approvals" && q.RecordKind != "proposals" {
		return q, time.Time{}, time.Time{}, fault.Invalid
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 100 || q.ProposalID != "" && !value.ValidID(q.ProposalID) {
		return q, time.Time{}, time.Time{}, fault.Invalid
	}
	if q.Status != "" {
		if q.RecordKind != "proposals" {
			return q, time.Time{}, time.Time{}, fault.Invalid
		}
		switch q.Status {
		case "draft", "submitted", "approved", "rejected", "withdrawn":
		default:
			return q, time.Time{}, time.Time{}, fault.Invalid
		}
	}
	if (q.From == "") != (q.To == "") {
		return q, time.Time{}, time.Time{}, fault.Invalid
	}
	var from, to time.Time
	if q.From != "" {
		var e error
		from, e = parseChangesTime(q.From)
		if e != nil {
			return q, from, to, e
		}
		to, e = parseChangesTime(q.To)
		if e != nil || !from.Before(to) {
			return q, from, to, fault.Invalid
		}
		q.From = from.Format(time.RFC3339Nano)
		q.To = to.Format(time.RFC3339Nano)
	}
	return q, from, to, nil
}

func (s *Service) Changes(ctx context.Context, q Request, employee string, query ChangesQuery) (ChangesView, error) {
	query, from, to, e := normalizeChanges(query)
	if e != nil {
		return ChangesView{}, e
	}
	a, e := s.employee(ctx, q, employee)
	if e != nil {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
	}
	scope, e := s.financialScope(ctx, s.Store, a, employee)
	if e != nil {
		return ChangesView{}, e
	}
	if !scope.Broad && (query.RecordKind == "proposals" && len(scope.Proposals) == 0 || query.RecordKind == "approvals" && len(scope.Events) == 0) {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", fault.NotFound)
	}
	b, e := s.basis(ctx, a, employee)
	if e != nil {
		return ChangesView{}, e
	}
	if query.RecordKind == "proposal_revisions" {
		return s.proposalRevisions(ctx, q, a, employee, query, b, scope)
	}
	cursorBinding, e := s.cursorBinding(a, employee, query, b, scope, 0, q.TokenHash)
	if e != nil {
		return ChangesView{}, e
	}
	after := ""
	if query.Cursor != "" {
		after, e = s.parseCursor(query.Cursor, cursorBinding)
		if e != nil {
			return ChangesView{}, e
		}
	}
	out := ChangesView{RecordKind: query.RecordKind, CompRevision: number(b.Aggregate), Proposals: []ProposalView{}, Approvals: []ApprovalView{}, Revisions: []ProposalRevisionView{}, AuthorizationUntil: s.authorizationUntil(a)}
	proposals := []ProposalRecord{}
	approvals := []ApprovalRecord{}
	events := []EventRecord{}
	terms := []TermRecord{}
	last := ""
	more := false
	if query.RecordKind == "proposals" {
		proposals, e = s.Store.CompensationProposals(ctx, a.OrgID, employee, query, scope, from, to, after, query.Limit+1)
		if e != nil {
			return ChangesView{}, e
		}
		if len(proposals) > query.Limit {
			more = true
			proposals = proposals[:query.Limit]
		}
		for _, p := range proposals {
			if p.OrgID != a.OrgID || p.EmployeeID != employee {
				return ChangesView{}, fault.Unavailable
			}
			v, err := s.projectProposal(ctx, a, p)
			if err != nil {
				return ChangesView{}, err
			}
			out.Proposals = append(out.Proposals, v)
			last = p.RecordedAt.UTC().Format(time.RFC3339Nano) + "|" + p.ID
		}
	} else {
		approvals, e = s.Store.CompensationApprovals(ctx, a.OrgID, employee, query, scope, from, to, after, query.Limit+1)
		if e != nil {
			return ChangesView{}, e
		}
		if len(approvals) > query.Limit {
			more = true
			approvals = approvals[:query.Limit]
		}
		for _, p := range approvals {
			if p.OrgID != a.OrgID || p.EmployeeID != employee {
				return ChangesView{}, fault.Unavailable
			}
			visible, err := s.Store.CompensationApprovalEvents(ctx, a.OrgID, p.ID, scope, 101)
			if err != nil {
				return ChangesView{}, err
			}
			if len(visible) > 100 {
				return ChangesView{}, fault.Unavailable
			}
			v := ApprovalView{ID: p.ID, EmployeeID: p.EmployeeID, ProposalID: p.ProposalID, ProposalRevision: number(p.ProposalRevision), CompRevision: number(p.CompRevision), ApproverSubjectID: p.ApproverSubjectID, ApprovedAt: p.RecordedAt.UTC().Format(time.RFC3339Nano), Events: []ApprovalEventView{}, Members: []MemberMapping{}}
			for _, event := range visible {
				if event.OrgID != a.OrgID || event.EmployeeID != employee || event.ApprovalID != p.ID {
					return ChangesView{}, fault.Unavailable
				}
				ev, err := s.projectEvent(ctx, a, event, false)
				if err != nil {
					return ChangesView{}, err
				}
				events = append(events, event)
				v.Events = append(v.Events, ev)
				if scope.Broad && event.MemberKey != "" {
					v.Members = append(v.Members, MemberMapping{event.MemberKey, event.ID, event.AfterTermID})
				}
				for _, view := range []*TermView{ev.Before, ev.After} {
					if view != nil {
						t, err := s.Store.CompensationTerm(ctx, a.OrgID, view.ID)
						if err != nil {
							return ChangesView{}, err
						}
						terms = append(terms, t)
					}
				}
			}
			if len(v.Events) == 0 {
				return ChangesView{}, fault.Conflict
			}
			if scope.Broad && s.allows(a, "compensation.read", employee) {
				var decision decisionPayload
				if e = s.open(ctx, s.Store, a.OrgID, p.PayloadID, binding(a.OrgID, employee, p.ID, p.ID, "compensation_decision", "compensation.decision.v1"), &decision); e != nil {
					return ChangesView{}, e
				}
				v.Reason = decision.Reason
				v.DecisionReason = decision.DecisionReason
			}
			out.Approvals = append(out.Approvals, v)
			last = p.RecordedAt.UTC().Format(time.RFC3339Nano) + "|" + p.ID
		}
	}
	if more {
		out.NextCursor, e = s.signCursor(cursorBinding, last)
		if e != nil {
			return ChangesView{}, e
		}
	}
	e = s.release(ctx, q, a, employee, "OP-COMP-02", b, func(tx Tx, current authz.Snapshot) error {
		nowScope, err := s.financialScope(ctx, tx, current, employee)
		if err != nil {
			return err
		}
		nowBinding, err := s.cursorBinding(current, employee, query, b, nowScope, 0, q.TokenHash)
		if err != nil {
			return err
		}
		if nowBinding != cursorBinding {
			return fault.Forbidden
		}
		for _, p := range proposals {
			if err = s.require(current, employee, []authz.ObjectReference{ref("compensation_proposal", p.ID)}); err != nil {
				return err
			}
			if err = recheckProposal(ctx, tx, p); err != nil {
				return err
			}
		}
		for _, p := range out.Proposals {
			for _, permission := range p.Permissions {
				if !s.allows(current, permission.Capability, employee, ref("compensation_proposal", p.ID)) {
					return fault.Forbidden
				}
			}
		}
		for _, p := range approvals {
			v, err := tx.CompensationApproval(ctx, p.OrgID, p.ID)
			if err != nil {
				return err
			}
			if v != p {
				return fault.Conflict
			}
		}
		for _, event := range events {
			if err = s.require(current, employee, []authz.ObjectReference{ref("compensation_event", event.ID)}); err != nil {
				return err
			}
			if err = recheckEvent(ctx, tx, event); err != nil {
				return err
			}
		}
		for _, t := range terms {
			if err = s.require(current, employee, []authz.ObjectReference{ref("compensation_term", t.ID)}); err != nil {
				return err
			}
			if err = recheckTerm(ctx, tx, t); err != nil {
				return err
			}
		}
		return nil
	})
	if e != nil {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
	}
	return out, nil
}

func revisionWindowValid(p ProposalRecord, rows []RevisionRecord, before int64, limit int) bool {
	if p.Revision < 1 || len(rows) > limit || before == 0 && (len(rows) == 0 || rows[0].Revision != p.Revision) {
		return false
	}
	var previous int64
	for i, r := range rows {
		if r.OrgID != p.OrgID || r.EmployeeID != p.EmployeeID || r.ProposalID != p.ID || r.Revision < 1 || r.Revision > p.Revision || before != 0 && r.Revision >= before || i > 0 && r.Revision >= previous {
			return false
		}
		if r.Revision == p.Revision || r.ID == p.RevisionID {
			if r.ID != p.RevisionID || r.Revision != p.Revision || r.PayloadID != p.PayloadID || r.Status != p.Status || r.Kind != p.Kind || r.EffectiveDate != p.EffectiveDate || r.BasisRevision != p.BasisRevision || !equalString(r.BeforeTermID, p.BeforeTermID) {
				return false
			}
		}
		previous = r.Revision
	}
	return true
}

func (s *Service) proposalRevisions(ctx context.Context, q Request, a authz.Snapshot, employee string, query ChangesQuery, b readBasis, scope Scope) (ChangesView, error) {
	line := []authz.ObjectReference{ref("compensation_proposal", query.ProposalID)}
	if e := s.require(a, employee, line); e != nil {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
	}
	p, e := s.Store.CompensationProposal(ctx, a.OrgID, query.ProposalID)
	if e != nil {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
	}
	if p.OrgID != a.OrgID || p.EmployeeID != employee {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", fault.NotFound)
	}
	cursorBinding, e := s.cursorBinding(a, employee, query, b, scope, p.Revision, q.TokenHash)
	if e != nil {
		return ChangesView{}, e
	}
	before := int64(0)
	if query.Cursor != "" {
		before, e = s.parseRevisionCursor(query.Cursor, cursorBinding)
		if e != nil || before > p.Revision {
			return ChangesView{}, fault.Invalid
		}
	}
	window, e := s.Store.CompensationRevisions(ctx, a.OrgID, p.ID, before, query.Limit+1)
	if e != nil {
		return ChangesView{}, e
	}
	if !revisionWindowValid(p, window, before, query.Limit+1) {
		return ChangesView{}, fault.Unavailable
	}
	head, e := s.projectProposal(ctx, a, p)
	if e != nil {
		return ChangesView{}, e
	}
	out := ChangesView{RecordKind: query.RecordKind, CompRevision: number(b.Aggregate), Proposals: []ProposalView{head}, Approvals: []ApprovalView{}, Revisions: make([]ProposalRevisionView, 0, query.Limit), AuthorizationUntil: s.authorizationUntil(a)}
	page := window
	if len(page) > query.Limit {
		page = page[:query.Limit]
	}
	for _, r := range page {
		if e = s.require(a, employee, line); e != nil {
			return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
		}
		body := proposalPayload{Command: ProposalCommand{Kind: head.Kind, EffectiveDate: head.EffectiveDate, CompRevision: head.CompRevision, BeforeTermID: head.BeforeTermID, After: head.After, Reason: head.Reason, Members: head.Members}, DecisionReason: head.DecisionReason}
		if r.Revision != p.Revision {
			historical := ProposalRecord{OrgID: r.OrgID, EmployeeID: r.EmployeeID, ID: r.ProposalID, Kind: r.Kind, Status: r.Status, RevisionID: r.ID, PayloadID: r.PayloadID, EffectiveDate: r.EffectiveDate, BeforeTermID: r.BeforeTermID, Revision: r.Revision, BasisRevision: r.BasisRevision}
			body, e = s.loadCommand(ctx, historical)
			if e != nil {
				return ChangesView{}, e
			}
		}
		if body.Command.Members == nil {
			body.Command.Members = []CorrectionMember{}
		}
		out.Revisions = append(out.Revisions, ProposalRevisionView{Revision: number(r.Revision), Status: r.Status, RecordedAt: r.RecordedAt.UTC().Format(time.RFC3339Nano), Command: body.Command, DecisionReason: body.DecisionReason})
	}
	if len(window) > query.Limit {
		out.NextCursor, e = s.signCursor(cursorBinding, number(page[len(page)-1].Revision))
		if e != nil {
			return ChangesView{}, e
		}
	}
	e = s.release(ctx, q, a, employee, "OP-COMP-02", b, func(tx Tx, current authz.Snapshot) error {
		if err := s.require(current, employee, line); err != nil {
			return err
		}
		if err := recheckProposal(ctx, tx, p); err != nil {
			return err
		}
		nowScope, err := s.financialScope(ctx, tx, current, employee)
		if err != nil {
			return err
		}
		nowBinding, err := s.cursorBinding(current, employee, query, b, nowScope, p.Revision, q.TokenHash)
		if err != nil {
			return err
		}
		if nowBinding != cursorBinding {
			return fault.Forbidden
		}
		lockedWindow, err := tx.CompensationRevisions(ctx, a.OrgID, p.ID, before, query.Limit+1)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(lockedWindow, window) {
			return fault.Conflict
		}
		for _, permission := range head.Permissions {
			if !s.allows(current, permission.Capability, employee, line...) {
				return fault.Forbidden
			}
		}
		return nil
	})
	if e != nil {
		return ChangesView{}, s.denied(ctx, q, a, "OP-COMP-02", e)
	}
	return out, nil
}
