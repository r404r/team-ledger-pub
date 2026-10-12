package compensation

import (
	"context"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"math"
	"reflect"
	"time"
)

func (s *Service) objectProposal(ctx context.Context, q Request, id string) (authz.Snapshot, ProposalRecord, error) {
	if !value.ValidID(id) {
		return authz.Snapshot{}, ProposalRecord{}, fault.Invalid
	}
	a, e := s.session(ctx, s.Store, q, "", "")
	if e != nil {
		return a, ProposalRecord{}, e
	}
	p, e := s.Store.CompensationProposal(ctx, a.OrgID, id)
	if e != nil {
		return a, p, e
	}
	a, e = s.session(ctx, s.Store, q, a.OrgID, p.EmployeeID)
	return a, p, e
}
func (s *Service) references(ctx context.Context, r Reader, a authz.Snapshot, employee string, c ProposalCommand) error {
	emp, e := r.Employee(ctx, employee)
	if e != nil || emp.OrgID != a.OrgID {
		return fault.NotFound
	}
	validDate := func(d string) bool {
		return d >= emp.Lifecycle.ValidFrom && (emp.Lifecycle.ValidTo == nil || d < *emp.Lifecycle.ValidTo)
	}
	if !validDate(c.EffectiveDate) {
		return fault.Invalid
	}
	checkTerm := func(id string) error {
		t, e := r.CompensationTerm(ctx, a.OrgID, id)
		if e != nil {
			return e
		}
		if t.EmployeeID != employee || !s.allows(a, "compensation.read", employee, ref("compensation_term", id)) {
			return fault.NotFound
		}
		return nil
	}
	if c.BeforeTermID != nil {
		if e = checkTerm(*c.BeforeTermID); e != nil {
			return e
		}
	}
	events, e := r.CompensationEvents(ctx, a.OrgID, employee)
	if e != nil {
		return e
	}
	active, e := activeEvents(events)
	if e != nil {
		return e
	}
	byID := make(map[string]EventRecord, len(active))
	for _, v := range active {
		byID[v.ID] = v
	}
	if c.Kind == "initial" && len(active) != 0 {
		return fault.Conflict
	}
	for _, m := range c.Members {
		if !validDate(m.EffectiveDate) {
			return fault.Invalid
		}
		original, e := r.CompensationEvent(ctx, a.OrgID, m.OriginalEventID)
		if e != nil {
			return e
		}
		if original.EmployeeID != employee || !s.allows(a, "compensation.read", employee, ref("compensation_event", original.ID)) {
			return fault.NotFound
		}
		if _, ok := byID[original.ID]; !ok {
			return fault.Conflict
		}
		if m.BeforeRef != nil && m.BeforeRef.TermID != nil {
			if e = checkTerm(*m.BeforeRef.TermID); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) replay(ctx context.Context, q Request, a authz.Snapshot, employee, op string, digest []byte, line []authz.ObjectReference, cap string) (Result, bool, error) {
	prior, ok, e := s.Store.CompensationReceipt(ctx, a.OrgID, a.SubjectID, op, q.Key)
	if e != nil || !ok {
		return Result{}, ok, e
	}
	b, e := s.basis(ctx, a, employee)
	if e != nil {
		return Result{}, true, e
	}
	var out Result
	e = s.Store.WithCompensationTx(ctx, a.OrgID, func(tx Tx) error {
		current, e := s.guard(ctx, tx, q, a, employee, b)
		if e != nil {
			return e
		}
		if e = s.require(current, employee, line, cap); e != nil {
			return e
		}
		p, e := tx.CompensationProposal(ctx, a.OrgID, prior.Result.ID)
		if e != nil || p.EmployeeID != employee {
			return fault.NotFound
		}
		stored, found, e := tx.CompensationReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key)
		if e != nil {
			return e
		}
		if !found {
			return fault.Conflict
		}
		out, e = matchReceipt(stored, digest)
		if e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, current, employee, op, "allowed"))
	})
	if e != nil {
		return Result{}, true, s.denied(ctx, q, a, op, e)
	}
	return out, true, nil
}
func (s *Service) commit(ctx context.Context, q Request, a authz.Snapshot, employee, op, cap string, digest []byte, b readBasis, w Write, result Result, line []authz.ObjectReference, c ProposalCommand, prior *ProposalRecord, events []EventRecord) (Result, error) {
	var out Result
	e := s.Store.WithCompensationTx(ctx, a.OrgID, func(tx Tx) error {
		current, e := s.guard(ctx, tx, q, a, employee, b)
		if e != nil {
			return e
		}
		if e = s.require(current, employee, line, cap); e != nil {
			return e
		}
		stored, found, e := tx.CompensationReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key)
		if e != nil {
			return e
		}
		if found {
			out, e = matchReceipt(stored, digest)
			return e
		}
		aggregate, e := tx.CompensationAggregate(ctx, a.OrgID, employee)
		if e != nil {
			return e
		}
		if aggregate.Revision != b.Aggregate || aggregate.Revision != w.ExpectedCompRevision {
			return fault.Conflict
		}
		if prior != nil {
			p, e := tx.CompensationProposal(ctx, a.OrgID, prior.ID)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(p, *prior) {
				return fault.Conflict
			}
			if w.Approval != nil && p.AuthorSubjectID == current.SubjectID {
				return fault.Forbidden
			}
		}
		if w.Proposal.Status != "rejected" && w.Proposal.Status != "withdrawn" {
			if e = s.references(ctx, tx, current, employee, c); e != nil {
				return e
			}
		}
		if w.Approval != nil {
			locked, e := tx.CompensationEvents(ctx, a.OrgID, employee)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(locked, events) {
				return fault.Conflict
			}
			all := make([]EventRecord, 0, len(locked)+len(w.Events))
			all = append(all, locked...)
			all = append(all, w.Events...)
			projected, e := simulate(all)
			if e != nil {
				return e
			}
			for i := range projected {
				projected[i].Revision = w.Aggregate.Revision
			}
			if !reflect.DeepEqual(projected, w.Schedule) {
				return fault.Conflict
			}
		}
		if e = tx.CommitCompensation(ctx, w); e != nil {
			return e
		}
		out = result
		out.Proposal = nil
		if e = tx.SaveCompensationReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key, Receipt{Digest: digest, Result: out}); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, current, employee, op, "allowed"))
	})
	if e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	return out, nil
}
func revisionWrite(p ProposalRecord, actor string, c ProposalCommand, status string, n int64, id string, basis int64, at time.Time) (ProposalRecord, RevisionRecord) {
	p.Kind, p.Status, p.Revision, p.RevisionID, p.PayloadID, p.EffectiveDate, p.BeforeTermID, p.BasisRevision = c.Kind, status, n, id, id, c.EffectiveDate, c.BeforeTermID, basis
	v := RevisionRecord{OrgID: p.OrgID, EmployeeID: p.EmployeeID, ID: id, ProposalID: p.ID, PayloadID: id, Status: status, Kind: c.Kind, EffectiveDate: c.EffectiveDate, ActorSubjectID: actor, BeforeTermID: c.BeforeTermID, Revision: n, BasisRevision: basis, RecordedAt: at}
	return p, v
}
func (s *Service) CreateProposal(ctx context.Context, q Request, employee string, c ProposalCommand) (Result, error) {
	const op = "OP-COMP-03"
	a, e := s.employee(ctx, q, employee)
	if e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	if e = s.require(a, employee, nil, "compensation.propose"); e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	if e = validateCommand(s.Policy, c); e != nil {
		return Result{}, e
	}
	digest, e := s.digest(q, a, op, employee, c)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, employee, op, digest, nil, "compensation.propose"); ok || e != nil {
		return r, e
	}
	b, e := s.basis(ctx, a, employee)
	if e != nil {
		return Result{}, e
	}
	basis, _ := compRevision(c.CompRevision)
	if basis != b.Aggregate {
		return Result{}, fault.Conflict
	}
	if e = s.references(ctx, s.Store, a, employee, c); e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	id, version := value.NewID(), value.NewID()
	p := ProposalRecord{OrgID: a.OrgID, EmployeeID: employee, ID: id, AuthorSubjectID: a.SubjectID, RecordedAt: s.clock()}
	p, v := revisionWrite(p, a.SubjectID, c, "draft", 1, version, basis, p.RecordedAt)
	payload, e := s.seal(ctx, binding(a.OrgID, employee, id, version, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: c})
	if e != nil {
		return Result{}, e
	}
	w := Write{Aggregate: Aggregate{OrgID: a.OrgID, EmployeeID: employee, Revision: basis}, ExpectedCompRevision: basis, Proposal: p, Revision: v, Payloads: []Payload{payload}}
	result := Result{ID: id, Revision: "1", CompRevision: number(basis), Status: "draft", Members: []MemberMapping{}}
	return s.commit(ctx, q, a, employee, op, "compensation.propose", digest, b, w, result, nil, c, nil, nil)
}
func (s *Service) EditProposal(ctx context.Context, q Request, id string, cmd DraftCommand) (Result, error) {
	const op = "OP-COMP-04"
	a, p, e := s.objectProposal(ctx, q, id)
	if e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	line := []authz.ObjectReference{ref("compensation_proposal", id)}
	if e = s.require(a, p.EmployeeID, line, "compensation.propose"); e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	c := ProposalCommand{Kind: cmd.Kind, EffectiveDate: cmd.EffectiveDate, CompRevision: cmd.CompRevision, BeforeTermID: cmd.BeforeTermID, After: cmd.After, Reason: cmd.Reason, Members: cmd.Members}
	n, e := revision(cmd.Revision)
	if e != nil {
		return Result{}, e
	}
	if e = validateCommand(s.Policy, c); e != nil {
		return Result{}, e
	}
	digest, e := s.digest(q, a, op, id, cmd)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, p.EmployeeID, op, digest, line, "compensation.propose"); ok || e != nil {
		return r, e
	}
	b, e := s.basis(ctx, a, p.EmployeeID)
	if e != nil {
		return Result{}, e
	}
	basis, _ := compRevision(cmd.CompRevision)
	if p.Status != "draft" || p.Revision != n || basis != b.Aggregate {
		return Result{}, fault.Conflict
	}
	if e = s.references(ctx, s.Store, a, p.EmployeeID, c); e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	next, v := revisionWrite(p, a.SubjectID, c, "draft", n+1, value.NewID(), basis, s.clock())
	payload, e := s.seal(ctx, binding(a.OrgID, p.EmployeeID, id, v.ID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: c})
	if e != nil {
		return Result{}, e
	}
	w := Write{Aggregate: Aggregate{OrgID: a.OrgID, EmployeeID: p.EmployeeID, Revision: basis}, ExpectedCompRevision: basis, Proposal: next, ExpectedProposalRevision: n, Revision: v, Payloads: []Payload{payload}}
	result := Result{ID: id, Revision: number(n + 1), CompRevision: number(basis), Status: "draft", Members: []MemberMapping{}}
	return s.commit(ctx, q, a, p.EmployeeID, op, "compensation.propose", digest, b, w, result, line, c, &p, nil)
}
func (s *Service) TransitionProposal(ctx context.Context, q Request, id string, cmd TransitionCommand) (Result, error) {
	const op = "OP-COMP-05"
	a, p, e := s.objectProposal(ctx, q, id)
	if e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	line := []authz.ObjectReference{ref("compensation_proposal", id)}
	cap := "compensation.propose"
	if cmd.Action == "approve" || cmd.Action == "reject" {
		cap = "compensation.approve"
	}
	if e = s.require(a, p.EmployeeID, line, cap); e != nil {
		return Result{}, s.denied(ctx, q, a, op, e)
	}
	n, e := revision(cmd.Revision)
	if e != nil {
		return Result{}, e
	}
	basis, e := compRevision(cmd.CompRevision)
	if e != nil {
		return Result{}, e
	}
	if !safeText(cmd.DecisionReason, 4096, cmd.Action == "approve" || cmd.Action == "reject" || cmd.Action == "withdraw") {
		return Result{}, fault.Invalid
	}
	if cmd.Action != "submit" && cmd.Action != "approve" && cmd.Action != "reject" && cmd.Action != "withdraw" {
		return Result{}, fault.Invalid
	}
	if cmd.Action == "submit" && cmd.DecisionReason != "" {
		return Result{}, fault.Invalid
	}
	digest, e := s.digest(q, a, op, id, cmd)
	if e != nil {
		return Result{}, e
	}
	if r, ok, e := s.replay(ctx, q, a, p.EmployeeID, op, digest, line, cap); ok || e != nil {
		return r, e
	}
	if p.Revision != n || (cmd.Action == "submit" || cmd.Action == "approve") && p.BasisRevision != basis {
		return Result{}, fault.Conflict
	}
	status := ""
	switch cmd.Action {
	case "submit":
		if p.Status == "draft" {
			status = "submitted"
		}
	case "withdraw":
		if p.Status == "draft" || p.Status == "submitted" {
			status = "withdrawn"
		}
	case "approve":
		if p.Status == "submitted" {
			status = "approved"
		}
	case "reject":
		if p.Status == "submitted" {
			status = "rejected"
		}
	}
	if status == "" {
		return Result{}, fault.Conflict
	}
	if status == "approved" && p.AuthorSubjectID == a.SubjectID {
		return Result{}, s.denied(ctx, q, a, op, fault.Forbidden)
	}
	b, e := s.basis(ctx, a, p.EmployeeID)
	if e != nil {
		return Result{}, e
	}
	if basis != b.Aggregate {
		return Result{}, fault.Conflict
	}
	payload, e := s.loadCommand(ctx, p)
	if e != nil {
		return Result{}, e
	}
	c := payload.Command
	if status != "rejected" && status != "withdrawn" {
		if e = s.references(ctx, s.Store, a, p.EmployeeID, c); e != nil {
			return Result{}, s.denied(ctx, q, a, op, e)
		}
	}
	next, v := revisionWrite(p, a.SubjectID, c, status, n+1, value.NewID(), p.BasisRevision, s.clock())
	w := Write{Aggregate: Aggregate{OrgID: a.OrgID, EmployeeID: p.EmployeeID, Revision: basis}, ExpectedCompRevision: basis, Proposal: next, ExpectedProposalRevision: n, Revision: v}
	result := Result{ID: id, Revision: number(n + 1), CompRevision: number(basis), Status: status, Members: []MemberMapping{}}
	var events []EventRecord
	if status == "approved" {
		events, e = s.Store.CompensationEvents(ctx, a.OrgID, p.EmployeeID)
		if e != nil {
			return Result{}, e
		}
		if e = s.prepareApproval(ctx, a, p, c, cmd.DecisionReason, events, &w, &result); e != nil {
			return Result{}, e
		}
	}
	sealed, e := s.seal(ctx, binding(a.OrgID, p.EmployeeID, id, v.ID, "compensation_proposal", "compensation.proposal.v1"), proposalPayload{Command: c, DecisionReason: cmd.DecisionReason})
	if e != nil {
		return Result{}, e
	}
	w.Payloads = append(w.Payloads, sealed)
	return s.commit(ctx, q, a, p.EmployeeID, op, cap, digest, b, w, result, line, c, &p, events)
}
func (s *Service) prepareApproval(ctx context.Context, a authz.Snapshot, p ProposalRecord, c ProposalCommand, decision string, existing []EventRecord, w *Write, result *Result) error {
	var sequence int64
	for _, e := range existing {
		if e.Sequence > sequence {
			sequence = e.Sequence
		}
	}
	count := 1
	if c.Kind == "correction" {
		count = len(c.Members)
	}
	if sequence > math.MaxInt64-int64(count) || w.ExpectedCompRevision == math.MaxInt64 {
		return fault.Conflict
	}
	approvalID := value.NewID()
	w.Aggregate.Revision++
	w.ReplaceSchedule = true
	w.Proposal.ApprovalID = new(approvalID)
	w.Approval = &ApprovalRecord{OrgID: a.OrgID, EmployeeID: p.EmployeeID, ID: approvalID, ProposalID: p.ID, ProposalRevisionID: p.RevisionID, ApproverSubjectID: a.SubjectID, AuthorSubjectID: p.AuthorSubjectID, PayloadID: approvalID, ProposalRevision: p.Revision, BasisRevision: p.BasisRevision, CompRevision: w.Aggregate.Revision, RecordedAt: s.clock()}
	termInputs := make([]*Terms, 0, count)
	mapping := make(map[string]MemberMapping, count)
	if c.Kind == "correction" {
		for _, m := range c.Members {
			v := MemberMapping{MemberKey: m.MemberKey, EventID: value.NewID()}
			if m.Action == "replace" {
				v.TermID = new(value.NewID())
			}
			mapping[m.MemberKey] = v
		}
	}
	appendFact := func(kind, date, key string, before, after, corrects *string, eventID string, terms *Terms) {
		sequence++
		e := EventRecord{OrgID: a.OrgID, EmployeeID: p.EmployeeID, ID: eventID, ApprovalID: approvalID, Kind: kind, EffectiveDate: date, MemberKey: key, BeforeTermID: before, AfterTermID: after, CorrectsEventID: corrects, Sequence: sequence}
		w.Events = append(w.Events, e)
		if after != nil {
			t := TermRecord{OrgID: a.OrgID, EmployeeID: p.EmployeeID, ID: *after, EventID: eventID, ApprovalID: approvalID, PayloadID: *after, EffectiveDate: date, Version: sequence}
			w.Terms = append(w.Terms, t)
			termInputs = append(termInputs, terms)
		}
	}
	if c.Kind != "correction" {
		id, term := value.NewID(), new(value.NewID())
		appendFact(c.Kind, c.EffectiveDate, "", c.BeforeTermID, term, nil, id, c.After)
	} else {
		for _, m := range c.Members {
			v := mapping[m.MemberKey]
			var before *string
			if m.BeforeRef != nil {
				if m.BeforeRef.TermID != nil {
					before = m.BeforeRef.TermID
				} else {
					before = mapping[*m.BeforeRef.MemberKey].TermID
				}
			}
			kind := "correction_replacement"
			if m.Action == "reverse" {
				kind = "correction_reversal"
			}
			appendFact(kind, m.EffectiveDate, m.MemberKey, before, v.TermID, new(m.OriginalEventID), v.EventID, m.After)
			result.Members = append(result.Members, v)
		}
	}
	all := make([]EventRecord, 0, len(existing)+len(w.Events))
	all = append(all, existing...)
	all = append(all, w.Events...)
	projected, e := simulate(all)
	if e != nil {
		return e
	}
	w.Schedule = projected
	for i := range w.Events {
		event := &w.Events[i]
		if event.Kind != "correction_reversal" {
			continue
		}
		for _, segment := range projected {
			if segment.EffectiveDate > event.EffectiveDate {
				break
			}
			if segment.ValidTo == nil || event.EffectiveDate < *segment.ValidTo {
				event.AfterTermID = new(segment.TermID)
			}
		}
		for j := range result.Members {
			if result.Members[j].EventID == event.ID {
				result.Members[j].TermID = event.AfterTermID
				break
			}
		}
	}
	for i := range w.Schedule {
		w.Schedule[i].Revision = w.Aggregate.Revision
	}
	// Only a complete legal chain reaches external encryption.
	payload, e := s.seal(ctx, binding(a.OrgID, p.EmployeeID, approvalID, approvalID, "compensation_decision", "compensation.decision.v1"), decisionPayload{Reason: c.Reason, DecisionReason: decision})
	if e != nil {
		return e
	}
	w.Payloads = append(w.Payloads, payload)
	for i, t := range w.Terms {
		payload, e = s.seal(ctx, binding(a.OrgID, p.EmployeeID, t.ID, t.ID, "compensation_terms", "compensation.terms.v1"), termInputs[i])
		if e != nil {
			return e
		}
		w.Payloads = append(w.Payloads, payload)
	}
	result.CompRevision = number(w.Aggregate.Revision)
	return nil
}
