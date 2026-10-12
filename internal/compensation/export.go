package compensation

import (
	"context"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"reflect"
	"sort"
	"time"
)

const exportOperation = "OP-SEC-05"
const exportByteLimit = 8 * 1024 * 1024

type exportEnvelope struct {
	Kind     string                 `json:"kind"`
	ExportID string                 `json:"export_id"`
	Status   string                 `json:"status"`
	Reason   string                 `json:"reason,omitempty"`
	Proposal *ProposalView          `json:"compensation_proposal,omitempty"`
	Event    *ApprovalEventView     `json:"compensation_event,omitempty"`
	Term     *TermView              `json:"compensation_term,omitempty"`
	Approval *exportApprovalContext `json:"approval,omitempty"`
}
type exportApprovalContext struct {
	ID                string `json:"id"`
	ApproverSubjectID string `json:"approver_subject_id"`
	ApprovedAt        string `json:"approved_at"`
	Reason            string `json:"reason,omitempty"`
	DecisionReason    string `json:"decision_reason,omitempty"`
}
type exportRecord struct {
	Object             ExportObject
	Employee, Revision string
	Proposal           *ProposalRecord
	Event              *EventRecord
	Term               *TermRecord
	Snapshot           authz.Snapshot
	Basis              readBasis
	Encoded            []byte
	Hints              []Permission
	VisibleTerms       [2]string
	// BroadRead records that encoded event group fields (member key and shared
	// approval reasons) were authorized by employee-wide compensation.read.
	BroadRead bool
}

func encodeExport(v exportEnvelope) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, fault.Unavailable
	}
	return append(b, '\n'), nil
}
func (s *Service) exportPermission(a authz.Snapshot, r exportRecord) error {
	return s.require(a, r.Employee, []authz.ObjectReference{ref(r.Object.Kind, r.Object.ID)}, "sensitive.export")
}
func (s *Service) validateExport(ctx context.Context, tx Tx, a authz.Snapshot, r exportRecord) error {
	if e := s.exportPermission(a, r); e != nil {
		return e
	}
	for _, hint := range r.Hints {
		if !s.allows(a, hint.Capability, r.Employee, ref(r.Object.Kind, r.Object.ID)) {
			return fault.Forbidden
		}
	}
	if r.BroadRead && !s.allows(a, "compensation.read", r.Employee) {
		return fault.Forbidden
	}
	for _, id := range r.VisibleTerms {
		if id != "" {
			if e := s.require(a, r.Employee, []authz.ObjectReference{ref("compensation_term", id)}, "sensitive.export"); e != nil {
				return e
			}
		}
	}
	switch r.Object.Kind {
	case "compensation_proposal":
		p, e := tx.CompensationProposal(ctx, a.OrgID, r.Object.ID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(p, *r.Proposal) {
			return fault.Conflict
		}
	case "compensation_event":
		v, e := tx.CompensationEvent(ctx, a.OrgID, r.Object.ID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(v, *r.Event) {
			return fault.Conflict
		}
	case "compensation_term":
		v, e := tx.CompensationTerm(ctx, a.OrgID, r.Object.ID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(v, *r.Term) {
			return fault.Conflict
		}
	default:
		return fault.Invalid
	}
	return nil
}

// exportGuard takes every owner lock in one canonical order, then checks every
// exact object. It performs no encryption or decryption inside the transaction.
func (s *Service) exportGuard(ctx context.Context, tx Tx, q Request, a authz.Snapshot, records []exportRecord) error {
	if e := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); e != nil {
		return e
	}
	employees := make([]string, 0, len(records))
	seen := map[string]bool{}
	for _, r := range records {
		if !seen[r.Employee] {
			employees = append(employees, r.Employee)
			seen[r.Employee] = true
		}
	}
	sort.Strings(employees)
	for _, employee := range employees {
		if e := tx.LockCompensationEmployee(ctx, a.OrgID, employee); e != nil {
			return e
		}
	}
	graph, e := tx.GraphState(ctx, a.OrgID)
	if e != nil {
		return e
	}
	for _, r := range records {
		current, e := s.session(ctx, tx, q, a.OrgID, r.Employee)
		if e != nil {
			return e
		}
		old := r.Snapshot
		if current.OrgID != old.OrgID || current.SubjectID != old.SubjectID || current.AuthEpoch != old.AuthEpoch || current.SubjectEpoch != old.SubjectEpoch || current.SessionEpoch != old.SessionEpoch || current.Timezone != old.Timezone {
			return fault.Forbidden
		}
		day, e := businessDay(current, s.clock())
		if e != nil {
			return e
		}
		aggregate, e := tx.CompensationAggregate(ctx, a.OrgID, r.Employee)
		if e != nil {
			return e
		}
		if graph.Revision != r.Basis.Graph || day != r.Basis.Day || aggregate.Revision != r.Basis.Aggregate {
			return fault.Conflict
		}
		if e = s.validateExport(ctx, tx, current, r); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) exportPartial(ctx context.Context, q Request, a authz.Snapshot, id, reason string, cause error, emit func(ExportEvent) error) error {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	e := s.Store.WithCompensationTx(auditCtx, a.OrgID, func(tx Tx) error { return tx.Audit(auditCtx, s.audit(q, a, "", exportOperation, "partial")) })
	b, encodingErr := encodeExport(exportEnvelope{Kind: "partial", ExportID: id, Status: "partial", Reason: reason})
	if encodingErr == nil {
		defer clear(b)
		_ = emit(ExportEvent{EncodedJSON: b})
	}
	if e != nil {
		return fault.AuditUnavailable
	}
	if cause == nil {
		return fault.Unavailable
	}
	return cause
}
func (s *Service) Export(ctx context.Context, q Request, cmd ExportCommand, emit func(ExportEvent) error) (string, error) {
	a, e := s.session(ctx, s.Store, q, "", "")
	if e != nil {
		return "", s.denied(ctx, q, a, exportOperation, e)
	}
	if emit == nil || cmd.Format != "ndjson" || len(cmd.Objects) < 1 || len(cmd.Objects) > 100 || !value.ValidID(q.Key) {
		return "", fault.Invalid
	}
	seen := map[authz.ObjectReference]bool{}
	records := make([]exportRecord, 0, len(cmd.Objects))
	// Authorize the complete requested set before the first financial decrypt.
	for _, object := range cmd.Objects {
		if object.Kind != "compensation_proposal" && object.Kind != "compensation_event" && object.Kind != "compensation_term" {
			return "", fault.Invalid
		}
		if !value.ValidID(object.ID) {
			return "", fault.Invalid
		}
		if _, ok := value.Revision(object.ExpectedRevision); !ok {
			return "", fault.Invalid
		}
		target := ref(object.Kind, object.ID)
		if seen[target] {
			return "", fault.Invalid
		}
		seen[target] = true
		r := exportRecord{Object: object}
		switch object.Kind {
		case "compensation_proposal":
			p, err := s.Store.CompensationProposal(ctx, a.OrgID, object.ID)
			if err != nil {
				return "", s.denied(ctx, q, a, exportOperation, err)
			}
			r.Proposal, r.Employee, r.Revision = &p, p.EmployeeID, number(p.Revision)
		case "compensation_event":
			v, err := s.Store.CompensationEvent(ctx, a.OrgID, object.ID)
			if err != nil {
				return "", s.denied(ctx, q, a, exportOperation, err)
			}
			r.Event, r.Employee, r.Revision = &v, v.EmployeeID, number(v.Sequence)
		case "compensation_term":
			v, err := s.Store.CompensationTerm(ctx, a.OrgID, object.ID)
			if err != nil {
				return "", s.denied(ctx, q, a, exportOperation, err)
			}
			r.Term, r.Employee, r.Revision = &v, v.EmployeeID, number(v.Version)
		}
		r.Snapshot, e = s.session(ctx, s.Store, q, a.OrgID, r.Employee)
		if e != nil {
			return "", s.denied(ctx, q, a, exportOperation, e)
		}
		if e = s.exportPermission(r.Snapshot, r); e != nil {
			return "", s.denied(ctx, q, a, exportOperation, e)
		}
		r.Basis, e = s.basis(ctx, r.Snapshot, r.Employee)
		if e != nil {
			return "", e
		}
		records = append(records, r)
	}
	digest, e := s.digest(q, a, exportOperation, "financial", cmd)
	if e != nil {
		return "", e
	}
	stored, replayed, e := s.Store.CompensationReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key)
	if e != nil {
		return "", e
	}
	exportID := value.NewID()
	if replayed {
		safe, e := matchReceipt(stored, digest)
		if e != nil {
			return "", e
		}
		if !value.ValidID(safe.ID) {
			return "", fault.Unavailable
		}
		exportID = safe.ID
	}
	for _, r := range records {
		if r.Revision != r.Object.ExpectedRevision {
			return "", fault.Conflict
		}
	}
	header, e := encodeExport(exportEnvelope{Kind: "header", ExportID: exportID, Status: "prepared"})
	if e != nil {
		return "", e
	}
	defer clear(header)
	complete, e := encodeExport(exportEnvelope{Kind: "complete", ExportID: exportID, Status: "complete"})
	if e != nil {
		return "", e
	}
	defer clear(complete)
	partial, e := encodeExport(exportEnvelope{Kind: "partial", ExportID: exportID, Status: "partial", Reason: "RELEASE_DENIED"})
	if e != nil {
		return "", e
	}
	budget := len(header) + len(complete) + len(partial)
	clear(partial)
	defer func() {
		for i := range records {
			clear(records[i].Encoded)
		}
	}()
	for i := range records {
		r := &records[i]
		envelope := exportEnvelope{Kind: "object", ExportID: exportID, Status: "prepared"}
		if e = s.exportPermission(r.Snapshot, *r); e != nil {
			return "", s.denied(ctx, q, a, exportOperation, e)
		}
		switch r.Object.Kind {
		case "compensation_proposal":
			v, err := s.projectProposal(ctx, r.Snapshot, *r.Proposal)
			if err != nil {
				return "", err
			}
			envelope.Proposal = &v
			r.Hints = v.Permissions
		case "compensation_term":
			v, err := s.projectTerm(ctx, *r.Term)
			if err != nil {
				return "", err
			}
			envelope.Term = &v
		case "compensation_event":
			v, err := s.projectEvent(ctx, r.Snapshot, *r.Event, true)
			if err != nil {
				return "", err
			}
			envelope.Event = &v
			if v.Before != nil {
				r.VisibleTerms[0] = v.Before.ID
			}
			if v.After != nil {
				r.VisibleTerms[1] = v.After.ID
			}
			approval, err := s.Store.CompensationApproval(ctx, a.OrgID, r.Event.ApprovalID)
			if err != nil || approval.EmployeeID != r.Employee {
				return "", fault.Unavailable
			}
			var decision decisionPayload
			if r.BroadRead = s.allows(r.Snapshot, "compensation.read", r.Employee); r.BroadRead {
				err = s.open(ctx, s.Store, a.OrgID, approval.PayloadID, binding(a.OrgID, r.Employee, approval.ID, approval.ID, "compensation_decision", "compensation.decision.v1"), &decision)
				if err != nil {
					return "", err
				}
			}
			envelope.Approval = &exportApprovalContext{ID: approval.ID, ApproverSubjectID: approval.ApproverSubjectID, ApprovedAt: approval.RecordedAt.UTC().Format(time.RFC3339Nano), Reason: decision.Reason, DecisionReason: decision.DecisionReason}
		}
		r.Encoded, e = encodeExport(envelope)
		if e != nil {
			return "", e
		}
		budget += len(r.Encoded)
		if budget > exportByteLimit {
			return "", fault.Invalid
		}
	}
	// Prepare receipt/audit atomically before the first output byte. A concurrent
	// original-key request may have prepared first: don't substitute its ID into
	// already budgeted bytes; conflict asks the client to replay the exact request.
	e = s.Store.WithCompensationTx(ctx, a.OrgID, func(tx Tx) error {
		if e := s.exportGuard(ctx, tx, q, a, records); e != nil {
			return e
		}
		prior, found, e := tx.CompensationReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key)
		if e != nil {
			return e
		}
		if found {
			result, e := matchReceipt(prior, digest)
			if e != nil {
				return e
			}
			if result.ID != exportID {
				return fault.Conflict
			}
		} else {
			if replayed {
				return fault.Conflict
			}
			if e = tx.SaveCompensationReceipt(ctx, a.OrgID, a.SubjectID, exportOperation, q.Key, Receipt{Digest: digest, Result: Result{ID: exportID, Status: "prepared", Members: []MemberMapping{}}}); e != nil {
				return e
			}
		}
		return tx.Audit(ctx, s.audit(q, a, "", exportOperation, "allowed"))
	})
	if e != nil {
		return "", s.denied(ctx, q, a, exportOperation, e)
	}
	if e = emit(ExportEvent{EncodedJSON: header}); e != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", fault.Unavailable, emit)
	}
	for _, r := range records {
		e = s.release(ctx, q, r.Snapshot, r.Employee, exportOperation, r.Basis, func(tx Tx, current authz.Snapshot) error { return s.validateExport(ctx, tx, current, r) })
		if e != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, "RELEASE_DENIED", e, emit)
		}
		if e = emit(ExportEvent{EncodedJSON: r.Encoded}); e != nil {
			return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", fault.Unavailable, emit)
		}
	}
	e = s.Store.WithCompensationTx(ctx, a.OrgID, func(tx Tx) error {
		if e := s.exportGuard(ctx, tx, q, a, records); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, a, "", exportOperation, "allowed"))
	})
	if e != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, "RELEASE_DENIED", e, emit)
	}
	if e = emit(ExportEvent{EncodedJSON: complete}); e != nil {
		return exportID, s.exportPartial(ctx, q, a, exportID, "WRITE_FAILED", fault.Unavailable, emit)
	}
	return exportID, nil
}
