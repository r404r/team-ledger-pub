package compensation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"io"
	"math"
	"strconv"
	"time"
)

const purpose = "compensation_management"

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
func number(n int64) string { return strconv.FormatInt(n, 10) }
func revision(v string) (int64, error) {
	n, ok := value.Revision(v)
	if !ok || n == math.MaxInt64 {
		return 0, fault.Invalid
	}
	return n, nil
}
func compRevision(v string) (int64, error) {
	if v == "0" {
		return 0, nil
	}
	return revision(v)
}
func businessDay(a authz.Snapshot, now time.Time) (string, error) {
	l, e := time.LoadLocation(a.Timezone)
	if e != nil || a.Timezone == "" {
		return "", fault.Unavailable
	}
	return now.In(l).Format("2006-01-02"), nil
}
func ref(kind, id string) authz.ObjectReference { return authz.ObjectReference{Kind: kind, ID: id} }
func (s *Service) session(ctx context.Context, r Reader, q Request, org, employee string) (authz.Snapshot, error) {
	if s == nil || r == nil || len(q.TokenHash) != 32 {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	a, e := r.Security(ctx, q.TokenHash, org, employee)
	if e != nil {
		return a, e
	}
	if !a.Valid(s.clock()) {
		return a, fault.Unauthenticated
	}
	if q.Purpose != purpose {
		return a, fault.Forbidden
	}
	if !s.Policy.Enabled || s.Policy.Validate() != nil {
		return a, fault.NotFound
	}
	return a, nil
}
func (s *Service) employee(ctx context.Context, q Request, id string) (authz.Snapshot, error) {
	if !value.ValidID(id) {
		return authz.Snapshot{}, fault.Invalid
	}
	a, e := s.session(ctx, s.Store, q, "", id)
	if e != nil {
		return a, e
	}
	emp, e := s.Store.Employee(ctx, id)
	if e != nil || emp.OrgID != a.OrgID {
		return a, fault.NotFound
	}
	return a, nil
}
func (s *Service) allows(a authz.Snapshot, cap, employee string, line ...authz.ObjectReference) bool {
	if len(line) == 0 {
		return a.Allows(cap, "financial", employee, purpose, s.clock())
	}
	return a.AllowsObject(cap, "financial", employee, purpose, s.clock(), line...)
}
func (s *Service) require(a authz.Snapshot, employee string, line []authz.ObjectReference, caps ...string) error {
	if !s.allows(a, "compensation.read", employee, line...) {
		return fault.NotFound
	}
	for _, c := range caps {
		if !s.allows(a, c, employee, line...) {
			return fault.Forbidden
		}
	}
	return nil
}
func (s *Service) audit(q Request, a authz.Snapshot, employee, op, outcome string) organization.Audit {
	return organization.Audit{ID: value.NewID(), OrgID: a.OrgID, SubjectID: a.SubjectID, EmployeeID: employee, Operation: op, Purpose: q.Purpose, RequestID: q.RequestID, Outcome: outcome, At: s.clock()}
}
func (s *Service) denied(ctx context.Context, q Request, a authz.Snapshot, op string, e error) error {
	if e != nil && a.OrgID != "" && (errors.Is(e, fault.NotFound) || errors.Is(e, fault.Forbidden) || errors.Is(e, fault.Unauthenticated)) {
		if err := s.Store.AuditDenied(ctx, s.audit(q, a, "", op, "denied")); err != nil {
			return err
		}
	}
	return e
}
func binding(org, employee, record, version, kind, schema string) sensitive.Context {
	return sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: record, VersionID: version, ObjectKind: kind, Purpose: "financial", SchemaType: schema, SchemaVersion: 1}
}
func (s *Service) seal(ctx context.Context, b sensitive.Context, v any) (Payload, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 16384 {
		clear(raw)
		return Payload{}, fault.Invalid
	}
	defer clear(raw)
	env, e := s.Cipher.Seal(ctx, b, raw)
	if e != nil {
		return Payload{}, fault.Unavailable
	}
	return Payload{ID: b.VersionID, Envelope: env, RecordedAt: s.clock()}, nil
}
func (s *Service) open(ctx context.Context, r Reader, org, id string, b sensitive.Context, v any) error {
	p, e := r.CompensationPayload(ctx, org, id)
	if e != nil {
		return e
	}
	raw, e := s.Cipher.Open(ctx, b, p.Envelope)
	if e != nil {
		return fault.Unavailable
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(v); e != nil {
		return fault.Unavailable
	}
	if e = decoder.Decode(new(any)); e != io.EOF {
		return fault.Unavailable
	}
	return nil
}

type proposalPayload struct {
	Command        ProposalCommand `json:"command"`
	DecisionReason string          `json:"decision_reason"`
}
type decisionPayload struct {
	Reason         string `json:"reason"`
	DecisionReason string `json:"decision_reason"`
}

func equalString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func (s *Service) loadCommand(ctx context.Context, p ProposalRecord) (proposalPayload, error) {
	var out proposalPayload
	e := s.open(ctx, s.Store, p.OrgID, p.PayloadID, binding(p.OrgID, p.EmployeeID, p.ID, p.RevisionID, "compensation_proposal", "compensation.proposal.v1"), &out)
	if e == nil {
		e = validateCommand(s.Policy, out.Command)
	}
	if e == nil && (out.Command.Kind != p.Kind || out.Command.EffectiveDate != p.EffectiveDate || out.Command.CompRevision != number(p.BasisRevision) || !equalString(out.Command.BeforeTermID, p.BeforeTermID)) {
		e = fault.Unavailable
	}
	return out, e
}
func (s *Service) digest(q Request, a authz.Snapshot, op, target string, cmd any) ([]byte, error) {
	if len(s.DigestKey) < 32 || !value.ValidID(q.Key) {
		return nil, fault.Invalid
	}
	raw, e := json.Marshal(struct {
		Org, Subject, Operation, Target, Purpose string
		Command                                  any
	}{a.OrgID, a.SubjectID, op, target, q.Purpose, cmd})
	if e != nil {
		return nil, fault.Invalid
	}
	defer clear(raw)
	h := hmac.New(sha256.New, s.DigestKey)
	h.Write(raw)
	return h.Sum(nil), nil
}
func matchReceipt(r Receipt, d []byte) (Result, error) {
	if !hmac.Equal(r.Digest, d) {
		return Result{}, fault.Mismatch
	}
	r.Result.Proposal = nil
	return r.Result, nil
}

type readBasis struct {
	Graph     int64
	Day       string
	Aggregate int64
}

func (s *Service) basis(ctx context.Context, a authz.Snapshot, employee string) (readBasis, error) {
	d, e := businessDay(a, s.clock())
	if e != nil {
		return readBasis{}, e
	}
	g, e := s.Store.GraphState(ctx, a.OrgID)
	if e != nil {
		return readBasis{}, e
	}
	b, e := s.Store.CompensationAggregate(ctx, a.OrgID, employee)
	return readBasis{Graph: g.Revision, Day: d, Aggregate: b.Revision}, e
}
func (s *Service) guard(ctx context.Context, tx Tx, q Request, a authz.Snapshot, employee string, b readBasis) (authz.Snapshot, error) {
	if e := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); e != nil {
		return a, e
	}
	if e := tx.LockCompensationEmployee(ctx, a.OrgID, employee); e != nil {
		return a, e
	}
	current, e := s.session(ctx, tx, q, a.OrgID, employee)
	if e != nil {
		return current, e
	}
	if current.OrgID != a.OrgID || current.SubjectID != a.SubjectID || current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch || current.SessionEpoch != a.SessionEpoch || current.Timezone != a.Timezone {
		return current, fault.Forbidden
	}
	d, e := businessDay(current, s.clock())
	if e != nil {
		return current, e
	}
	g, e := tx.GraphState(ctx, a.OrgID)
	if e != nil {
		return current, e
	}
	if d != b.Day || g.Revision != b.Graph {
		return current, fault.Conflict
	}
	return current, nil
}
func (s *Service) release(ctx context.Context, q Request, a authz.Snapshot, employee, op string, b readBasis, validate func(Tx, authz.Snapshot) error) error {
	return s.Store.WithCompensationTx(ctx, a.OrgID, func(tx Tx) error {
		current, e := s.guard(ctx, tx, q, a, employee, b)
		if e != nil {
			return e
		}
		aggregate, e := tx.CompensationAggregate(ctx, a.OrgID, employee)
		if e != nil {
			return e
		}
		if aggregate.Revision != b.Aggregate {
			return fault.Conflict
		}
		if e = validate(tx, current); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, current, employee, op, "allowed"))
	})
}
func (s *Service) authorizationUntil(a authz.Snapshot) string {
	until := a.ExpiresAt
	if a.IdleExpiresAt.Before(until) {
		until = a.IdleExpiresAt
	}
	if a.MFAUntil.Before(until) {
		until = a.MFAUntil
	}
	for _, g := range a.Grants {
		if g.Category == "financial" && !g.Revoked && !s.clock().Before(g.ValidFrom) && s.clock().Before(g.ExpiresAt) && g.ExpiresAt.Before(until) {
			until = g.ExpiresAt
		}
	}
	if l, e := time.LoadLocation(a.Timezone); e == nil {
		now := s.clock().In(l)
		midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, l)
		if midnight.Before(until) {
			until = midnight
		}
	}
	return until.UTC().Format(time.RFC3339Nano)
}
