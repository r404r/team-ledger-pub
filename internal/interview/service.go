package interview

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Service struct {
	Store                Store
	Cipher               sensitive.Cipher
	DigestKey, CursorKey []byte
	CommandMAC           func([]byte) ([]byte, error)
	CursorMAC            func([]byte) ([]byte, error)
	Now                  func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
func (s *Service) session(ctx context.Context, r Reader, q Request, org, employee string) (authz.Snapshot, error) {
	if r == nil || len(q.TokenHash) != 32 {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	a, e := r.Security(ctx, q.TokenHash, org, employee)
	if e != nil {
		return a, e
	}
	if !a.Valid(s.clock()) {
		return a, fault.Unauthenticated
	}
	if q.Purpose != "interview_followup" {
		return a, fault.Forbidden
	}
	return a, nil
}
func day(a authz.Snapshot, now time.Time) (string, error) {
	l, e := time.LoadLocation(a.Timezone)
	if e != nil || a.Timezone == "" {
		return "", fault.Unavailable
	}
	return now.In(l).Format("2006-01-02"), nil
}
func ref(kind, id string) authz.ObjectReference { return authz.ObjectReference{Kind: kind, ID: id} }
func interviewLine(i Record) []authz.ObjectReference {
	return []authz.ObjectReference{ref("interview", i.ID)}
}
func headLine(h Head) []authz.ObjectReference {
	return []authz.ObjectReference{ref("interview", h.InterviewID), ref("note_head", h.ID)}
}
func versionLine(v Version) []authz.ObjectReference {
	return []authz.ObjectReference{ref("interview", v.InterviewID), ref("note_head", v.HeadID), ref("note_version", v.ID)}
}
func actionLine(a ActionRecord) []authz.ObjectReference {
	return []authz.ObjectReference{ref("interview", a.InterviewID), ref("action_item", a.ID)}
}
func (s *Service) allows(a authz.Snapshot, cap, cat, employee string, line []authz.ObjectReference) bool {
	if len(line) == 0 {
		return a.Allows(cap, cat, employee, "interview_followup", s.clock())
	}
	return a.AllowsObject(cap, cat, employee, "interview_followup", s.clock(), line...)
}
func (s *Service) require(a authz.Snapshot, employee, cat string, line []authz.ObjectReference, caps ...string) error {
	for _, c := range caps {
		if !s.allows(a, c, cat, employee, line) {
			return fault.NotFound
		}
	}
	return nil
}
func (s *Service) requireInterviewCreate(a authz.Snapshot, employee string, line []authz.ObjectReference) error {
	if !s.allows(a, "interview.read", "metadata", employee, line) {
		return fault.NotFound
	}
	if s.allows(a, "interview.write", "metadata", employee, line) || a.StaffDefaultCanCreateInterview(employee, s.clock()) {
		return nil
	}
	return fault.NotFound
}

func category(c string) bool {
	return c == "shared" || c == "manager_private" || c == "hr_confidential"
}
func text(t string, max int, required bool) bool {
	return utf8.ValidString(t) && len(t) <= max && (!required || strings.TrimSpace(t) != "")
}
func revision(v string, zero bool) (int64, error) {
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 0 || (!zero && n == 0) || strconv.FormatInt(n, 10) != v || n == math.MaxInt64 {
		return 0, fault.Invalid
	}
	return n, nil
}
func number(n int64) string { return strconv.FormatInt(n, 10) }
func timestamp(v string) (time.Time, error) {
	if !strings.HasSuffix(v, "Z") || strings.Contains(v, ",") {
		return time.Time{}, fault.Invalid
	}
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil || t.Year() < 1 || t.Nanosecond()%1000 != 0 {
		return time.Time{}, fault.Invalid
	}
	if p := strings.IndexByte(v, '.'); p >= 0 && len(v)-p-2 > 6 {
		return time.Time{}, fault.Invalid
	}
	return t.UTC(), nil
}
func actual(v *string, now time.Time) (*time.Time, error) {
	if v == nil {
		return nil, nil
	}
	t, e := timestamp(*v)
	if e != nil || t.After(now) {
		return nil, fault.Invalid
	}
	return &t, nil
}
func (s *Service) audit(q Request, a authz.Snapshot, employee, op, outcome string) organization.Audit {
	return organization.Audit{ID: value.NewID(), OrgID: a.OrgID, SubjectID: a.SubjectID, EmployeeID: employee, Operation: op, Purpose: q.Purpose, RequestID: q.RequestID, Outcome: outcome, At: s.clock()}
}
func (s *Service) denied(ctx context.Context, q Request, a authz.Snapshot, op string, e error) error {
	if e == nil {
		return nil
	}
	if a.OrgID != "" && (errors.Is(e, fault.NotFound) || errors.Is(e, fault.Forbidden) || errors.Is(e, fault.Unauthenticated)) {
		if err := s.Store.AuditDenied(ctx, s.audit(q, a, "", op, "denied")); err != nil {
			return err
		}
	}
	return e
}
func (s *Service) digest(q Request, a authz.Snapshot, op, id string, cmd any) ([]byte, error) {
	if !value.ValidID(q.Key) {
		return nil, fault.Invalid
	}
	b, e := json.Marshal(struct {
		Org, Subject, Operation, Target, Purpose string
		Command                                  any
	}{a.OrgID, a.SubjectID, op, id, q.Purpose, cmd})
	if e != nil {
		return nil, fault.Invalid
	}
	defer clear(b)
	if s.CommandMAC != nil {
		return s.CommandMAC(b)
	}
	if len(s.DigestKey) < 32 {
		return nil, fault.Invalid
	}
	h := hmac.New(sha256.New, s.DigestKey)
	h.Write(b)
	return h.Sum(nil), nil
}
func receiptMatch(r Receipt, d []byte) (Result, error) {
	if !hmac.Equal(r.Digest, d) {
		return Result{}, fault.Mismatch
	}
	return r.Result, nil
}
func (s *Service) replay(ctx context.Context, q Request, a authz.Snapshot, op string, d []byte) (Result, bool, error) {
	previous, found, e := s.Store.InterviewReceipt(ctx, a.OrgID, a.SubjectID, op, q.Key)
	if e != nil || !found {
		return Result{}, found, e
	}
	var result Result
	e = s.Store.WithInterviewTx(ctx, a.OrgID, func(tx Tx) error {
		if e := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); e != nil {
			return e
		}
		var employee, cat string
		var line []authz.ObjectReference
		var caps []string
		create := false
		switch op {
		case "OP-INT-02", "OP-INT-03":
			i, e := tx.Interview(ctx, a.OrgID, previous.Result.ID)
			if e != nil {
				return e
			}
			employee = i.EmployeeID
			cat = "metadata"
			line = interviewLine(i)
			caps = []string{"interview.read", "interview.write"}
			create = op == "OP-INT-02"
		case "OP-INT-05":
			v, e := tx.InterviewVersion(ctx, a.OrgID, previous.Result.ID)
			if e != nil {
				return e
			}
			employee = v.EmployeeID
			cat = v.Category
			line = []authz.ObjectReference{ref("interview", v.InterviewID), ref("note_head", v.HeadID)}
			caps = []string{"note.read", "note.write"}
			if previous.Result.Status == "published" {
				caps = append(caps, "note.publish")
			}
		case "OP-INT-07", "OP-INT-08":
			item, e := tx.InterviewAction(ctx, a.OrgID, previous.Result.ID)
			if e != nil {
				return e
			}
			employee = item.EmployeeID
			cat = "shared"
			line = actionLine(item)
			caps = []string{"action.read", "action.write"}
		default:
			return fault.Invalid
		}
		if e := tx.LockInterviewEmployee(ctx, a.OrgID, employee); e != nil {
			return e
		}
		current, e := s.session(ctx, tx, q, a.OrgID, employee)
		if e != nil {
			return e
		}
		if create {
			e = s.requireInterviewCreate(current, employee, line)
		} else {
			e = s.require(current, employee, cat, line, caps...)
		}
		if e != nil {
			return e
		}
		oldDay, e := day(a, s.clock())
		if e != nil {
			return e
		}
		currentDay, e := day(current, s.clock())
		if e != nil {
			return e
		}
		if current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch || oldDay != currentDay {
			return fault.Forbidden
		}
		receipt, ok, e := tx.InterviewReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key)
		if e != nil {
			return e
		}
		if !ok {
			return fault.Conflict
		}
		result, e = receiptMatch(receipt, d)
		return e
	})
	return result, true, s.denied(ctx, q, a, op, e)
}
func (s *Service) commit(ctx context.Context, q Request, a authz.Snapshot, employee, op string, d []byte, w Write, result Result, validate func(Tx, authz.Snapshot) error) (Result, error) {
	var out Result
	subjects := []string{a.SubjectID}
	if w.Interview != nil {
		for _, p := range w.Interview.Participants {
			if p.Kind == "subject" {
				subjects = append(subjects, p.ID)
			}
		}
	}
	if w.Action != nil && w.Action.Owner.Kind == "subject" {
		subjects = append(subjects, w.Action.Owner.ID)
	}
	e := s.Store.WithInterviewTx(ctx, a.OrgID, func(tx Tx) error {
		if e := tx.LockSubjects(ctx, a.OrgID, subjects); e != nil {
			return e
		}
		if e := tx.LockInterviewEmployee(ctx, a.OrgID, employee); e != nil {
			return e
		}
		current, e := s.session(ctx, tx, q, a.OrgID, employee)
		if e != nil {
			return e
		}
		if e = validate(tx, current); e != nil {
			return e
		}
		r, ok, e := tx.InterviewReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key)
		if e != nil {
			return e
		}
		if ok {
			out, e = receiptMatch(r, d)
			return e
		}
		if current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch {
			return fault.Forbidden
		}
		if e = tx.CommitInterview(ctx, w); e != nil {
			return e
		}
		out = result
		if e = tx.SaveInterviewReceipt(ctx, a.OrgID, current.SubjectID, op, q.Key, Receipt{Digest: d, Result: out}); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(q, current, employee, op, "allowed"))
	})
	return out, s.denied(ctx, q, a, op, e)
}
func binding(org, employee, record, version, kind, schema string) sensitive.Context {
	return sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: record, VersionID: version, ObjectKind: kind, Purpose: "interview", SchemaType: schema, SchemaVersion: 1}
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
	p, e := r.InterviewPayload(ctx, org, id)
	if e != nil {
		return e
	}
	raw, e := s.Cipher.Open(ctx, b, p.Envelope)
	if e != nil {
		return fault.Unavailable
	}
	defer clear(raw)
	if e = json.Unmarshal(raw, v); e != nil {
		return fault.Unavailable
	}
	return nil
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
func (s *Service) objectInterview(ctx context.Context, q Request, id string) (authz.Snapshot, Record, error) {
	a, e := s.session(ctx, s.Store, q, "", "")
	if e != nil {
		return a, Record{}, e
	}
	if !value.ValidID(id) {
		return a, Record{}, fault.Invalid
	}
	i, e := s.Store.Interview(ctx, a.OrgID, id)
	if e != nil {
		return a, i, e
	}
	a, e = s.session(ctx, s.Store, q, a.OrgID, i.EmployeeID)
	return a, i, e
}

type cursor struct {
	Org, Subject, Day, Query, Last string
	Auth, SubjectEpoch, Graph      int64
}

func (s *Service) cursorDigest(raw []byte) ([]byte, error) {
	if s.CursorMAC != nil {
		frame := append([]byte("TEAMLEDGER-INTERVIEW-CURSOR\x00V1\x00"), raw...)
		defer clear(frame)
		return s.CursorMAC(frame)
	}
	if len(s.CursorKey) < 32 {
		return nil, fault.Unavailable
	}
	h := hmac.New(sha256.New, s.CursorKey)
	h.Write(raw)
	return h.Sum(nil), nil
}

func (s *Service) cursor(ctx context.Context, a authz.Snapshot, query, token string) (cursor, error) {
	d, e := day(a, s.clock())
	if e != nil {
		return cursor{}, e
	}
	g, e := s.Store.GraphState(ctx, a.OrgID)
	if e != nil {
		return cursor{}, e
	}
	base := cursor{Org: a.OrgID, Subject: a.SubjectID, Day: d, Query: query, Auth: a.AuthEpoch, SubjectEpoch: a.SubjectEpoch, Graph: g.Revision}
	if token == "" {
		return base, nil
	}
	if len(token) > 4096 || s.CursorMAC == nil && len(s.CursorKey) < 32 {
		return base, fault.Invalid
	}
	b, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(b) <= 32 {
		return base, fault.Invalid
	}
	raw, mac := b[:len(b)-32], b[len(b)-32:]
	expected, macErr := s.cursorDigest(raw)
	if macErr != nil || !hmac.Equal(mac, expected) {
		return base, fault.Invalid
	}
	var old cursor
	if json.Unmarshal(raw, &old) != nil {
		return base, fault.Invalid
	}
	last := old.Last
	old.Last = ""
	if old != base {
		return base, fault.Conflict
	}
	base.Last = last
	return base, nil
}
func (s *Service) encodeCursor(c cursor, last string) (*string, error) {
	if s.CursorMAC == nil && len(s.CursorKey) < 32 {
		return nil, fault.Unavailable
	}
	c.Last = last
	b, e := json.Marshal(c)
	if e != nil {
		return nil, fault.Unavailable
	}
	mac, e := s.cursorDigest(b)
	if e != nil {
		return nil, e
	}
	b = append(b, mac...)
	return new(base64.RawURLEncoding.EncodeToString(b)), nil
}
func limit(n, def int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 1 || n > 100 {
		return 0, fault.Invalid
	}
	return n, nil
}
