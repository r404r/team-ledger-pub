package compensation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

type changesCursor struct {
	Version int       `json:"v"`
	Binding string    `json:"binding"`
	After   string    `json:"after"`
	Expires time.Time `json:"expires"`
}

func (s *Service) cursorBinding(a authz.Snapshot, employee string, q ChangesQuery, b readBasis, scope Scope, head int64, sessionHash []byte) (string, error) {
	q.Cursor = ""
	raw, e := json.Marshal(struct {
		Org, Subject, Employee      string
		Purpose                     string
		ProposalHead                int64
		SessionHash                 []byte
		Auth, SubjectEpoch, Session int64
		Basis                       readBasis
		Query                       ChangesQuery
		Scope                       Scope
		Assignments                 []authz.Assignment
		Grants                      []authz.Grant
		JobAssignments, Relations   []authz.Tenure
	}{a.OrgID, a.SubjectID, employee, purpose, head, sessionHash, a.AuthEpoch, a.SubjectEpoch, a.SessionEpoch, b, q, scope, a.Assignments, a.Grants, a.JobAssignments, a.Relations})
	if e != nil || len(s.CursorKey) < 32 {
		return "", fault.Unavailable
	}
	h := hmac.New(sha256.New, s.CursorKey)
	h.Write([]byte("TEAMLEDGER-COMPENSATION-CURSOR-BINDING-v1\x00"))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
func (s *Service) signCursor(binding, after string) (string, error) {
	if len(s.CursorKey) < 32 {
		return "", fault.Unavailable
	}
	raw, e := json.Marshal(changesCursor{1, binding, after, s.clock().Add(15 * time.Minute)})
	if e != nil {
		return "", fault.Unavailable
	}
	h := hmac.New(sha256.New, s.CursorKey)
	h.Write([]byte("TEAMLEDGER-COMPENSATION-CURSOR-v1\x00"))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
func (s *Service) cursorPosition(token, binding string) (string, error) {
	if len(token) > 8192 || len(s.CursorKey) < 32 {
		return "", fault.Invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", fault.Invalid
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return "", fault.Invalid
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return "", fault.Invalid
	}
	h := hmac.New(sha256.New, s.CursorKey)
	h.Write([]byte("TEAMLEDGER-COMPENSATION-CURSOR-v1\x00"))
	h.Write(raw)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return "", fault.Invalid
	}
	var c changesCursor
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 || !hmac.Equal([]byte(c.Binding), []byte(binding)) || !s.clock().Before(c.Expires) || c.Expires.After(s.clock().Add(15*time.Minute)) {
		return "", fault.Invalid
	}
	return c.After, nil
}
func (s *Service) parseCursor(token, binding string) (string, error) {
	after, e := s.cursorPosition(token, binding)
	if e != nil {
		return "", e
	}
	key := strings.Split(after, "|")
	if len(key) != 2 || !value.ValidID(key[1]) {
		return "", fault.Invalid
	}
	t, e := time.Parse(time.RFC3339Nano, key[0])
	if e != nil || t.UTC().Format(time.RFC3339Nano) != key[0] {
		return "", fault.Invalid
	}
	return after, nil
}
func (s *Service) parseRevisionCursor(token, binding string) (int64, error) {
	after, e := s.cursorPosition(token, binding)
	if e != nil {
		return 0, e
	}
	n, ok := value.Revision(after)
	if !ok {
		return 0, fault.Invalid
	}
	return n, nil
}
