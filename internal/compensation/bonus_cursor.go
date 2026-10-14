package compensation

import (
	"encoding/base64"
	"encoding/json"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
)

func (s *Service) bonusCursorBinding(a authz.Snapshot, employee string, query BonusQuery, revision int64, sessionHash []byte) (string, error) {
	query.Cursor = ""
	raw, err := json.Marshal(struct {
		Org, Subject, Employee           string
		Revision                         int64
		SessionHash                      []byte
		Auth, SubjectEpoch, SessionEpoch int64
		Query                            BonusQuery
		Assignments                      []authz.Assignment
		Grants                           []authz.Grant
		JobAssignments, Relations        []authz.Tenure
	}{a.OrgID, a.SubjectID, employee, revision, sessionHash, a.AuthEpoch, a.SubjectEpoch, a.SessionEpoch, query, a.Assignments, a.Grants, a.JobAssignments, a.Relations})
	if err != nil {
		return "", fault.Unavailable
	}
	frame := append([]byte("TEAMLEDGER-BONUS-CURSOR-BINDING-v1\x00"), raw...)
	defer clear(frame)
	digest, err := s.cursorDigest(frame)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(digest), nil
}

func pageBonus[T any](values []T, after string, limit int, key func(T) string) ([]T, string) {
	start := 0
	for start < len(values) && key(values[start]) <= after {
		start++
	}
	end := start + limit
	if end >= len(values) {
		return values[start:], ""
	}
	return values[start:end], key(values[end-1])
}
