package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
)

type cursorPayload struct {
	Version      int               `json:"v"`
	Org          string            `json:"org"`
	Subject      string            `json:"subject"`
	AuthEpoch    int64             `json:"auth_epoch"`
	SubjectEpoch int64             `json:"subject_epoch"`
	SessionEpoch int64             `json:"session_epoch"`
	Filter       [sha256.Size]byte `json:"filter"`
	AfterTime    time.Time         `json:"after_time"`
	AfterID      string            `json:"after_id"`
	ExpiresAt    time.Time         `json:"expires_at"`
}

func auditFilterDigest(filter Filter) [sha256.Size]byte {
	filter.Cursor = ""
	raw, _ := json.Marshal(filter)
	return sha256.Sum256(raw)
}

func (s *Service) sealCursor(current authz.Snapshot, filter Filter, last Event, now time.Time) (string, error) {
	if len(s.CursorKey) != sha256.Size {
		return "", fault.Unavailable
	}
	payload := cursorPayload{Version: 1, Org: current.OrgID, Subject: current.SubjectID, AuthEpoch: current.AuthEpoch, SubjectEpoch: current.SubjectEpoch, SessionEpoch: current.SessionEpoch, Filter: auditFilterDigest(filter), AfterTime: last.RecordedAt, AfterID: last.ID, ExpiresAt: now.Add(15 * time.Minute)}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fault.Unavailable
	}
	mac := hmac.New(sha256.New, s.CursorKey)
	mac.Write([]byte("TEAMLEDGER-AUDIT-CURSOR\x00V1\x00"))
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) openCursor(token string, current authz.Snapshot, filter Filter, now time.Time) (time.Time, string, error) {
	if len(token) > 4096 || len(s.CursorKey) != sha256.Size {
		return time.Time{}, "", fault.Invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return time.Time{}, "", fault.Invalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != parts[0] {
		return time.Time{}, "", fault.Invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size {
		return time.Time{}, "", fault.Invalid
	}
	mac := hmac.New(sha256.New, s.CursorKey)
	mac.Write([]byte("TEAMLEDGER-AUDIT-CURSOR\x00V1\x00"))
	mac.Write(raw)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return time.Time{}, "", fault.Invalid
	}
	var payload cursorPayload
	if json.Unmarshal(raw, &payload) != nil || payload.Version != 1 || payload.Org != current.OrgID || payload.Subject != current.SubjectID || payload.AuthEpoch != current.AuthEpoch || payload.SubjectEpoch != current.SubjectEpoch || payload.SessionEpoch != current.SessionEpoch || payload.Filter != auditFilterDigest(filter) || !now.Before(payload.ExpiresAt) || payload.ExpiresAt.After(now.Add(15*time.Minute)) || payload.AfterTime.After(now) || payload.AfterID == "" {
		return time.Time{}, "", fault.Conflict
	}
	return payload.AfterTime, payload.AfterID, nil
}
