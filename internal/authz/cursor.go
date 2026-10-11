package authz

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

const cursorPayloadSize = 1 + 36 + 36 + 8 + 8 + 10 + 36 + sha256.Size

func filterDigest(f Filter) [32]byte {
	// Cursor itself is not a filter. The limit is bound: changing the query is
	// an explicit new search, never continuing a cursor in another context.
	b, _ := json.Marshal(struct {
		Subject, Kind, Scope, Category, Purpose, State, Grant string
		Limit                                                 int
	}{f.SubjectID, f.ScopeKind, f.ScopeID, f.Category, f.Purpose, f.State, f.GrantID, f.Limit})
	return sha256.Sum256(b)
}

func (s *Service) cursorMAC(payload []byte) ([]byte, error) {
	if len(s.CursorKey) != 32 || len(s.DigestKey) != 32 || bytes.Equal(s.CursorKey, s.DigestKey) {
		return nil, fault.Unavailable
	}
	mac := hmac.New(sha256.New, s.CursorKey)
	mac.Write([]byte("TEAMLEDGER-GRANT-CURSOR\x00V1\x00"))
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (s *Service) sealCursor(current Snapshot, filter Filter, day, last string, now time.Time) (string, error) {
	if !value.ValidID(current.OrgID) || !value.ValidID(current.SubjectID) || !value.ValidID(last) || !value.ValidDate(day) || current.AuthEpoch <= 0 {
		return "", fault.Unavailable
	}
	var payload [cursorPayloadSize + sha256.Size]byte
	payload[0] = 1
	copy(payload[1:37], current.OrgID)
	copy(payload[37:73], current.SubjectID)
	binary.BigEndian.PutUint64(payload[73:81], uint64(current.AuthEpoch))
	binary.BigEndian.PutUint64(payload[81:89], uint64(now.UnixMicro()))
	copy(payload[89:99], day)
	copy(payload[99:135], last)
	digest := filterDigest(filter)
	copy(payload[135:cursorPayloadSize], digest[:])
	mac, err := s.cursorMAC(payload[:cursorPayloadSize])
	if err != nil {
		return "", err
	}
	copy(payload[cursorPayloadSize:], mac)
	return base64.RawURLEncoding.EncodeToString(payload[:]), nil
}

func (s *Service) openCursor(token string, current Snapshot, filter Filter, day string, now time.Time) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != cursorPayloadSize+sha256.Size || base64.RawURLEncoding.EncodeToString(raw) != token {
		return "", fault.Invalid
	}
	mac, err := s.cursorMAC(raw[:cursorPayloadSize])
	if err != nil {
		return "", err
	}
	if raw[0] != 1 || !hmac.Equal(mac, raw[cursorPayloadSize:]) {
		return "", fault.Invalid
	}
	issued := time.UnixMicro(int64(binary.BigEndian.Uint64(raw[81:89]))).UTC()
	digest := filterDigest(filter)
	if string(raw[1:37]) != current.OrgID || string(raw[37:73]) != current.SubjectID || strconv.FormatUint(binary.BigEndian.Uint64(raw[73:81]), 10) != strconv.FormatInt(current.AuthEpoch, 10) || string(raw[89:99]) != day || !hmac.Equal(raw[135:cursorPayloadSize], digest[:]) || issued.After(now) || !now.Before(issued.Add(15*time.Minute)) {
		return "", fault.Conflict
	}
	last := string(raw[99:135])
	if !value.ValidID(last) {
		return "", fault.Invalid
	}
	return last, nil
}
