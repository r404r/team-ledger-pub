package organization

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"strconv"
	"time"
)

type organizationCursor struct {
	Version                                                             int `json:"v"`
	Domain, Org, Subject, SubjectEpoch, Day, Graph, Epoch, Filter, Last string
	Issued                                                              int64
}

func (s *Service) queryDigest(domain string, filter any, q string) (string, error) {
	b, err := json.Marshal(filter)
	if err != nil {
		return "", fault.Invalid
	}
	frame := append([]byte("TEAMLEDGER-ORGANIZATION-FILTER\x00V1\x00"+domain+"\x00"), b...)
	frame = append(frame, 0)
	frame = append(frame, q...)
	defer clear(frame)
	if s.CommandMAC != nil {
		digest, macErr := s.CommandMAC(frame)
		return base64.RawURLEncoding.EncodeToString(digest), macErr
	}
	if len(s.DigestKey) != 32 {
		return "", fault.Unavailable
	}
	m := hmac.New(sha256.New, s.DigestKey)
	m.Write(frame)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}
func (s *Service) queryCursorMAC(data []byte) ([]byte, error) {
	frame := append([]byte("TEAMLEDGER-ORGANIZATION-CURSOR\x00V1\x00"), data...)
	defer clear(frame)
	if s.CursorMAC != nil {
		return s.CursorMAC(frame)
	}
	if len(s.CursorKey) != 32 || len(s.DigestKey) != 32 || bytes.Equal(s.CursorKey, s.DigestKey) {
		return nil, fault.Unavailable
	}
	m := hmac.New(sha256.New, s.CursorKey)
	m.Write(frame)
	return m.Sum(nil), nil
}
func (s *Service) sealQueryCursor(domain string, snap authz.Snapshot, g Graph, day, filter, last string) (string, error) {
	p := organizationCursor{Version: 1, Domain: domain, Org: snap.OrgID, Subject: snap.SubjectID, SubjectEpoch: strconv.FormatInt(snap.SubjectEpoch, 10), Day: day, Graph: strconv.FormatInt(g.Revision, 10), Epoch: strconv.FormatInt(snap.AuthEpoch, 10), Filter: filter, Last: last, Issued: s.clock().UnixMicro()}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fault.Unavailable
	}
	mac, err := s.queryCursorMAC(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(append(b, mac...)), nil
}
func (s *Service) openQueryCursor(token, domain string, snap authz.Snapshot, g Graph, day, filter string) (string, error) {
	if len(token) > 4096 {
		return "", fault.Invalid
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) <= sha256.Size || base64.RawURLEncoding.EncodeToString(b) != token {
		return "", fault.Invalid
	}
	data, signature := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	mac, err := s.queryCursorMAC(data)
	if err != nil {
		return "", err
	}
	if !hmac.Equal(mac, signature) {
		return "", fault.Invalid
	}
	var p organizationCursor
	if json.Unmarshal(data, &p) != nil || p.Version != 1 || p.Domain != domain {
		return "", fault.Invalid
	}
	now := s.clock()
	issued := time.UnixMicro(p.Issued)
	if p.Org != snap.OrgID || p.Subject != snap.SubjectID || p.SubjectEpoch != strconv.FormatInt(snap.SubjectEpoch, 10) || p.Day != day || p.Graph != strconv.FormatInt(g.Revision, 10) || p.Epoch != strconv.FormatInt(snap.AuthEpoch, 10) || p.Filter != filter || issued.After(now) || !now.Before(issued.Add(15*time.Minute)) {
		return "", fault.Conflict
	}
	return p.Last, nil
}
