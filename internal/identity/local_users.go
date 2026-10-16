package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

const localUserCursorTTL = 15 * time.Minute

type LocalUserRequest struct {
	SessionHash     []byte
	Username        string
	InitialPassword string
	Key             string
	RequestID       string
}

type LocalUserQuery struct {
	SessionHash []byte
	Cursor      string
	Limit       int
	RequestID   string
}

type LocalUser struct {
	AccountID              string    `json:"account_id"`
	SubjectID              string    `json:"subject_id"`
	Username               string    `json:"username"`
	Active                 bool      `json:"active"`
	PasswordChangeRequired bool      `json:"password_change_required"`
	MFAStatus              string    `json:"mfa_status"`
	CreatedAt              time.Time `json:"created_at"`
}

type LocalUserPage struct {
	Items       []LocalUser `json:"items"`
	NextCursor  *string     `json:"next_cursor"`
	Consistency string      `json:"consistency"`
}

type LocalUserResult struct {
	AccountID string `json:"account_id"`
	SubjectID string `json:"subject_id"`
}

type LocalUserRecord struct {
	AccountID, SubjectID, MFAStatus string
	Username                        sensitive.Envelope
	Active, PasswordChangeRequired  bool
	CreatedAt                       time.Time
}

type LocalUserStoreQuery struct {
	SessionHash                             []byte
	ExpectedOrgID, ExpectedSubjectID, After string
	ExpectedAuthEpoch                       int64
	Limit                                   int
	RequestID                               string
	Now                                     time.Time
}

type LocalUserProvision struct {
	SessionHash                          []byte
	ExpectedOrgID, ExpectedSubjectID     string
	ExpectedAuthEpoch                    int64
	RequestID, Key, AccountID, SubjectID string
	UsernameDigest, CommandDigest        []byte
	UsernameKey, CommandKey, PepperKey   sensitive.KeyReference
	UsernameEnvelope                     sensitive.Envelope
	PasswordPHC                          string
	Now                                  time.Time
}

type localUserCursorPayload struct {
	Version   int    `json:"v"`
	OrgID     string `json:"org"`
	SubjectID string `json:"subject"`
	AuthEpoch string `json:"epoch"`
	After     string `json:"after"`
	Limit     int    `json:"limit"`
	Issued    int64  `json:"issued"`
}

type localUserCursorWire struct {
	Payload    string `json:"payload"`
	KeyID      string `json:"key_id"`
	KeyVersion uint32 `json:"key_version"`
	MAC        string `json:"mac"`
}

func authorizeLocalUsers(snapshot authz.Snapshot, now time.Time) error {
	if !snapshot.Valid(now) {
		return fault.Unauthenticated
	}
	if !snapshot.Allows("identity.manage", "audit", "", authz.ManagementPurpose, now) {
		return fault.Forbidden
	}
	return nil
}

func localUserCursorFrame(payload []byte) []byte {
	return localFrame("TEAMLEDGER-LOCAL-USER-CURSOR\x00V1", payload)
}

func (s *Service) sealLocalUserCursor(ctx context.Context, snapshot authz.Snapshot, after string, limit int, now time.Time) (string, error) {
	payload := localUserCursorPayload{Version: 1, OrgID: snapshot.OrgID, SubjectID: snapshot.SubjectID, AuthEpoch: strconv.FormatInt(snapshot.AuthEpoch, 10), After: after, Limit: limit, Issued: now.UnixMicro()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fault.Unavailable
	}
	frame := localUserCursorFrame(raw)
	defer clear(frame)
	mac, err := s.keys.MAC(ctx, sensitive.DomainCursorToken, frame)
	if err != nil || mac.KeyID == "" || mac.Version == 0 || len(mac.Digest) != sha256.Size {
		clear(mac.Digest)
		return "", fault.Unavailable
	}
	defer clear(mac.Digest)
	wire := localUserCursorWire{Payload: base64.RawURLEncoding.EncodeToString(raw), KeyID: mac.KeyID, KeyVersion: mac.Version, MAC: base64.RawURLEncoding.EncodeToString(mac.Digest)}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return "", fault.Unavailable
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (s *Service) openLocalUserCursor(ctx context.Context, token string, snapshot authz.Snapshot, limit int, now time.Time) (string, error) {
	if len(token) == 0 || len(token) > 4096 {
		return "", fault.Invalid
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != token {
		return "", fault.Invalid
	}
	var wire localUserCursorWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.KeyID == "" || wire.KeyVersion == 0 {
		return "", fault.Invalid
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return "", fault.Invalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(wire.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != wire.Payload {
		return "", fault.Invalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(wire.MAC)
	if err != nil || len(mac) != sha256.Size || base64.RawURLEncoding.EncodeToString(mac) != wire.MAC {
		return "", fault.Invalid
	}
	frame := localUserCursorFrame(raw)
	defer clear(frame)
	valid, err := s.keys.Verify(ctx, sensitive.DomainCursorToken, sensitive.KeyReference{KeyID: wire.KeyID, Version: wire.KeyVersion}, frame, mac)
	if err != nil {
		return "", fault.Unavailable
	}
	if !valid {
		return "", fault.Invalid
	}
	var payload localUserCursorPayload
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", fault.Invalid
	}
	issued := time.UnixMicro(payload.Issued).UTC()
	if payload.Version != 1 || payload.OrgID != snapshot.OrgID || payload.SubjectID != snapshot.SubjectID || payload.AuthEpoch != strconv.FormatInt(snapshot.AuthEpoch, 10) || payload.Limit != limit || !value.ValidID(payload.After) || issued.After(now) || !now.Before(issued.Add(localUserCursorTTL)) {
		return "", fault.Conflict
	}
	return payload.After, nil
}

func (s *Service) ListLocalUsers(ctx context.Context, request LocalUserQuery) (LocalUserPage, error) {
	if s == nil || s.local == nil || len(request.SessionHash) != sha256.Size || request.Limit < 1 || request.Limit > 100 || !value.ValidID(request.RequestID) {
		return LocalUserPage{}, fault.Invalid
	}
	now := s.now()
	current, err := s.local.store.Security(ctx, request.SessionHash, "", "")
	if err != nil {
		return LocalUserPage{}, err
	}
	if err = authorizeLocalUsers(current, now); err != nil {
		return LocalUserPage{}, err
	}
	after := ""
	if request.Cursor != "" {
		after, err = s.openLocalUserCursor(ctx, request.Cursor, current, request.Limit, now)
		if err != nil {
			return LocalUserPage{}, err
		}
	}
	records, err := s.local.store.ListLocalUsers(ctx, LocalUserStoreQuery{SessionHash: request.SessionHash, ExpectedOrgID: current.OrgID, ExpectedSubjectID: current.SubjectID, ExpectedAuthEpoch: current.AuthEpoch, After: after, Limit: request.Limit, RequestID: request.RequestID, Now: now})
	if err != nil {
		return LocalUserPage{}, err
	}
	page := LocalUserPage{Items: make([]LocalUser, 0, request.Limit), Consistency: "current"}
	more := len(records) > request.Limit
	if more {
		records = records[:request.Limit]
	}
	for _, record := range records {
		plain, openErr := s.local.usernameCipher.Open(ctx, record.Username.Context, record.Username)
		if openErr != nil {
			clear(plain)
			return LocalUserPage{}, fault.Unavailable
		}
		username := string(plain)
		clear(plain)
		if _, canonicalErr := CanonicalLocalUsername(username); canonicalErr != nil {
			return LocalUserPage{}, fault.Unavailable
		}
		page.Items = append(page.Items, LocalUser{AccountID: record.AccountID, SubjectID: record.SubjectID, Username: username, Active: record.Active, PasswordChangeRequired: record.PasswordChangeRequired, MFAStatus: record.MFAStatus, CreatedAt: record.CreatedAt})
	}
	if more {
		cursor, cursorErr := s.sealLocalUserCursor(ctx, current, page.Items[len(page.Items)-1].AccountID, request.Limit, now)
		if cursorErr != nil {
			return LocalUserPage{}, cursorErr
		}
		page.NextCursor = &cursor
	}
	return page, nil
}

func (s *Service) CreateLocalUser(ctx context.Context, request LocalUserRequest) (LocalUserResult, error) {
	if s == nil || s.local == nil || len(request.SessionHash) != sha256.Size || !value.ValidID(request.Key) || !value.ValidID(request.RequestID) {
		return LocalUserResult{}, fault.Invalid
	}
	username, err := CanonicalLocalUsername(request.Username)
	if err != nil {
		return LocalUserResult{}, err
	}
	now := s.now()
	current, err := s.local.store.Security(ctx, request.SessionHash, "", "")
	if err != nil {
		return LocalUserResult{}, err
	}
	if err = authorizeLocalUsers(current, now); err != nil {
		return LocalUserResult{}, err
	}
	usernameMAC, err := LocalUsernameMAC(ctx, s.local.keys, username)
	if err != nil {
		return LocalUserResult{}, err
	}
	defer clear(usernameMAC.Digest)
	phc, pepper, err := NewPasswordCredential(ctx, s.local.keys, request.InitialPassword)
	if err != nil {
		return LocalUserResult{}, err
	}
	accountID, subjectID := value.NewID(), value.NewID()
	binding := sensitive.Context{OrgID: current.OrgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	envelope, err := s.local.usernameCipher.Seal(ctx, binding, []byte(username))
	if err != nil {
		return LocalUserResult{}, fault.Unavailable
	}
	defer clear(envelope.SealedBytes)
	commandPlain := append(localFrame("username", []byte(username)), localFrame("initial_password", []byte(request.InitialPassword))...)
	defer clear(commandPlain)
	commandFrame := localFrame("TEAMLEDGER-LOCAL-USER-CREATE\x00V1", commandPlain)
	defer clear(commandFrame)
	commandMAC, err := s.local.keys.MAC(ctx, sensitive.DomainCommandReceipt, commandFrame)
	if err != nil || commandMAC.KeyID == "" || commandMAC.Version == 0 || len(commandMAC.Digest) != sha256.Size {
		clear(commandMAC.Digest)
		return LocalUserResult{}, fault.Unavailable
	}
	defer clear(commandMAC.Digest)
	return s.local.store.CreateLocalUser(ctx, LocalUserProvision{SessionHash: request.SessionHash, ExpectedOrgID: current.OrgID, ExpectedSubjectID: current.SubjectID, ExpectedAuthEpoch: current.AuthEpoch, RequestID: request.RequestID, Key: request.Key, AccountID: accountID, SubjectID: subjectID, UsernameDigest: usernameMAC.Digest, CommandDigest: commandMAC.Digest, UsernameKey: sensitive.KeyReference{KeyID: usernameMAC.KeyID, Version: usernameMAC.Version}, CommandKey: sensitive.KeyReference{KeyID: commandMAC.KeyID, Version: commandMAC.Version}, PepperKey: pepper, UsernameEnvelope: envelope, PasswordPHC: phc, Now: now})
}
