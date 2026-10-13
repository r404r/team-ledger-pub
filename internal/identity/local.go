package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 1
	argonKeyLen  = 32
)

type LocalKeyService interface {
	MAC(context.Context, sensitive.KeyDomain, []byte) (sensitive.MACValue, error)
}

type LocalCredential struct {
	AccountID, OrgID, SubjectID, PepperKeyID, PHC string
	UsernameDigest                                []byte
	PepperVersion                                 uint32
	CredentialRevision                            int64
	Active                                        bool
	Failures                                      int64
	RetryAfter                                    time.Time
}

type LocalSessionIssue struct {
	UsernameDigest, TokenHash, CSRFHash []byte
	Now, ExpiresAt, IdleExpiresAt       time.Time
	RequestID                           string
	CredentialRevision                  int64
}

type LocalStore interface {
	IdentityMode(context.Context) (string, error)
	LookupLocalCredential(context.Context, []byte) (LocalCredential, error)
	RecordLocalFailure(context.Context, []byte, string, time.Time) error
	IssueLocalSession(context.Context, LocalSessionIssue) error
	ChangeLocalPassword(context.Context, []byte, int64, string, sensitive.KeyReference, string, time.Time) error
}

type LocalLoginRequest struct {
	Username, Password, ReturnTo, RequestID string
}
type LocalPasswordChangeRequest struct {
	SessionHash                  []byte
	CurrentPassword, NewPassword string
	RequestID                    string
}

type localAuthenticator struct {
	store LocalStore
	keys  LocalKeyService
	fake  string
}

func CanonicalLocalUsername(raw string) (string, error) {
	if !utf8.ValidString(raw) || len(raw) < 3 || len(raw) > 64 || raw != strings.TrimSpace(raw) {
		return "", fault.Invalid
	}
	canonical := strings.ToLower(raw)
	for i := range len(canonical) {
		c := canonical[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return "", fault.Invalid
	}
	return canonical, nil
}

func validLocalPassword(password string) bool {
	return utf8.ValidString(password) && len(password) >= 12 && len(password) <= 256 && !strings.ContainsRune(password, 0)
}

func localFrame(label string, raw []byte) []byte {
	out := make([]byte, 0, len(label)+4+len(raw))
	out = append(out, label...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(raw)))
	return append(out, raw...)
}

func LocalUsernameMAC(ctx context.Context, keys LocalKeyService, username string) (sensitive.MACValue, error) {
	canonical, err := CanonicalLocalUsername(username)
	if err != nil || keys == nil {
		return sensitive.MACValue{}, fault.Invalid
	}
	frame := localFrame("TEAMLEDGER-LOCAL-USERNAME\x00V1", []byte(canonical))
	defer clear(frame)
	value, err := keys.MAC(ctx, sensitive.DomainLocalUsernameLookup, frame)
	if err != nil || value.Version == 0 || len(value.Digest) != 32 || value.KeyID == "" {
		clear(value.Digest)
		return sensitive.MACValue{}, fault.Unavailable
	}
	return value, nil
}

func localPasswordMAC(ctx context.Context, keys LocalKeyService, password string) (sensitive.MACValue, error) {
	if !validLocalPassword(password) || keys == nil {
		return sensitive.MACValue{}, fault.Invalid
	}
	frame := localFrame("TEAMLEDGER-LOCAL-PASSWORD\x00V1", []byte(password))
	defer clear(frame)
	value, err := keys.MAC(ctx, sensitive.DomainLocalPasswordPepper, frame)
	if err != nil || value.Version == 0 || len(value.Digest) != 32 || value.KeyID == "" {
		clear(value.Digest)
		return sensitive.MACValue{}, fault.Unavailable
	}
	return value, nil
}

func passwordPHC(input, salt []byte) (string, error) {
	if len(input) != 32 || len(salt) != 16 {
		return "", fault.Invalid
	}
	digest := argon2.IDKey(input, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer clear(digest)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

func NewPasswordCredential(ctx context.Context, keys LocalKeyService, password string) (string, sensitive.KeyReference, error) {
	pepper, err := localPasswordMAC(ctx, keys, password)
	if err != nil {
		return "", sensitive.KeyReference{}, err
	}
	defer clear(pepper.Digest)
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", sensitive.KeyReference{}, fault.Unavailable
	}
	defer clear(salt)
	phc, err := passwordPHC(pepper.Digest, salt)
	return phc, sensitive.KeyReference{KeyID: pepper.KeyID, Version: pepper.Version}, err
}

func verifyPHC(phc string, input []byte) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=1" {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	defer clear(salt)
	defer clear(want)
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != argonKeyLen || len(input) != 32 {
		return false
	}
	got := argon2.IDKey(input, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer clear(got)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func newLocalAuthenticator(ctx context.Context, store LocalStore, keys LocalKeyService) (*localAuthenticator, error) {
	if store == nil || keys == nil {
		return nil, fault.Unavailable
	}
	pepper, err := localPasswordMAC(ctx, keys, "teamledger-fake-password")
	if err != nil {
		return nil, err
	}
	defer clear(pepper.Digest)
	fake, err := passwordPHC(pepper.Digest, []byte("local-fake-salt!"))
	if err != nil {
		return nil, err
	}
	return &localAuthenticator{store: store, keys: keys, fake: fake}, nil
}

func NewLocal(ctx context.Context, store Store, local LocalStore, csrfKey []byte, keys LocalKeyService) (*Service, error) {
	if store == nil || local == nil || len(csrfKey) != 32 {
		return nil, fault.Unavailable
	}
	mode, err := local.IdentityMode(ctx)
	if err != nil || mode != "local" {
		return nil, fault.Unavailable
	}
	authenticator, err := newLocalAuthenticator(ctx, local, keys)
	if err != nil {
		return nil, err
	}
	return &Service{Store: store, csrfKey: bytes.Clone(csrfKey), Now: time.Now, mode: "local", local: authenticator}, nil
}

func (s *Service) LocalLogin(ctx context.Context, request LocalLoginRequest) (LoginResult, error) {
	if s == nil || s.local == nil || !value.ValidID(request.RequestID) || !AllowedReturn(request.ReturnTo) {
		return LoginResult{}, fault.Invalid
	}
	username, err := LocalUsernameMAC(ctx, s.local.keys, request.Username)
	if err != nil {
		return LoginResult{}, err
	}
	defer clear(username.Digest)
	credential, lookupErr := s.local.store.LookupLocalCredential(ctx, username.Digest)
	password, passwordErr := localPasswordMAC(ctx, s.local.keys, request.Password)
	if passwordErr != nil {
		return LoginResult{}, passwordErr
	}
	defer clear(password.Digest)
	now := s.now()
	phc := s.local.fake
	validAccount := lookupErr == nil && credential.Active && credential.RetryAfter.Before(now) && credential.PepperVersion == password.Version && credential.PepperKeyID == password.KeyID
	if validAccount {
		phc = credential.PHC
	}
	validPassword := verifyPHC(phc, password.Digest)
	if !validAccount || !validPassword {
		if err = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, fault.Unauthenticated
	}
	cookie, raw, err := randomToken()
	if err != nil {
		return LoginResult{}, err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write([]byte("TEAMLEDGER-CSRF\x00"))
	_, _ = mac.Write(raw)
	csrfHash := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
	issue := LocalSessionIssue{UsernameDigest: username.Digest, TokenHash: hash[:], CSRFHash: csrfHash[:], Now: now, ExpiresAt: now.Add(8 * time.Hour), IdleExpiresAt: now.Add(30 * time.Minute), RequestID: request.RequestID, CredentialRevision: credential.CredentialRevision}
	if err = s.local.store.IssueLocalSession(ctx, issue); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionCookie: cookie, ReturnTo: request.ReturnTo, ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) ChangeLocalPassword(ctx context.Context, request LocalPasswordChangeRequest) error {
	if s == nil || s.local == nil || len(request.SessionHash) != 32 || !value.ValidID(request.RequestID) {
		return fault.Invalid
	}
	session, err := s.Store.IdentitySession(ctx, request.SessionHash, s.now())
	if err != nil {
		return err
	}
	credential, err := s.local.store.LookupLocalCredential(ctx, session.IdentityDigest)
	if err != nil || !credential.Active {
		return fault.Unauthenticated
	}
	current, err := localPasswordMAC(ctx, s.local.keys, request.CurrentPassword)
	if err != nil {
		return err
	}
	valid := current.Version == credential.PepperVersion && current.KeyID == credential.PepperKeyID && verifyPHC(credential.PHC, current.Digest)
	clear(current.Digest)
	if !valid {
		return fault.Unauthenticated
	}
	phc, key, err := NewPasswordCredential(ctx, s.local.keys, request.NewPassword)
	if err != nil {
		return err
	}
	return s.local.store.ChangeLocalPassword(ctx, request.SessionHash, credential.CredentialRevision, phc, key, request.RequestID, s.now())
}
