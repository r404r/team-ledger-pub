package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
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

type MACKeyService interface {
	MAC(context.Context, sensitive.KeyDomain, []byte) (sensitive.MACValue, error)
	Verify(context.Context, sensitive.KeyDomain, sensitive.KeyReference, []byte, []byte) (bool, error)
}

type LocalKeyService interface {
	MACKeyService
}

type LocalCredential struct {
	AccountID, OrgID, SubjectID, PepperKeyID, UsernameKeyID, PHC string
	UsernameDigest                                               []byte
	UsernameKeyVersion, PepperVersion                            uint32
	CredentialRevision, MFAGeneration                            int64
	MFAStatus                                                    string
	Factor                                                       *LocalMFAFactor
	RecoveryKeyID                                                string
	RecoveryKeyVersion                                           uint32
	RecoveryDigest                                               []byte
	Active, PasswordChangeRequired                               bool
	Failures                                                     int64
	RetryAfter                                                   time.Time
}

type LocalSessionIssue struct {
	UsernameDigest, TokenHash, CSRFHash                        []byte
	Now, ExpiresAt, IdleExpiresAt, MFAUntil                    time.Time
	RequestID, CSRFKeyID, CSRFToken, UsernameKeyID, AccessKind string
	CredentialRevision, FactorGeneration, AcceptedStep         int64
	CSRFVersion, UsernameKeyVersion                            uint32
	AMR                                                        []string
	Factor                                                     *LocalMFAFactor
}

type LocalStore interface {
	LocalMFAStore
	authz.Reader
	IdentityMode(context.Context) (string, error)
	LookupLocalCredential(context.Context, []byte) (LocalCredential, error)
	RecordLocalFailure(context.Context, []byte, string, time.Time) error
	IssueLocalSession(context.Context, LocalSessionIssue) error
	UpgradeLocalCredential(context.Context, []byte, int64, string, sensitive.KeyReference, time.Time) error
	ChangeLocalPassword(context.Context, []byte, int64, string, sensitive.KeyReference, string, time.Time) error
	ListLocalUsers(context.Context, LocalUserStoreQuery) ([]LocalUserRecord, error)
	CreateLocalUser(context.Context, LocalUserProvision) (LocalUserResult, error)
}

type LocalLoginRequest struct {
	Username, Password, TOTPCode, ReturnTo, RequestID string
}
type LocalPasswordChangeRequest struct {
	SessionHash                  []byte
	CurrentPassword, NewPassword string
	RequestID                    string
}

type localAuthenticator struct {
	store   LocalStore
	keys    LocalKeyService
	cipher  sensitive.Cipher
	fake    string
	fakeKey sensitive.KeyReference
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

func CSRFToken(ctx context.Context, keys MACKeyService, raw []byte) (string, sensitive.KeyReference, error) {
	if keys == nil || len(raw) == 0 {
		return "", sensitive.KeyReference{}, fault.Unavailable
	}
	frame := append([]byte("TEAMLEDGER-CSRF\x00"), raw...)
	defer clear(frame)
	value, err := keys.MAC(ctx, sensitive.DomainCSRFToken, frame)
	if err != nil || value.Version == 0 || value.KeyID == "" || len(value.Digest) != sha256.Size {
		clear(value.Digest)
		return "", sensitive.KeyReference{}, fault.Unavailable
	}
	token := base64.RawURLEncoding.EncodeToString(value.Digest)
	clear(value.Digest)
	return token, sensitive.KeyReference{KeyID: value.KeyID, Version: value.Version}, nil
}

func LocalUsernameLookupFrame(username string) ([]byte, error) {
	canonical, err := CanonicalLocalUsername(username)
	if err != nil {
		return nil, err
	}
	return localFrame("TEAMLEDGER-LOCAL-USERNAME\x00V1", []byte(canonical)), nil
}

func LocalUsernameMAC(ctx context.Context, keys LocalKeyService, username string) (sensitive.MACValue, error) {
	frame, err := LocalUsernameLookupFrame(username)
	if err != nil || keys == nil {
		return sensitive.MACValue{}, fault.Invalid
	}
	defer clear(frame)
	value, err := keys.MAC(ctx, sensitive.DomainLocalUsernameLookup, frame)
	if err != nil || value.Version == 0 || len(value.Digest) != 32 || value.KeyID == "" {
		clear(value.Digest)
		return sensitive.MACValue{}, fault.Unavailable
	}
	return value, nil
}

func passwordFrame(input []byte) []byte {
	return localFrame("TEAMLEDGER-LOCAL-PASSWORD\x00V2", input)
}

func passwordPHC(ctx context.Context, keys LocalKeyService, password string, salt []byte) (string, sensitive.KeyReference, error) {
	if !validLocalPassword(password) || keys == nil || len(salt) != 16 {
		return "", sensitive.KeyReference{}, fault.Invalid
	}
	input := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer clear(input)
	frame := passwordFrame(input)
	defer clear(frame)
	pepper, err := keys.MAC(ctx, sensitive.DomainLocalPasswordPepper, frame)
	if err != nil || pepper.Version == 0 || len(pepper.Digest) != 32 || pepper.KeyID == "" {
		clear(pepper.Digest)
		return "", sensitive.KeyReference{}, fault.Unavailable
	}
	defer clear(pepper.Digest)
	phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(pepper.Digest))
	return phc, sensitive.KeyReference{KeyID: pepper.KeyID, Version: pepper.Version}, nil
}

func NewPasswordCredential(ctx context.Context, keys LocalKeyService, password string) (string, sensitive.KeyReference, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", sensitive.KeyReference{}, fault.Unavailable
	}
	defer clear(salt)
	return passwordPHC(ctx, keys, password, salt)
}

func verifyPHC(ctx context.Context, keys LocalKeyService, phc, password string, reference sensitive.KeyReference) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=1" || reference.KeyID == "" || reference.Version == 0 || !validLocalPassword(password) {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	defer clear(salt)
	defer clear(want)
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	input := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	defer clear(input)
	frame := passwordFrame(input)
	defer clear(frame)
	ok, err := keys.Verify(ctx, sensitive.DomainLocalPasswordPepper, reference, frame, want)
	return err == nil && ok
}

func newLocalAuthenticator(ctx context.Context, store LocalStore, keys LocalKeyService, cipher sensitive.Cipher) (*localAuthenticator, error) {
	if store == nil || keys == nil || cipher.Wrapper == nil {
		return nil, fault.Unavailable
	}
	fake, reference, err := passwordPHC(ctx, keys, "teamledger-fake-password", []byte("local-fake-salt!"))
	if err != nil {
		return nil, err
	}
	return &localAuthenticator{store: store, keys: keys, cipher: cipher, fake: fake, fakeKey: reference}, nil
}

func NewLocal(ctx context.Context, store Store, local LocalStore, keys LocalKeyService, cipher sensitive.Cipher) (*Service, error) {
	if store == nil || local == nil || keys == nil || cipher.Wrapper == nil {
		return nil, fault.Unavailable
	}
	mode, err := local.IdentityMode(ctx)
	if err != nil || mode != "local" {
		return nil, fault.Unavailable
	}
	authenticator, err := newLocalAuthenticator(ctx, local, keys, cipher)
	if err != nil {
		return nil, err
	}
	return &Service{Store: store, keys: keys, Now: time.Now, mode: "local", local: authenticator}, nil
}

func (s *Service) localSessionIssue(ctx context.Context, _ []byte, accessKind string, recentMFA bool, requestID string) (string, LocalSessionIssue, error) {
	if s == nil || s.local == nil || !value.ValidID(requestID) || accessKind != "business" && accessKind != "mfa_enrollment" && accessKind != "mfa_recovery" && accessKind != "password_change" {
		return "", LocalSessionIssue{}, fault.Invalid
	}
	cookie, raw, err := randomToken()
	if err != nil {
		return "", LocalSessionIssue{}, err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	csrf, csrfKey, err := CSRFToken(ctx, s.keys, raw)
	if err != nil {
		return "", LocalSessionIssue{}, err
	}
	csrfHash := sha256.Sum256([]byte(csrf))
	now := s.now()
	issue := LocalSessionIssue{TokenHash: hash[:], CSRFHash: csrfHash[:], CSRFKeyID: csrfKey.KeyID, CSRFToken: csrf, CSRFVersion: csrfKey.Version, AccessKind: accessKind, Now: now, RequestID: requestID}
	if accessKind == "business" {
		issue.ExpiresAt, issue.IdleExpiresAt = now.Add(8*time.Hour), now.Add(30*time.Minute)
		issue.AMR = []string{"pwd", "otp"}
		if recentMFA {
			issue.MFAUntil = now.Add(localMFATTL)
		}
	} else {
		issue.ExpiresAt, issue.IdleExpiresAt = now.Add(localMFATTL), now.Add(localMFATTL)
		issue.AMR = []string{"pwd"}
	}
	if issue.MFAUntil.IsZero() {
		issue.MFAUntil = time.Unix(0, 0).UTC()
	}
	return cookie, issue, nil
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
	now := s.now()
	phc, reference := s.local.fake, s.local.fakeKey
	validAccount := lookupErr == nil && credential.Active && credential.RetryAfter.Before(now)
	if validAccount {
		phc = credential.PHC
		reference = sensitive.KeyReference{KeyID: credential.PepperKeyID, Version: credential.PepperVersion}
	}
	validPassword := verifyPHC(ctx, s.local.keys, phc, request.Password, reference)
	if !validAccount || !validPassword {
		if err = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, fault.Unauthenticated
	}
	probe, err := s.local.keys.MAC(ctx, sensitive.DomainLocalPasswordPepper, []byte("TEAMLEDGER-LOCAL-PASSWORD-ACTIVE\x00V1"))
	if err != nil || probe.Version == 0 || probe.KeyID == "" {
		clear(probe.Digest)
		return LoginResult{}, fault.Unavailable
	}
	clear(probe.Digest)
	if credential.PepperVersion != probe.Version || credential.PepperKeyID != probe.KeyID {
		upgradedPHC, upgradedKey, upgradeErr := NewPasswordCredential(ctx, s.local.keys, request.Password)
		if upgradeErr != nil {
			return LoginResult{}, upgradeErr
		}
		if upgradeErr = s.local.store.UpgradeLocalCredential(ctx, username.Digest, credential.CredentialRevision, upgradedPHC, upgradedKey, now); upgradeErr != nil {
			return LoginResult{}, upgradeErr
		}
	}
	acceptedStep := int64(0)
	accessKind, recentMFA := "mfa_enrollment", false
	if credential.PasswordChangeRequired {
		accessKind = "password_change"
	} else if credential.MFAStatus == "active" {
		if credential.Factor == nil {
			return LoginResult{}, fault.Unavailable
		}
		if request.TOTPCode == "" {
			return LoginResult{}, MFARequired
		}
		plain, openErr := s.local.cipher.Open(ctx, credential.Factor.Envelope.Context, credential.Factor.Envelope)
		if openErr != nil || len(plain) != totpSecretBytes {
			clear(plain)
			return LoginResult{}, fault.Unavailable
		}
		var valid bool
		acceptedStep, valid = verifyTOTP(plain, normalizeTOTPCode(request.TOTPCode), now, credential.Factor.LastAcceptedStep)
		clear(plain)
		if !valid {
			if err = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now); err != nil {
				return LoginResult{}, err
			}
			return LoginResult{}, fault.Unauthenticated
		}
		accessKind, recentMFA = "business", true
	} else if credential.MFAStatus != "enrollment_required" {
		return LoginResult{}, fault.Unavailable
	}
	cookie, issue, err := s.localSessionIssue(ctx, nil, accessKind, recentMFA, request.RequestID)
	if err != nil {
		return LoginResult{}, err
	}
	issue.UsernameDigest, issue.UsernameKeyID, issue.UsernameKeyVersion = username.Digest, credential.UsernameKeyID, credential.UsernameKeyVersion
	issue.CredentialRevision, issue.FactorGeneration, issue.AcceptedStep = credential.CredentialRevision, credential.MFAGeneration, acceptedStep
	if err = s.local.store.IssueLocalSession(ctx, issue); err != nil {
		return LoginResult{}, err
	}
	next := ""
	if accessKind == "mfa_enrollment" {
		next = "enroll"
	} else if accessKind == "password_change" {
		next = "change_password"
	}
	return LoginResult{SessionCookie: cookie, CSRFToken: issue.CSRFToken, ReturnTo: request.ReturnTo, Next: next, ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) ChangeLocalPassword(ctx context.Context, request LocalPasswordChangeRequest) error {
	if s == nil || s.local == nil || len(request.SessionHash) != 32 || !value.ValidID(request.RequestID) {
		return fault.Invalid
	}
	session, err := s.Store.IdentitySession(ctx, request.SessionHash, s.now())
	if err != nil {
		return err
	}
	if session.AccessKind != "business" && session.AccessKind != "password_change" {
		return fault.Unauthenticated
	}
	credential, err := s.local.store.LookupLocalCredential(ctx, session.IdentityDigest)
	if err != nil || !credential.Active {
		return fault.Unauthenticated
	}
	valid := verifyPHC(ctx, s.local.keys, credential.PHC, request.CurrentPassword, sensitive.KeyReference{KeyID: credential.PepperKeyID, Version: credential.PepperVersion})
	if !valid {
		return fault.Unauthenticated
	}
	if request.NewPassword == request.CurrentPassword {
		return fault.Invalid
	}
	phc, key, err := NewPasswordCredential(ctx, s.local.keys, request.NewPassword)
	if err != nil {
		return err
	}
	return s.local.store.ChangeLocalPassword(ctx, request.SessionHash, credential.CredentialRevision, phc, key, request.RequestID, s.now())
}
