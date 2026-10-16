package identity

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

const localMFATTL = 10 * time.Minute

type LocalMFAFactor struct {
	AccountID, OrgID, FactorID   string
	Generation, LastAcceptedStep int64
	Envelope                     sensitive.Envelope
}

type LocalMFAEnrollment struct {
	AccountID, OrgID, EnrollmentID, Mode string
	Generation, Attempts                 int64
	ExpiresAt                            time.Time
	BoundSessionHash                     []byte
	Envelope                             sensitive.Envelope
}

type LocalSessionCredential struct {
	Session    Session
	Credential LocalCredential
}

type LocalMFAEnrollmentInput struct {
	SessionHash  []byte
	Enrollment   LocalMFAEnrollment
	AcceptedStep int64
	RequestID    string
	Now          time.Time
}

type LocalMFAConfirmInput struct {
	SessionHash              []byte
	EnrollmentID             string
	Generation, AcceptedStep int64
	Recovery                 sensitive.MACValue
	NewSession               LocalSessionIssue
	RequestID                string
	Now                      time.Time
}

type LocalMFARecoveryInput struct {
	CredentialRevision                          int64
	UsernameDigest, RecoveryDigest, InputDigest []byte
	RecoveryKey                                 sensitive.KeyReference
	Enrollment                                  LocalMFAEnrollment
	NewSession                                  LocalSessionIssue
	RequestID                                   string
	Now                                         time.Time
}

type LocalMFARotateInput struct {
	SessionHash              []byte
	Generation, AcceptedStep int64
	Recovery                 *sensitive.MACValue
	NewSession               LocalSessionIssue
	RequestID                string
	Now                      time.Time
}

type LocalMFAStore interface {
	LocalCredentialBySession(context.Context, []byte, time.Time) (LocalSessionCredential, error)
	BeginLocalMFAEnrollment(context.Context, LocalMFAEnrollmentInput) error
	LocalMFAEnrollment(context.Context, []byte, time.Time) (LocalMFAEnrollment, error)
	RecordLocalMFAEnrollmentFailure(context.Context, []byte, string, time.Time) error
	ConfirmLocalMFAEnrollment(context.Context, LocalMFAConfirmInput) error
	BeginLocalMFARecovery(context.Context, LocalMFARecoveryInput) error
	RotateLocalMFASession(context.Context, LocalMFARotateInput) error
	CancelLocalMFAEnrollment(context.Context, []byte, string, time.Time) error
}

type LocalMFAPendingResult struct {
	Secret, URI, Mode string
	ExpiresAt         time.Time
}

type LocalMFAConfirmResult struct {
	SessionCookie, CSRFToken, RecoveryCode string
	ExpiresAt                              time.Time
}

type LocalMFARecoveryRequest struct {
	Username, Password, RecoveryCode, ReturnTo, RequestID string
}

type LocalMFAStepUpRequest struct {
	SessionHash                                     []byte
	Password, TOTPCode, Action, ReturnTo, RequestID string
}

type LocalMFAReplaceRequest struct {
	SessionHash                   []byte
	Password, TOTPCode, RequestID string
}

type LocalMFARecoveryCodeRequest struct {
	SessionHash                   []byte
	Password, TOTPCode, RequestID string
}

func mfaContext(orgID, accountID, versionID, kind string) sensitive.Context {
	schema := "identity.local_mfa_factor.v1"
	if kind == "local_mfa_enrollment" {
		schema = "identity.local_mfa_enrollment.v1"
	}
	return sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: versionID, ObjectKind: kind, Purpose: "identity", SchemaType: schema, SchemaVersion: 1}
}

func recoveryFrame(accountID string, generation int64, code string) []byte {
	out := []byte("TEAMLEDGER-LOCAL-RECOVERY\x00V1")
	out = binary.BigEndian.AppendUint32(out, uint32(len(accountID)))
	out = append(out, accountID...)
	out = binary.BigEndian.AppendUint64(out, uint64(generation))
	out = binary.BigEndian.AppendUint32(out, uint32(len(code)))
	return append(out, code...)
}

func (s *Service) recoveryMAC(ctx context.Context, accountID string, generation int64, code string) (sensitive.MACValue, error) {
	canonical, err := canonicalRecoveryCode(code)
	if err != nil || s == nil || s.local == nil {
		return sensitive.MACValue{}, fault.Invalid
	}
	frame := recoveryFrame(accountID, generation, canonical)
	defer clear(frame)
	value, err := s.local.keys.MAC(ctx, sensitive.DomainLocalRecoveryCode, frame)
	if err != nil || value.KeyID == "" || value.Version == 0 || len(value.Digest) != 32 {
		clear(value.Digest)
		return sensitive.MACValue{}, fault.Unavailable
	}
	return value, nil
}

func enrollmentURI(secret string) string {
	return "otpauth://totp/" + url.PathEscape("TeamLedger") + "?" + url.Values{
		"secret": {secret}, "issuer": {"TeamLedger"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"},
	}.Encode()
}

func (s *Service) sealEnrollment(ctx context.Context, owner LocalSessionCredential, mode string, sessionHash []byte) (LocalMFAEnrollment, string, error) {
	if mode != "initial" && mode != "replace" && mode != "recovery" || len(sessionHash) != 32 {
		return LocalMFAEnrollment{}, "", fault.Invalid
	}
	secret, encoded, err := newTOTPSecret()
	if err != nil {
		return LocalMFAEnrollment{}, "", fault.Unavailable
	}
	defer clear(secret)
	id := value.NewID()
	generation := owner.Credential.MFAGeneration
	if generation <= 0 || generation == int64(^uint64(0)>>1) {
		return LocalMFAEnrollment{}, "", fault.Unavailable
	}
	generation++
	binding := mfaContext(owner.Credential.OrgID, owner.Credential.AccountID, id, "local_mfa_enrollment")
	envelope, err := s.local.cipher.Seal(ctx, binding, secret)
	if err != nil {
		return LocalMFAEnrollment{}, "", fault.Unavailable
	}
	now := s.now()
	return LocalMFAEnrollment{AccountID: owner.Credential.AccountID, OrgID: owner.Credential.OrgID, EnrollmentID: id, Mode: mode, Generation: generation, ExpiresAt: now.Add(localMFATTL), BoundSessionHash: append([]byte(nil), sessionHash...), Envelope: envelope}, encoded, nil
}

func (s *Service) LocalMFABegin(ctx context.Context, sessionHash []byte, request LocalMFAReplaceRequest) (LocalMFAPendingResult, error) {
	if s == nil || s.local == nil || len(sessionHash) != 32 || !value.ValidID(request.RequestID) {
		return LocalMFAPendingResult{}, fault.Invalid
	}
	owner, err := s.local.store.LocalCredentialBySession(ctx, sessionHash, s.now())
	if err != nil {
		return LocalMFAPendingResult{}, err
	}
	mode, accepted := "initial", int64(0)
	if owner.Session.AccessKind == "business" {
		mode = "replace"
		accepted, err = s.verifySessionFactors(ctx, owner, request.Password, request.TOTPCode)
		if err != nil {
			return LocalMFAPendingResult{}, err
		}
	} else if owner.Session.AccessKind != "mfa_enrollment" || owner.Credential.MFAStatus != "enrollment_required" {
		return LocalMFAPendingResult{}, fault.Forbidden
	}
	enrollment, secret, err := s.sealEnrollment(ctx, owner, mode, sessionHash)
	if err != nil {
		return LocalMFAPendingResult{}, err
	}
	if err = s.local.store.BeginLocalMFAEnrollment(ctx, LocalMFAEnrollmentInput{SessionHash: sessionHash, Enrollment: enrollment, AcceptedStep: accepted, RequestID: request.RequestID, Now: s.now()}); err != nil {
		return LocalMFAPendingResult{}, err
	}
	return LocalMFAPendingResult{Secret: secret, URI: enrollmentURI(secret), Mode: mode, ExpiresAt: enrollment.ExpiresAt}, nil
}

func (s *Service) LocalMFAPending(ctx context.Context, sessionHash []byte) (LocalMFAPendingResult, error) {
	enrollment, err := s.local.store.LocalMFAEnrollment(ctx, sessionHash, s.now())
	if err != nil {
		return LocalMFAPendingResult{}, err
	}
	plain, err := s.local.cipher.Open(ctx, enrollment.Envelope.Context, enrollment.Envelope)
	if err != nil || len(plain) != totpSecretBytes {
		clear(plain)
		return LocalMFAPendingResult{}, fault.Unavailable
	}
	secret := unpaddedBase32.EncodeToString(plain)
	clear(plain)
	return LocalMFAPendingResult{Secret: secret, URI: enrollmentURI(secret), Mode: enrollment.Mode, ExpiresAt: enrollment.ExpiresAt}, nil
}

func (s *Service) LocalMFAConfirm(ctx context.Context, sessionHash []byte, code, requestID string) (LocalMFAConfirmResult, error) {
	if len(sessionHash) != 32 || !value.ValidID(requestID) {
		return LocalMFAConfirmResult{}, fault.Invalid
	}
	enrollment, err := s.local.store.LocalMFAEnrollment(ctx, sessionHash, s.now())
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	plain, err := s.local.cipher.Open(ctx, enrollment.Envelope.Context, enrollment.Envelope)
	if err != nil || len(plain) != totpSecretBytes {
		clear(plain)
		return LocalMFAConfirmResult{}, fault.Unavailable
	}
	step, valid := verifyTOTP(plain, code, s.now(), -1)
	if !valid {
		clear(plain)
		_ = s.local.store.RecordLocalMFAEnrollmentFailure(ctx, sessionHash, requestID, s.now())
		return LocalMFAConfirmResult{}, fault.Unauthenticated
	}
	factorID := value.NewID()
	factorBinding := mfaContext(enrollment.OrgID, enrollment.AccountID, factorID, "local_mfa_factor")
	factorEnvelope, err := s.local.cipher.Seal(ctx, factorBinding, plain)
	clear(plain)
	if err != nil {
		return LocalMFAConfirmResult{}, fault.Unavailable
	}
	recoveryCode, err := newRecoveryCode()
	if err != nil {
		return LocalMFAConfirmResult{}, fault.Unavailable
	}
	recovery, err := s.recoveryMAC(ctx, enrollment.AccountID, enrollment.Generation, recoveryCode)
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	cookie, issue, err := s.localSessionIssue(ctx, sessionHash, "business", true, requestID)
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	input := LocalMFAConfirmInput{SessionHash: sessionHash, EnrollmentID: enrollment.EnrollmentID, Generation: enrollment.Generation, AcceptedStep: step, Recovery: recovery, NewSession: issue, RequestID: requestID, Now: s.now()}
	input.NewSession.Factor = &LocalMFAFactor{AccountID: enrollment.AccountID, OrgID: enrollment.OrgID, FactorID: factorID, Generation: enrollment.Generation, LastAcceptedStep: step, Envelope: factorEnvelope}
	if err = s.local.store.ConfirmLocalMFAEnrollment(ctx, input); err != nil {
		return LocalMFAConfirmResult{}, err
	}
	return LocalMFAConfirmResult{SessionCookie: cookie, CSRFToken: issue.CSRFToken, RecoveryCode: recoveryCode, ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) verifySessionFactors(ctx context.Context, owner LocalSessionCredential, password, code string) (int64, error) {
	credential := owner.Credential
	if owner.Session.AccessKind != "business" || credential.MFAStatus != "active" || credential.Factor == nil || !verifyPHC(ctx, s.local.keys, credential.PHC, password, sensitive.KeyReference{KeyID: credential.PepperKeyID, Version: credential.PepperVersion}) {
		return 0, fault.Unauthenticated
	}
	plain, err := s.local.cipher.Open(ctx, credential.Factor.Envelope.Context, credential.Factor.Envelope)
	if err != nil || len(plain) != totpSecretBytes {
		clear(plain)
		return 0, fault.Unavailable
	}
	step, ok := verifyTOTP(plain, code, s.now(), credential.Factor.LastAcceptedStep)
	clear(plain)
	if !ok {
		return 0, fault.Unauthenticated
	}
	return step, nil
}

func (s *Service) LocalStepUp(ctx context.Context, request LocalMFAStepUpRequest) (LoginResult, error) {
	if !AllowedStepUpAction(request.Action) || !AllowedReturn(request.ReturnTo) || len(request.SessionHash) != 32 || !value.ValidID(request.RequestID) {
		return LoginResult{}, fault.Invalid
	}
	owner, err := s.local.store.LocalCredentialBySession(ctx, request.SessionHash, s.now())
	if err != nil {
		return LoginResult{}, err
	}
	step, err := s.verifySessionFactors(ctx, owner, request.Password, request.TOTPCode)
	if err != nil {
		return LoginResult{}, err
	}
	cookie, issue, err := s.localSessionIssue(ctx, request.SessionHash, "business", true, request.RequestID)
	if err != nil {
		return LoginResult{}, err
	}
	if err = s.local.store.RotateLocalMFASession(ctx, LocalMFARotateInput{SessionHash: request.SessionHash, Generation: owner.Credential.MFAGeneration, AcceptedStep: step, NewSession: issue, RequestID: request.RequestID, Now: s.now()}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionCookie: cookie, CSRFToken: issue.CSRFToken, ReturnTo: request.ReturnTo, ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) LocalMFARecoveryCode(ctx context.Context, request LocalMFARecoveryCodeRequest) (LocalMFAConfirmResult, error) {
	if len(request.SessionHash) != 32 || !value.ValidID(request.RequestID) {
		return LocalMFAConfirmResult{}, fault.Invalid
	}
	owner, err := s.local.store.LocalCredentialBySession(ctx, request.SessionHash, s.now())
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	step, err := s.verifySessionFactors(ctx, owner, request.Password, request.TOTPCode)
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	code, err := newRecoveryCode()
	if err != nil {
		return LocalMFAConfirmResult{}, fault.Unavailable
	}
	mac, err := s.recoveryMAC(ctx, owner.Credential.AccountID, owner.Credential.MFAGeneration, code)
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	cookie, issue, err := s.localSessionIssue(ctx, request.SessionHash, "business", true, request.RequestID)
	if err != nil {
		return LocalMFAConfirmResult{}, err
	}
	if err = s.local.store.RotateLocalMFASession(ctx, LocalMFARotateInput{SessionHash: request.SessionHash, Generation: owner.Credential.MFAGeneration, AcceptedStep: step, Recovery: &mac, NewSession: issue, RequestID: request.RequestID, Now: s.now()}); err != nil {
		return LocalMFAConfirmResult{}, err
	}
	return LocalMFAConfirmResult{SessionCookie: cookie, CSRFToken: issue.CSRFToken, RecoveryCode: code, ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) LocalMFARecover(ctx context.Context, request LocalMFARecoveryRequest) (LoginResult, error) {
	if !value.ValidID(request.RequestID) || !AllowedReturn(request.ReturnTo) {
		return LoginResult{}, fault.Invalid
	}
	username, err := LocalUsernameMAC(ctx, s.local.keys, request.Username)
	if err != nil {
		return LoginResult{}, err
	}
	defer clear(username.Digest)
	credential, lookupErr := s.local.store.LookupLocalCredential(ctx, username.Digest)
	now := s.now()
	valid := lookupErr == nil && credential.Active && credential.MFAStatus == "active" && credential.RetryAfter.Before(now) && verifyPHC(ctx, s.local.keys, credential.PHC, request.Password, sensitive.KeyReference{KeyID: credential.PepperKeyID, Version: credential.PepperVersion})
	if !valid {
		_ = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now)
		return LoginResult{}, fault.Unauthenticated
	}
	provided, err := s.recoveryMAC(ctx, credential.AccountID, credential.MFAGeneration, request.RecoveryCode)
	if err != nil {
		_ = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now)
		return LoginResult{}, fault.Unauthenticated
	}
	inputFrame := append([]byte("TEAMLEDGER-LOCAL-RECOVERY-REQUEST\x00V1"), provided.Digest...)
	inputHash := sha256.Sum256(inputFrame)
	clear(inputFrame)
	placeholder := LocalSessionCredential{Credential: credential}
	cookie, issue, err := s.localSessionIssue(ctx, nil, "mfa_recovery", false, request.RequestID)
	if err != nil {
		return LoginResult{}, err
	}
	hash := issue.TokenHash
	placeholder.Session = Session{Hash: hash, AccessKind: "mfa_recovery"}
	enrollment, _, err := s.sealEnrollment(ctx, placeholder, "recovery", hash)
	if err != nil {
		return LoginResult{}, err
	}
	start := LocalMFARecoveryInput{CredentialRevision: credential.CredentialRevision, UsernameDigest: username.Digest, RecoveryDigest: provided.Digest, RecoveryKey: sensitive.KeyReference{KeyID: provided.KeyID, Version: provided.Version}, InputDigest: inputHash[:], Enrollment: enrollment, NewSession: issue, RequestID: request.RequestID, Now: now}
	if err = s.local.store.BeginLocalMFARecovery(ctx, start); err != nil {
		if err == fault.Unauthenticated {
			_ = s.local.store.RecordLocalFailure(ctx, username.Digest, request.RequestID, now)
		}
		return LoginResult{}, err
	}
	return LoginResult{SessionCookie: cookie, CSRFToken: issue.CSRFToken, ReturnTo: request.ReturnTo, Next: "recover", ExpiresAt: issue.ExpiresAt}, nil
}

func (s *Service) LocalMFACancel(ctx context.Context, sessionHash []byte, requestID string) error {
	if len(sessionHash) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	return s.local.store.CancelLocalMFAEnrollment(ctx, sessionHash, requestID, s.now())
}

func normalizeTOTPCode(code string) string { return code }
