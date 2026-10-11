package identity

import (
	"context"
	"net/http"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
)

type OIDCConfig struct {
	Issuer, ClientID, ClientSecret, RedirectURI string
	HTTPClient                                  *http.Client
	IdentityKey, TransactionKey                 []byte
	MFAACR                                      string
	MFAAMR                                      []string
}
type BeginRequest struct {
	Mode, Action, ReturnTo, RequestID string
	SessionHash                       []byte
}
type Authorization struct {
	URL, BrowserCookie string
	ExpiresAt          time.Time
}
type CallbackRequest struct{ Code, State, BrowserCookie, RequestID string }
type LoginResult struct {
	SessionCookie, ReturnTo string
	ExpiresAt               time.Time
}

var MFARequired = &fault.Fault{Status: 403, Code: "MFA_REQUIRED", Reason: "MFA_REQUIRED"}

// Transaction contains safe routing/binding metadata and AEAD ciphertext only.
// Its state and browser proof are hashes, never bearer values.
type Transaction struct {
	StateHash, BindingHash, Sealed []byte
	CreatedAt, ExpiresAt           time.Time
	Mode, Action, ReturnTo         string
	PreviousHash                   []byte
	ExpectedOrg, ExpectedSubject   string
	ExpectedEpoch                  int64
	ExpectedIdentity               []byte
}
type Identity struct {
	Digest           []byte
	KeyVersion       int
	OrgID, SubjectID string
	Active           bool
}
type Session struct {
	Hash, IdentityDigest     []byte
	OrgID, SubjectID         string
	Epoch                    int64
	ExpiresAt, IdleExpiresAt time.Time
}
type SessionIssue struct {
	Transaction                                       Transaction
	IdentityDigest, TokenHash, CSRFHash               []byte
	Now, ExpiresAt, IdleExpiresAt, MFAUntil, AuthTime time.Time
	ACR                                               string
	AMR                                               []string
	RequestID                                         string
}

// Store methods own their complete database transaction. External OIDC I/O must
// finish before IssueSession; all current owner/epoch/guard checks happen there.
type Store interface {
	SaveOIDCTransaction(context.Context, Transaction) error
	ConsumeOIDCTransaction(context.Context, []byte, []byte, time.Time) (Transaction, error)
	IdentitySession(context.Context, []byte, time.Time) (Session, error)
	IssueSession(context.Context, SessionIssue) error
	TouchSession(context.Context, []byte, time.Time) error
	LogoutSession(context.Context, []byte, string, time.Time) error
	AuditIdentityDenied(context.Context, string, string, time.Time) error
}
type MappingStore interface {
	BindIdentity(context.Context, Identity, string, time.Time) error
	UnbindIdentity(context.Context, Identity, string, time.Time) error
}
