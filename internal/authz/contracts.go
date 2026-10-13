package authz

import (
	"context"
	"time"
)

const ManagementPurpose = "security_administration"

type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type RelationReference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type ObjectReference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type ObjectInfo struct {
	Reference                      ObjectReference
	EmployeeID, Category, Revision string
	Published                      bool
	Lineage                        []ObjectReference
}

type Authority struct {
	ID            string    `json:"id"`
	Capability    string    `json:"capability"`
	Category      string    `json:"category"`
	Scope         Scope     `json:"scope"`
	Purpose       string    `json:"purpose"`
	ValidFrom     time.Time `json:"valid_from"`
	ExpiresAt     time.Time `json:"expires_at"`
	MFARequired   bool      `json:"mfa_required"`
	ApprovedBy    string    `json:"approved_by"`
	ApprovedAt    time.Time `json:"approved_at"`
	PolicyVersion string    `json:"policy_version"`
}

type AuthorityHint struct {
	Authority
	DelegableScopes []Scope `json:"delegable_scopes"`
}

type GrantDTO struct {
	ID                      string             `json:"id"`
	OrgID                   string             `json:"org_id"`
	SubjectID               string             `json:"subject_id"`
	Capability              string             `json:"capability"`
	Category                string             `json:"category"`
	Scope                   Scope              `json:"scope"`
	Purpose                 string             `json:"purpose"`
	ValidFrom               time.Time          `json:"valid_from"`
	ExpiresAt               time.Time          `json:"expires_at"`
	MFARequired             bool               `json:"mfa_required"`
	RelationBound           bool               `json:"relation_bound"`
	RelationRef             *RelationReference `json:"relation_ref"`
	RelationActorEmployeeID string             `json:"-"`
	ObjectRef               *ObjectReference   `json:"object_ref"`
	ObjectEmployeeID        string             `json:"-"`
	ApprovedSourceRefs      []ObjectReference  `json:"approved_source_refs"`
	Revision                string             `json:"revision"`
	Status                  string             `json:"status"`
	AuthorityID             *string            `json:"authority_id"`
	PolicyVersion           *string            `json:"policy_version"`
	ApprovedBy              *string            `json:"approved_by"`
	ApprovedAt              *time.Time         `json:"approved_at"`
	IssuedBy                *string            `json:"issued_by"`
	IssuedAt                *time.Time         `json:"issued_at"`
	RevokedBy               *string            `json:"revoked_by"`
	RevokedAt               *time.Time         `json:"revoked_at"`
	RevokeReason            *string            `json:"revoke_reason"`
}

type IssueCommand struct {
	SubjectID          string             `json:"subject_id"`
	Capability         string             `json:"capability"`
	Category           string             `json:"category"`
	Scope              Scope              `json:"scope"`
	Purpose            string             `json:"purpose"`
	ValidFrom          string             `json:"valid_from"`
	ExpiresAt          string             `json:"expires_at"`
	MFARequired        bool               `json:"mfa_required"`
	RelationBound      bool               `json:"relation_bound"`
	RelationRef        *RelationReference `json:"relation_ref"`
	ObjectRef          *ObjectReference   `json:"object_ref"`
	ApprovedSourceRefs []ObjectReference  `json:"approved_source_refs,omitempty"`
	AuthorityID        string             `json:"authority_id"`
	ExpectedRevision   string             `json:"expected_revision"`
}

type RevokeCommand struct {
	ExpectedRevision  string `json:"expected_revision"`
	ExpectedAuthEpoch string `json:"expected_auth_epoch"`
	Reason            string `json:"reason"`
}

type Result struct {
	ID        string `json:"id"`
	Revision  string `json:"revision"`
	Status    string `json:"status"`
	AuthEpoch string `json:"auth_epoch"`
}

type Filter struct {
	SubjectID, ScopeKind, ScopeID, Category, Purpose, State, GrantID, Cursor string
	Capability, ObjectKind, ObjectID                                         string
	Limit                                                                    int
}

type Page struct {
	Items       []GrantDTO      `json:"items"`
	NextCursor  *string         `json:"next_cursor"`
	AsOf        string          `json:"as_of"`
	Consistency string          `json:"consistency"`
	AuthEpoch   string          `json:"auth_epoch"`
	Authorities []AuthorityHint `json:"authorities"`
}

type Request struct {
	TokenHash               []byte
	Purpose, Key, RequestID string
}

type Receipt struct {
	Digest []byte
	Result Result
}

type Audit struct {
	ID, OrgID, SubjectID, GrantID, Operation, Purpose, RequestID, Outcome string
	At                                                                    time.Time
}

// Repository filters authority coverage in SQL before limiting grant rows.
// Subject qualification and scope ownership are rechecked under the same guards.
type Reader interface {
	Security(context.Context, []byte, string, string) (Snapshot, error)
	Authorities(context.Context, string, string, time.Time) ([]Authority, error)
	Grant(context.Context, string, string) (GrantDTO, error)
	Object(context.Context, string, ObjectReference) (ObjectInfo, error)
	VisibleGrants(context.Context, string, []Authority, Filter, string, time.Time) ([]GrantDTO, error)
	Qualified(context.Context, string, string, string, Scope, time.Time) (bool, error)
	ScopeCovered(context.Context, string, Scope, Scope, time.Time) (bool, error)
	RelationQualified(context.Context, string, string, Scope, RelationReference, time.Time) (bool, error)
	OwnsScope(context.Context, string, Scope, time.Time) (bool, error)
	GrantReceipt(context.Context, string, string, string, string) (Receipt, bool, error)
}

type Tx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	LockScope(context.Context, string, Scope) error
	InsertGrant(context.Context, GrantDTO) error
	RevokeGrant(context.Context, string, string, int64, string, time.Time, string) error
	BumpEpoch(context.Context, string, int64) (int64, error)
	SaveGrantReceipt(context.Context, string, string, string, string, Receipt) error
	GrantAudit(context.Context, Audit) error
}

type Store interface {
	Reader
	WithGrantTx(context.Context, string, func(Tx) error) error
	GrantAuditDenied(context.Context, Audit) error
}
