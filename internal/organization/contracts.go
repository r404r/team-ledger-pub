package organization

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type Fault struct {
	Status       int
	Code, Reason string
}

func (e *Fault) Error() string { return e.Code }

var (
	Invalid          = &Fault{422, "INVALID_INPUT", "INVALID_INPUT"}
	Unauthenticated  = &Fault{401, "UNAUTHENTICATED", "SESSION_INVALID"}
	NotFound         = &Fault{404, "NOT_FOUND", "NOT_FOUND"}
	Forbidden        = &Fault{403, "FORBIDDEN", "ACTION_FORBIDDEN"}
	Conflict         = &Fault{409, "CONFLICT", "REVISION_STALE"}
	Mismatch         = &Fault{409, "CONFLICT", "IDEMPOTENCY_MISMATCH"}
	Unavailable      = &Fault{503, "UNAVAILABLE", "DEPENDENCY_UNAVAILABLE"}
	AuditUnavailable = &Fault{503, "UNAVAILABLE", "AUDIT_UNAVAILABLE"}
	Busy             = &Fault{503, "UNAVAILABLE", "WRITE_BUSY"}
)

type Contact struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}
type Profile struct {
	DisplayName    string   `json:"display_name"`
	WorkContact    *Contact `json:"work_contact,omitempty"`
	ProfileSummary string   `json:"profile_summary,omitempty"`
}
type Lifecycle struct {
	ValidFrom string  `json:"valid_from"`
	ValidTo   *string `json:"valid_to"`
}
type CreateCommand struct {
	Profile   Profile   `json:"profile"`
	Lifecycle Lifecycle `json:"lifecycle"`
}
type UpdateCommand struct {
	ExpectedRevision string  `json:"expected_profile_revision"`
	Profile          Profile `json:"profile"`
	EditReason       string  `json:"edit_reason"`
}
type ProfilePayload struct {
	Profile
	EditReason string `json:"edit_reason,omitempty"`
}
type Employee struct {
	ID, OrgID, HeadID string
	Revision          int64
	Lifecycle         Lifecycle
}
type Version struct {
	ID, EmployeeID, OrgID, SupersedesID string
	Number                              int64
	Envelope                            sensitive.Envelope
	RecordedAt                          time.Time
}
type Request struct {
	TokenHash               []byte
	Purpose, Key, RequestID string
}
type Result struct {
	ID       string `json:"id"`
	Revision string `json:"profile_revision"`
}
type View struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Revision          string    `json:"profile_revision,omitempty"`
	Lifecycle         Lifecycle `json:"lifecycle"`
	AsOf              string    `json:"as_of"`
	AuthorizationDate string    `json:"authorization_date"`
	Profile           *Profile  `json:"profile,omitempty"`
}
type Receipt struct {
	Digest []byte
	Result Result
}
type Audit struct {
	ID, OrgID, SubjectID, EmployeeID, Operation, Purpose, RequestID, Outcome string
	At                                                                       time.Time
}

type Reader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	Employee(context.Context, string) (Employee, error)
	Version(context.Context, string, string, string) (Version, error)
	Receipt(context.Context, string, string, string, string) (Receipt, bool, error)
}
type Tx interface {
	Reader
	Create(context.Context, Employee, Version) error
	Replace(context.Context, Employee, Version, int64) error
	SaveReceipt(context.Context, string, string, string, string, Receipt) error
	Audit(context.Context, Audit) error
}
type Store interface {
	Reader
	WithTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, Audit) error
}
