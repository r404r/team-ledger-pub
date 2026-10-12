package audit

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
)

const Purpose = authz.ManagementPurpose

type Request struct {
	TokenHash []byte
	Purpose   string
	RequestID string
}

type Filter struct {
	SubjectID  string
	EmployeeID string
	GrantID    string
	Operation  string
	Purpose    string
	Outcome    string
	From       string
	To         string
	Cursor     string
	Limit      int
}

type Query struct {
	Filter
	FromTime  *time.Time
	ToTime    *time.Time
	AfterTime *time.Time
	AfterID   string
}

type Event struct {
	ID               string    `json:"id"`
	SubjectID        *string   `json:"subject_id"`
	EmployeeID       *string   `json:"employee_id"`
	GrantID          *string   `json:"grant_id"`
	Operation        string    `json:"operation"`
	Purpose          string    `json:"purpose"`
	RequestID        string    `json:"request_id"`
	Outcome          string    `json:"outcome"`
	RecordedAt       time.Time `json:"recorded_at"`
	ActorKind        string    `json:"actor_kind"`
	TargetSubjectID  *string   `json:"target_subject_id"`
	TargetEmployeeID *string   `json:"target_employee_id"`
}

type Page struct {
	Items              []Event   `json:"items"`
	NextCursor         *string   `json:"next_cursor"`
	Consistency        string    `json:"consistency"`
	AuthorizationUntil time.Time `json:"authorization_until"`
}

type Delivery struct {
	Event
	OrgID      *string   `json:"org_id"`
	ClaimToken string    `json:"-"`
	Attempt    int64     `json:"attempt"`
	ClaimUntil time.Time `json:"-"`
}

type DeliveryReceipt struct {
	ReceiptID string `json:"receipt_id"`
	Digest    []byte `json:"-"`
}

type DeliveryStore interface {
	ClaimAuditDelivery(context.Context, time.Time, time.Duration) (Delivery, bool, error)
	AckAuditDelivery(context.Context, string, string, DeliveryReceipt, time.Time) error
	RetryAuditDelivery(context.Context, string, string, time.Time) error
	AuditDeliveryBacklog(context.Context, time.Time) (int64, *time.Time, error)
}

type Reader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	AuditEvents(context.Context, string, Query) ([]Event, error)
}

type Tx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	Audit(context.Context, organization.Audit) error
}

type Store interface {
	Reader
	WithAuditTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, organization.Audit) error
}
