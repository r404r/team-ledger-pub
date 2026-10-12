package compensation

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
)

type BonusMoney struct {
	Currency    string `json:"currency"`
	Scale       int    `json:"scale"`
	AmountMinor string `json:"amount_minor"`
}

type BonusTargetPayload struct {
	Basis  string     `json:"basis"`
	Amount BonusMoney `json:"amount"`
	Reason string     `json:"reason"`
}

type BonusTargetCommand struct {
	PeriodStart   string             `json:"period_start"`
	PeriodEnd     string             `json:"period_end"`
	BonusRevision string             `json:"bonus_revision"`
	InitialState  string             `json:"initial_state"`
	Target        BonusTargetPayload `json:"target"`
}

type BonusTargetTransition struct {
	Action        string `json:"action"`
	Revision      string `json:"revision"`
	BonusRevision string `json:"bonus_revision"`
	Reason        string `json:"reason"`
}

type BonusAwardPayload struct {
	PeriodStart string     `json:"period_start"`
	PeriodEnd   string     `json:"period_end"`
	Category    string     `json:"category"`
	Reason      string     `json:"reason"`
	Amount      BonusMoney `json:"amount"`
}

type BonusAwardCommand struct {
	BonusRevision   string            `json:"bonus_revision"`
	TargetID        *string           `json:"target_id"`
	CorrectsAwardID *string           `json:"corrects_award_id"`
	Award           BonusAwardPayload `json:"award"`
}

type BonusAwardEditCommand struct {
	Revision        string            `json:"revision"`
	BonusRevision   string            `json:"bonus_revision"`
	TargetID        *string           `json:"target_id"`
	CorrectsAwardID *string           `json:"corrects_award_id"`
	Award           BonusAwardPayload `json:"award"`
}

type BonusAwardTransition struct {
	Action         string `json:"action"`
	Revision       string `json:"revision"`
	BonusRevision  string `json:"bonus_revision"`
	DecisionReason string `json:"decision_reason"`
}

type BonusPaymentCommand struct {
	BonusRevision     string     `json:"bonus_revision"`
	BusinessSource    string     `json:"business_source"`
	ExternalFactID    string     `json:"external_fact_id"`
	Kind              string     `json:"kind"`
	PaidDate          string     `json:"paid_date"`
	EvidenceReference string     `json:"evidence_reference"`
	Reason            string     `json:"reason"`
	Amount            BonusMoney `json:"amount"`
	AwardID           *string    `json:"award_id"`
	OriginalPaymentID *string    `json:"original_payment_id"`
}

type BonusExtensionCommand struct {
	CompRevision  string           `json:"comp_revision"`
	SchemaType    string           `json:"schema_type"`
	SchemaVersion int              `json:"schema_version"`
	SupersedesID  *string          `json:"supersedes_id"`
	Payload       CompensationMemo `json:"payload"`
}

type BonusQuery struct {
	PeriodStart, PeriodEnd, RecordKind, RecordID, Cursor string
	Limit                                                int
}

type BonusTargetView struct {
	ID            string             `json:"id"`
	EmployeeID    string             `json:"employee_id"`
	PeriodStart   string             `json:"period_start"`
	PeriodEnd     string             `json:"period_end"`
	State         string             `json:"state"`
	Revision      string             `json:"revision"`
	BonusRevision string             `json:"bonus_revision"`
	RecordedAt    string             `json:"recorded_at"`
	Target        BonusTargetPayload `json:"target"`
}

type BonusAwardView struct {
	ID              string            `json:"id"`
	EmployeeID      string            `json:"employee_id"`
	State           string            `json:"state"`
	Revision        string            `json:"revision"`
	BonusRevision   string            `json:"bonus_revision"`
	AuthorSubjectID string            `json:"author_subject_id"`
	RecordedAt      string            `json:"recorded_at"`
	TargetID        *string           `json:"target_id"`
	CorrectsAwardID *string           `json:"corrects_award_id"`
	ApprovalID      *string           `json:"approval_id"`
	Award           BonusAwardPayload `json:"award"`
	DecisionReason  string            `json:"decision_reason"`
}

type BonusPaymentView struct {
	ID                string     `json:"id"`
	EmployeeID        string     `json:"employee_id"`
	Kind              string     `json:"kind"`
	PaidDate          string     `json:"paid_date"`
	RecordedAt        string     `json:"recorded_at"`
	AwardID           *string    `json:"award_id"`
	OriginalPaymentID *string    `json:"original_payment_id"`
	Amount            BonusMoney `json:"amount"`
	EvidenceReference string     `json:"evidence_reference"`
	Reason            string     `json:"reason"`
	Anomalies         []string   `json:"anomalies"`
}

type BonusExtensionView struct {
	ID            string           `json:"id"`
	EmployeeID    string           `json:"employee_id"`
	SchemaType    string           `json:"schema_type"`
	Revision      string           `json:"revision"`
	CompRevision  string           `json:"comp_revision"`
	RecordedAt    string           `json:"recorded_at"`
	SchemaVersion int              `json:"schema_version"`
	SupersedesID  *string          `json:"supersedes_id"`
	Payload       CompensationMemo `json:"payload"`
}

type BonusView struct {
	EmployeeID         string               `json:"employee_id"`
	BonusRevision      string               `json:"bonus_revision"`
	CompRevision       string               `json:"comp_revision"`
	AuthorizationUntil string               `json:"authorization_until"`
	NextCursor         string               `json:"next_cursor"`
	Targets            []BonusTargetView    `json:"targets"`
	Awards             []BonusAwardView     `json:"awards"`
	Payments           []BonusPaymentView   `json:"payments"`
	Balances           []BonusBalance       `json:"balances"`
	Anomalies          []BonusAnomaly       `json:"anomalies"`
	Extensions         []BonusExtensionView `json:"extensions"`
	Permissions        []Permission         `json:"permissions"`
}

type BonusResult struct {
	ID            string `json:"id"`
	Revision      string `json:"revision"`
	BonusRevision string `json:"bonus_revision"`
	CompRevision  string `json:"comp_revision"`
	State         string `json:"state"`
}

type BonusAggregateRecord struct {
	OrgID, EmployeeID string
	Revision          int64
}

type BonusTargetRecord struct {
	OrgID, EmployeeID, ID, State, VersionID, PayloadID, PeriodStart, PeriodEnd, ActorSubjectID string
	Revision, BasisRevision                                                                    int64
	RecordedAt                                                                                 time.Time
}

type BonusAwardRecord struct {
	OrgID, EmployeeID, ID, State, VersionID, PayloadID, AuthorSubjectID, PeriodStart, PeriodEnd string
	TargetID, CorrectsAwardID, ApprovalID                                                       *string
	Revision, BasisRevision                                                                     int64
	RecordedAt                                                                                  time.Time
}

type BonusApprovalRecord struct {
	OrgID, EmployeeID, ID, AwardID, AwardVersionID, ApproverSubjectID, PayloadID string
	AwardRevision, BasisRevision, BonusRevision                                  int64
	RecordedAt                                                                   time.Time
}

type BonusPaymentRecord struct {
	OrgID, EmployeeID, ID, PayloadID, Kind, PaidDate, BusinessSource string
	AwardID, OriginalPaymentID                                       *string
	BusinessKeyVersion, BasisRevision                                int64
	BusinessDigest                                                   []byte
	RecordedAt                                                       time.Time
}

type BonusExtensionRecord struct {
	OrgID, EmployeeID, ID, PayloadID, SchemaType string
	SchemaVersion, Revision, BasisRevision       int64
	SupersedesID                                 *string
	RecordedAt                                   time.Time
}

type BonusSnapshot struct {
	Aggregate  BonusAggregateRecord
	Targets    []BonusTargetRecord
	Awards     []BonusAwardRecord
	Approvals  []BonusApprovalRecord
	Payments   []BonusPaymentRecord
	Extensions []BonusExtensionRecord
}

type BonusPageQuery struct {
	Kind, PeriodStart, PeriodEnd, RecordID, After string
	Limit                                         int
}

type BonusSnapshotPage struct {
	Snapshot BonusSnapshot
	More     bool
}

type BonusWrite struct {
	Aggregate              BonusAggregateRecord
	ExpectedBonusRevision  int64
	ExpectedCompRevision   *int64
	Target                 *BonusTargetRecord
	ExpectedTargetRevision int64
	Award                  *BonusAwardRecord
	ExpectedAwardRevision  int64
	Approval               *BonusApprovalRecord
	Payment                *BonusPaymentRecord
	Extension              *BonusExtensionRecord
	Payloads               []Payload
	Operation, CommandKey  string
	CommandDigest          []byte
	Result                 BonusResult
	Audit                  organization.Audit
}

type BonusReader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	CompensationAggregate(context.Context, string, string) (Aggregate, error)
	BonusSnapshot(context.Context, string, string) (BonusSnapshot, error)
	BonusAggregate(context.Context, string, string) (BonusAggregateRecord, error)
	BonusSnapshotPage(context.Context, string, string, BonusPageQuery) (BonusSnapshotPage, error)
	BonusPayload(context.Context, string, string) (Payload, error)
	BonusCommandReceipt(context.Context, string, string, string, string) (BonusResult, []byte, bool, error)
	BonusPaymentByDigest(context.Context, string, string, int64, []byte) (BonusPaymentRecord, bool, error)
	BonusHMACReady(context.Context, string) (int64, string, error)
}

type BonusTx interface {
	Tx
	BonusReader
	LockSubjects(context.Context, string, []string) error
	LockBonusEmployee(context.Context, string, string) error
	LockCompensationEmployee(context.Context, string, string) error
	CommitBonus(context.Context, BonusWrite) error
}

type BonusStore interface {
	BonusReader
	WithBonusTx(context.Context, string, func(BonusTx) error) error
}

type BonusHMACMaintenanceApproval struct {
	ApprovedBySubjectID string
	RequestID           string
	ApprovalDigest      []byte
}

type BonusHMACMaintenanceStore interface {
	BonusStore
	ReindexBonusPaymentHMAC(context.Context, string, int64, string, int, BonusHMACMaintenanceApproval, func(BonusPaymentRecord) ([]byte, error)) error
}
