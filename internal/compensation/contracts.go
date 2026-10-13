package compensation

import (
	"context"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"time"
)

type Service struct {
	Store                Store
	Cipher               sensitive.Cipher
	DigestKey, CursorKey []byte
	BonusHMACKeys        map[int64][]byte
	BonusHMACKeyIDs      map[int64]string
	BonusHMACActive      int64
	Policy               Policy
	Now                  func() time.Time
	Batches              BatchStore
}
type Policy struct {
	Enabled                bool              `json:"enabled"`
	Currencies             map[string]int    `json:"currencies"`
	Units                  []string          `json:"units"`
	PaymentFrequencies     []string          `json:"payment_frequencies"`
	TaxBases               []string          `json:"tax_bases"`
	RoundingModes          []string          `json:"rounding_modes"`
	ControlledBonusSources []string          `json:"controlled_bonus_sources,omitempty"`
	SpecialReasonCatalog   map[string]string `json:"special_reason_catalog,omitempty"`
}
type Request struct {
	TokenHash               []byte
	Purpose, Key, RequestID string
}
type Permission struct {
	Capability string `json:"capability"`
	Category   string `json:"category"`
}
type Component struct {
	Code             string  `json:"code"`
	Unit             string  `json:"unit"`
	PaymentFrequency string  `json:"payment_frequency"`
	TaxBasis         string  `json:"tax_basis"`
	AmountMinor      *string `json:"amount_minor"`
	Rate             *string `json:"rate"`
}
type Terms struct {
	Currency         string      `json:"currency"`
	Scale            int         `json:"scale"`
	AmountMinor      *string     `json:"amount_minor"`
	Rate             *string     `json:"rate"`
	Unit             string      `json:"unit"`
	PaymentFrequency string      `json:"payment_frequency"`
	TaxBasis         string      `json:"tax_basis"`
	Components       []Component `json:"components"`
}
type BeforeRef struct {
	TermID    *string `json:"term_id"`
	MemberKey *string `json:"member_key"`
}
type CorrectionMember struct {
	MemberKey       string     `json:"member_key"`
	Action          string     `json:"action"`
	OriginalEventID string     `json:"original_event_id"`
	EffectiveDate   string     `json:"effective_date"`
	BeforeRef       *BeforeRef `json:"before_ref"`
	After           *Terms     `json:"after"`
}
type ProposalCommand struct {
	Kind          string             `json:"kind"`
	EffectiveDate string             `json:"effective_date"`
	CompRevision  string             `json:"comp_revision"`
	BeforeTermID  *string            `json:"before_term_id"`
	After         *Terms             `json:"after"`
	Reason        string             `json:"reason"`
	Members       []CorrectionMember `json:"members"`
}
type DraftCommand struct {
	Kind          string             `json:"kind"`
	EffectiveDate string             `json:"effective_date"`
	CompRevision  string             `json:"comp_revision"`
	BeforeTermID  *string            `json:"before_term_id"`
	After         *Terms             `json:"after"`
	Reason        string             `json:"reason"`
	Members       []CorrectionMember `json:"members"`
	Revision      string             `json:"revision"`
}
type TransitionCommand struct {
	Action         string `json:"action"`
	Revision       string `json:"revision"`
	CompRevision   string `json:"comp_revision"`
	DecisionReason string `json:"decision_reason"`
}
type TermView struct {
	ID            string  `json:"id"`
	Revision      string  `json:"revision"`
	EmployeeID    string  `json:"employee_id"`
	EffectiveDate string  `json:"effective_date"`
	ValidTo       *string `json:"valid_to"`
	EventID       string  `json:"event_id"`
	Terms         Terms   `json:"terms"`
}
type ProposalRevisionView struct {
	Revision       string          `json:"revision"`
	Status         string          `json:"status"`
	RecordedAt     string          `json:"recorded_at"`
	Command        ProposalCommand `json:"command"`
	DecisionReason string          `json:"decision_reason"`
}
type ProposalView struct {
	ID              string             `json:"id"`
	EmployeeID      string             `json:"employee_id"`
	Kind            string             `json:"kind"`
	Status          string             `json:"status"`
	Revision        string             `json:"revision"`
	CompRevision    string             `json:"comp_revision"`
	AuthorSubjectID string             `json:"author_subject_id"`
	RecordedAt      string             `json:"recorded_at"`
	EffectiveDate   string             `json:"effective_date"`
	BeforeTermID    *string            `json:"before_term_id"`
	After           *Terms             `json:"after"`
	Reason          string             `json:"reason"`
	Members         []CorrectionMember `json:"members"`
	DecisionReason  string             `json:"decision_reason"`
	ApprovalID      *string            `json:"approval_id"`
	Permissions     []Permission       `json:"permissions"`
}
type CurrentQuery struct {
	AsOf        string
	FutureLimit int
}
type CurrentView struct {
	EmployeeID         string       `json:"employee_id"`
	AsOf               string       `json:"as_of"`
	CompRevision       string       `json:"comp_revision"`
	AuthorizationUntil string       `json:"authorization_until"`
	CurrentTerm        *TermView    `json:"current_term"`
	FutureTerms        []TermView   `json:"future_terms"`
	Permissions        []Permission `json:"permissions"`
}
type ChangesQuery struct {
	From, To, RecordKind, ProposalID, Status, Cursor string
	Limit                                            int
}
type ApprovalEventView struct {
	ID              string    `json:"id"`
	Revision        string    `json:"revision"`
	Kind            string    `json:"kind"`
	EffectiveDate   string    `json:"effective_date"`
	BeforeTermID    *string   `json:"before_term_id"`
	AfterTermID     *string   `json:"after_term_id"`
	CorrectsEventID *string   `json:"corrects_event_id"`
	Before          *TermView `json:"before"`
	After           *TermView `json:"after"`
	MemberKey       string    `json:"member_key"`
}
type ApprovalView struct {
	ID                string              `json:"id"`
	EmployeeID        string              `json:"employee_id"`
	ProposalID        string              `json:"proposal_id"`
	ProposalRevision  string              `json:"proposal_revision"`
	CompRevision      string              `json:"comp_revision"`
	ApproverSubjectID string              `json:"approver_subject_id"`
	ApprovedAt        string              `json:"approved_at"`
	DecisionReason    string              `json:"decision_reason"`
	Reason            string              `json:"reason"`
	Events            []ApprovalEventView `json:"events"`
	Members           []MemberMapping     `json:"members"`
}
type ChangesView struct {
	RecordKind         string                 `json:"record_kind"`
	CompRevision       string                 `json:"comp_revision"`
	Proposals          []ProposalView         `json:"proposals"`
	Approvals          []ApprovalView         `json:"approvals"`
	Revisions          []ProposalRevisionView `json:"revisions"`
	NextCursor         string                 `json:"next_cursor"`
	AuthorizationUntil string                 `json:"authorization_until"`
}
type MemberMapping struct {
	MemberKey string  `json:"member_key"`
	EventID   string  `json:"event_id"`
	TermID    *string `json:"term_id"`
}
type Result struct {
	ID           string          `json:"id"`
	Revision     string          `json:"revision"`
	CompRevision string          `json:"comp_revision"`
	Status       string          `json:"status"`
	Proposal     *ProposalView   `json:"proposal"`
	Members      []MemberMapping `json:"members"`
}
type ExportObject struct {
	Kind             string `json:"kind"`
	ID               string `json:"id"`
	ExpectedRevision string `json:"expected_revision"`
}
type ExportCommand struct {
	Format  string         `json:"format"`
	Objects []ExportObject `json:"objects"`
}
type ExportEvent struct {
	EncodedJSON []byte `json:"-"`
}

// Metadata records never contain financial amounts or reasons.
type Aggregate struct {
	OrgID, EmployeeID string
	Revision          int64
}
type ProposalRecord struct {
	OrgID, EmployeeID, ID, Kind, Status, AuthorSubjectID, RevisionID, PayloadID, EffectiveDate string
	BeforeTermID                                                                               *string
	Revision, BasisRevision                                                                    int64
	RecordedAt                                                                                 time.Time
	ApprovalID                                                                                 *string
}
type RevisionRecord struct {
	OrgID, EmployeeID, ID, ProposalID, PayloadID, Status, Kind, EffectiveDate, ActorSubjectID string
	BeforeTermID                                                                              *string
	Revision, BasisRevision                                                                   int64
	RecordedAt                                                                                time.Time
}
type ApprovalRecord struct {
	OrgID, EmployeeID, ID, ProposalID, ProposalRevisionID, ApproverSubjectID, AuthorSubjectID, PayloadID string
	ProposalRevision, BasisRevision, CompRevision                                                        int64
	RecordedAt                                                                                           time.Time
}
type EventRecord struct {
	OrgID, EmployeeID, ID, ApprovalID, Kind, EffectiveDate, MemberKey string
	BeforeTermID, AfterTermID, CorrectsEventID                        *string
	Sequence                                                          int64
}
type TermRecord struct {
	OrgID, EmployeeID, ID, EventID, ApprovalID, PayloadID, EffectiveDate string
	Version                                                              int64
}
type ScheduleRecord struct {
	OrgID, EmployeeID, EffectiveDate, TermID, EventID string
	ValidTo                                           *string
	Revision                                          int64
}
type Payload struct {
	ID         string
	Envelope   sensitive.Envelope
	RecordedAt time.Time
}
type Receipt struct {
	Digest []byte
	Result Result
}
type Scope struct {
	Broad                    bool
	Proposals, Events, Terms []string
}
type Write struct {
	Aggregate                Aggregate
	ExpectedCompRevision     int64
	Proposal                 ProposalRecord
	ExpectedProposalRevision int64
	Revision                 RevisionRecord
	Approval                 *ApprovalRecord
	Events                   []EventRecord
	Terms                    []TermRecord
	Schedule                 []ScheduleRecord
	ReplaceSchedule          bool
	Payloads                 []Payload
}
type Reader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	Employee(context.Context, string) (organization.Employee, error)
	GraphState(context.Context, string) (organization.Graph, error)
	CompensationAggregate(context.Context, string, string) (Aggregate, error)
	CompensationProposal(context.Context, string, string) (ProposalRecord, error)
	CompensationRevisions(context.Context, string, string, int64, int) ([]RevisionRecord, error)
	CompensationApproval(context.Context, string, string) (ApprovalRecord, error)
	CompensationEvent(context.Context, string, string) (EventRecord, error)
	CompensationTerm(context.Context, string, string) (TermRecord, error)
	CompensationEvents(context.Context, string, string) ([]EventRecord, error)
	CompensationApprovalEvents(context.Context, string, string, Scope, int) ([]EventRecord, error)
	CompensationSchedule(context.Context, string, string, CurrentQuery) ([]ScheduleRecord, error)
	CompensationPayload(context.Context, string, string) (Payload, error)
	CompensationReceipt(context.Context, string, string, string, string) (Receipt, bool, error)
	CompensationProposals(context.Context, string, string, ChangesQuery, Scope, time.Time, time.Time, string, int) ([]ProposalRecord, error)
	CompensationApprovals(context.Context, string, string, ChangesQuery, Scope, time.Time, time.Time, string, int) ([]ApprovalRecord, error)
}
type Tx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	LockCompensationEmployee(context.Context, string, string) error
	CommitCompensation(context.Context, Write) error
	SaveCompensationReceipt(context.Context, string, string, string, string, Receipt) error
	Audit(context.Context, organization.Audit) error
}
type Store interface {
	Reader
	WithCompensationTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, organization.Audit) error
}
