package assessment

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type Request struct {
	TokenHash               []byte
	Purpose, Key, RequestID string
}

type Cadence struct {
	Unit  string `json:"unit"`
	Count int    `json:"count"`
}

type PauseInterval struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type StandingPolicyCommand struct {
	ServiceSubjectID string `json:"service_subject_id"`
	Audience         string `json:"audience"`
	ExpiresAt        string `json:"expires_at"`
	ProviderPolicyID string `json:"provider_policy_id"`
	TemplateVersion  string `json:"template_version"`
}

type PolicyCommand struct {
	ExpectedRevision string                 `json:"expected_revision"`
	Cadence          Cadence                `json:"cadence"`
	AnchorDate       string                 `json:"anchor_date"`
	Timezone         string                 `json:"timezone"`
	DueOffsetDays    int                    `json:"due_offset_days"`
	LocalDueTime     string                 `json:"local_due_time"`
	WindowThrough    string                 `json:"window_through"`
	PauseIntervals   []PauseInterval        `json:"pause_intervals"`
	Purpose          string                 `json:"purpose"`
	AIMode           string                 `json:"ai_mode"`
	RequiredFields   []string               `json:"required_fields"`
	Standing         *StandingPolicyCommand `json:"standing_policy,omitempty"`
}

type Policy struct {
	OrgID, EmployeeID string
	Revision          int64
	PolicyCommand
	UpdatedBy string
	UpdatedAt time.Time
}

type PolicyView struct {
	Revision       string                 `json:"revision"`
	Cadence        Cadence                `json:"cadence"`
	AnchorDate     string                 `json:"anchor_date"`
	Timezone       string                 `json:"timezone"`
	DueOffsetDays  int                    `json:"due_offset_days"`
	LocalDueTime   string                 `json:"local_due_time"`
	WindowThrough  string                 `json:"window_through"`
	PauseIntervals []PauseInterval        `json:"pause_intervals"`
	Purpose        string                 `json:"purpose"`
	AIMode         string                 `json:"ai_mode"`
	RequiredFields []string               `json:"required_fields"`
	Standing       *StandingPolicyCommand `json:"standing_policy,omitempty"`
	UpdatedBy      string                 `json:"updated_by"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type Window struct {
	OrgID, EmployeeID, ID string
	PolicyRevision        int64
	LocalStart, LocalEnd  string
	StartAt, EndAt, DueAt time.Time
	Paused                bool
}

type WindowView struct {
	ID             string    `json:"id"`
	PolicyRevision string    `json:"policy_revision"`
	LocalStart     string    `json:"local_start"`
	LocalEnd       string    `json:"local_end"`
	StartAt        time.Time `json:"start_at"`
	EndAt          time.Time `json:"end_at"`
	DueAt          time.Time `json:"due_at"`
	Paused         bool      `json:"paused"`
}

type StatusQuery struct {
	WindowID, From, To string
}

type Coverage struct {
	Interviews string `json:"interviews"`
	Actions    string `json:"actions"`
	Notes      string `json:"notes"`
}

type DeterministicFacts struct {
	ScheduledCount     int `json:"scheduled_count"`
	OccurredCount      int `json:"occurred_count"`
	BackfilledCount    int `json:"backfilled_count"`
	CompleteCount      int `json:"complete_count"`
	IncompleteCount    int `json:"incomplete_count"`
	UnknownCount       int `json:"unknown_count"`
	OpenActionCount    int `json:"open_action_count"`
	DueActionCount     int `json:"due_action_count"`
	OverdueActionCount int `json:"overdue_action_count"`
}

type WindowStatus struct {
	Window WindowView         `json:"window"`
	State  string             `json:"state"`
	Facts  DeterministicFacts `json:"facts"`
}

type StatusView struct {
	State         string         `json:"state"`
	Policy        *PolicyView    `json:"policy"`
	Items         []WindowStatus `json:"items"`
	Coverage      Coverage       `json:"coverage"`
	AIState       string         `json:"ai_state"`
	AIBlockReason string         `json:"ai_block_reason,omitempty"`
}

type InterviewFact struct {
	ID                             string
	Status                         string
	ScheduledAt                    time.Time
	ActualStartedAt, ActualEndedAt *time.Time
	Backfilled                     bool
	HasPublishedSharedNote         bool
}

type ActionFact struct {
	Status     string
	DueDate    *string
	OccurredAt time.Time
}

type Receipt struct {
	Digest []byte
	Policy Policy
}

type Reader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	Employee(context.Context, string) (organization.Employee, error)
	AssessmentPolicy(context.Context, string, string) (Policy, bool, error)
	AssessmentWindows(context.Context, string, string, int64) ([]Window, error)
	AssessmentWindow(context.Context, string, string, string) (Window, error)
	AssessmentInterviewFacts(context.Context, string, string, Window, bool) ([]InterviewFact, error)
	AssessmentActionFacts(context.Context, string, string, bool) ([]ActionFact, error)
	AssessmentReceipt(context.Context, string, string, string) (Receipt, bool, error)
}

type Tx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	LockInterviewEmployee(context.Context, string, string) error
	SaveAssessmentPolicy(context.Context, Policy, []Window) error
	SaveAssessmentReceipt(context.Context, string, string, string, Receipt) error
	Audit(context.Context, organization.Audit) error
	AssessmentResultCurrent(context.Context, string, string, string, int64, []byte) error
}

type Store interface {
	Reader
	WithAssessmentTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, organization.Audit) error
}

type StructuredInput struct {
	Window       WindowView         `json:"window"`
	Facts        DeterministicFacts `json:"facts"`
	Template     string             `json:"template"`
	SourceDigest string             `json:"source_digest"`
}

type InputView struct {
	ID          string          `json:"id"`
	EmployeeID  string          `json:"employee_id"`
	WindowID    string          `json:"window_id"`
	Status      string          `json:"status"`
	RequestedBy string          `json:"requested_by"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	ApprovedAt  time.Time       `json:"approved_at,omitempty"`
	Input       StructuredInput `json:"input"`
}

type AssessmentCommand struct {
	WindowID string `json:"window_id"`
}

type ApproveCommand struct {
	InputID          string `json:"input_id"`
	ProviderPolicyID string `json:"provider_policy_id"`
	Audience         string `json:"audience"`
}

type Job struct {
	OrgID, EmployeeID, ID, InputID, WindowID           string
	ResultID                                           string
	ProviderPolicyID, Audience, State, LeaseOwner      string
	Attempt, MaxAttempts                               int
	Fence                                              int64
	GenerationDigest, SourceDigest, LeaseTokenHash     []byte
	LeaseExpiresAt, DeadlineAt, CreatedAt, CompletedAt time.Time
	ErrorCode                                          string
	Input                                              StructuredInput
}

type JobView struct {
	ID               string    `json:"id"`
	EmployeeID       string    `json:"employee_id"`
	ResultID         string    `json:"result_id,omitempty"`
	WindowID         string    `json:"window_id"`
	State            string    `json:"state"`
	ProviderPolicyID string    `json:"provider_policy_id"`
	Audience         string    `json:"audience"`
	Attempt          int       `json:"attempt"`
	MaxAttempts      int       `json:"max_attempts"`
	CreatedAt        time.Time `json:"created_at"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
	ErrorCode        string    `json:"error_code,omitempty"`
}

type WorkerRequest struct {
	WorkerID, Key, RequestID string
	CertDigest               []byte
}

type Lease struct {
	JobID            string          `json:"job_id"`
	EmployeeID       string          `json:"employee_id"`
	ProviderPolicyID string          `json:"provider_policy_id"`
	Audience         string          `json:"audience"`
	Attempt          int             `json:"attempt"`
	Fence            int64           `json:"fence"`
	Token            string          `json:"token"`
	ExpiresAt        time.Time       `json:"expires_at"`
	DeadlineAt       time.Time       `json:"deadline_at"`
	Input            StructuredInput `json:"input"`
}

type Citation struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ResultDocument struct {
	Summary string     `json:"summary"`
	Claims  []string   `json:"claims"`
	Sources []Citation `json:"sources"`
}

type Result struct {
	OrgID, EmployeeID, ID, JobID, Status string
	Revision                             int64
	Document                             ResultDocument
	SourceDigest                         []byte
	CreatedAt, UpdatedAt                 time.Time
}

type ResultView struct {
	ID        string         `json:"id"`
	JobID     string         `json:"job_id"`
	Status    string         `json:"status"`
	Revision  string         `json:"revision"`
	Document  ResultDocument `json:"document"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ResultCommand struct {
	ResultID         string         `json:"result_id"`
	ExpectedRevision string         `json:"expected_revision"`
	Action           string         `json:"action"`
	Document         ResultDocument `json:"document"`
}

type ProviderPolicy struct {
	ID, Audience string
	Enabled      bool
	ExpiresAt    time.Time
}

type EncryptedResult struct {
	Result   Result
	Envelope sensitive.Envelope
}

type ExportObject = organization.ExportObject
type ExportCommand = organization.ExportCommand
type ExportEvent struct {
	EncodedJSON []byte `json:"-"`
}
type ExportTx interface {
	organization.ExportTx
	AssessmentResult(context.Context, string, string) (Result, sensitive.Envelope, error)
}
type ExportStore interface {
	organization.ExportStore
	AutomationStore
	WithAssessmentExportTx(context.Context, string, func(ExportTx) error) error
}

type ServiceIdentity struct {
	TokenHash []byte
}

type ScheduledWindow struct {
	Window
	ServiceSubjectID, ApprovedBy, Audience, ProviderPolicyID string
	ExpiresAt                                                time.Time
}

type ScanReport struct {
	Scanned, Enqueued, Blocked int
}

type WorkerIdentity struct {
	OrgID      string
	CertDigest []byte
}

type AutomationStore interface {
	Reader
	AssessmentSourceEpoch(context.Context, string, string) (int64, error)
	CreateAssessmentInput(context.Context, authz.Snapshot, []byte, int64, Window, StructuredInput, []byte, []byte, time.Time, organization.Audit) (InputView, error)
	ApproveAssessmentInput(context.Context, authz.Snapshot, string, string, string, time.Time, organization.Audit) (Job, error)
	ClaimAssessmentJob(context.Context, string, string, string, []byte, time.Time, time.Duration) (Job, string, error)
	HeartbeatAssessmentJob(context.Context, string, string, string, int64, []byte, time.Time, time.Duration) (time.Time, error)
	AssessmentJobResultReceipt(context.Context, string, string, string, []byte) (Result, bool, error)
	CompleteAssessmentJob(context.Context, string, string, string, int64, []byte, []byte, EncryptedResult, time.Time) (Result, error)
	FailAssessmentJob(context.Context, string, string, string, int64, []byte, string, time.Time) error
	AssessmentResult(context.Context, string, string) (Result, sensitive.Envelope, error)
	SaveAssessmentResult(context.Context, authz.Snapshot, []byte, Result, sensitive.Envelope, string, time.Time, organization.Audit) (Result, error)
	ListAssessmentJobs(context.Context, string, string) ([]Job, error)
	DueAssessmentWindows(context.Context, time.Time) ([]ScheduledWindow, error)
	CreateScheduledAssessment(context.Context, authz.Snapshot, []byte, int64, ScheduledWindow, StructuredInput, []byte, []byte, time.Time) (bool, error)
	RecordAssessmentScan(context.Context, ScheduledWindow, string, time.Time) error
}
