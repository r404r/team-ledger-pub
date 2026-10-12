package assessment

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
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

type PolicyCommand struct {
	ExpectedRevision string          `json:"expected_revision"`
	Cadence          Cadence         `json:"cadence"`
	AnchorDate       string          `json:"anchor_date"`
	Timezone         string          `json:"timezone"`
	DueOffsetDays    int             `json:"due_offset_days"`
	LocalDueTime     string          `json:"local_due_time"`
	WindowThrough    string          `json:"window_through"`
	PauseIntervals   []PauseInterval `json:"pause_intervals"`
	Purpose          string          `json:"purpose"`
	AIMode           string          `json:"ai_mode"`
	RequiredFields   []string        `json:"required_fields"`
}

type Policy struct {
	OrgID, EmployeeID string
	Revision          int64
	PolicyCommand
	UpdatedBy string
	UpdatedAt time.Time
}

type PolicyView struct {
	Revision       string          `json:"revision"`
	Cadence        Cadence         `json:"cadence"`
	AnchorDate     string          `json:"anchor_date"`
	Timezone       string          `json:"timezone"`
	DueOffsetDays  int             `json:"due_offset_days"`
	LocalDueTime   string          `json:"local_due_time"`
	WindowThrough  string          `json:"window_through"`
	PauseIntervals []PauseInterval `json:"pause_intervals"`
	Purpose        string          `json:"purpose"`
	AIMode         string          `json:"ai_mode"`
	RequiredFields []string        `json:"required_fields"`
	UpdatedBy      string          `json:"updated_by"`
	UpdatedAt      time.Time       `json:"updated_at"`
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
}

type Store interface {
	Reader
	WithAssessmentTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, organization.Audit) error
}
