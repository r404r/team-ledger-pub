package interview

import (
	"context"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"time"
)

type Request struct {
	TokenHash               []byte
	Purpose, Key, RequestID string
}
type Party struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Permission struct {
	Capability string `json:"capability"`
	Category   string `json:"category"`
}
type CreateCommand struct {
	ScheduledAt     string  `json:"scheduled_at"`
	Participants    []Party `json:"participants"`
	Backfilled      bool    `json:"backfilled"`
	ActualStartedAt *string `json:"actual_started_at"`
	ActualEndedAt   *string `json:"actual_ended_at"`
}
type TransitionCommand struct {
	Action           string  `json:"action"`
	ExpectedRevision string  `json:"expected_revision"`
	ActualStartedAt  *string `json:"actual_started_at"`
	ActualEndedAt    *string `json:"actual_ended_at"`
	Backfilled       bool    `json:"backfilled"`
	Reason           string  `json:"reason"`
}
type ListQuery struct {
	From, To, Status, Cursor string
	Limit                    int
}
type DetailQuery struct {
	IncludeSections  []string
	IncludeActions   bool
	Category, Cursor string
	Limit            int
}
type InterviewView struct {
	ID              string     `json:"id"`
	EmployeeID      string     `json:"employee_id"`
	Status          string     `json:"status"`
	Revision        string     `json:"revision"`
	ScheduledAt     time.Time  `json:"scheduled_at"`
	ActualStartedAt *time.Time `json:"actual_started_at"`
	ActualEndedAt   *time.Time `json:"actual_ended_at"`
	Backfilled      bool       `json:"backfilled"`
	RecordedAt      time.Time  `json:"recorded_at"`
	AuthorSubjectID string     `json:"author_subject_id"`
	Participants    []Party    `json:"participants"`
}
type ListView struct {
	Items       []InterviewView `json:"items"`
	NextCursor  *string         `json:"next_cursor"`
	AsOf        string          `json:"as_of"`
	Consistency string          `json:"consistency"`
	Permissions []Permission    `json:"permissions"`
}
type DetailView struct {
	Interview       InterviewView        `json:"interview"`
	InterviewEvents []InterviewEventView `json:"interview_events"`
	Sections        []SectionView        `json:"sections"`
	ActionItems     []ActionView         `json:"action_items"`
	Permissions     []Permission         `json:"permissions"`
	NextCursor      *string              `json:"next_cursor"`
}
type InterviewEventView struct {
	ID              string     `json:"id"`
	Status          string     `json:"status"`
	Revision        string     `json:"revision"`
	AuthorSubjectID string     `json:"author_subject_id"`
	RecordedAt      time.Time  `json:"recorded_at"`
	ActualStartedAt *time.Time `json:"actual_started_at"`
	ActualEndedAt   *time.Time `json:"actual_ended_at"`
	Backfilled      bool       `json:"backfilled"`
	Reason          *string    `json:"reason,omitempty"`
}
type SectionView struct {
	HeadID             string     `json:"head_id,omitempty"`
	Category           string     `json:"category"`
	HeadRevision       *string    `json:"head_revision"`
	Versions           []NoteView `json:"versions"`
	DraftVersionID     *string    `json:"draft_version_id,omitempty"`
	PublishedVersionID *string    `json:"published_version_id,omitempty"`
}
type SourceRef struct {
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	ExpectedVersion string `json:"expected_version"`
}
type NoteCommand struct {
	HeadID               *string     `json:"head_id"`
	Category             string      `json:"category"`
	ExpectedHeadRevision string      `json:"expected_head_revision"`
	Text                 string      `json:"text"`
	EditReason           string      `json:"edit_reason"`
	Action               string      `json:"action"`
	SupersedesVersionID  *string     `json:"supersedes_version_id"`
	SourceRefs           []SourceRef `json:"source_refs"`
	ConfirmMinimized     bool        `json:"confirm_minimized"`
}
type NoteView struct {
	ID                  string      `json:"id"`
	HeadID              string      `json:"head_id,omitempty"`
	InterviewID         string      `json:"interview_id"`
	EmployeeID          string      `json:"employee_id"`
	Category            string      `json:"category"`
	Status              string      `json:"status"`
	VersionNo           string      `json:"version_no"`
	AuthorSubjectID     string      `json:"author_subject_id"`
	RecordedAt          time.Time   `json:"recorded_at"`
	SupersedesVersionID *string     `json:"supersedes_version_id,omitempty"`
	Text                string      `json:"text"`
	EditReason          string      `json:"edit_reason"`
	SourceRefs          []SourceRef `json:"source_refs"`
}
type ActionCommand struct {
	ExpectedRevision  string      `json:"expected_revision"`
	MinimalSharedText string      `json:"minimal_shared_text"`
	Owner             Party       `json:"owner"`
	DueDate           *string     `json:"due_date"`
	SourceRefs        []SourceRef `json:"source_refs"`
	ConfirmMinimized  bool        `json:"confirm_minimized"`
}
type ActionTransitionCommand struct {
	Action           string `json:"action"`
	ExpectedRevision string `json:"expected_revision"`
	SafeBlockerText  string `json:"safe_blocker_text"`
}
type ActionEventView struct {
	ID              string    `json:"id"`
	Status          string    `json:"status"`
	Revision        string    `json:"revision"`
	AuthorSubjectID string    `json:"author_subject_id"`
	RecordedAt      time.Time `json:"recorded_at"`
	SafeBlockerText string    `json:"safe_blocker_text"`
}
type ActionView struct {
	ID                string            `json:"id"`
	InterviewID       string            `json:"interview_id"`
	EmployeeID        string            `json:"employee_id"`
	Revision          string            `json:"revision"`
	Status            string            `json:"status"`
	MinimalSharedText string            `json:"minimal_shared_text"`
	SafeBlockerText   string            `json:"safe_blocker_text"`
	Owner             Party             `json:"owner"`
	DueDate           *string           `json:"due_date"`
	Overdue           bool              `json:"overdue"`
	RecordedAt        time.Time         `json:"recorded_at"`
	SourceRefs        []SourceRef       `json:"source_refs"`
	Events            []ActionEventView `json:"events"`
}
type Result struct {
	ID                string  `json:"id"`
	Status            string  `json:"status,omitempty"`
	Revision          string  `json:"revision,omitempty"`
	HeadID            *string `json:"head_id,omitempty"`
	HeadRevision      *string `json:"head_revision,omitempty"`
	VersionNo         *string `json:"version_no,omitempty"`
	InterviewRevision *string `json:"interview_revision,omitempty"`
}
type ExportObject struct {
	Kind             string `json:"kind"`
	ID               string `json:"id"`
	ExpectedRevision string `json:"expected_revision"`
}
type ExportCommand struct {
	Objects []ExportObject `json:"objects"`
	Format  string         `json:"format"`
}
type ExportEvent struct {
	Kind        string         `json:"kind"`
	ExportID    string         `json:"export_id,omitempty"`
	Status      string         `json:"status,omitempty"`
	NoteVersion *NoteView      `json:"note_version,omitempty"`
	ActionItem  *ActionView    `json:"action_item,omitempty"`
	Interview   *InterviewView `json:"interview,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	EncodedJSON []byte         `json:"-"`
}

// Records carry no plaintext; payloads use an independently configured cipher.
type Record struct {
	InterviewView
	OrgID  string
	Number int64
}
type Head struct {
	OrgID, ID, InterviewID, EmployeeID, Category, DraftID, PublishedID string
	Revision, ACLEpoch                                                 int64
}
type Version struct {
	NoteView
	// Canonical ownership survives redaction of the separately released NoteView.
	HeadID              string
	OrgID, PayloadID    string
	Number, SourceEpoch int64
	ContentDigest       []byte
}
type ActionRecord struct {
	ActionView
	OrgID, PayloadID string
	Number           int64
	EventRecords     []Event
}
type Event struct {
	ActionEventView
	OrgID, ActionID, InterviewID, EmployeeID, PayloadID string
	Number                                              int64
}
type TransitionEvent struct {
	OrgID, ID, InterviewID, EmployeeID, Status, AuthorSubjectID, PayloadID string
	Revision                                                               int64
	ActualStartedAt, ActualEndedAt                                         *time.Time
	Backfilled                                                             bool
	RecordedAt                                                             time.Time
}
type Payload struct {
	ID         string
	Envelope   sensitive.Envelope
	RecordedAt time.Time
}
type SourceFact struct {
	SourceRef
	Category, EmployeeID string
	Epoch                int64
}
type Receipt struct {
	Digest []byte
	Result Result
}
type Scope struct {
	Broad                                bool
	Interviews, Heads, Versions, Actions []string
}
type Write struct {
	Interview                 *Record
	ExpectedInterviewRevision int64
	Head                      *Head
	ExpectedHeadRevision      int64
	Version                   *Version
	Action                    *ActionRecord
	ExpectedActionRevision    int64
	Event                     *Event
	Transition                *TransitionEvent
	Payloads                  []Payload
	Sources                   []SourceFact
}
type Reader interface {
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	Employee(context.Context, string) (organization.Employee, error)
	GraphState(context.Context, string) (organization.Graph, error)
	Interview(context.Context, string, string) (Record, error)
	InterviewEvents(context.Context, string, string) ([]TransitionEvent, error)
	InterviewHead(context.Context, string, string, string) (Head, bool, error)
	InterviewVersion(context.Context, string, string) (Version, error)
	InterviewAction(context.Context, string, string) (ActionRecord, error)
	InterviewPayload(context.Context, string, string) (Payload, error)
	InterviewSources(context.Context, string, string) ([]SourceFact, error)
	InterviewReceipt(context.Context, string, string, string, string) (Receipt, bool, error)
	InterviewParty(context.Context, string, Party, bool, string) (bool, error)
	InterviewList(context.Context, string, string, ListQuery, Scope, time.Time, time.Time, string, int) ([]Record, error)
	InterviewVersions(context.Context, string, string, string, Scope, string, int) ([]Version, error)
	InterviewActions(context.Context, string, string, Scope, string, int) ([]ActionRecord, error)
}
type Tx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	LockInterviewEmployee(context.Context, string, string) error
	CommitInterview(context.Context, Write) error
	SaveInterviewReceipt(context.Context, string, string, string, string, Receipt) error
	Audit(context.Context, organization.Audit) error
}
type Store interface {
	Reader
	WithInterviewTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, organization.Audit) error
}
