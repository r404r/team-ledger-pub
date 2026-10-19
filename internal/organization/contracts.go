package organization

import (
	"context"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type Contact struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}
type Profile = WorkforceProfile
type Lifecycle struct {
	ValidFrom string  `json:"valid_from"`
	ValidTo   *string `json:"valid_to"`
}
type InitialEmployment struct {
	LegalEntityID string `json:"legal_entity_id"`
	LocationCode  string `json:"location_code"`
}
type InitialEducation struct {
	Level string `json:"level"`
}
type InitialJobAssignment struct {
	DepartmentID  string           `json:"department_id"`
	JobFamilyID   *string          `json:"job_family_id,omitempty"`
	CareerLevelID *string          `json:"career_level_id,omitempty"`
	Position      *PositionPayload `json:"position,omitempty"`
}

type CreateCommand struct {
	Profile                 Profile               `json:"profile"`
	Lifecycle               Lifecycle             `json:"lifecycle"`
	StaffCode               *string               `json:"staff_code,omitempty"`
	Employment              *InitialEmployment    `json:"employment,omitempty"`
	Education               *InitialEducation     `json:"education,omitempty"`
	JobAssignment           *InitialJobAssignment `json:"job_assignment,omitempty"`
	ManagerEmployeeID       *string               `json:"manager_employee_id,omitempty"`
	ExpectedCatalogRevision *string               `json:"expected_catalog_revision,omitempty"`
	ExpectedGraphRevision   *string               `json:"expected_graph_revision,omitempty"`
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
	ID                string `json:"id"`
	Revision          string `json:"profile_revision"`
	WorkforceRevision string `json:"workforce_revision,omitempty"`
	GraphRevision     string `json:"graph_revision,omitempty"`
}
type View struct {
	ID                string              `json:"id"`
	OrgID             string              `json:"org_id"`
	Revision          string              `json:"profile_revision,omitempty"`
	Lifecycle         Lifecycle           `json:"lifecycle"`
	AsOf              string              `json:"as_of"`
	AuthorizationDate string              `json:"authorization_date"`
	Profile           *Profile            `json:"profile,omitempty"`
	GraphRevision     string              `json:"graph_revision,omitempty"`
	Identifiers       []IdentifierView    `json:"identifiers"`
	Employment        []EmploymentView    `json:"employment"`
	Education         []EducationView     `json:"education"`
	JobAssignments    []JobAssignmentView `json:"job_assignments"`
	ReportingLines    []ReportingView     `json:"reporting_lines"`
	DirectManager     *ReportingView      `json:"direct_manager,omitempty"`
	HOD               *ReportingView      `json:"hod,omitempty"`
}
type Receipt struct {
	Digest []byte
	Result Result
}
type Audit struct {
	ID, OrgID, SubjectID, EmployeeID, GrantID, Operation, Purpose, RequestID, Outcome string
	At                                                                                time.Time
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
type ExportReceipt struct {
	Digest   []byte
	ExportID string
}
type ExportTx interface {
	Reader
	LockSubjects(context.Context, string, []string) error
	ExportReceipt(context.Context, string, string, string, string) (ExportReceipt, bool, error)
	SaveExportReceipt(context.Context, string, string, string, string, ExportReceipt, time.Time) error
	Audit(context.Context, Audit) error
}
type ExportStore interface {
	Store
	WithExportTx(context.Context, string, func(ExportTx) error) error
}

type Reader interface {
	StructureReader
	WorkforceReader
	Security(context.Context, []byte, string, string) (authz.Snapshot, error)
	Employee(context.Context, string) (Employee, error)
	Version(context.Context, string, string, string) (Version, error)
	Receipt(context.Context, string, string, string, string) (Receipt, bool, error)
}
type Tx interface {
	StructureTx
	Reader
	LockSubjects(context.Context, string, []string) error
	Create(context.Context, Employee, Version) error
	Replace(context.Context, Employee, Version, int64) error
	SaveReceipt(context.Context, string, string, string, string, Receipt) error
	Audit(context.Context, Audit) error
	WorkforceReceipt(context.Context, string, string, string, string) (WorkforceCommandReceipt, bool, error)
	CommitCatalogChange(context.Context, string, int64, int64, CatalogWrite) (int64, int64, error)
	CommitWorkforceChange(context.Context, string, int64, int64, map[string]int64, WorkforceWrite) (int64, int64, map[string]int64, error)
	SaveWorkforceReceipt(context.Context, string, string, string, string, WorkforceCommandReceipt) error
}
type Store interface {
	Reader
	WithTx(context.Context, string, func(Tx) error) error
	AuditDenied(context.Context, Audit) error
}
