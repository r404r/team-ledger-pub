package organization

import (
	"context"
	"time"
)

type PositionPayload struct {
	Title        string  `json:"title"`
	PositionCode *string `json:"position_code,omitempty"`
	Description  *string `json:"description,omitempty"`
}
type Relation struct {
	ID, OrgID, Kind, EmployeeID, ManagerEmployeeID, ReportingKind string
	IsPrimary                                                     bool
	Lifecycle                                                     Lifecycle
	EffectiveTo                                                   *string
	Superseded                                                    bool
	ChangeID, EndChangeID, SupersedesID, PayloadID                string
}
type Graph struct {
	OrgID               string
	Revision, AuthEpoch int64
	Employees           []Employee
	Relations           []Relation
}
type StructureChange struct {
	ID, OrgID, SubjectID, ReasonPayloadID string
	RecordedAt                            time.Time
	GraphBefore, GraphAfter               int64
	Items                                 []HistoryRelation
}
type TreeQuery struct {
	AsOf, RootDepartmentID string
	Depth, Limit           int
	IncludeLabels          bool
}
type TreeNode struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Kind      string    `json:"kind"`
	Lifecycle Lifecycle `json:"lifecycle"`
	Label     *string   `json:"label,omitempty"`
}
type TreeEdge struct {
	ID           string  `json:"id"`
	ChildUnitID  string  `json:"child_unit_id"`
	ParentUnitID string  `json:"parent_unit_id"`
	ValidFrom    string  `json:"valid_from"`
	ValidTo      *string `json:"valid_to"`
}
type TreeEmployee struct {
	ID           string   `json:"id"`
	DepartmentID string   `json:"department_id"`
	Profile      *Profile `json:"profile,omitempty"`
}
type TreeView struct {
	OrgID             string         `json:"org_id"`
	AsOf              string         `json:"as_of"`
	AuthorizationDate string         `json:"authorization_date"`
	GraphRevision     string         `json:"graph_revision"`
	AuthEpoch         string         `json:"auth_epoch"`
	Nodes             []TreeNode     `json:"nodes"`
	Edges             []TreeEdge     `json:"edges"`
	Employees         []TreeEmployee `json:"employees"`
}
type ReportingView struct {
	ID                string  `json:"id"`
	EmployeeID        string  `json:"employee_id"`
	ManagerEmployeeID string  `json:"manager_employee_id"`
	Kind              string  `json:"kind"`
	ValidFrom         string  `json:"valid_from"`
	ValidTo           *string `json:"valid_to"`
}
type DirectoryQuery struct {
	AsOf           string `json:"as_of"`
	DepartmentID   string `json:"department_id,omitempty"`
	EmployeeID     string `json:"employee_id,omitempty"`
	Lifecycle      string `json:"lifecycle,omitempty"`
	Q              string `json:"q,omitempty"`
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	IncludeProfile bool   `json:"include_profile,omitempty"`
}
type DirectoryPage struct {
	Items             []View  `json:"items"`
	NextCursor        *string `json:"next_cursor"`
	AsOf              string  `json:"as_of"`
	Consistency       string  `json:"consistency"`
	AuthorizationDate string  `json:"authorization_date"`
	GraphRevision     string  `json:"graph_revision"`
	AuthEpoch         string  `json:"auth_epoch"`
	SearchIncomplete  bool    `json:"search_incomplete"`
}
type DirectoryScope struct {
	Org               bool
	Employees         []string
	Departments       []string
	AuthorizationDate string
}
type HistoryQuery struct {
	From, To, Cursor string
	Limit            int
}
type HistoryRelation struct {
	Action            string           `json:"action"`
	Kind              string           `json:"kind"`
	ID                string           `json:"id"`
	EmployeeID        string           `json:"employee_id,omitempty"`
	ManagerEmployeeID string           `json:"manager_employee_id,omitempty"`
	ReportingKind     string           `json:"reporting_kind,omitempty"`
	IsPrimary         *bool            `json:"is_primary,omitempty"`
	ValidFrom         string           `json:"valid_from,omitempty"`
	ValidTo           *string          `json:"valid_to"`
	EffectiveTo       *string          `json:"effective_to,omitempty"`
	EndDate           *string          `json:"end_date,omitempty"`
	SupersedesID      string           `json:"supersedes_id,omitempty"`
	Superseded        bool             `json:"superseded,omitempty"`
	Position          *PositionPayload `json:"position,omitempty"`
	PayloadID         string           `json:"-"`
}
type HistoryItem struct {
	ID             string            `json:"id"`
	ActorSubjectID string            `json:"actor_subject_id"`
	RecordedAt     time.Time         `json:"recorded_at"`
	GraphBefore    string            `json:"graph_before"`
	GraphAfter     string            `json:"graph_after"`
	Items          []HistoryRelation `json:"items"`
	Reason         *string           `json:"reason,omitempty"`
}
type HistoryPage struct {
	Items             []HistoryItem `json:"items"`
	NextCursor        *string       `json:"next_cursor"`
	From              string        `json:"from,omitempty"`
	To                string        `json:"to,omitempty"`
	AsOf              string        `json:"as_of,omitempty"`
	Consistency       string        `json:"consistency"`
	AuthorizationDate string        `json:"authorization_date"`
	GraphRevision     string        `json:"graph_revision"`
	AuthEpoch         string        `json:"auth_epoch"`
}

type StructureReader interface {
	Graph(context.Context, string) (Graph, error)
	GraphState(context.Context, string) (Graph, error)
	EmployeeRelations(context.Context, string, string, string) ([]Relation, error)
	DirectoryCandidates(context.Context, string, string, DirectoryQuery, DirectoryScope, int) ([]Employee, error)
	StructureHistory(context.Context, string, string, HistoryQuery, time.Time, string, int) ([]StructureChange, error)
}
type StructureTx interface {
	StructureReader
	LockGraph(context.Context, string) error
}
