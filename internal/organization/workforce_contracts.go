package organization

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/sensitive"
	"golang.org/x/text/unicode/norm"
)

const (
	LocationShanghai = "Shanghai"
	LocationWuxi     = "Wuxi"
	LocationTokyo    = "Tokyo"

	EducationMaster   = "Master"
	EducationBachelor = "Bachelor"
	EducationDiploma  = "Diploma"
)

type WorkforceProfile struct {
	LocalName      string   `json:"local_name,omitempty"`
	EnglishName    string   `json:"english_name,omitempty"`
	WorkContact    *Contact `json:"work_contact,omitempty"`
	ProfileSummary string   `json:"profile_summary,omitempty"`
}

type LegalEntityView struct {
	ID             string  `json:"id"`
	VersionID      string  `json:"version_id,omitempty"`
	Code           string  `json:"code"`
	DisplayName    string  `json:"display_name,omitempty"`
	LabelPayloadID string  `json:"-"`
	ValidFrom      string  `json:"valid_from,omitempty"`
	ValidTo        *string `json:"valid_to,omitempty"`
	Active         bool    `json:"active"`
}

type OrgUnitView struct {
	ID             string  `json:"id"`
	VersionID      string  `json:"version_id,omitempty"`
	Code           string  `json:"code"`
	Label          string  `json:"label,omitempty"`
	LabelPayloadID string  `json:"-"`
	Kind           string  `json:"kind"`
	ValidFrom      string  `json:"valid_from"`
	ValidTo        *string `json:"valid_to"`
	Active         bool    `json:"active"`
}

type OrgUnitParentView struct {
	ID           string  `json:"id"`
	ChildUnitID  string  `json:"child_unit_id"`
	ParentUnitID string  `json:"parent_unit_id"`
	ValidFrom    string  `json:"valid_from"`
	ValidTo      *string `json:"valid_to"`
	Active       bool    `json:"active"`
}

type JobFamilyView struct {
	ID        string  `json:"id"`
	VersionID string  `json:"version_id,omitempty"`
	Code      string  `json:"code"`
	Label     string  `json:"label"`
	ValidFrom string  `json:"valid_from,omitempty"`
	ValidTo   *string `json:"valid_to,omitempty"`
	Active    bool    `json:"active"`
}

type CareerLevelView struct {
	ID        string  `json:"id"`
	VersionID string  `json:"version_id,omitempty"`
	Code      string  `json:"code"`
	Label     string  `json:"label"`
	Rank      int     `json:"rank"`
	ValidFrom string  `json:"valid_from,omitempty"`
	ValidTo   *string `json:"valid_to,omitempty"`
	Active    bool    `json:"active"`
}

type EducationLevelView struct {
	Code string `json:"code"`
	Rank int    `json:"rank"`
}

type IdentifierView struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"`
	StaffCode string  `json:"staff_code,omitempty"`
	ValidFrom string  `json:"valid_from"`
	ValidTo   *string `json:"valid_to"`
	PayloadID string  `json:"-"`
}

type EmploymentView struct {
	ID            string  `json:"id"`
	LegalEntityID string  `json:"legal_entity_id"`
	LocationCode  string  `json:"location_code"`
	Kind          string  `json:"kind"`
	ValidFrom     string  `json:"valid_from"`
	ValidTo       *string `json:"valid_to"`
}

type EducationView struct {
	ID          string  `json:"id"`
	Level       string  `json:"level"`
	Institution *string `json:"institution,omitempty"`
	Field       *string `json:"field,omitempty"`
	AwardDate   *string `json:"award_date,omitempty"`
	ValidFrom   string  `json:"valid_from"`
	ValidTo     *string `json:"valid_to"`
	PayloadID   string  `json:"-"`
}

type JobAssignmentView struct {
	ID            string           `json:"id"`
	DepartmentID  string           `json:"department_id"`
	JobFamilyID   *string          `json:"job_family_id,omitempty"`
	CareerLevelID *string          `json:"career_level_id,omitempty"`
	Position      *PositionPayload `json:"position,omitempty"`
	ValidFrom     string           `json:"valid_from"`
	ValidTo       *string          `json:"valid_to"`
	PayloadID     string           `json:"-"`
}

type WorkforceFacts struct {
	Identifiers    []IdentifierView    `json:"identifiers"`
	Employment     []EmploymentView    `json:"employment"`
	Education      []EducationView     `json:"education"`
	JobAssignments []JobAssignmentView `json:"job_assignments"`
	ReportingLines []ReportingView     `json:"reporting_lines"`
}

type WorkforceCatalogQuery struct {
	Kind    string
	AsOf    string
	History bool
	Cursor  string
	Limit   int
}

type WorkforceCatalogs struct {
	CatalogRevision string               `json:"catalog_revision"`
	GraphRevision   string               `json:"graph_revision"`
	AsOf            string               `json:"as_of"`
	History         bool                 `json:"history"`
	NextCursor      *string              `json:"next_cursor"`
	LegalEntities   []LegalEntityView    `json:"legal_entities"`
	Locations       []string             `json:"locations"`
	OrgUnits        []OrgUnitView        `json:"org_units"`
	OrgUnitParents  []OrgUnitParentView  `json:"org_unit_parents"`
	EducationLevels []EducationLevelView `json:"education_levels"`
	JobFamilies     []JobFamilyView      `json:"job_families"`
	CareerLevels    []CareerLevelView    `json:"career_levels"`
}

type WorkforcePayload struct {
	ID         string
	Envelope   sensitive.Envelope
	RecordedAt time.Time
}

type WorkforceReader interface {
	WorkforceCatalogs(context.Context, string, string) (WorkforceCatalogs, error)
	WorkforceCatalogHistory(context.Context, string, string, string, int) (WorkforceCatalogs, string, bool, error)
	WorkforcePayload(context.Context, string, string) (WorkforcePayload, error)
	EmployeeWorkforceFacts(context.Context, string, string, string) (WorkforceFacts, error)
}

// NormalizeStaffCode preserves case, internal whitespace and leading zeroes.
// NFC is the only normalization; visually similar but byte-distinct codes stay distinct.
func NormalizeStaffCode(code string) (string, bool) {
	if !utf8.ValidString(code) || code == "" || strings.TrimSpace(code) != code {
		return "", false
	}
	code = norm.NFC.String(code)
	if len(code) == 0 || len(code) > 64 {
		return "", false
	}
	return code, true
}

func validWorkforceProfile(profile WorkforceProfile) bool {
	if !validOptionalName(profile.LocalName) || !validOptionalName(profile.EnglishName) || (profile.LocalName == "" && profile.EnglishName == "") {
		return false
	}
	if !utf8.ValidString(profile.ProfileSummary) || len(profile.ProfileSummary) > 16<<10 {
		return false
	}
	if profile.WorkContact != nil {
		if !utf8.ValidString(profile.WorkContact.Email) || !utf8.ValidString(profile.WorkContact.Phone) || len(profile.WorkContact.Email) > 320 || len(profile.WorkContact.Phone) > 64 {
			return false
		}
	}
	return true
}

func validOptionalName(name string) bool {
	return utf8.ValidString(name) && len(name) <= 256 && (name == "" || strings.TrimSpace(name) == name)
}

func validLocation(code string) bool {
	return code == LocationShanghai || code == LocationWuxi || code == LocationTokyo
}

func validEducationLevel(code string) bool {
	return utf8.ValidString(code) && code != "" && len(code) <= 64 && strings.TrimSpace(code) == code
}
