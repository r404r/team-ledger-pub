package organization

import (
	"strings"
	"unicode/utf8"

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
	ID          string `json:"id"`
	Code        string `json:"code"`
	DisplayName string `json:"display_name,omitempty"`
	Active      bool   `json:"active"`
}

type OrgUnitView struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Label  string `json:"label,omitempty"`
	Kind   string `json:"kind"`
	Active bool   `json:"active"`
}

type JobFamilyView struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Label  string `json:"label,omitempty"`
	Active bool   `json:"active"`
}

type CareerLevelView struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Label  string `json:"label,omitempty"`
	Rank   int    `json:"rank"`
	Active bool   `json:"active"`
}

type WorkforceCatalogs struct {
	CatalogRevision string            `json:"catalog_revision"`
	GraphRevision   string            `json:"graph_revision"`
	LegalEntities   []LegalEntityView `json:"legal_entities"`
	Locations       []string          `json:"locations"`
	OrgUnits        []OrgUnitView     `json:"org_units"`
	EducationLevels []string          `json:"education_levels"`
	JobFamilies     []JobFamilyView   `json:"job_families"`
	CareerLevels    []CareerLevelView `json:"career_levels"`
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
	return code == EducationMaster || code == EducationBachelor || code == EducationDiploma
}
