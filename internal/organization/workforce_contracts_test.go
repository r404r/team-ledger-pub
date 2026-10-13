package organization

import (
	"strings"
	"testing"
)

func TestStaffCodeNormalizationPreservesBusinessIdentity(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		valid       bool
	}{
		{"001 AbC", "001 AbC", true},
		{"e\u0301-01", "é-01", true},
		{" AbC", "", false},
		{"AbC ", "", false},
		{"", "", false},
		{strings.Repeat("a", 65), "", false},
		{string([]byte{0xff}), "", false},
	} {
		got, valid := NormalizeStaffCode(tc.input)
		if valid != tc.valid || got != tc.want {
			t.Fatalf("NormalizeStaffCode(%q) = (%q,%v), want (%q,%v)", tc.input, got, valid, tc.want, tc.valid)
		}
	}
}

func TestWorkforceProfileRequiresOneBoundedBilingualName(t *testing.T) {
	for _, profile := range []WorkforceProfile{
		{LocalName: "王小明"},
		{EnglishName: "Ming Wang"},
		{LocalName: "王小明", EnglishName: "Ming Wang", WorkContact: &Contact{Email: "ming@example.test"}},
	} {
		if !validWorkforceProfile(profile) {
			t.Fatalf("valid workforce profile rejected: %#v", profile)
		}
	}
	for _, profile := range []WorkforceProfile{
		{},
		{LocalName: " 王小明"},
		{EnglishName: strings.Repeat("a", 257)},
		{LocalName: "王小明", WorkContact: &Contact{Email: strings.Repeat("a", 321)}},
	} {
		if validWorkforceProfile(profile) {
			t.Fatalf("invalid workforce profile accepted: %#v", profile)
		}
	}
}

func TestFixedWorkforceCatalogValues(t *testing.T) {
	for _, code := range []string{LocationShanghai, LocationWuxi, LocationTokyo} {
		if !validLocation(code) {
			t.Fatal("fixed location rejected:", code)
		}
	}
	for _, code := range []string{"shanghai", "Osaka", ""} {
		if validLocation(code) {
			t.Fatal("unknown location accepted:", code)
		}
	}
	for _, code := range []string{EducationMaster, EducationBachelor, EducationDiploma} {
		if !validEducationLevel(code) {
			t.Fatal("fixed education level rejected:", code)
		}
	}
	for _, code := range []string{"PhD", "master", ""} {
		if validEducationLevel(code) {
			t.Fatal("unknown education level accepted:", code)
		}
	}
}
