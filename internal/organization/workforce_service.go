package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

type catalogLabel struct {
	Label string `json:"label"`
}

type legalEntityLabel struct {
	DisplayName string `json:"display_name"`
}

func (s *Service) Catalogs(ctx context.Context, request Request, org string, query WorkforceCatalogQuery) (WorkforceCatalogs, error) {
	if !value.ValidID(org) || request.Purpose != "organization_management" || !validCatalogQuery(query) {
		return WorkforceCatalogs{}, fault.Invalid
	}
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-09")
	if err != nil {
		return WorkforceCatalogs{}, s.denied(ctx, request, snapshot, "OP-ORG-09", err)
	}
	day, err := s.authorizationDay(snapshot)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	if query.AsOf == "" {
		query.AsOf = day
	}
	catalogs, err := s.Store.WorkforceCatalogs(ctx, org, query.AsOf)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	catalogs.AsOf = query.AsOf
	if query.Limit == 0 {
		query.Limit = 50
	}
	filterCatalogs(&catalogs, query.Kind, query.Limit)
	includeLabels := snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock())
	if !includeLabels {
		for i := range catalogs.LegalEntities {
			catalogs.LegalEntities[i].LabelPayloadID = ""
		}
		for i := range catalogs.OrgUnits {
			catalogs.OrgUnits[i].LabelPayloadID = ""
		}
		return catalogs, nil
	}
	for i := range catalogs.LegalEntities {
		var label legalEntityLabel
		if err = s.openWorkforcePayload(ctx, org, "", catalogs.LegalEntities[i].ID, catalogs.LegalEntities[i].LabelPayloadID, "legal_entity", "pii.legal_entity_label.v1", &label); err != nil {
			return WorkforceCatalogs{}, err
		}
		if !validCatalogLabel(label.DisplayName) {
			return WorkforceCatalogs{}, fault.Unavailable
		}
		catalogs.LegalEntities[i].DisplayName = label.DisplayName
		catalogs.LegalEntities[i].LabelPayloadID = ""
	}
	for i := range catalogs.OrgUnits {
		var label catalogLabel
		if err = s.openWorkforcePayload(ctx, org, "", catalogs.OrgUnits[i].ID, catalogs.OrgUnits[i].LabelPayloadID, "org_unit", "pii.org_unit_label.v1", &label); err != nil {
			return WorkforceCatalogs{}, err
		}
		if !validCatalogLabel(label.Label) {
			return WorkforceCatalogs{}, fault.Unavailable
		}
		catalogs.OrgUnits[i].Label = label.Label
		catalogs.OrgUnits[i].LabelPayloadID = ""
	}
	return catalogs, nil
}

func (s *Service) openWorkforcePayload(ctx context.Context, org, employee, record, id, kind, schema string, target any) error {
	if !value.ValidID(id) {
		return fault.Unavailable
	}
	payload, err := s.Store.WorkforcePayload(ctx, org, id)
	if err != nil {
		return err
	}
	binding := sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: record, VersionID: id, ObjectKind: kind, Purpose: "pii", SchemaType: schema, SchemaVersion: 1}
	plain, err := s.Cipher.Open(ctx, binding, payload.Envelope)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return fault.Unavailable
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		return fault.Unavailable
	}
	return nil
}

func validCatalogQuery(query WorkforceCatalogQuery) bool {
	if query.AsOf != "" && !value.ValidDate(query.AsOf) || query.History || query.Cursor != "" || query.Limit < 0 || query.Limit > 100 {
		return false
	}
	return oneOf(query.Kind, "", "legal_entity", "location", "business_group", "division", "department", "education_level", "job_family", "career_level")
}

func filterCatalogs(catalogs *WorkforceCatalogs, kind string, limit int) {
	if kind != "" && kind != "legal_entity" {
		catalogs.LegalEntities = []LegalEntityView{}
	}
	if kind != "" && kind != "location" {
		catalogs.Locations = []string{}
	}
	if kind == "business_group" || kind == "division" || kind == "department" {
		filtered := make([]OrgUnitView, 0, len(catalogs.OrgUnits))
		for _, item := range catalogs.OrgUnits {
			if item.Kind == kind {
				filtered = append(filtered, item)
			}
		}
		catalogs.OrgUnits = filtered
	} else if kind != "" {
		catalogs.OrgUnits = []OrgUnitView{}
	}
	if kind != "" && kind != "education_level" {
		catalogs.EducationLevels = []EducationLevelView{}
	}
	if kind != "" && kind != "job_family" {
		catalogs.JobFamilies = []JobFamilyView{}
	}
	if kind != "" && kind != "career_level" {
		catalogs.CareerLevels = []CareerLevelView{}
	}
	if len(catalogs.LegalEntities) > limit {
		catalogs.LegalEntities = catalogs.LegalEntities[:limit]
	}
	if len(catalogs.Locations) > limit {
		catalogs.Locations = catalogs.Locations[:limit]
	}
	if len(catalogs.OrgUnits) > limit {
		catalogs.OrgUnits = catalogs.OrgUnits[:limit]
	}
	if len(catalogs.EducationLevels) > limit {
		catalogs.EducationLevels = catalogs.EducationLevels[:limit]
	}
	if len(catalogs.JobFamilies) > limit {
		catalogs.JobFamilies = catalogs.JobFamilies[:limit]
	}
	if len(catalogs.CareerLevels) > limit {
		catalogs.CareerLevels = catalogs.CareerLevels[:limit]
	}
}

func validCatalogLabel(label string) bool {
	return utf8.ValidString(label) && strings.TrimSpace(label) != "" && len(label) <= 256
}
