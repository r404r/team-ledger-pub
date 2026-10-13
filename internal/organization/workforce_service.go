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

func (s *Service) Catalogs(ctx context.Context, request Request, org string, includeLabels bool) (WorkforceCatalogs, error) {
	if !value.ValidID(org) || request.Purpose != "organization_management" {
		return WorkforceCatalogs{}, fault.Invalid
	}
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-09")
	if err != nil {
		return WorkforceCatalogs{}, s.denied(ctx, request, snapshot, "OP-ORG-09", err)
	}
	if includeLabels && !snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock()) {
		return WorkforceCatalogs{}, s.denied(ctx, request, snapshot, "OP-ORG-09", fault.Forbidden)
	}
	day, err := s.authorizationDay(snapshot)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	catalogs, err := s.Store.WorkforceCatalogs(ctx, org, day)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
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

func validCatalogLabel(label string) bool {
	return utf8.ValidString(label) && strings.TrimSpace(label) != "" && len(label) <= 256
}
