package organization

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
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
	if query.History {
		return s.catalogHistory(ctx, request, snapshot, org, day, query)
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

func (s *Service) catalogHistory(ctx context.Context, request Request, snapshot authz.Snapshot, org, day string, query WorkforceCatalogQuery) (WorkforceCatalogs, error) {
	if query.Limit == 0 {
		query.Limit = 50
	}
	current, err := s.Store.WorkforceCatalogs(ctx, org, day)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	revision, err := strconv.ParseInt(current.CatalogRevision, 10, 64)
	if err != nil {
		return WorkforceCatalogs{}, fault.Unavailable
	}
	graph := Graph{Revision: revision}
	filter := struct {
		Kind  string
		Limit int
	}{query.Kind, query.Limit}
	digest, err := s.queryDigest("catalog-history", filter, "")
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	after := ""
	if query.Cursor != "" {
		after, err = s.openQueryCursor(query.Cursor, "catalog-history", snapshot, graph, day, digest)
		if err != nil {
			return WorkforceCatalogs{}, err
		}
	}
	catalogs, last, more, err := s.Store.WorkforceCatalogHistory(ctx, org, query.Kind, after, query.Limit+1)
	if err != nil {
		return WorkforceCatalogs{}, err
	}
	if more && last != "" {
		token, sealErr := s.sealQueryCursor("catalog-history", snapshot, graph, day, digest, last)
		if sealErr != nil {
			return WorkforceCatalogs{}, sealErr
		}
		catalogs.NextCursor = &token
	}
	includeLabels := snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock())
	for i := range catalogs.LegalEntities {
		if !includeLabels {
			catalogs.LegalEntities[i].LabelPayloadID = ""
			continue
		}
		var label legalEntityLabel
		item := &catalogs.LegalEntities[i]
		if err = s.openWorkforcePayload(ctx, org, "", item.ID, item.LabelPayloadID, "legal_entity", "pii.legal_entity_label.v1", &label); err != nil || !validCatalogLabel(label.DisplayName) {
			return WorkforceCatalogs{}, fault.Unavailable
		}
		item.DisplayName, item.LabelPayloadID = label.DisplayName, ""
	}
	for i := range catalogs.OrgUnits {
		if !includeLabels {
			catalogs.OrgUnits[i].LabelPayloadID = ""
			continue
		}
		var label catalogLabel
		item := &catalogs.OrgUnits[i]
		if err = s.openWorkforcePayload(ctx, org, "", item.ID, item.LabelPayloadID, "org_unit", "pii.org_unit_label.v1", &label); err != nil || !validCatalogLabel(label.Label) {
			return WorkforceCatalogs{}, fault.Unavailable
		}
		item.Label, item.LabelPayloadID = label.Label, ""
	}
	return catalogs, nil
}

func (s *Service) ChangeCatalogs(ctx context.Context, request Request, org string, command CatalogChangeCommand) (CatalogChangeResult, error) {
	const operation = "OP-ORG-09"
	if !value.ValidID(org) || !value.ValidID(request.Key) || request.Purpose != "organization_management" || !validCatalogChange(command) {
		return CatalogChangeResult{}, fault.Invalid
	}
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", operation)
	if err != nil {
		return CatalogChangeResult{}, s.denied(ctx, request, snapshot, operation, err)
	}
	needsPII := catalogChangesNeedPII(command.Changes)
	if !snapshot.Allows("organization.write", "metadata", "", request.Purpose, s.clock()) ||
		needsPII && (!snapshot.Allows("pii.read", "pii", "", request.Purpose, s.clock()) || !snapshot.Allows("pii.write", "pii", "", request.Purpose, s.clock())) {
		return CatalogChangeResult{}, s.denied(ctx, request, snapshot, operation, fault.Forbidden)
	}
	expectedCatalog, _ := value.Revision(command.ExpectedCatalogRevision)
	expectedGraph, _ := value.Revision(command.ExpectedGraphRevision)
	digest, err := s.digest(request, snapshot, operation, org, command)
	if err != nil {
		return CatalogChangeResult{}, err
	}
	write := CatalogWrite{ID: value.NewID(), OrgID: org, SubjectID: snapshot.SubjectID, RecordedAt: s.clock(), Items: make([]CatalogPreparedItem, len(command.Changes))}
	for i, item := range command.Changes {
		prepared := CatalogPreparedItem{Command: item, ID: value.NewID(), VersionID: value.NewID()}
		if item.Action == "end" {
			prepared.ID, prepared.VersionID = *item.Ref, *item.Ref
		} else if item.Action == "replace" && item.Kind != "org_unit_parent" {
			prepared.ID = *item.Ref
		} else if item.Kind == "org_unit_parent" {
			prepared.ID = prepared.VersionID
		}
		if item.Action != "end" {
			switch item.Kind {
			case "legal_entity":
				payload, sealErr := s.sealWorkforceCatalog(ctx, org, prepared.ID, "legal_entity", "pii.legal_entity_label.v1", legalEntityLabel{DisplayName: *item.Label})
				if sealErr != nil {
					return CatalogChangeResult{}, sealErr
				}
				prepared.Payload = &payload
			case "business_group", "division", "department":
				payload, sealErr := s.sealWorkforceCatalog(ctx, org, prepared.ID, "org_unit", "pii.org_unit_label.v1", catalogLabel{Label: *item.Label})
				if sealErr != nil {
					return CatalogChangeResult{}, sealErr
				}
				prepared.Payload = &payload
			}
		}
		write.Items[i] = prepared
	}
	var result CatalogChangeResult
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
		if err := tx.LockGraph(ctx, org); err != nil {
			return err
		}
		if err := tx.LockSubjects(ctx, org, []string{snapshot.SubjectID}); err != nil {
			return err
		}
		current, err := s.authorize(ctx, tx, request, org, "", operation)
		if err != nil {
			return err
		}
		if !current.Allows("organization.write", "metadata", "", request.Purpose, s.clock()) ||
			needsPII && (!current.Allows("pii.read", "pii", "", request.Purpose, s.clock()) || !current.Allows("pii.write", "pii", "", request.Purpose, s.clock())) {
			return fault.Forbidden
		}
		if receipt, found, err := tx.WorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key); err != nil {
			return err
		} else if found {
			if !hmac.Equal(receipt.Digest, digest) {
				return fault.Conflict
			}
			result = receipt.Result
			return nil
		}
		catalogRevision, graphRevision, err := tx.CommitCatalogChange(ctx, org, expectedCatalog, expectedGraph, write)
		if err != nil {
			return err
		}
		result = CatalogChangeResult{ID: write.ID, CatalogRevision: strconv.FormatInt(catalogRevision, 10), GraphRevision: strconv.FormatInt(graphRevision, 10), Items: make([]CatalogChangeItemResult, len(write.Items))}
		for i, item := range write.Items {
			result.Items[i] = CatalogChangeItemResult{Kind: item.Command.Kind, ID: item.ID, VersionID: item.VersionID}
		}
		if err = tx.SaveWorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key, WorkforceCommandReceipt{Digest: digest, Result: result}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(request, current, "", operation, "allowed"))
	})
	if err != nil {
		return CatalogChangeResult{}, s.denied(ctx, request, snapshot, operation, err)
	}
	return result, nil
}

func (s *Service) ChangeWorkforce(ctx context.Context, request Request, org string, command WorkforceChangeCommand) (WorkforceChangeResult, error) {
	const operation = "OP-ORG-10"
	if !value.ValidID(org) || !value.ValidID(request.Key) || request.Purpose != "organization_management" || !validWorkforceChange(command) {
		return WorkforceChangeResult{}, fault.Invalid
	}
	snapshot, err := s.authenticateWorkforceRoot(ctx, s.Store, request, org)
	if err != nil {
		return WorkforceChangeResult{}, s.denied(ctx, request, snapshot, operation, err)
	}
	if err = s.authorizeWorkforceEndpoints(ctx, s.Store, request, snapshot, command); err != nil {
		return WorkforceChangeResult{}, s.denied(ctx, request, snapshot, operation, err)
	}
	expectedCatalog, _ := value.Revision(command.ExpectedCatalogRevision)
	expectedGraph, _ := value.Revision(command.ExpectedGraphRevision)
	expectedEmployees := make(map[string]int64, len(command.ExpectedEmployeeRevision))
	for employee, revision := range command.ExpectedEmployeeRevision {
		expectedEmployees[employee], _ = value.Revision(revision)
	}
	digest, err := s.digest(request, snapshot, operation, org, command)
	if err != nil {
		return WorkforceChangeResult{}, err
	}
	write, err := s.prepareWorkforceWrite(ctx, org, snapshot.SubjectID, command)
	if err != nil {
		return WorkforceChangeResult{}, err
	}
	var result WorkforceChangeResult
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
		if err := tx.LockGraph(ctx, org); err != nil {
			return err
		}
		if err := tx.LockSubjects(ctx, org, []string{snapshot.SubjectID}); err != nil {
			return err
		}
		current, err := s.authenticateWorkforceRoot(ctx, tx, request, org)
		if err != nil {
			return err
		}
		if err = s.authorizeWorkforceEndpoints(ctx, tx, request, current, command); err != nil {
			return err
		}
		if receipt, found, err := tx.WorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key); err != nil {
			return err
		} else if found {
			if !hmac.Equal(receipt.Digest, digest) {
				return fault.Conflict
			}
			result = receipt.Result
			return nil
		}
		catalogRevision, graphRevision, employeeRevisions, err := tx.CommitWorkforceChange(ctx, org, expectedCatalog, expectedGraph, expectedEmployees, write)
		if err != nil {
			return err
		}
		result = WorkforceChangeResult{ID: write.ID, CatalogRevision: strconv.FormatInt(catalogRevision, 10), GraphRevision: strconv.FormatInt(graphRevision, 10), EmployeeRevisions: make(map[string]string, len(employeeRevisions)), Items: make([]CatalogChangeItemResult, len(write.Items))}
		for employee, revision := range employeeRevisions {
			result.EmployeeRevisions[employee] = strconv.FormatInt(revision, 10)
		}
		for i, item := range write.Items {
			result.Items[i] = CatalogChangeItemResult{Kind: item.Command.Kind, ID: item.ID}
		}
		if err = tx.SaveWorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key, WorkforceCommandReceipt{Digest: digest, Result: result}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(request, current, "", operation, "allowed"))
	})
	if err != nil {
		return WorkforceChangeResult{}, s.denied(ctx, request, snapshot, operation, err)
	}
	return result, nil
}
func (s *Service) prepareWorkforceWrite(ctx context.Context, org, subject string, command WorkforceChangeCommand) (WorkforceWrite, error) {
	write := WorkforceWrite{ID: value.NewID(), OrgID: org, SubjectID: subject, RecordedAt: s.clock(), Items: make([]WorkforcePreparedItem, len(command.Changes))}
	if command.Reason != nil {
		payload, err := s.sealWorkforceFact(ctx, org, "", write.ID, "structure_change", "org.structure.reason.v1", struct {
			Reason string `json:"reason"`
		}{Reason: *command.Reason})
		if err != nil {
			return WorkforceWrite{}, err
		}
		write.ReasonPayload = &payload
	}
	for i, item := range command.Changes {
		prepared := WorkforcePreparedItem{Command: item, ID: value.NewID()}
		if item.Action == "end" && item.Kind != "employee_lifecycle" {
			prepared.ID = *item.Ref
		}
		switch item.Kind {
		case "identifier":
			if item.Action != "end" {
				normalized, _ := NormalizeStaffCode(*item.StaffCode)
				frame := []byte("staff-code\x00" + org + "\x00" + normalized)
				if s.StaffCodeMAC != nil {
					macValue, err := s.StaffCodeMAC(ctx, frame)
					if err != nil || macValue.Version == 0 || macValue.KeyID == "" || len(macValue.Digest) != sha256.Size {
						clear(macValue.Digest)
						return WorkforceWrite{}, fault.Unavailable
					}
					prepared.Digest, prepared.DigestKeyID, prepared.DigestKeyVersion = macValue.Digest, macValue.KeyID, macValue.Version
				} else {
					mac := hmac.New(sha256.New, s.DigestKey)
					_, _ = mac.Write(frame)
					prepared.Digest, prepared.DigestKeyID, prepared.DigestKeyVersion = mac.Sum(nil), "legacy-process-key", 1
				}
				payload, err := s.sealWorkforceFact(ctx, org, item.EmployeeID, prepared.ID, "employee_identifier", "pii.employee_identifier.v1", struct {
					StaffCode string `json:"staff_code"`
				}{StaffCode: normalized})
				if err != nil {
					return WorkforceWrite{}, err
				}
				prepared.Payload = &payload
			}
		case "education":
			if item.Action != "end" {
				payload, err := s.sealWorkforceFact(ctx, org, item.EmployeeID, prepared.ID, "education_record", "pii.education.v1", struct {
					Institution *string `json:"institution,omitempty"`
					Field       *string `json:"field,omitempty"`
					AwardDate   *string `json:"award_date,omitempty"`
				}{item.Institution, item.Field, item.AwardDate})
				if err != nil {
					return WorkforceWrite{}, err
				}
				prepared.Payload = &payload
			}
		case "job_assignment":
			if item.Action != "end" && item.Position != nil {
				payload, err := s.sealWorkforceFact(ctx, org, item.EmployeeID, prepared.ID, "job_assignment", "pii.job_assignment_position.v1", *item.Position)
				if err != nil {
					return WorkforceWrite{}, err
				}
				prepared.Payload = &payload
			}
		}
		write.Items[i] = prepared
	}
	return write, nil
}

func (s *Service) authenticateWorkforceRoot(ctx context.Context, reader Reader, request Request, org string) (authz.Snapshot, error) {
	if len(request.TokenHash) != 32 || reader == nil {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	snapshot, err := reader.Security(ctx, request.TokenHash, "", "")
	if err != nil {
		return snapshot, err
	}
	if !snapshot.Valid(s.clock()) {
		return snapshot, fault.Unauthenticated
	}
	if snapshot.OrgID != org {
		return snapshot, fault.NotFound
	}
	return snapshot, nil
}

func (s *Service) authorizeWorkforceEndpoints(ctx context.Context, reader Reader, request Request, root authz.Snapshot, command WorkforceChangeCommand) error {
	type requirement struct {
		write    bool
		writePII bool
		readOnly bool
	}
	requirements := make(map[string]requirement, len(command.Changes))
	for _, item := range command.Changes {
		required := requirements[item.EmployeeID]
		required.write = true
		required.writePII = required.writePII || item.Kind == "identifier" || item.Kind == "education" || item.Kind == "job_assignment" && item.Position != nil
		requirements[item.EmployeeID] = required
		if item.ManagerEmployeeID != nil {
			manager := requirements[*item.ManagerEmployeeID]
			if *item.ManagerEmployeeID != item.EmployeeID {
				manager.readOnly = true
			}
			requirements[*item.ManagerEmployeeID] = manager
		}
	}
	employees := make([]string, 0, len(requirements))
	for employee := range requirements {
		employees = append(employees, employee)
	}
	sort.Strings(employees)
	for _, employee := range employees {
		object, err := reader.Employee(ctx, employee)
		if err != nil {
			return err
		}
		if object.OrgID != root.OrgID {
			return fault.NotFound
		}
		snapshot, err := reader.Security(ctx, request.TokenHash, "", employee)
		if err != nil {
			return err
		}
		if snapshot.SubjectID != root.SubjectID || snapshot.AuthEpoch != root.AuthEpoch {
			return fault.Forbidden
		}
		required := requirements[employee]
		if required.readOnly && !snapshot.Allows("organization.read", "metadata", employee, request.Purpose, s.clock()) {
			return fault.Forbidden
		}
		if required.write {
			if !snapshot.Allows("organization.write", "metadata", employee, request.Purpose, s.clock()) {
				return fault.Forbidden
			}
			if required.writePII && (!snapshot.Allows("pii.read", "pii", employee, request.Purpose, s.clock()) || !snapshot.Allows("pii.write", "pii", employee, request.Purpose, s.clock())) {
				return fault.Forbidden
			}
		}
	}
	return nil
}

func workforceChangesNeedPII(command WorkforceChangeCommand) bool {
	if command.Reason != nil {
		return true
	}
	for _, item := range command.Changes {
		if item.Kind == "identifier" || item.Kind == "education" || item.Kind == "job_assignment" && item.Position != nil {
			return true
		}
	}
	return false
}

func (s *Service) sealWorkforceFact(ctx context.Context, org, employee, owner, kind, schema string, body any) (WorkforcePayload, error) {
	plain, err := json.Marshal(body)
	if err != nil || len(plain) > 16<<10 {
		clear(plain)
		return WorkforcePayload{}, fault.Invalid
	}
	defer clear(plain)
	payload := WorkforcePayload{ID: value.NewID(), RecordedAt: s.clock()}
	binding := sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: owner, VersionID: payload.ID, ObjectKind: kind, Purpose: "pii", SchemaType: schema, SchemaVersion: 1}
	payload.Envelope, err = s.Cipher.Seal(ctx, binding, plain)
	if err != nil {
		return WorkforcePayload{}, fault.Unavailable
	}
	return payload, nil
}

func catalogChangesNeedPII(items []CatalogChangeItem) bool {
	for _, item := range items {
		if item.Kind == "legal_entity" || item.Kind == "business_group" || item.Kind == "division" || item.Kind == "department" {
			return true
		}
	}
	return false
}

func (s *Service) sealWorkforceCatalog(ctx context.Context, org, owner, kind, schema string, body any) (WorkforcePayload, error) {
	plain, err := json.Marshal(body)
	if err != nil || len(plain) > 16<<10 {
		clear(plain)
		return WorkforcePayload{}, fault.Invalid
	}
	defer clear(plain)
	payload := WorkforcePayload{ID: value.NewID(), RecordedAt: s.clock()}
	binding := sensitive.Context{OrgID: org, RecordID: owner, VersionID: payload.ID, ObjectKind: kind, Purpose: "pii", SchemaType: schema, SchemaVersion: 1}
	payload.Envelope, err = s.Cipher.Seal(ctx, binding, plain)
	if err != nil {
		return WorkforcePayload{}, fault.Unavailable
	}
	return payload, nil
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
	if query.AsOf != "" && !value.ValidDate(query.AsOf) || query.Limit < 0 || query.Limit > 100 {
		return false
	}
	if query.History {
		return query.AsOf == "" && oneOf(query.Kind, "legal_entity", "business_group", "division", "department", "org_unit_parent", "job_family", "career_level")
	}
	return query.Cursor == "" && oneOf(query.Kind, "", "legal_entity", "location", "business_group", "division", "department", "org_unit_parent", "education_level", "job_family", "career_level")
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
	if kind != "" && kind != "org_unit_parent" {
		catalogs.OrgUnitParents = []OrgUnitParentView{}
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
	if len(catalogs.OrgUnitParents) > limit {
		catalogs.OrgUnitParents = catalogs.OrgUnitParents[:limit]
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
