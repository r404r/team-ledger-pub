package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

func (t *transaction) WorkforceReceipt(ctx context.Context, org, subject, operation, key string) (organization.WorkforceCommandReceipt, bool, error) {
	var receipt organization.WorkforceCommandReceipt
	var encoded string
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT digest,result_json FROM workforce_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?"), org, subject, operation, key).Scan(&receipt.Digest, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, safeError(err)
	}
	if json.Unmarshal([]byte(encoded), &receipt.Result) != nil {
		return organization.WorkforceCommandReceipt{}, false, fault.Unavailable
	}
	return receipt, true, nil
}

func (t *transaction) SaveWorkforceReceipt(ctx context.Context, org, subject, operation, key string, receipt organization.WorkforceCommandReceipt) error {
	encoded, err := json.Marshal(receipt.Result)
	if err != nil {
		return fault.Invalid
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO workforce_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_change_id,graph_revision,catalog_revision,result_json) VALUES(?,?,?,?,?,1,?,?,?,?)"), org, subject, operation, key, receipt.Digest, receipt.Result.ID, receipt.Result.GraphRevision, receipt.Result.CatalogRevision, string(encoded))
	return safeError(err)
}

func (t *transaction) CommitCatalogChange(ctx context.Context, org string, expectedCatalog, expectedGraph int64, write organization.CatalogWrite) (int64, int64, error) {
	if org != t.org || write.OrgID != org || !value.ValidID(write.ID) || !value.ValidID(write.SubjectID) || expectedCatalog < 1 || expectedGraph < 1 || expectedCatalog == math.MaxInt64 || expectedGraph == math.MaxInt64 || len(write.Items) < 1 || len(write.Items) > 100 {
		return 0, 0, fault.Invalid
	}
	var catalogRevision, graphRevision int64
	if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT catalog_revision,graph_revision FROM organization WHERE id=?"), org).Scan(&catalogRevision, &graphRevision); err != nil {
		return 0, 0, safeError(err)
	}
	if catalogRevision != expectedCatalog || graphRevision != expectedGraph {
		return 0, 0, fault.Conflict
	}
	advancesGraph := false
	for _, item := range write.Items {
		if item.Command.Kind == "business_group" || item.Command.Kind == "division" || item.Command.Kind == "department" || item.Command.Kind == "org_unit_parent" {
			advancesGraph = true
		}
	}
	nextGraph := expectedGraph
	if advancesGraph {
		nextGraph++
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after,reason_payload_id) VALUES(?,?,?,?,?,?,?,?,NULL)"), org, write.ID, write.SubjectID, t.bindTime(write.RecordedAt), expectedGraph, nextGraph, expectedCatalog, expectedCatalog+1)
	if err != nil {
		return 0, 0, safeError(err)
	}
	for ordinal, item := range write.Items {
		if item.Payload != nil {
			if err = t.insertWorkforcePayload(ctx, *item.Payload); err != nil {
				return 0, 0, err
			}
		}
		switch item.Command.Action {
		case "create":
			err = t.insertCatalogCreate(ctx, org, write.ID, item)
		case "end", "replace":
			err = t.changeCatalogVersion(ctx, org, write.ID, item)
		default:
			err = fault.Invalid
		}
		if err != nil {
			return 0, 0, err
		}
		validFrom := item.Command.ValidFrom
		if item.Command.Action == "replace" {
			validFrom = item.Command.EffectiveTo
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change_item(org_id,change_id,ordinal,action,kind,fact_id,employee_id,owner_id,valid_from,valid_to,effective_to,supersedes_id) VALUES(?,?,?,?,?,?,NULL,?,?,?,?,?)"), org, write.ID, ordinal, item.Command.Action, item.Command.Kind, item.VersionID, item.ID, nullablePointer(validFrom), nullablePointer(item.Command.ValidTo), nullablePointer(item.Command.EffectiveTo), nullablePointer(item.Command.Ref))
		if err != nil {
			return 0, 0, safeError(err)
		}
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE organization SET catalog_revision=catalog_revision+1,graph_revision=? WHERE id=? AND catalog_revision=? AND graph_revision=?"), nextGraph, org, expectedCatalog, expectedGraph)
	if err = structureAffected(result, err, fault.Conflict); err != nil {
		return 0, 0, err
	}
	return expectedCatalog + 1, nextGraph, nil
}

func (t *transaction) CommitWorkforceChange(ctx context.Context, org string, expectedCatalog, expectedGraph int64, expectedEmployees map[string]int64, write organization.WorkforceWrite) (int64, int64, map[string]int64, error) {
	if org != t.org || write.OrgID != org || !value.ValidID(write.ID) || !value.ValidID(write.SubjectID) || expectedCatalog < 1 || expectedGraph < 1 || len(expectedEmployees) == 0 || len(write.Items) < 1 || len(write.Items) > 100 {
		return 0, 0, nil, fault.Invalid
	}
	var catalogRevision, graphRevision int64
	if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT catalog_revision,graph_revision FROM organization WHERE id=?"), org).Scan(&catalogRevision, &graphRevision); err != nil {
		return 0, 0, nil, safeError(err)
	}
	if catalogRevision != expectedCatalog || graphRevision != expectedGraph {
		return 0, 0, nil, fault.Conflict
	}
	nextEmployees := make(map[string]int64, len(expectedEmployees))
	for employee, expected := range expectedEmployees {
		if !value.ValidID(employee) || expected < 1 || expected == math.MaxInt64 {
			return 0, 0, nil, fault.Invalid
		}
		var current int64
		if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT workforce_revision FROM employee WHERE org_id=? AND id=?"), org, employee).Scan(&current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, 0, nil, fault.Conflict
			}
			return 0, 0, nil, safeError(err)
		}
		if current != expected {
			return 0, 0, nil, fault.Conflict
		}
		nextEmployees[employee] = expected + 1
	}
	advancesGraph := false
	for _, item := range write.Items {
		if _, ok := expectedEmployees[item.Command.EmployeeID]; !ok {
			return 0, 0, nil, fault.Invalid
		}
		if item.Command.Kind == "reporting" || item.Command.Kind == "employee_lifecycle" {
			advancesGraph = true
		}
	}
	nextGraph := expectedGraph
	if advancesGraph {
		nextGraph++
	}
	reasonID := any(nil)
	if write.ReasonPayload != nil {
		if err := t.insertOrganizationPayload(ctx, *write.ReasonPayload); err != nil {
			return 0, 0, nil, err
		}
		reasonID = write.ReasonPayload.ID
	}
	if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after,reason_payload_id) VALUES(?,?,?,?,?,?,?,?,?)"), org, write.ID, write.SubjectID, t.bindTime(write.RecordedAt), expectedGraph, nextGraph, expectedCatalog, expectedCatalog, reasonID); err != nil {
		return 0, 0, nil, safeError(err)
	}
	for ordinal, item := range write.Items {
		if item.Payload != nil {
			if err := t.insertWorkforcePayload(ctx, *item.Payload); err != nil {
				return 0, 0, nil, err
			}
		}
		if err := t.applyWorkforceItem(ctx, org, write.ID, write.RecordedAt, item); err != nil {
			return 0, 0, nil, err
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change_item(org_id,change_id,ordinal,action,kind,fact_id,employee_id,owner_id,valid_from,valid_to,effective_to,supersedes_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), org, write.ID, ordinal, item.Command.Action, item.Command.Kind, item.ID, item.Command.EmployeeID, item.Command.EmployeeID, nullablePointer(item.Command.ValidFrom), nullablePointer(item.Command.ValidTo), nullablePointer(item.Command.EffectiveTo), nullablePointer(item.Command.Ref)); err != nil {
			return 0, 0, nil, safeError(err)
		}
	}
	for employee, expected := range expectedEmployees {
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE employee SET workforce_revision=workforce_revision+1 WHERE org_id=? AND id=? AND workforce_revision=?"), org, employee, expected)
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, nil, err
		}
	}
	if advancesGraph {
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE organization SET graph_revision=? WHERE id=? AND catalog_revision=? AND graph_revision=?"), nextGraph, org, expectedCatalog, expectedGraph)
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, nil, err
		}
		result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch<?"), org, int64(math.MaxInt64))
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, nil, err
		}
	}
	return expectedCatalog, nextGraph, nextEmployees, nil
}

func (t *transaction) applyWorkforceItem(ctx context.Context, org, changeID string, recordedAt time.Time, item organization.WorkforcePreparedItem) error {
	command := item.Command
	if command.Kind == "employee_lifecycle" {
		return t.applyEmployeeLifecycle(ctx, org, changeID, item)
	}
	if command.Action == "end" {
		return t.endWorkforceItem(ctx, org, changeID, item)
	}
	revision, supersedes, err := int64(1), any(nil), error(nil)
	if command.Action == "replace" {
		if command.Ref == nil || command.EffectiveTo == nil {
			return fault.Invalid
		}
		revision, err = t.closeWorkforceItem(ctx, org, changeID, item)
		if err != nil {
			return err
		}
		revision++
		supersedes = *command.Ref
	}
	switch command.Kind {
	case "identifier":
		result, insertErr := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO employee_identifier_owner(org_id,kind,key_version,digest,employee_id,claimed_at) VALUES(?,'staff_code',1,?,?,?) ON CONFLICT(org_id,kind,key_version,digest) DO NOTHING"), org, item.Digest, command.EmployeeID, t.bindTime(recordedAt))
		if insertErr != nil {
			return safeError(insertErr)
		}
		if n, _ := result.RowsAffected(); n == 0 {
			var owner string
			if err = t.tx.QueryRowContext(ctx, t.structureSQL("SELECT employee_id FROM employee_identifier_owner WHERE org_id=? AND kind='staff_code' AND key_version=1 AND digest=?"), org, item.Digest).Scan(&owner); err != nil || owner != command.EmployeeID {
				return fault.Conflict
			}
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO employee_business_identifier(org_id,id,employee_id,kind,lookup_key_version,lookup_digest,payload_id,valid_from,valid_to,recorded_at,change_id,revision,supersedes_id) VALUES(?,?,?,'staff_code',1,?,?,?,?,?,?,?,?)"), org, item.ID, command.EmployeeID, item.Digest, item.Payload.ID, *command.ValidFrom, nullablePointer(command.ValidTo), t.bindTime(recordedAt), changeID, revision, supersedes)
	case "employment":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO employment_spell(org_id,id,employee_id,legal_entity_id,location_code,kind,valid_from,valid_to,recorded_at,change_id,revision,supersedes_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), org, item.ID, command.EmployeeID, *command.LegalEntityID, *command.LocationCode, *command.EmploymentKind, *command.ValidFrom, nullablePointer(command.ValidTo), t.bindTime(recordedAt), changeID, revision, supersedes)
	case "education":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO education_record(org_id,id,employee_id,level_code,payload_id,valid_from,valid_to,recorded_at,change_id,revision,supersedes_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), org, item.ID, command.EmployeeID, *command.EducationLevel, item.Payload.ID, *command.ValidFrom, nullablePointer(command.ValidTo), t.bindTime(recordedAt), changeID, revision, supersedes)
	case "job_assignment":
		var payloadID any
		if item.Payload != nil {
			payloadID = item.Payload.ID
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO job_assignment(org_id,id,employee_id,department_id,job_family_id,career_level_id,payload_kind,position_payload_id,is_primary,valid_from,valid_to,recorded_at,change_id,revision,supersedes_id) VALUES(?,?,?,?,?,?,CASE WHEN ? IS NULL THEN NULL ELSE 'job_assignment' END,?,1,?,?,?,?,?,?)"), org, item.ID, command.EmployeeID, *command.DepartmentID, nullablePointer(command.JobFamilyID), nullablePointer(command.CareerLevelID), payloadID, payloadID, *command.ValidFrom, nullablePointer(command.ValidTo), t.bindTime(recordedAt), changeID, revision, supersedes)
	case "reporting":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO reporting_line(org_id,id,employee_id,manager_employee_id,kind,valid_from,valid_to,effective_to,superseded,change_id,end_change_id,supersedes_id) VALUES(?,?,?,?,?,?,?,NULL,?,?,NULL,?)"), org, item.ID, command.EmployeeID, *command.ManagerEmployeeID, *command.ReportingKind, *command.ValidFrom, nullablePointer(command.ValidTo), false, changeID, supersedes)
	case "employee_lifecycle":
		return fault.Invalid
	default:
		return fault.Invalid
	}
	return safeError(err)
}

func (t *transaction) applyEmployeeLifecycle(ctx context.Context, org, changeID string, item organization.WorkforcePreparedItem) error {
	command := item.Command
	var headID, headFrom string
	var headTo sql.NullString
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT h.id,h.valid_from,h.valid_to FROM employee_lifecycle_history h WHERE h.org_id=? AND h.employee_id=? AND NOT EXISTS(SELECT 1 FROM employee_lifecycle_history n WHERE n.org_id=h.org_id AND n.employee_id=h.employee_id AND n.supersedes_id=h.id)"), org, command.EmployeeID).Scan(&headID, &headFrom, &headTo)
	if err != nil {
		return safeError(err)
	}
	supersedes, validFrom, validTo := headID, "", any(nil)
	switch command.Action {
	case "add":
		if !headTo.Valid || command.ValidFrom == nil || headTo.String > *command.ValidFrom {
			return fault.Conflict
		}
		validFrom, validTo = *command.ValidFrom, nullablePointer(command.ValidTo)
	case "replace":
		if command.Ref == nil || *command.Ref != headID || command.ValidFrom == nil {
			return fault.Conflict
		}
		validFrom, validTo = *command.ValidFrom, nullablePointer(command.ValidTo)
	case "end":
		if command.Ref == nil || *command.Ref != headID || command.EffectiveTo == nil || headFrom >= *command.EffectiveTo {
			return fault.Conflict
		}
		validFrom, validTo = headFrom, *command.EffectiveTo
	default:
		return fault.Invalid
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO employee_lifecycle_history(org_id,id,employee_id,valid_from,valid_to,change_id,supersedes_id) VALUES(?,?,?,?,?,?,?)"), org, item.ID, command.EmployeeID, validFrom, validTo, changeID, supersedes)
	if err != nil {
		return safeError(err)
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE employee SET valid_from=?,valid_to=? WHERE org_id=? AND id=?"), validFrom, validTo, org, command.EmployeeID)
	return safeError(err)
}

func (t *transaction) endWorkforceItem(ctx context.Context, org, changeID string, item organization.WorkforcePreparedItem) error {
	if item.Command.Ref == nil || item.Command.EffectiveTo == nil {
		return fault.Invalid
	}
	_, err := t.closeWorkforceItem(ctx, org, changeID, item)
	return err
}

func (t *transaction) closeWorkforceItem(ctx context.Context, org, changeID string, item organization.WorkforcePreparedItem) (int64, error) {
	command := item.Command
	table := map[string]string{"identifier": "employee_business_identifier", "employment": "employment_spell", "education": "education_record", "job_assignment": "job_assignment", "reporting": "reporting_line", "employee_lifecycle": "employee_lifecycle_history"}[command.Kind]
	if table == "" || command.Ref == nil || command.EffectiveTo == nil {
		return 0, fault.Invalid
	}
	var validFrom string
	var revision int64
	revisionColumn := "revision"
	if command.Kind == "reporting" || command.Kind == "employee_lifecycle" {
		revisionColumn = "1"
	}
	if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT valid_from,"+revisionColumn+" FROM "+table+" WHERE org_id=? AND id=? AND employee_id=? AND valid_to IS NULL"), org, *command.Ref, command.EmployeeID).Scan(&validFrom, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fault.Conflict
		}
		return 0, safeError(err)
	}
	if validFrom >= *command.EffectiveTo {
		return 0, fault.Conflict
	}
	query := "UPDATE " + table + " SET valid_to=? WHERE org_id=? AND id=? AND employee_id=? AND valid_to IS NULL"
	if command.Kind == "reporting" {
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE reporting_line SET effective_to=?,superseded=true,end_change_id=? WHERE org_id=? AND id=? AND employee_id=? AND effective_to IS NULL"), *command.EffectiveTo, changeID, org, *command.Ref, command.EmployeeID)
		return revision, structureAffected(result, err, fault.Conflict)
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL(query), *command.EffectiveTo, org, *command.Ref, command.EmployeeID)
	if err = structureAffected(result, err, fault.Conflict); err == nil && command.Kind == "employee_lifecycle" {
		_, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE employee SET valid_to=? WHERE org_id=? AND id=?"), *command.EffectiveTo, org, command.EmployeeID)
	}
	return revision, safeError(err)
}

func (t *transaction) insertCatalogCreate(ctx context.Context, org, changeID string, item organization.CatalogPreparedItem) error {
	command := item.Command
	var err error
	switch command.Kind {
	case "legal_entity":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO legal_entity(org_id,id,code,kind) VALUES(?,?,?,'branch_company')"), org, item.ID, *command.Code)
		if err == nil {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO legal_entity_version(org_id,id,legal_entity_id,label_payload_id,valid_from,valid_to,revision,change_id) VALUES(?,?,?,?,?,?,1,?)"), org, item.VersionID, item.ID, item.Payload.ID, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	case "business_group", "division", "department":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit(org_id,id,code,kind) VALUES(?,?,?,?)"), org, item.ID, *command.Code, command.Kind)
		if err == nil {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit_version(org_id,id,org_unit_id,label_payload_id,valid_from,valid_to,revision,change_id) VALUES(?,?,?,?,?,?,1,?)"), org, item.VersionID, item.ID, item.Payload.ID, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	case "job_family":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO job_family(org_id,id,code) VALUES(?,?,?)"), org, item.ID, *command.Code)
		if err == nil {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO job_family_version(org_id,id,job_family_id,label,valid_from,valid_to,revision,change_id) VALUES(?,?,?,?,?,?,1,?)"), org, item.VersionID, item.ID, *command.Label, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	case "career_level":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO career_level(org_id,id,code) VALUES(?,?,?)"), org, item.ID, *command.Code)
		if err == nil {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO career_level_version(org_id,id,career_level_id,label,rank,valid_from,valid_to,revision,change_id) VALUES(?,?,?,?,?,?,?,1,?)"), org, item.VersionID, item.ID, *command.Label, *command.Rank, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	case "org_unit_parent":
		if err = t.validateCatalogParent(ctx, org, *command.Ref, *command.ParentRef); err == nil {
			err = t.ensureParentWindowFree(ctx, org, *command.Ref, *command.ValidFrom, command.ValidTo, "")
		}
		if err == nil {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit_parent_history(org_id,id,child_unit_id,parent_unit_id,valid_from,valid_to,change_id) VALUES(?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, *command.ParentRef, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	default:
		return fault.Invalid
	}
	return safeError(err)
}

func (t *transaction) changeCatalogVersion(ctx context.Context, org, changeID string, item organization.CatalogPreparedItem) error {
	command := item.Command
	if command.Ref == nil || command.EffectiveTo == nil {
		return fault.Invalid
	}
	if command.Kind == "org_unit_parent" {
		return t.changeCatalogParent(ctx, org, changeID, item)
	}
	table, ownerColumn := catalogVersionTarget(command.Kind)
	if table == "" {
		return fault.Invalid
	}
	var priorID, validFrom string
	var revision int64
	query := "SELECT id,valid_from,revision FROM " + table + " WHERE org_id=? AND " + ownerColumn + "=? AND valid_to IS NULL"
	if err := t.tx.QueryRowContext(ctx, t.structureSQL(query), org, *command.Ref).Scan(&priorID, &validFrom, &revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fault.Conflict
		}
		return safeError(err)
	}
	if validFrom >= *command.EffectiveTo || revision == math.MaxInt64 {
		return fault.Conflict
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE "+table+" SET valid_to=? WHERE org_id=? AND id=? AND valid_to IS NULL"), *command.EffectiveTo, org, priorID)
	if err = structureAffected(result, err, fault.Conflict); err != nil {
		return err
	}
	if command.Action == "end" {
		return nil
	}
	switch command.Kind {
	case "legal_entity":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO legal_entity_version(org_id,id,legal_entity_id,label_payload_id,valid_from,valid_to,revision,supersedes_id,change_id) VALUES(?,?,?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, item.Payload.ID, *command.EffectiveTo, nullablePointer(command.ValidTo), revision+1, priorID, changeID)
	case "business_group", "division", "department":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit_version(org_id,id,org_unit_id,label_payload_id,valid_from,valid_to,revision,supersedes_id,change_id) VALUES(?,?,?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, item.Payload.ID, *command.EffectiveTo, nullablePointer(command.ValidTo), revision+1, priorID, changeID)
	case "job_family":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO job_family_version(org_id,id,job_family_id,label,valid_from,valid_to,revision,supersedes_id,change_id) VALUES(?,?,?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, *command.Label, *command.EffectiveTo, nullablePointer(command.ValidTo), revision+1, priorID, changeID)
	case "career_level":
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO career_level_version(org_id,id,career_level_id,label,rank,valid_from,valid_to,revision,supersedes_id,change_id) VALUES(?,?,?,?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, *command.Label, *command.Rank, *command.EffectiveTo, nullablePointer(command.ValidTo), revision+1, priorID, changeID)
	}
	return safeError(err)
}

func catalogVersionTarget(kind string) (string, string) {
	switch kind {
	case "legal_entity":
		return "legal_entity_version", "legal_entity_id"
	case "business_group", "division", "department":
		return "org_unit_version", "org_unit_id"
	case "job_family":
		return "job_family_version", "job_family_id"
	case "career_level":
		return "career_level_version", "career_level_id"
	default:
		return "", ""
	}
}

func (t *transaction) changeCatalogParent(ctx context.Context, org, changeID string, item organization.CatalogPreparedItem) error {
	command := item.Command
	var child, validFrom string
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT child_unit_id,valid_from FROM org_unit_parent_history WHERE org_id=? AND id=? AND valid_to IS NULL"), org, *command.Ref).Scan(&child, &validFrom)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.Conflict
	}
	if err != nil {
		return safeError(err)
	}
	if validFrom >= *command.EffectiveTo {
		return fault.Conflict
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE org_unit_parent_history SET valid_to=? WHERE org_id=? AND id=? AND valid_to IS NULL"), *command.EffectiveTo, org, *command.Ref)
	if err = structureAffected(result, err, fault.Conflict); err != nil || command.Action == "end" {
		return err
	}
	if err = t.validateCatalogParent(ctx, org, child, *command.ParentRef); err != nil {
		return err
	}
	if err = t.ensureParentWindowFree(ctx, org, child, *command.EffectiveTo, nil, *command.Ref); err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit_parent_history(org_id,id,child_unit_id,parent_unit_id,valid_from,valid_to,change_id) VALUES(?,?,?,?,?,NULL,?)"), org, item.VersionID, child, *command.ParentRef, *command.EffectiveTo, changeID)
	return safeError(err)
}

func (t *transaction) ensureParentWindowFree(ctx context.Context, org, child, from string, to *string, exclude string) error {
	end := "9999-12-31"
	if to != nil {
		end = *to
	}
	var count int
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT count(*) FROM org_unit_parent_history WHERE org_id=? AND child_unit_id=? AND id<>? AND valid_from<? AND COALESCE(valid_to,'9999-12-31')>?"), org, child, exclude, end, from).Scan(&count)
	if err != nil {
		return safeError(err)
	}
	if count != 0 {
		return fault.Conflict
	}
	return nil
}

func (t *transaction) validateCatalogParent(ctx context.Context, org, child, parent string) error {
	var childKind, parentKind string
	if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT kind FROM org_unit WHERE org_id=? AND id=?"), org, child).Scan(&childKind); err != nil {
		return safeError(err)
	}
	if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT kind FROM org_unit WHERE org_id=? AND id=?"), org, parent).Scan(&parentKind); err != nil {
		return safeError(err)
	}
	if childKind == "division" && parentKind == "business_group" || childKind == "department" && parentKind == "division" {
		return nil
	}
	return fault.Invalid
}

func (t *transaction) insertWorkforcePayload(ctx context.Context, payload organization.WorkforcePayload) error {
	envelope := payload.Envelope
	binding := envelope.Context
	if payload.ID != binding.VersionID || binding.OrgID != t.org || binding.RecordID == "" || binding.Purpose != "pii" || binding.SchemaVersion != 1 {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), binding.OrgID, payload.ID, binding.ObjectKind, binding.RecordID, nullable(binding.EmployeeID), binding.RecordID, binding.VersionID, binding.Purpose, binding.SchemaType, binding.SchemaVersion, envelope.FormatVersion, envelope.Algorithm, envelope.DEKID, envelope.Key.KEKID, envelope.Key.Version, envelope.Key.Data, envelope.SealedBytes, t.bindTime(payload.RecordedAt))
	return safeError(err)
}

func nullablePointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
