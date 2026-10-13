package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"

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
		if item.Command.Action != "create" {
			return 0, 0, fault.Invalid
		}
		if item.Payload != nil {
			if err = t.insertWorkforcePayload(ctx, *item.Payload); err != nil {
				return 0, 0, err
			}
		}
		if err = t.insertCatalogCreate(ctx, org, write.ID, item); err != nil {
			return 0, 0, err
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change_item(org_id,change_id,ordinal,action,kind,fact_id,owner_id,valid_from,valid_to,effective_to,supersedes_id) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)"), org, write.ID, ordinal, item.Command.Action, item.Command.Kind, item.VersionID, item.ID, nullablePointer(item.Command.ValidFrom), nullablePointer(item.Command.ValidTo), nil)
		if err != nil {
			return 0, 0, safeError(err)
		}
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE organization SET catalog_revision=catalog_revision+1,graph_revision=? WHERE id=? AND catalog_revision=? AND graph_revision=?"), nextGraph, org, expectedCatalog, expectedGraph)
	if err = structureAffected(result, err, fault.Conflict); err != nil {
		return 0, 0, err
	}
	if advancesGraph {
		result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch<?"), org, int64(math.MaxInt64))
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, err
		}
	}
	return expectedCatalog + 1, nextGraph, nil
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
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO org_unit_parent_history(org_id,id,child_unit_id,parent_unit_id,valid_from,valid_to,change_id) VALUES(?,?,?,?,?,?,?)"), org, item.VersionID, *command.Ref, *command.ParentRef, *command.ValidFrom, nullablePointer(command.ValidTo), changeID)
		}
	default:
		return fault.Invalid
	}
	return safeError(err)
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
