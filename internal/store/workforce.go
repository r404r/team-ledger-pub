package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (r *Repository) WorkforceCatalogs(ctx context.Context, org string) (organization.WorkforceCatalogs, error) {
	return r.read().WorkforceCatalogs(ctx, org)
}

func (r *Repository) WorkforcePayload(ctx context.Context, org, id string) (organization.WorkforcePayload, error) {
	return r.read().WorkforcePayload(ctx, org, id)
}

func (r reader) WorkforceCatalogs(ctx context.Context, org string) (organization.WorkforceCatalogs, error) {
	out := organization.WorkforceCatalogs{
		LegalEntities: []organization.LegalEntityView{}, Locations: []string{}, OrgUnits: []organization.OrgUnitView{},
		EducationLevels: []string{}, JobFamilies: []organization.JobFamilyView{}, CareerLevels: []organization.CareerLevelView{},
	}
	var catalogRevision, graphRevision int64
	if err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT catalog_revision,graph_revision FROM organization WHERE id=?"), org).Scan(&catalogRevision, &graphRevision); errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	} else if err != nil {
		return out, safeError(err)
	}
	out.CatalogRevision = strconv.FormatInt(catalogRevision, 10)
	out.GraphRevision = strconv.FormatInt(graphRevision, 10)

	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT id,code,label_payload_id,active FROM legal_entity WHERE org_id=? ORDER BY code,id"), org)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.LegalEntityView
		if err = rows.Scan(&item.ID, &item.Code, &item.LabelPayloadID, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.LegalEntities = append(out.LegalEntities, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, "SELECT code FROM work_location ORDER BY code")
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var code string
		if err = rows.Scan(&code); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.Locations = append(out.Locations, code)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,code,label_payload_id,kind,active FROM org_unit WHERE org_id=? ORDER BY kind,code,id"), org)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.OrgUnitView
		if err = rows.Scan(&item.ID, &item.Code, &item.LabelPayloadID, &item.Kind, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.OrgUnits = append(out.OrgUnits, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, "SELECT code FROM education_level ORDER BY code")
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var code string
		if err = rows.Scan(&code); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.EducationLevels = append(out.EducationLevels, code)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,code,name,active FROM job_family WHERE org_id=? ORDER BY code,id"), org)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.JobFamilyView
		if err = rows.Scan(&item.ID, &item.Code, &item.Label, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.JobFamilies = append(out.JobFamilies, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,code,name,rank,active FROM career_level WHERE org_id=? ORDER BY rank,code,id"), org)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.CareerLevelView
		if err = rows.Scan(&item.ID, &item.Code, &item.Label, &item.Rank, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.CareerLevels = append(out.CareerLevels, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()
	return out, nil
}

func (r reader) WorkforcePayload(ctx context.Context, org, id string) (organization.WorkforcePayload, error) {
	var payload organization.WorkforcePayload
	var employee sql.NullString
	var recorded dbTime
	envelope := &payload.Envelope
	binding := &envelope.Context
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT id,org_id,employee_id,record_id,version_id,owner_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM workforce_payload WHERE org_id=? AND id=?"), org, id).Scan(&payload.ID, &binding.OrgID, &employee, &binding.RecordID, &binding.VersionID, &binding.ObjectKind, &binding.Purpose, &binding.SchemaType, &binding.SchemaVersion, &envelope.FormatVersion, &envelope.Algorithm, &envelope.DEKID, &envelope.Key.KEKID, &envelope.Key.Version, &envelope.Key.Data, &envelope.SealedBytes, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return payload, fault.NotFound
	}
	if err != nil {
		return organization.WorkforcePayload{}, safeError(err)
	}
	binding.EmployeeID = employee.String
	payload.RecordedAt = recorded.Time
	return payload, nil
}
