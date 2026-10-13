package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (r *Repository) WorkforceCatalogs(ctx context.Context, org, asOf string) (organization.WorkforceCatalogs, error) {
	return r.read().WorkforceCatalogs(ctx, org, asOf)
}

func (r *Repository) WorkforcePayload(ctx context.Context, org, id string) (organization.WorkforcePayload, error) {
	return r.read().WorkforcePayload(ctx, org, id)
}

func (r reader) WorkforceCatalogs(ctx context.Context, org, asOf string) (organization.WorkforceCatalogs, error) {
	out := organization.WorkforceCatalogs{
		LegalEntities: []organization.LegalEntityView{}, Locations: []string{}, OrgUnits: []organization.OrgUnitView{},
		EducationLevels: []organization.EducationLevelView{}, JobFamilies: []organization.JobFamilyView{}, CareerLevels: []organization.CareerLevelView{},
	}
	var catalogRevision, graphRevision int64
	if err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT catalog_revision,graph_revision FROM organization WHERE id=?"), org).Scan(&catalogRevision, &graphRevision); errors.Is(err, sql.ErrNoRows) {
		return out, fault.NotFound
	} else if err != nil {
		return out, safeError(err)
	}
	out.CatalogRevision = strconv.FormatInt(catalogRevision, 10)
	out.GraphRevision = strconv.FormatInt(graphRevision, 10)

	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT e.id,e.code,v.label_payload_id,TRUE FROM legal_entity e JOIN legal_entity_version v ON v.org_id=e.org_id AND v.legal_entity_id=e.id WHERE e.org_id=? AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?) ORDER BY e.code,e.id"), org, asOf, asOf)
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

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT u.id,u.code,v.label_payload_id,u.kind,TRUE FROM org_unit u JOIN org_unit_version v ON v.org_id=u.org_id AND v.org_unit_id=u.id WHERE u.org_id=? AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?) ORDER BY u.kind,u.code,u.id"), org, asOf, asOf)
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

	rows, err = r.db.QueryContext(ctx, "SELECT code,rank FROM education_level ORDER BY rank DESC")
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var level organization.EducationLevelView
		if err = rows.Scan(&level.Code, &level.Rank); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		out.EducationLevels = append(out.EducationLevels, level)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT f.id,f.code,v.label,TRUE FROM job_family f JOIN job_family_version v ON v.org_id=f.org_id AND v.job_family_id=f.id WHERE f.org_id=? AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?) ORDER BY f.code,f.id"), org, asOf, asOf)
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

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT c.id,c.code,v.label,v.rank,TRUE FROM career_level c JOIN career_level_version v ON v.org_id=c.org_id AND v.career_level_id=c.id WHERE c.org_id=? AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?) ORDER BY v.rank,c.code,c.id"), org, asOf, asOf)
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
