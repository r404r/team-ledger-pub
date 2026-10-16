package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (r *Repository) WorkforceCatalogs(ctx context.Context, org, asOf string) (organization.WorkforceCatalogs, error) {
	return r.read().WorkforceCatalogs(ctx, org, asOf)
}

func (r *Repository) WorkforceCatalogHistory(ctx context.Context, org, kind, after string, limit int) (organization.WorkforceCatalogs, string, bool, error) {
	return r.read().WorkforceCatalogHistory(ctx, org, kind, after, limit)
}

func (r *Repository) WorkforcePayload(ctx context.Context, org, id string) (organization.WorkforcePayload, error) {
	return r.read().WorkforcePayload(ctx, org, id)
}

func (r *Repository) EmployeeWorkforceFacts(ctx context.Context, org, employee, asOf string) (organization.WorkforceFacts, error) {
	return r.read().EmployeeWorkforceFacts(ctx, org, employee, asOf)
}

func (r reader) WorkforceCatalogs(ctx context.Context, org, asOf string) (organization.WorkforceCatalogs, error) {
	out := organization.WorkforceCatalogs{
		LegalEntities: []organization.LegalEntityView{}, Locations: []string{}, OrgUnits: []organization.OrgUnitView{}, OrgUnitParents: []organization.OrgUnitParentView{},
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

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT u.id,u.code,v.label_payload_id,u.kind,"+r.structureDate("v.valid_from")+","+r.structureDate("v.valid_to")+",TRUE FROM org_unit u JOIN org_unit_version v ON v.org_id=u.org_id AND v.org_unit_id=u.id WHERE u.org_id=? AND v.valid_from<=? AND (v.valid_to IS NULL OR v.valid_to>?) ORDER BY u.kind,u.code,u.id"), org, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.OrgUnitView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.Code, &item.LabelPayloadID, &item.Kind, &item.ValidFrom, &to, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.OrgUnits = append(out.OrgUnits, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,child_unit_id,parent_unit_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+",TRUE FROM org_unit_parent_history WHERE org_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY child_unit_id,parent_unit_id,id"), org, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.OrgUnitParentView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.ChildUnitID, &item.ParentUnitID, &item.ValidFrom, &to, &item.Active); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.OrgUnitParents = append(out.OrgUnitParents, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT code,rank FROM education_level WHERE org_id=? ORDER BY rank DESC,code"), org)
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

func (r reader) WorkforceCatalogHistory(ctx context.Context, org, kind, after string, limit int) (organization.WorkforceCatalogs, string, bool, error) {
	out := organization.WorkforceCatalogs{
		History: true, LegalEntities: []organization.LegalEntityView{}, Locations: []string{}, OrgUnits: []organization.OrgUnitView{}, OrgUnitParents: []organization.OrgUnitParentView{},
		EducationLevels: []organization.EducationLevelView{}, JobFamilies: []organization.JobFamilyView{}, CareerLevels: []organization.CareerLevelView{},
	}
	var catalogRevision, graphRevision int64
	if err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT catalog_revision,graph_revision FROM organization WHERE id=?"), org).Scan(&catalogRevision, &graphRevision); errors.Is(err, sql.ErrNoRows) {
		return out, "", false, fault.NotFound
	} else if err != nil {
		return out, "", false, safeError(err)
	}
	out.CatalogRevision, out.GraphRevision = strconv.FormatInt(catalogRevision, 10), strconv.FormatInt(graphRevision, 10)
	if limit < 1 || limit > 101 {
		return out, "", false, fault.Invalid
	}
	afterDate, afterID := "0001-01-01", ""
	if after != "" {
		parts := strings.Split(after, "|")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return out, "", false, fault.Invalid
		}
		afterDate, afterID = parts[0], parts[1]
	}
	var rows *sql.Rows
	var err error
	switch kind {
	case "legal_entity":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT e.id,v.id,e.code,v.label_payload_id,"+r.structureDate("v.valid_from")+","+r.structureDate("v.valid_to")+" FROM legal_entity e JOIN legal_entity_version v ON v.org_id=e.org_id AND v.legal_entity_id=e.id WHERE e.org_id=? AND (v.valid_from>? OR (v.valid_from=? AND v.id>?)) ORDER BY v.valid_from,v.id LIMIT ?"), org, afterDate, afterDate, afterID, limit)
	case "business_group", "division", "department":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT u.id,v.id,u.code,v.label_payload_id,u.kind,"+r.structureDate("v.valid_from")+","+r.structureDate("v.valid_to")+" FROM org_unit u JOIN org_unit_version v ON v.org_id=u.org_id AND v.org_unit_id=u.id WHERE u.org_id=? AND u.kind=? AND (v.valid_from>? OR (v.valid_from=? AND v.id>?)) ORDER BY v.valid_from,v.id LIMIT ?"), org, kind, afterDate, afterDate, afterID, limit)
	case "org_unit_parent":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,child_unit_id,parent_unit_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM org_unit_parent_history WHERE org_id=? AND (valid_from>? OR (valid_from=? AND id>?)) ORDER BY valid_from,id LIMIT ?"), org, afterDate, afterDate, afterID, limit)
	case "job_family":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT f.id,v.id,f.code,v.label,"+r.structureDate("v.valid_from")+","+r.structureDate("v.valid_to")+" FROM job_family f JOIN job_family_version v ON v.org_id=f.org_id AND v.job_family_id=f.id WHERE f.org_id=? AND (v.valid_from>? OR (v.valid_from=? AND v.id>?)) ORDER BY v.valid_from,v.id LIMIT ?"), org, afterDate, afterDate, afterID, limit)
	case "career_level":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT c.id,v.id,c.code,v.label,v.rank,"+r.structureDate("v.valid_from")+","+r.structureDate("v.valid_to")+" FROM career_level c JOIN career_level_version v ON v.org_id=c.org_id AND v.career_level_id=c.id WHERE c.org_id=? AND (v.valid_from>? OR (v.valid_from=? AND v.id>?)) ORDER BY v.valid_from,v.id LIMIT ?"), org, afterDate, afterDate, afterID, limit)
	default:
		return out, "", false, fault.Invalid
	}
	if err != nil {
		return out, "", false, safeError(err)
	}
	defer rows.Close()
	keys := make([]string, 0, limit)
	for rows.Next() {
		var to sql.NullString
		switch kind {
		case "legal_entity":
			var item organization.LegalEntityView
			if err = rows.Scan(&item.ID, &item.VersionID, &item.Code, &item.LabelPayloadID, &item.ValidFrom, &to); err == nil {
				item.ValidTo, item.Active = stringPtr(to), !to.Valid
				out.LegalEntities = append(out.LegalEntities, item)
				keys = append(keys, item.ValidFrom+"|"+item.VersionID)
			}
		case "business_group", "division", "department":
			var item organization.OrgUnitView
			if err = rows.Scan(&item.ID, &item.VersionID, &item.Code, &item.LabelPayloadID, &item.Kind, &item.ValidFrom, &to); err == nil {
				item.ValidTo, item.Active = stringPtr(to), !to.Valid
				out.OrgUnits = append(out.OrgUnits, item)
				keys = append(keys, item.ValidFrom+"|"+item.VersionID)
			}
		case "org_unit_parent":
			var item organization.OrgUnitParentView
			if err = rows.Scan(&item.ID, &item.ChildUnitID, &item.ParentUnitID, &item.ValidFrom, &to); err == nil {
				item.ValidTo, item.Active = stringPtr(to), !to.Valid
				out.OrgUnitParents = append(out.OrgUnitParents, item)
				keys = append(keys, item.ValidFrom+"|"+item.ID)
			}
		case "job_family":
			var item organization.JobFamilyView
			if err = rows.Scan(&item.ID, &item.VersionID, &item.Code, &item.Label, &item.ValidFrom, &to); err == nil {
				item.ValidTo, item.Active = stringPtr(to), !to.Valid
				out.JobFamilies = append(out.JobFamilies, item)
				keys = append(keys, item.ValidFrom+"|"+item.VersionID)
			}
		case "career_level":
			var item organization.CareerLevelView
			if err = rows.Scan(&item.ID, &item.VersionID, &item.Code, &item.Label, &item.Rank, &item.ValidFrom, &to); err == nil {
				item.ValidTo, item.Active = stringPtr(to), !to.Valid
				out.CareerLevels = append(out.CareerLevels, item)
				keys = append(keys, item.ValidFrom+"|"+item.VersionID)
			}
		}
		if err != nil {
			return out, "", false, safeError(err)
		}
	}
	if err = rows.Err(); err != nil {
		return out, "", false, safeError(err)
	}
	more := len(keys) == limit
	if more {
		keys = keys[:len(keys)-1]
		switch kind {
		case "legal_entity":
			out.LegalEntities = out.LegalEntities[:len(keys)]
		case "business_group", "division", "department":
			out.OrgUnits = out.OrgUnits[:len(keys)]
		case "org_unit_parent":
			out.OrgUnitParents = out.OrgUnitParents[:len(keys)]
		case "job_family":
			out.JobFamilies = out.JobFamilies[:len(keys)]
		case "career_level":
			out.CareerLevels = out.CareerLevels[:len(keys)]
		}
	}
	last := ""
	if len(keys) != 0 {
		last = keys[len(keys)-1]
	}
	return out, last, more, nil
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

func (r reader) EmployeeWorkforceFacts(ctx context.Context, org, employee, asOf string) (organization.WorkforceFacts, error) {
	out := organization.WorkforceFacts{
		Identifiers: []organization.IdentifierView{}, Employment: []organization.EmploymentView{}, Education: []organization.EducationView{},
		JobAssignments: []organization.JobAssignmentView{}, ReportingLines: []organization.ReportingView{},
	}
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT id,kind,payload_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM employee_business_identifier WHERE org_id=? AND employee_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY valid_from,id"), org, employee, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.IdentifierView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.Kind, &item.PayloadID, &item.ValidFrom, &to); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.Identifiers = append(out.Identifiers, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,legal_entity_id,location_code,kind,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM employment_spell WHERE org_id=? AND employee_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY valid_from,id"), org, employee, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.EmploymentView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.LegalEntityID, &item.LocationCode, &item.Kind, &item.ValidFrom, &to); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.Employment = append(out.Employment, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,level_code,payload_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM education_record WHERE org_id=? AND employee_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY valid_from,id"), org, employee, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.EducationView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.Level, &item.PayloadID, &item.ValidFrom, &to); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.Education = append(out.Education, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,department_id,job_family_id,career_level_id,position_payload_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM job_assignment WHERE org_id=? AND employee_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) ORDER BY valid_from,id"), org, employee, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.JobAssignmentView
		var family, level, payload, to sql.NullString
		if err = rows.Scan(&item.ID, &item.DepartmentID, &family, &level, &payload, &item.ValidFrom, &to); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.JobFamilyID, item.CareerLevelID, item.ValidTo = stringPtr(family), stringPtr(level), stringPtr(to)
		item.PayloadID = payload.String
		out.JobAssignments = append(out.JobAssignments, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT id,employee_id,manager_employee_id,kind,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM reporting_line WHERE org_id=? AND employee_id=? AND superseded=false AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) AND (effective_to IS NULL OR effective_to>?) ORDER BY valid_from,id"), org, employee, asOf, asOf, asOf)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var item organization.ReportingView
		var to sql.NullString
		if err = rows.Scan(&item.ID, &item.EmployeeID, &item.ManagerEmployeeID, &item.Kind, &item.ValidFrom, &to); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		item.ValidTo = stringPtr(to)
		out.ReportingLines = append(out.ReportingLines, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, safeError(err)
	}
	rows.Close()
	return out, nil
}
