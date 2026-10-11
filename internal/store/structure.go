package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

func (r *Repository) Graph(ctx context.Context, org string) (organization.Graph, error) {
	return r.read().Graph(ctx, org)
}
func (r *Repository) GraphState(ctx context.Context, org string) (organization.Graph, error) {
	return r.read().GraphState(ctx, org)
}
func (r *Repository) EmployeeRelations(ctx context.Context, org, employee, asOf string) ([]organization.Relation, error) {
	return r.read().EmployeeRelations(ctx, org, employee, asOf)
}
func (r *Repository) OrganizationPayload(ctx context.Context, org, id string) (organization.OrganizationPayload, error) {
	return r.read().OrganizationPayload(ctx, org, id)
}
func (r *Repository) StructureReceipt(ctx context.Context, org, subject, operation, key string) (organization.StructureReceipt, bool, error) {
	return r.read().StructureReceipt(ctx, org, subject, operation, key)
}
func (r *Repository) DirectoryCandidates(ctx context.Context, org, after string, query organization.DirectoryQuery, scope organization.DirectoryScope, limit int) ([]organization.Employee, error) {
	return r.read().DirectoryCandidates(ctx, org, after, query, scope, limit)
}
func (r *Repository) StructureHistory(ctx context.Context, org, employee string, query organization.HistoryQuery, after time.Time, afterID string, limit int) ([]organization.StructureChange, error) {
	return r.read().StructureHistory(ctx, org, employee, query, after, afterID, limit)
}

// Structure SQL uses question-mark placeholders until the complete predicate is
// assembled, so authorization and keyset predicates always precede LIMIT.
func (r reader) structureSQL(query string) string {
	if r.backend == "sqlite" {
		return query
	}
	var result strings.Builder
	n := 0
	for _, ch := range query {
		if ch == '?' {
			n++
			result.WriteByte('$')
			result.WriteString(strconv.Itoa(n))
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String()
}
func (r reader) structureDate(column string) string {
	if r.backend == "postgres" {
		return "to_char(" + column + ",'YYYY-MM-DD')"
	}
	return column
}
func structureDateValid(value string) bool {
	d, err := time.Parse("2006-01-02", value)
	return err == nil && d.Year() >= 1 && d.Year() <= 9999 && d.Format("2006-01-02") == value
}
func structureDateArg(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
func (r reader) structureTime(at time.Time) any {
	if r.backend == "sqlite" {
		return at.UTC().UnixMicro()
	}
	return at.UTC().Truncate(time.Microsecond)
}
func structurePlaceholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// GraphState deliberately loads no organization topology or sensitive payloads.
func (r reader) GraphState(ctx context.Context, org string) (organization.Graph, error) {
	g := organization.Graph{OrgID: org}
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT o.graph_revision,a.auth_epoch FROM organization o JOIN authorization_guard a ON a.org_id=o.id WHERE o.id=?"), org).Scan(&g.Revision, &g.AuthEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return g, fault.NotFound
	}
	if err != nil {
		return organization.Graph{}, safeError(err)
	}
	return g, nil
}

func (r reader) Graph(ctx context.Context, org string) (organization.Graph, error) {
	g, err := r.GraphState(ctx, org)
	if err != nil {
		return organization.Graph{}, err
	}
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,id,code,label_payload_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+" FROM team WHERE org_id=? ORDER BY id"), org)
	if err != nil {
		return organization.Graph{}, safeError(err)
	}
	for rows.Next() {
		var team organization.Team
		var label, to sql.NullString
		if err = rows.Scan(&team.OrgID, &team.ID, &team.Code, &label, &team.Lifecycle.ValidFrom, &to); err != nil {
			rows.Close()
			return organization.Graph{}, safeError(err)
		}
		team.LabelPayloadID, team.Lifecycle.ValidTo = label.String, stringPtr(to)
		g.Teams = append(g.Teams, team)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return organization.Graph{}, safeError(err)
	}
	g.Employees, err = r.structureEmployees(ctx, "e.org_id=?", []any{org}, "")
	if err != nil {
		return organization.Graph{}, err
	}
	g.Relations, err = r.structureRelations(ctx, org, "", "")
	if err != nil {
		return organization.Graph{}, err
	}
	return g, nil
}

func (r reader) structureEmployees(ctx context.Context, predicate string, args []any, suffix string) ([]organization.Employee, error) {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT e.org_id,e.id,e.profile_head_id,e.profile_revision,"+r.structureDate("e.valid_from")+","+r.structureDate("e.valid_to")+" FROM employee e WHERE "+predicate+" ORDER BY e.id"+suffix), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := make([]organization.Employee, 0)
	for rows.Next() {
		var employee organization.Employee
		var to sql.NullString
		if err = rows.Scan(&employee.OrgID, &employee.ID, &employee.HeadID, &employee.Revision, &employee.Lifecycle.ValidFrom, &to); err != nil {
			return nil, safeError(err)
		}
		employee.Lifecycle.ValidTo = stringPtr(to)
		result = append(result, employee)
	}
	return result, safeError(rows.Err())
}

func (r reader) structureRelations(ctx context.Context, org, employee, asOf string) ([]organization.Relation, error) {
	result := make([]organization.Relation, 0)
	for _, kind := range []string{"team_parent", "membership", "position", "reporting_line"} {
		table, employeeColumn, teamColumn, parentColumn, managerColumn, reportingColumn, primaryColumn, payloadColumn := structureRelationColumns(kind)
		if employee != "" && kind == "team_parent" {
			continue
		}
		predicate, args := "org_id=?", []any{org}
		if employee != "" {
			predicate += " AND employee_id=?"
			args = append(args, employee)
		}
		if asOf != "" {
			predicate += " AND superseded=false AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) AND (effective_to IS NULL OR effective_to>?)"
			args = append(args, asOf, asOf, asOf)
		}
		query := "SELECT org_id,id," + employeeColumn + "," + teamColumn + "," + parentColumn + "," + managerColumn + "," + reportingColumn + "," + primaryColumn + "," + r.structureDate("valid_from") + "," + r.structureDate("valid_to") + "," + r.structureDate("effective_to") + ",superseded,change_id,end_change_id,supersedes_id," + payloadColumn + " FROM " + table + " WHERE " + predicate + " ORDER BY id"
		rows, err := r.db.QueryContext(ctx, r.structureSQL(query), args...)
		if err != nil {
			return nil, safeError(err)
		}
		for rows.Next() {
			relation, err := scanStructureRelation(rows, kind)
			if err != nil {
				rows.Close()
				return nil, err
			}
			result = append(result, relation)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, safeError(err)
		}
	}
	return result, nil
}
func structureRelationColumns(kind string) (table, employee, team, parent, manager, reporting, primary, payload string) {
	employee, team, parent, manager, reporting, primary, payload = "NULL", "NULL", "NULL", "NULL", "NULL", "false", "NULL"
	switch kind {
	case "team_parent":
		table, team, parent = "team_parent_history", "child_team_id", "parent_team_id"
	case "membership":
		table, employee, team, primary = "team_membership", "employee_id", "team_id", "is_primary"
	case "position":
		table, employee, team, primary, payload = "position_assignment", "employee_id", "team_id", "is_primary", "payload_id"
	case "reporting_line":
		table, employee, manager, reporting = "reporting_line", "employee_id", "manager_employee_id", "kind"
	}
	return
}
func scanStructureRelation(row interface{ Scan(...any) error }, kind string) (organization.Relation, error) {
	relation := organization.Relation{Kind: kind}
	var employee, team, parent, manager, reporting, to, effective, end, supersedes, payload sql.NullString
	err := row.Scan(&relation.OrgID, &relation.ID, &employee, &team, &parent, &manager, &reporting, &relation.IsPrimary, &relation.Lifecycle.ValidFrom, &to, &effective, &relation.Superseded, &relation.ChangeID, &end, &supersedes, &payload)
	if err != nil {
		return organization.Relation{}, safeError(err)
	}
	relation.EmployeeID, relation.TeamID, relation.ParentTeamID, relation.ManagerEmployeeID, relation.ReportingKind = employee.String, team.String, parent.String, manager.String, reporting.String
	relation.Lifecycle.ValidTo, relation.EffectiveTo = stringPtr(to), stringPtr(effective)
	relation.EndChangeID, relation.SupersedesID, relation.PayloadID = end.String, supersedes.String, payload.String
	return relation, nil
}
func (r reader) EmployeeRelations(ctx context.Context, org, employee, asOf string) ([]organization.Relation, error) {
	if !structureDateValid(asOf) {
		return nil, fault.Invalid
	}
	return r.structureRelations(ctx, org, employee, asOf)
}

func (r reader) DirectoryCandidates(ctx context.Context, org, after string, query organization.DirectoryQuery, scope organization.DirectoryScope, limit int) ([]organization.Employee, error) {
	// The extra authorized candidate is a pagination peek; the domain scans
	// and decrypts at most 500 candidates, never the peek.
	if limit < 1 || limit > 501 || !structureDateValid(query.AsOf) || !structureDateValid(scope.AuthorizationDate) {
		return nil, fault.Invalid
	}
	predicate, args := "e.org_id=? AND e.id>?", []any{org, after}
	if !scope.Org {
		allowed := make([]string, 0, 2)
		if len(scope.Employees) != 0 {
			allowed = append(allowed, "e.id IN ("+structurePlaceholders(len(scope.Employees))+")")
			for _, id := range scope.Employees {
				args = append(args, id)
			}
		}
		if len(scope.Teams) != 0 {
			allowed = append(allowed, "EXISTS (SELECT 1 FROM team_membership m JOIN team t ON t.org_id=m.org_id AND t.id=m.team_id WHERE m.org_id=e.org_id AND m.employee_id=e.id AND m.team_id IN ("+structurePlaceholders(len(scope.Teams))+") AND m.superseded=false AND m.is_primary=true AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) AND (m.effective_to IS NULL OR m.effective_to>?) AND t.valid_from<=? AND (t.valid_to IS NULL OR t.valid_to>?) AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?))")
			for _, id := range scope.Teams {
				args = append(args, id)
			}
			for range 7 {
				args = append(args, scope.AuthorizationDate)
			}
		}
		if len(allowed) == 0 {
			return []organization.Employee{}, nil
		}
		predicate += " AND (" + strings.Join(allowed, " OR ") + ")"
	}
	if query.EmployeeID != "" {
		predicate += " AND e.id=?"
		args = append(args, query.EmployeeID)
	}
	if query.TeamID != "" {
		predicate += " AND EXISTS (SELECT 1 FROM team_membership m WHERE m.org_id=e.org_id AND m.employee_id=e.id AND m.team_id=? AND m.superseded=false AND m.is_primary=true AND m.valid_from<=? AND (m.valid_to IS NULL OR m.valid_to>?) AND (m.effective_to IS NULL OR m.effective_to>?))"
		args = append(args, query.TeamID, query.AsOf, query.AsOf, query.AsOf)
	}
	switch query.Lifecycle {
	case "", "active":
		predicate += " AND e.valid_from<=? AND (e.valid_to IS NULL OR e.valid_to>?)"
		args = append(args, query.AsOf, query.AsOf)
	case "inactive":
		predicate += " AND (e.valid_from>? OR (e.valid_to IS NOT NULL AND e.valid_to<=?))"
		args = append(args, query.AsOf, query.AsOf)
	case "all":
	default:
		return nil, fault.Invalid
	}
	args = append(args, limit)
	return r.structureEmployees(ctx, predicate, args, " LIMIT ?")
}

func (r reader) OrganizationPayload(ctx context.Context, org, id string) (organization.OrganizationPayload, error) {
	var payload organization.OrganizationPayload
	var employee sql.NullString
	var recorded dbTime
	envelope := &payload.Envelope
	binding := &envelope.Context
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM organizational_payload WHERE org_id=? AND id=?"), org, id).Scan(&payload.ID, &binding.OrgID, &employee, &binding.RecordID, &binding.VersionID, &binding.ObjectKind, &binding.Purpose, &binding.SchemaType, &binding.SchemaVersion, &envelope.FormatVersion, &envelope.Algorithm, &envelope.DEKID, &envelope.Key.KEKID, &envelope.Key.Version, &envelope.Key.Data, &envelope.SealedBytes, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return payload, fault.NotFound
	}
	if err != nil {
		return organization.OrganizationPayload{}, safeError(err)
	}
	// The stored context is authenticated by the cipher; routing arguments must
	// never replace any of these fields.
	binding.EmployeeID, payload.RecordedAt = employee.String, recorded.Time
	return payload, nil
}

func structureResultRevisions(result organization.StructureResult) (int64, int64, bool) {
	graph, err := strconv.ParseInt(result.GraphRevision, 10, 64)
	if err != nil || graph < 1 || strconv.FormatInt(graph, 10) != result.GraphRevision {
		return 0, 0, false
	}
	epoch, err := strconv.ParseInt(result.AuthEpoch, 10, 64)
	if err != nil || epoch < 1 || strconv.FormatInt(epoch, 10) != result.AuthEpoch {
		return 0, 0, false
	}
	return graph, epoch, true
}
func structureResultValid(operation string, result organization.StructureResult) bool {
	if !value.ValidID(result.ID) || len(result.Items) > 100 {
		return false
	}
	switch operation {
	case "OP-ORG-02":
		return len(result.Items) == 0
	case "OP-ORG-03":
		if len(result.Items) == 0 {
			return false
		}
		for _, item := range result.Items {
			if !value.ValidID(item.ID) {
				return false
			}
			switch item.Kind {
			case "team_parent", "membership", "position", "reporting_line", "team_lifecycle", "employee_lifecycle":
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Receipt authority is immutable routing metadata, not current lifecycle or
// relation qualification. The latter must not invalidate an original result.
func (r reader) structureReceiptTargetsValid(ctx context.Context, org string, targets []organization.StructureAuthorityTarget) (bool, error) {
	if len(targets) == 0 || len(targets) > 1000 || !value.ValidID(org) {
		return false, nil
	}
	var rows strings.Builder
	args := make([]any, 0, 2*len(targets)+2)
	for _, target := range targets {
		if !value.ValidID(target.ID) {
			return false, nil
		}
		switch target.Capability {
		case "organization.read", "organization.write":
			if target.Category != "metadata" {
				return false, nil
			}
		case "pii.read", "pii.write":
			if target.Category != "pii" {
				return false, nil
			}
		default:
			return false, nil
		}
		switch target.Kind {
		case "org":
			if target.ID != org {
				return false, nil
			}
			continue
		case "team", "employee":
		default:
			return false, nil
		}
		if rows.Len() != 0 {
			rows.WriteByte(',')
		}
		rows.WriteString("(?,?)")
		args = append(args, target.Kind, target.ID)
	}
	if rows.Len() == 0 {
		return true, nil
	}
	args = append(args, org, org)
	var valid bool
	err := r.db.QueryRowContext(ctx, r.structureSQL("WITH targets(kind,id) AS (VALUES "+rows.String()+") SELECT NOT EXISTS(SELECT 1 FROM targets t WHERE (t.kind='employee' AND NOT EXISTS(SELECT 1 FROM employee e WHERE e.org_id=? AND e.id=t.id)) OR (t.kind='team' AND NOT EXISTS(SELECT 1 FROM team tm WHERE tm.org_id=? AND tm.id=t.id)))"), args...).Scan(&valid)
	return valid, safeError(err)
}
func (r reader) StructureReceipt(ctx context.Context, org, subject, operation, key string) (organization.StructureReceipt, bool, error) {
	var receipt organization.StructureReceipt
	var encoded, targetsEncoded string
	var team, change sql.NullString
	var keyVersion int
	var graph, epoch int64
	err := r.db.QueryRowContext(ctx, r.structureSQL("SELECT digest,digest_key_version,result_json,result_team_id,result_change_id,graph_revision,auth_epoch,authority_targets_json FROM structure_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?"), org, subject, operation, key).Scan(&receipt.Digest, &keyVersion, &encoded, &team, &change, &graph, &epoch, &targetsEncoded)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return organization.StructureReceipt{}, false, safeError(err)
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt.Result); err != nil || keyVersion != 1 || len(receipt.Digest) != 32 || !structureResultValid(operation, receipt.Result) {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	if decoder.Decode(new(any)) != io.EOF {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	targetDecoder := json.NewDecoder(strings.NewReader(targetsEncoded))
	targetDecoder.DisallowUnknownFields()
	if targetDecoder.Decode(&receipt.Targets) != nil {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	var trailing any
	if targetDecoder.Decode(&trailing) != io.EOF {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	targetsValid, err := r.structureReceiptTargetsValid(ctx, org, receipt.Targets)
	if err != nil {
		return organization.StructureReceipt{}, false, err
	}
	if !targetsValid {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	gotGraph, gotEpoch, valid := structureResultRevisions(receipt.Result)
	if !valid || gotGraph != graph || gotEpoch != epoch ||
		(operation == "OP-ORG-02" && (!team.Valid || change.Valid || team.String != receipt.Result.ID)) ||
		(operation == "OP-ORG-03" && (!change.Valid || team.Valid || change.String != receipt.Result.ID)) {
		return organization.StructureReceipt{}, false, fault.Unavailable
	}
	return receipt, true, nil
}
func (t *transaction) SaveStructureReceipt(ctx context.Context, org, subject, operation, key string, receipt organization.StructureReceipt) error {
	graph, epoch, valid := structureResultRevisions(receipt.Result)
	if org != t.org || !valid || !structureResultValid(operation, receipt.Result) || len(receipt.Digest) != 32 {
		return fault.Invalid
	}
	targetsValid, err := t.structureReceiptTargetsValid(ctx, org, receipt.Targets)
	if err != nil {
		return err
	}
	if !targetsValid {
		return fault.Invalid
	}
	var team, change any
	if operation == "OP-ORG-02" {
		team = receipt.Result.ID
	} else {
		change = receipt.Result.ID
	}
	encoded, err := json.Marshal(receipt.Result)
	if err != nil {
		return fault.Invalid
	}
	targetsEncoded, err := json.Marshal(receipt.Targets)
	if err != nil {
		return fault.Invalid
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_json,result_team_id,result_change_id,graph_revision,auth_epoch,authority_targets_json) VALUES(?,?,?,?,?,1,?,?,?,?,?,?)"), org, subject, operation, key, receipt.Digest, string(encoded), team, change, graph, epoch, string(targetsEncoded))
	return safeError(err)
}

func (r reader) StructureHistory(ctx context.Context, org, employee string, query organization.HistoryQuery, after time.Time, afterID string, limit int) ([]organization.StructureChange, error) {
	if limit < 1 || limit > 101 || (query.From == "") != (query.To == "") {
		return nil, fault.Invalid
	}
	predicate := "c.org_id=? AND EXISTS (SELECT 1 FROM structure_change_item i WHERE i.org_id=c.org_id AND i.change_id=c.id AND i.employee_id=?)"
	args := []any{org, employee}
	if query.From != "" {
		if !structureDateValid(query.From) || !structureDateValid(query.To) || query.From >= query.To {
			return nil, fault.Invalid
		}
		from, _ := time.Parse("2006-01-02", query.From)
		to, _ := time.Parse("2006-01-02", query.To)
		predicate += " AND c.recorded_at>=? AND c.recorded_at<?"
		args = append(args, r.structureTime(from), r.structureTime(to))
	}
	if !after.IsZero() || afterID != "" {
		if after.IsZero() || afterID == "" {
			return nil, fault.Invalid
		}
		predicate += " AND (c.recorded_at>? OR (c.recorded_at=? AND c.id>?))"
		args = append(args, r.structureTime(after), r.structureTime(after), afterID)
	}
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT c.id,c.org_id,c.subject_id,c.recorded_at,c.graph_before,c.graph_after,c.reason_payload_id FROM structure_change c WHERE "+predicate+" ORDER BY c.recorded_at,c.id LIMIT ?"), args...)
	if err != nil {
		return nil, safeError(err)
	}
	changes := make([]organization.StructureChange, 0)
	for rows.Next() {
		var change organization.StructureChange
		var recorded dbTime
		var reason sql.NullString
		if err = rows.Scan(&change.ID, &change.OrgID, &change.SubjectID, &recorded, &change.GraphBefore, &change.GraphAfter, &reason); err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		change.RecordedAt, change.ReasonPayloadID = recorded.Time, reason.String
		changes = append(changes, change)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safeError(err)
	}
	// Close the change rows before hydration: SQLite transactions share their
	// single connection, and no decryption or external KMS call happens here.
	for i := range changes {
		changes[i].Items, err = r.structureHistoryItems(ctx, org, changes[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return changes, nil
}
func (r reader) structureHistoryItems(ctx context.Context, org, change string) ([]organization.HistoryRelation, error) {
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT action,kind,relation_id,employee_id,team_id,manager_employee_id,parent_team_id,"+r.structureDate("valid_from")+","+r.structureDate("valid_to")+","+r.structureDate("end_date")+",supersedes_id FROM structure_change_item WHERE org_id=? AND change_id=? ORDER BY ordinal"), org, change)
	if err != nil {
		return nil, safeError(err)
	}
	items := make([]organization.HistoryRelation, 0)
	for rows.Next() {
		var item organization.HistoryRelation
		var employee, team, manager, parent, from, to, end, supersedes sql.NullString
		if err = rows.Scan(&item.Action, &item.Kind, &item.ID, &employee, &team, &manager, &parent, &from, &to, &end, &supersedes); err != nil {
			rows.Close()
			return nil, safeError(err)
		}
		item.EmployeeID, item.TeamID, item.ManagerEmployeeID, item.ParentTeamID = employee.String, team.String, manager.String, parent.String
		item.ValidFrom, item.ValidTo, item.EndDate, item.SupersedesID = from.String, stringPtr(to), stringPtr(end), supersedes.String
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, safeError(err)
	}
	for i := range items {
		item := &items[i]
		table, employee, team, parent, manager, reporting, primary, payload := structureRelationColumns(item.Kind)
		if table == "" {
			var object string
			switch item.Kind {
			case "employee_lifecycle":
				table, object = "employee_lifecycle_history", "employee_id"
			case "team_lifecycle":
				table, object = "team_lifecycle_history", "team_id"
			default:
				return nil, fault.Unavailable
			}
			var from string
			var to, supersedes sql.NullString
			err = r.db.QueryRowContext(ctx, r.structureSQL("SELECT "+r.structureDate("h.valid_from")+","+r.structureDate("h.valid_to")+",h.supersedes_id,EXISTS(SELECT 1 FROM "+table+" n WHERE n.org_id=h.org_id AND n."+object+"=h."+object+" AND n.supersedes_id=h.id) FROM "+table+" h WHERE h.org_id=? AND h.id=?"), org, item.ID).Scan(&from, &to, &supersedes, &item.Superseded)
			if err != nil {
				return nil, safeError(err)
			}
			item.ValidFrom, item.ValidTo, item.SupersedesID = from, stringPtr(to), supersedes.String
			continue
		}
		query := "SELECT org_id,id," + employee + "," + team + "," + parent + "," + manager + "," + reporting + "," + primary + "," + r.structureDate("valid_from") + "," + r.structureDate("valid_to") + "," + r.structureDate("effective_to") + ",superseded,change_id,end_change_id,supersedes_id," + payload + " FROM " + table + " WHERE org_id=? AND id=?"
		relation, err := scanStructureRelation(r.db.QueryRowContext(ctx, r.structureSQL(query), org, item.ID), item.Kind)
		if err != nil {
			return nil, err
		}
		item.EmployeeID, item.TeamID, item.ParentTeamID, item.ManagerEmployeeID, item.ReportingKind = relation.EmployeeID, relation.TeamID, relation.ParentTeamID, relation.ManagerEmployeeID, relation.ReportingKind
		item.ValidFrom, item.ValidTo, item.EffectiveTo, item.Superseded, item.SupersedesID = relation.Lifecycle.ValidFrom, relation.Lifecycle.ValidTo, relation.EffectiveTo, relation.Superseded, relation.SupersedesID
		item.PayloadID = relation.PayloadID
		if item.Kind == "membership" || item.Kind == "position" {
			item.IsPrimary = &relation.IsPrimary
		}
	}
	return items, nil
}

func (t *transaction) LockGraph(ctx context.Context, org string) error {
	if org != t.org {
		return fault.Invalid
	}
	if t.backend == "sqlite" {
		result, err := t.tx.ExecContext(ctx, "UPDATE organization SET graph_revision=graph_revision WHERE id=?", org)
		return structureAffected(result, err, fault.NotFound)
	}
	var revision int64
	err := t.tx.QueryRowContext(ctx, "SELECT graph_revision FROM organization WHERE id=$1 FOR UPDATE", org).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound
	}
	return safeError(err)
}
func structureAffected(result sql.Result, err error, missing error) error {
	if err != nil {
		return safeError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	if count != 1 {
		return missing
	}
	return nil
}

func (t *transaction) CommitStructure(ctx context.Context, org string, expected int64, write organization.StructureWrite) (int64, int64, error) {
	if org != t.org || !value.ValidID(org) || expected < 1 || expected == math.MaxInt64 || write.Change.OrgID != org || !value.ValidID(write.Change.ID) ||
		!value.ValidID(write.Change.SubjectID) || !structureOptionalIDsValid(write.Change.ReasonPayloadID) || len(write.Change.Items) == 0 || len(write.Change.Items) > 100 {
		return 0, 0, fault.Invalid
	}
	write.Change.GraphBefore, write.Change.GraphAfter = expected, expected+1
	for _, item := range write.Change.Items {
		if !structureHistoryFactValid(item) {
			return 0, 0, fault.Invalid
		}
	}
	if write.Team != nil && (write.Team.OrgID != org || !value.ValidID(write.Team.ID) || !structureOptionalIDsValid(write.Team.LabelPayloadID) || !structureLifecycleValid(write.Team.Lifecycle)) {
		return 0, 0, fault.Invalid
	}
	for _, relations := range [][]organization.Relation{write.Added, write.Ended, write.Superseded} {
		for _, relation := range relations {
			table, _, _, _, _, _, _, _ := structureRelationColumns(relation.Kind)
			if table == "" || relation.OrgID != org || !value.ValidID(relation.ID) ||
				!structureOptionalIDsValid(relation.EmployeeID, relation.TeamID, relation.ParentTeamID, relation.ManagerEmployeeID, relation.SupersedesID, relation.PayloadID) {
				return 0, 0, fault.Invalid
			}
		}
	}
	for _, relation := range write.Added {
		if relation.ChangeID != write.Change.ID || relation.Superseded || relation.EffectiveTo != nil || relation.EndChangeID != "" || !structureLifecycleValid(relation.Lifecycle) {
			return 0, 0, fault.Invalid
		}
	}
	for _, relation := range write.Ended {
		if relation.EndChangeID != write.Change.ID || relation.EffectiveTo == nil || !structureDateValid(*relation.EffectiveTo) {
			return 0, 0, fault.Invalid
		}
	}
	for _, fact := range write.Lifecycles {
		if fact.OrgID != org || !value.ValidID(fact.ID) || !value.ValidID(fact.ObjectID) || !structureOptionalIDsValid(fact.SupersedesID) || fact.ChangeID != write.Change.ID ||
			(fact.Kind != "team_lifecycle" && fact.Kind != "employee_lifecycle") || !structureLifecycleValid(fact.Lifecycle) {
			return 0, 0, fault.Invalid
		}
	}
	for _, payload := range write.Payloads {
		if !structurePayloadRoutingValid(org, write, payload) {
			return 0, 0, fault.Invalid
		}
	}
	var revision, epoch int64
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT o.graph_revision,a.auth_epoch FROM organization o JOIN authorization_guard a ON a.org_id=o.id WHERE o.id=?"), org).Scan(&revision, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, fault.NotFound
	}
	if err != nil {
		return 0, 0, safeError(err)
	}
	if revision != expected || epoch == math.MaxInt64 {
		return 0, 0, fault.Conflict
	}
	// Change ownership exists first. Typed payload and position/team references
	// are deliberately deferred by the schema, not replaced with free UUIDs.
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,reason_payload_id) VALUES(?,?,?,?,?,?,?)"), org, write.Change.ID, write.Change.SubjectID, t.bindTime(write.Change.RecordedAt), expected, expected+1, nullable(write.Change.ReasonPayloadID))
	if err != nil {
		return 0, 0, safeError(err)
	}
	if write.Team != nil {
		team := write.Team
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO team(org_id,id,code,valid_from,valid_to,label_payload_id) VALUES(?,?,?,?,?,?)"), org, team.ID, team.Code, team.Lifecycle.ValidFrom, structureDateArg(team.Lifecycle.ValidTo), nullable(team.LabelPayloadID))
		if err != nil {
			return 0, 0, safeError(err)
		}
	}
	for _, relation := range write.Ended {
		table, _, _, _, _, _, _, _ := structureRelationColumns(relation.Kind)
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE "+table+" SET effective_to=?,end_change_id=? WHERE org_id=? AND id=? AND superseded=false AND effective_to IS NULL AND end_change_id IS NULL AND valid_from<?"), *relation.EffectiveTo, write.Change.ID, org, relation.ID, *relation.EffectiveTo)
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, err
		}
	}
	for _, relation := range write.Superseded {
		table, _, _, _, _, _, _, _ := structureRelationColumns(relation.Kind)
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE "+table+" SET superseded=true WHERE org_id=? AND id=? AND superseded=false"), org, relation.ID)
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return 0, 0, err
		}
	}
	for _, relation := range write.Added {
		if err = t.insertStructureRelation(ctx, relation); err != nil {
			return 0, 0, err
		}
	}
	for i := range write.Lifecycles {
		fact := &write.Lifecycles[i]
		if err = t.insertStructureLifecycle(ctx, fact, write.Team != nil && fact.Kind == "team_lifecycle" && fact.ObjectID == write.Team.ID); err != nil {
			return 0, 0, err
		}
	}
	for _, payload := range write.Payloads {
		if err = t.insertOrganizationPayload(ctx, payload); err != nil {
			return 0, 0, err
		}
	}
	for ordinal, item := range write.Change.Items {
		// Lifecycle supersedes is derived from the immutable head when omitted
		// by the domain; persist the same exact chain in the command fact.
		for _, fact := range write.Lifecycles {
			if fact.ID == item.ID && fact.Kind == item.Kind {
				item.SupersedesID = fact.SupersedesID
			}
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO structure_change_item(org_id,change_id,ordinal,action,kind,relation_id,employee_id,team_id,manager_employee_id,parent_team_id,valid_from,valid_to,end_date,supersedes_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), org, write.Change.ID, ordinal, item.Action, item.Kind, item.ID, nullable(item.EmployeeID), nullable(item.TeamID), nullable(item.ManagerEmployeeID), nullable(item.ParentTeamID), nullable(item.ValidFrom), structureDateArg(item.ValidTo), structureDateArg(item.EndDate), nullable(item.SupersedesID))
		if err != nil {
			return 0, 0, safeError(err)
		}
	}
	result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE organization SET graph_revision=graph_revision+1 WHERE id=? AND graph_revision=? AND graph_revision<?"), org, expected, int64(math.MaxInt64))
	if err = structureAffected(result, err, fault.Conflict); err != nil {
		return 0, 0, err
	}
	result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch=? AND auth_epoch<?"), org, epoch, int64(math.MaxInt64))
	if err = structureAffected(result, err, fault.Conflict); err != nil {
		return 0, 0, err
	}
	return expected + 1, epoch + 1, nil
}
func structureOptionalIDsValid(ids ...string) bool {
	for _, id := range ids {
		if id != "" && !value.ValidID(id) {
			return false
		}
	}
	return true
}
func structureHistoryFactValid(item organization.HistoryRelation) bool {
	if !value.ValidID(item.ID) || !structureOptionalIDsValid(item.EmployeeID, item.TeamID, item.ParentTeamID, item.ManagerEmployeeID, item.SupersedesID) {
		return false
	}
	switch item.Kind {
	case "team_parent", "membership", "position", "reporting_line":
		if item.Action != "add" && item.Action != "end" && item.Action != "replace" {
			return false
		}
	case "team_lifecycle", "employee_lifecycle":
		if item.Action != "lifecycle" {
			return false
		}
	default:
		return false
	}
	return (item.ValidFrom == "" || structureDateValid(item.ValidFrom)) &&
		(item.ValidTo == nil || structureDateValid(*item.ValidTo)) &&
		(item.EndDate == nil || structureDateValid(*item.EndDate))
}
func structureLifecycleValid(lifecycle organization.Lifecycle) bool {
	return structureDateValid(lifecycle.ValidFrom) && (lifecycle.ValidTo == nil || (structureDateValid(*lifecycle.ValidTo) && *lifecycle.ValidTo > lifecycle.ValidFrom))
}
func structurePayloadRoutingValid(org string, write organization.StructureWrite, payload organization.OrganizationPayload) bool {
	binding := payload.Envelope.Context
	if binding.OrgID != org || binding.VersionID != payload.ID || payload.ID == "" || binding.Purpose != "pii" || binding.SchemaVersion != 1 {
		return false
	}
	switch binding.ObjectKind {
	case "team_label":
		return write.Team != nil && binding.EmployeeID == "" && binding.SchemaType == "org.team.label.v1" && binding.RecordID == write.Team.ID && payload.ID == write.Team.LabelPayloadID
	case "structure_change":
		return binding.EmployeeID == "" && binding.SchemaType == "org.structure.reason.v1" && binding.RecordID == write.Change.ID && payload.ID == write.Change.ReasonPayloadID
	case "position_assignment":
		if binding.SchemaType != "org.position.v1" {
			return false
		}
		for _, relation := range write.Added {
			if relation.Kind == "position" && relation.ID == binding.RecordID && relation.EmployeeID == binding.EmployeeID && relation.PayloadID == payload.ID {
				return true
			}
		}
	}
	return false
}
func (t *transaction) insertStructureRelation(ctx context.Context, relation organization.Relation) error {
	table, _, _, _, _, _, _, _ := structureRelationColumns(relation.Kind)
	columns := "org_id,id,valid_from,valid_to,effective_to,superseded,change_id,end_change_id,supersedes_id"
	args := []any{relation.OrgID, relation.ID, relation.Lifecycle.ValidFrom, structureDateArg(relation.Lifecycle.ValidTo), nil, false, relation.ChangeID, nil, nullable(relation.SupersedesID)}
	switch relation.Kind {
	case "team_parent":
		columns += ",child_team_id,parent_team_id"
		args = append(args, relation.TeamID, relation.ParentTeamID)
	case "membership":
		columns += ",employee_id,team_id,is_primary"
		args = append(args, relation.EmployeeID, relation.TeamID, relation.IsPrimary)
	case "position":
		columns += ",employee_id,team_id,is_primary,payload_id"
		args = append(args, relation.EmployeeID, nullable(relation.TeamID), relation.IsPrimary, relation.PayloadID)
	case "reporting_line":
		columns += ",employee_id,manager_employee_id,kind"
		args = append(args, relation.EmployeeID, relation.ManagerEmployeeID, relation.ReportingKind)
	default:
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO "+table+"("+columns+") VALUES("+structurePlaceholders(len(args))+")"), args...)
	return safeError(err)
}
func (t *transaction) insertOrganizationPayload(ctx context.Context, payload organization.OrganizationPayload) error {
	envelope := payload.Envelope
	binding := envelope.Context
	var team, position, change any
	switch binding.ObjectKind {
	case "team_label":
		team = binding.RecordID
	case "position_assignment":
		position = binding.RecordID
	case "structure_change":
		change = binding.RecordID
	default:
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO organizational_payload(org_id,id,employee_id,team_id,position_id,change_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), binding.OrgID, payload.ID, nullable(binding.EmployeeID), team, position, change, binding.RecordID, binding.VersionID, binding.ObjectKind, binding.Purpose, binding.SchemaType, binding.SchemaVersion, envelope.FormatVersion, envelope.Algorithm, envelope.DEKID, envelope.Key.KEKID, envelope.Key.Version, envelope.Key.Data, envelope.SealedBytes, t.bindTime(payload.RecordedAt))
	return safeError(err)
}
func (t *transaction) insertStructureLifecycle(ctx context.Context, fact *organization.LifecycleFact, newTeam bool) error {
	table, objectColumn, projection := "employee_lifecycle_history", "employee_id", "employee"
	if fact.Kind == "team_lifecycle" {
		table, objectColumn, projection = "team_lifecycle_history", "team_id", "team"
	}
	var head string
	err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT h.id FROM "+table+" h WHERE h.org_id=? AND h."+objectColumn+"=? AND NOT EXISTS (SELECT 1 FROM "+table+" n WHERE n.org_id=h.org_id AND n."+objectColumn+"=h."+objectColumn+" AND n.supersedes_id=h.id)"), fact.OrgID, fact.ObjectID).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		if !newTeam || fact.SupersedesID != "" {
			return fault.Conflict
		}
	} else if err != nil {
		return safeError(err)
	} else if newTeam || (fact.SupersedesID != "" && fact.SupersedesID != head) {
		return fault.Conflict
	}
	fact.SupersedesID = head
	if !newTeam {
		result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE "+projection+" SET valid_from=?,valid_to=? WHERE org_id=? AND id=?"), fact.Lifecycle.ValidFrom, structureDateArg(fact.Lifecycle.ValidTo), fact.OrgID, fact.ObjectID)
		if err = structureAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO "+table+"(org_id,id,"+objectColumn+",valid_from,valid_to,change_id,supersedes_id) VALUES(?,?,?,?,?,?,?)"), fact.OrgID, fact.ID, fact.ObjectID, fact.Lifecycle.ValidFrom, structureDateArg(fact.Lifecycle.ValidTo), fact.ChangeID, nullable(fact.SupersedesID))
	return safeError(err)
}
