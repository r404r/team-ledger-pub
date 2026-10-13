package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
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
	predicate, args := "org_id=?", []any{org}
	if employee != "" {
		predicate += " AND employee_id=?"
		args = append(args, employee)
	}
	if asOf != "" {
		predicate += " AND superseded=false AND valid_from<=? AND (valid_to IS NULL OR valid_to>?) AND (effective_to IS NULL OR effective_to>?)"
		args = append(args, asOf, asOf, asOf)
	}
	query := "SELECT org_id,id,employee_id,manager_employee_id,kind," + r.structureDate("valid_from") + "," + r.structureDate("valid_to") + "," + r.structureDate("effective_to") + ",superseded,change_id,end_change_id,supersedes_id FROM reporting_line WHERE " + predicate + " ORDER BY id"
	rows, err := r.db.QueryContext(ctx, r.structureSQL(query), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	result := make([]organization.Relation, 0)
	for rows.Next() {
		relation, err := scanStructureRelation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, relation)
	}
	return result, safeError(rows.Err())
}
func scanStructureRelation(row interface{ Scan(...any) error }) (organization.Relation, error) {
	relation := organization.Relation{Kind: "reporting_line"}
	var to, effective, end, supersedes sql.NullString
	err := row.Scan(&relation.OrgID, &relation.ID, &relation.EmployeeID, &relation.ManagerEmployeeID, &relation.ReportingKind, &relation.Lifecycle.ValidFrom, &to, &effective, &relation.Superseded, &relation.ChangeID, &end, &supersedes)
	if err != nil {
		return organization.Relation{}, safeError(err)
	}
	relation.Lifecycle.ValidTo, relation.EffectiveTo = stringPtr(to), stringPtr(effective)
	relation.EndChangeID, relation.SupersedesID = end.String, supersedes.String
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
		if len(scope.Employees) == 0 && len(scope.Departments) == 0 {
			return []organization.Employee{}, nil
		}
		predicate += " AND ("
		clauses := make([]string, 0, 2)
		if len(scope.Employees) != 0 {
			clauses = append(clauses, "e.id IN ("+structurePlaceholders(len(scope.Employees))+")")
			for _, id := range scope.Employees {
				args = append(args, id)
			}
		}
		if len(scope.Departments) != 0 {
			clauses = append(clauses, "EXISTS (SELECT 1 FROM job_assignment auth_assignment WHERE auth_assignment.org_id=e.org_id AND auth_assignment.employee_id=e.id AND auth_assignment.department_id IN ("+structurePlaceholders(len(scope.Departments))+") AND auth_assignment.valid_from<=? AND (auth_assignment.valid_to IS NULL OR auth_assignment.valid_to>?))")
			for _, id := range scope.Departments {
				args = append(args, id)
			}
			args = append(args, scope.AuthorizationDate, scope.AuthorizationDate)
		}
		predicate += strings.Join(clauses, " OR ") + ")"
	}
	if query.EmployeeID != "" {
		predicate += " AND e.id=?"
		args = append(args, query.EmployeeID)
	}
	if query.DepartmentID != "" {
		predicate += " AND EXISTS (SELECT 1 FROM job_assignment a WHERE a.org_id=e.org_id AND a.employee_id=e.id AND a.department_id=? AND a.valid_from<=? AND (a.valid_to IS NULL OR a.valid_to>?))"
		args = append(args, query.DepartmentID, query.AsOf, query.AsOf)
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
	rows, err := r.db.QueryContext(ctx, r.structureSQL("SELECT i.action,i.kind,i.fact_id,i.employee_id,"+r.structureDate("i.valid_from")+","+r.structureDate("i.valid_to")+","+r.structureDate("i.effective_to")+",i.supersedes_id,j.position_payload_id FROM structure_change_item i LEFT JOIN job_assignment j ON j.org_id=i.org_id AND j.id=i.fact_id AND i.kind='job_assignment' WHERE i.org_id=? AND i.change_id=? ORDER BY i.ordinal"), org, change)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := make([]organization.HistoryRelation, 0)
	for rows.Next() {
		var item organization.HistoryRelation
		var id, employee, from, to, effective, supersedes, payload sql.NullString
		if err = rows.Scan(&item.Action, &item.Kind, &id, &employee, &from, &to, &effective, &supersedes, &payload); err != nil {
			return nil, safeError(err)
		}
		item.ID, item.EmployeeID, item.ValidFrom, item.ValidTo = id.String, employee.String, from.String, stringPtr(to)
		item.EffectiveTo, item.SupersedesID, item.PayloadID = stringPtr(effective), supersedes.String, payload.String
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
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
