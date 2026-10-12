package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

var _ audit.Store = (*Repository)(nil)
var _ audit.Tx = (*transaction)(nil)

func (r *Repository) WithAuditTx(ctx context.Context, org string, fn func(audit.Tx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}

func (r *Repository) AuditEvents(ctx context.Context, org string, query audit.Query) ([]audit.Event, error) {
	return r.read().AuditEvents(ctx, org, query)
}

func (r reader) AuditEvents(ctx context.Context, org string, query audit.Query) ([]audit.Event, error) {
	if org == "" || query.Limit < 1 || query.Limit > 100 {
		return nil, fault.Invalid
	}
	where := []string{}
	args := make([]any, 0, 12)
	add := func(sqlite, postgres string, value any) {
		args = append(args, value)
		if r.backend == "sqlite" {
			where = append(where, sqlite)
		} else {
			where = append(where, fmt.Sprintf(postgres, len(args)))
		}
	}
	add("org_id=?", "org_id=$%d", org)
	for _, item := range []struct {
		value  string
		column string
	}{{query.SubjectID, "subject_id"}, {query.EmployeeID, "employee_id"}, {query.GrantID, "grant_id"}, {query.Operation, "operation"}, {query.Purpose, "purpose"}, {query.Outcome, "outcome"}} {
		if item.value != "" {
			add(item.column+"=?", item.column+"=$%d", item.value)
		}
	}
	if query.FromTime != nil {
		add("recorded_at>=?", "recorded_at>=$%d", r.bindTime(*query.FromTime))
	}
	if query.ToTime != nil {
		add("recorded_at<?", "recorded_at<$%d", r.bindTime(*query.ToTime))
	}
	if query.AfterTime != nil {
		args = append(args, r.bindTime(*query.AfterTime), query.AfterID)
		if r.backend == "sqlite" {
			where = append(where, "(recorded_at<? OR (recorded_at=? AND id<?))")
			args = append(args[:len(args)-1], args[len(args)-2], args[len(args)-1])
		} else {
			timePosition, idPosition := len(args)-1, len(args)
			where = append(where, fmt.Sprintf("(recorded_at<$%d OR (recorded_at=$%d AND id COLLATE \"C\"<$%d))", timePosition, timePosition, idPosition))
		}
	}
	args = append(args, query.Limit+1)
	limit := "?"
	order := "recorded_at DESC,id DESC"
	if r.backend == "postgres" {
		limit = fmt.Sprintf("$%d", len(args))
		order = "recorded_at DESC,id COLLATE \"C\" DESC"
	}
	statement := "SELECT id,subject_id,employee_id,grant_id,operation,purpose,request_id,outcome,recorded_at,actor_kind,target_subject_id,target_employee_id FROM audit_event WHERE " + strings.Join(where, " AND ") + " ORDER BY " + order + " LIMIT " + limit
	rows, err := r.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := make([]audit.Event, 0, query.Limit+1)
	for rows.Next() {
		var event audit.Event
		var subject, employee, grant, targetSubject, targetEmployee sql.NullString
		var recorded dbTime
		if err = rows.Scan(&event.ID, &subject, &employee, &grant, &event.Operation, &event.Purpose, &event.RequestID, &event.Outcome, &recorded, &event.ActorKind, &targetSubject, &targetEmployee); err != nil {
			return nil, safeError(err)
		}
		event.SubjectID, event.EmployeeID, event.GrantID = stringPtr(subject), stringPtr(employee), stringPtr(grant)
		event.TargetSubjectID, event.TargetEmployeeID = stringPtr(targetSubject), stringPtr(targetEmployee)
		event.RecordedAt = recorded.Time
		items = append(items, event)
	}
	return items, safeError(rows.Err())
}
