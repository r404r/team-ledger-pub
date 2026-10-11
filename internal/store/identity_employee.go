package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
)

func approvedEmployee(ctx context.Context, q reader, org, subject string) (string, error) {
	var employee string
	err := q.db.QueryRowContext(ctx, q.sql("SELECT employee_id FROM subject_employee WHERE org_id=? AND subject_id=?", "SELECT employee_id FROM subject_employee WHERE org_id=$1 AND subject_id=$2"), org, subject).Scan(&employee)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return employee, safeError(err)
}

// The enclosing native identity transaction already owns the authorization and
// subject guards. This is explicit correspondence, never automatic provisioning
// or a source of standing capabilities/grants. Existing links cannot be rebound.
func bindApprovedEmployee(ctx context.Context, q reader, m *identity.Identity) error {
	current, err := approvedEmployee(ctx, q, m.OrgID, m.SubjectID)
	if err != nil {
		return err
	}
	if m.EmployeeID == "" {
		m.EmployeeID = current
		return nil
	}
	if current != "" {
		if current != m.EmployeeID {
			return fault.Conflict
		}
		return nil
	}
	var exists int
	if err = q.db.QueryRowContext(ctx, q.sql("SELECT 1 FROM employee WHERE org_id=? AND id=?", "SELECT 1 FROM employee WHERE org_id=$1 AND id=$2"), m.OrgID, m.EmployeeID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fault.Invalid
		}
		return safeError(err)
	}
	if _, err = q.db.ExecContext(ctx, q.sql("INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES(?,?,?)", "INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES($1,$2,$3)"), m.OrgID, m.SubjectID, m.EmployeeID); err != nil {
		return safeError(err)
	}
	result, err := q.db.ExecContext(ctx, q.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch<9223372036854775807", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND auth_epoch<9223372036854775807"), m.OrgID)
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	if n != 1 {
		return fault.Unavailable
	}
	return nil
}
