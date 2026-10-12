package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

var _ audit.DeliveryStore = (*Repository)(nil)

func (r *Repository) ClaimAuditDelivery(ctx context.Context, now time.Time, lease time.Duration) (audit.Delivery, bool, error) {
	if lease < time.Second || lease > 5*time.Minute {
		return audit.Delivery{}, false, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return audit.Delivery{}, false, safeError(err)
	}
	defer tx.Rollback()
	token, until := value.NewID(), now.UTC().Truncate(time.Microsecond).Add(lease)
	boundNow, boundUntil := any(now.UTC().Truncate(time.Microsecond)), any(until)
	statement := "UPDATE audit_outbox SET state='inflight',attempt=attempt+1,claim_token=?,claim_until=? WHERE event_id=(SELECT event_id FROM audit_outbox WHERE (state='pending' AND available_at<=?) OR (state='inflight' AND claim_until<=?) ORDER BY available_at,event_id LIMIT 1)"
	args := []any{token, boundUntil, boundNow, boundNow}
	if r.Backend == "sqlite" {
		boundNow, boundUntil = now.UTC().UnixMicro(), until.UTC().UnixMicro()
		args = []any{token, boundUntil, boundNow, boundNow}
	} else {
		statement = "UPDATE audit_outbox SET state='inflight',attempt=attempt+1,claim_token=$1,claim_until=$2 WHERE event_id=(SELECT event_id FROM audit_outbox WHERE (state='pending' AND available_at<=$3) OR (state='inflight' AND claim_until<=$3) ORDER BY available_at,event_id LIMIT 1 FOR UPDATE SKIP LOCKED)"
		args = []any{token, boundUntil, boundNow}
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return audit.Delivery{}, false, safeError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed > 1 {
		return audit.Delivery{}, false, fault.Unavailable
	}
	if changed == 0 {
		if err = tx.Commit(); err != nil {
			return audit.Delivery{}, false, safeError(err)
		}
		return audit.Delivery{}, false, nil
	}
	query := "SELECT e.id,o.org_id,e.subject_id,e.employee_id,e.grant_id,e.operation,e.purpose,e.request_id,e.outcome,e.recorded_at,e.actor_kind,e.target_subject_id,e.target_employee_id,o.attempt,o.claim_until FROM audit_outbox o JOIN audit_event e ON e.id=o.event_id WHERE o.claim_token=? AND o.state='inflight'"
	if r.Backend == "postgres" {
		query = "SELECT e.id,o.org_id,e.subject_id,e.employee_id,e.grant_id,e.operation,e.purpose,e.request_id,e.outcome,e.recorded_at,e.actor_kind,e.target_subject_id,e.target_employee_id,o.attempt,o.claim_until FROM audit_outbox o JOIN audit_event e ON e.id=o.event_id WHERE o.claim_token=$1 AND o.state='inflight'"
	}
	var delivery audit.Delivery
	var org, subject, employee, grant, targetSubject, targetEmployee sql.NullString
	var recorded, claimUntil dbTime
	if err = tx.QueryRowContext(ctx, query, token).Scan(&delivery.ID, &org, &subject, &employee, &grant, &delivery.Operation, &delivery.Purpose, &delivery.RequestID, &delivery.Outcome, &recorded, &delivery.ActorKind, &targetSubject, &targetEmployee, &delivery.Attempt, &claimUntil); err != nil {
		return audit.Delivery{}, false, safeError(err)
	}
	delivery.OrgID, delivery.SubjectID, delivery.EmployeeID, delivery.GrantID = stringPtr(org), stringPtr(subject), stringPtr(employee), stringPtr(grant)
	delivery.TargetSubjectID, delivery.TargetEmployeeID = stringPtr(targetSubject), stringPtr(targetEmployee)
	delivery.RecordedAt, delivery.ClaimUntil, delivery.ClaimToken = recorded.Time, claimUntil.Time, token
	if err = tx.Commit(); err != nil {
		return audit.Delivery{}, false, safeError(err)
	}
	return delivery, true, nil
}

func (r *Repository) AckAuditDelivery(ctx context.Context, eventID, claimToken string, receipt audit.DeliveryReceipt, now time.Time) error {
	if !value.ValidID(eventID) || !value.ValidID(claimToken) || !value.ValidID(receipt.ReceiptID) || len(receipt.Digest) != 32 {
		return fault.Invalid
	}
	at := any(now.UTC().Truncate(time.Microsecond))
	query := "UPDATE audit_outbox SET state='acked',claim_token=NULL,claim_until=NULL,receipt_id=?,receipt_digest=?,acked_at=? WHERE event_id=? AND state='inflight' AND claim_token=? AND claim_until>?"
	args := []any{receipt.ReceiptID, receipt.Digest, at, eventID, claimToken, at}
	if r.Backend == "sqlite" {
		at = now.UTC().UnixMicro()
		args[2], args[5] = at, at
	} else {
		query = "UPDATE audit_outbox SET state='acked',claim_token=NULL,claim_until=NULL,receipt_id=$1,receipt_digest=$2,acked_at=$3 WHERE event_id=$4 AND state='inflight' AND claim_token=$5 AND claim_until>$3"
		args = []any{receipt.ReceiptID, receipt.Digest, at, eventID, claimToken}
	}
	result, err := r.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return safeError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fault.Conflict
	}
	return nil
}

func (r *Repository) RetryAuditDelivery(ctx context.Context, eventID, claimToken string, available time.Time) error {
	if !value.ValidID(eventID) || !value.ValidID(claimToken) {
		return fault.Invalid
	}
	at := any(available.UTC().Truncate(time.Microsecond))
	query := "UPDATE audit_outbox SET state='pending',claim_token=NULL,claim_until=NULL,available_at=? WHERE event_id=? AND state='inflight' AND claim_token=?"
	if r.Backend == "sqlite" {
		at = available.UTC().UnixMicro()
	} else {
		query = "UPDATE audit_outbox SET state='pending',claim_token=NULL,claim_until=NULL,available_at=$1 WHERE event_id=$2 AND state='inflight' AND claim_token=$3"
	}
	result, err := r.DB.ExecContext(ctx, query, at, eventID, claimToken)
	if err != nil {
		return safeError(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fault.Conflict
	}
	return nil
}

func (r *Repository) AuditDeliveryBacklog(ctx context.Context, now time.Time) (int64, *time.Time, error) {
	query := "SELECT count(*),min(e.recorded_at) FROM audit_outbox o JOIN audit_event e ON e.id=o.event_id WHERE o.state!='acked'"
	var count int64
	if r.Backend == "sqlite" {
		var oldest sql.NullInt64
		if err := r.DB.QueryRowContext(ctx, query).Scan(&count, &oldest); err != nil {
			return 0, nil, safeError(err)
		}
		if !oldest.Valid {
			return count, nil, nil
		}
		value := time.UnixMicro(oldest.Int64).UTC()
		return count, &value, nil
	}
	var oldest sql.NullTime
	if err := r.DB.QueryRowContext(ctx, query).Scan(&count, &oldest); err != nil {
		return 0, nil, safeError(err)
	}
	if !oldest.Valid {
		return count, nil, nil
	}
	value := oldest.Time.UTC().Truncate(time.Microsecond)
	return count, &value, nil
}
