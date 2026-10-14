package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

var _ compensation.BonusStore = (*Repository)(nil)
var _ compensation.BonusTx = (*transaction)(nil)

func (r *Repository) WithBonusTx(ctx context.Context, org string, fn func(compensation.BonusTx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}

func (r *Repository) BonusSnapshot(ctx context.Context, org, employee string) (compensation.BonusSnapshot, error) {
	return r.read().BonusSnapshot(ctx, org, employee)
}
func (r *Repository) BonusAggregate(ctx context.Context, org, employee string) (compensation.BonusAggregateRecord, error) {
	return r.read().BonusAggregate(ctx, org, employee)
}
func (r *Repository) BonusSnapshotPage(ctx context.Context, org, employee string, query compensation.BonusPageQuery) (compensation.BonusSnapshotPage, error) {
	return r.read().BonusSnapshotPage(ctx, org, employee, query)
}
func (r *Repository) BonusPayload(ctx context.Context, org, id string) (compensation.Payload, error) {
	return r.read().BonusPayload(ctx, org, id)
}
func (r *Repository) BonusCommandReceipt(ctx context.Context, org, subject, operation, key string) (compensation.BonusResult, []byte, bool, error) {
	return r.read().BonusCommandReceipt(ctx, org, subject, operation, key)
}
func (r *Repository) BonusPaymentByDigest(ctx context.Context, org, employee, keyID string, version int64, digest []byte) (compensation.BonusPaymentRecord, bool, error) {
	return r.read().BonusPaymentByDigest(ctx, org, employee, keyID, version, digest)
}
func (r *Repository) BonusHMACReady(ctx context.Context, org string) (int64, string, error) {
	return r.read().BonusHMACReady(ctx, org)
}
func (r *Repository) BonusTarget(ctx context.Context, org, id string) (compensation.BonusTargetRecord, error) {
	return r.read().BonusTarget(ctx, org, id)
}
func (r *Repository) BonusAward(ctx context.Context, org, id string) (compensation.BonusAwardRecord, error) {
	return r.read().BonusAward(ctx, org, id)
}

func (r reader) BonusAggregate(ctx context.Context, org, employee string) (compensation.BonusAggregateRecord, error) {
	out := compensation.BonusAggregateRecord{OrgID: org, EmployeeID: employee}
	err := r.db.QueryRowContext(ctx, r.sql("SELECT revision FROM bonus_aggregate WHERE org_id=? AND employee_id=?", "SELECT revision FROM bonus_aggregate WHERE org_id=$1 AND employee_id=$2"), org, employee).Scan(&out.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, safeError(err)
}

func bonusPageAfter(r reader, kind, after string) (any, string, error) {
	if after == "" {
		return nil, "", nil
	}
	at, id, ok := strings.Cut(after, "|")
	if !ok || id == "" {
		return nil, "", fault.Invalid
	}
	if kind == "payments" {
		if !strings.HasSuffix(at, "T00:00:00Z") {
			return nil, "", fault.Invalid
		}
		date := strings.TrimSuffix(at, "T00:00:00Z")
		if len(date) != 10 {
			return nil, "", fault.Invalid
		}
		return date, id, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, "", fault.Invalid
	}
	return r.bindTime(parsed), id, nil
}

func bonusPagePredicate(r reader, query compensation.BonusPageQuery, periodStartColumn, periodEndColumn, keyColumn string) (string, []any, error) {
	predicate := " WHERE org_id=? AND employee_id=?"
	args := []any{}
	if query.RecordID != "" {
		predicate += " AND id=?"
		args = append(args, query.RecordID)
	}
	if query.PeriodStart != "" {
		predicate += " AND " + periodEndColumn + ">=?"
		args = append(args, query.PeriodStart)
	}
	if query.PeriodEnd != "" {
		predicate += " AND " + periodStartColumn + "<=?"
		args = append(args, query.PeriodEnd)
	}
	after, id, err := bonusPageAfter(r, query.Kind, query.After)
	if err != nil {
		return "", nil, err
	}
	if after != nil {
		predicate += " AND (" + keyColumn + ">? OR (" + keyColumn + "=? AND id>?))"
		args = append(args, after, after, id)
	}
	return predicate, args, nil
}

func (r reader) BonusSnapshotPage(ctx context.Context, org, employee string, query compensation.BonusPageQuery) (compensation.BonusSnapshotPage, error) {
	out := compensation.BonusSnapshotPage{Snapshot: compensation.BonusSnapshot{Targets: []compensation.BonusTargetRecord{}, Awards: []compensation.BonusAwardRecord{}, Approvals: []compensation.BonusApprovalRecord{}, Payments: []compensation.BonusPaymentRecord{}, Extensions: []compensation.BonusExtensionRecord{}}}
	if query.Limit < 1 || query.Limit > 100 {
		return out, fault.Invalid
	}
	var err error
	out.Snapshot.Aggregate, err = r.BonusAggregate(ctx, org, employee)
	if err != nil {
		return out, err
	}
	startColumn, endColumn := "period_start", "period_end"
	if query.Kind == "payments" {
		startColumn, endColumn = "paid_date", "paid_date"
	} else if query.Kind == "extensions" {
		query.PeriodStart, query.PeriodEnd = "", ""
		startColumn, endColumn = "recorded_at", "recorded_at"
	}
	predicate, args, err := bonusPagePredicate(r, query, startColumn, endColumn, map[string]string{"targets": "recorded_at", "awards": "recorded_at", "payments": "paid_date", "extensions": "recorded_at"}[query.Kind])
	if err != nil {
		return out, err
	}
	args = append([]any{org, employee}, args...)
	args = append(args, query.Limit+1)
	var rows *sql.Rows
	switch query.Kind {
	case "targets":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,state,version_id,payload_id,"+r.structureDate("period_start")+","+r.structureDate("period_end")+",actor_subject_id,revision,basis_revision,recorded_at FROM bonus_target"+predicate+" ORDER BY recorded_at,id LIMIT ?"), args...)
	case "awards":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,state,version_id,payload_id,author_subject_id,"+r.structureDate("period_start")+","+r.structureDate("period_end")+",target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at FROM bonus_award"+predicate+" ORDER BY recorded_at,id LIMIT ?"), args...)
	case "payments":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,payload_id,kind,"+r.structureDate("paid_date")+",business_source,award_id,original_payment_id,business_key_id,business_key_version,basis_revision,business_digest,recorded_at FROM bonus_payment"+predicate+" ORDER BY paid_date,id LIMIT ?"), args...)
	case "extensions":
		rows, err = r.db.QueryContext(ctx, r.structureSQL("SELECT org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,supersedes_id,recorded_at FROM compensation_extension_version"+predicate+" ORDER BY recorded_at,id LIMIT ?"), args...)
	default:
		return out, fault.Invalid
	}
	if err != nil {
		return out, safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var at dbTime
		switch query.Kind {
		case "targets":
			var v compensation.BonusTargetRecord
			err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.PeriodStart, &v.PeriodEnd, &v.ActorSubjectID, &v.Revision, &v.BasisRevision, &at)
			v.RecordedAt = at.Time
			out.Snapshot.Targets = append(out.Snapshot.Targets, v)
		case "awards":
			var v compensation.BonusAwardRecord
			err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.AuthorSubjectID, &v.PeriodStart, &v.PeriodEnd, &v.TargetID, &v.CorrectsAwardID, &v.ApprovalID, &v.Revision, &v.BasisRevision, &at)
			v.RecordedAt = at.Time
			out.Snapshot.Awards = append(out.Snapshot.Awards, v)
		case "payments":
			var v compensation.BonusPaymentRecord
			err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.PayloadID, &v.Kind, &v.PaidDate, &v.BusinessSource, &v.AwardID, &v.OriginalPaymentID, &v.BusinessKeyID, &v.BusinessKeyVersion, &v.BasisRevision, &v.BusinessDigest, &at)
			v.RecordedAt = at.Time
			out.Snapshot.Payments = append(out.Snapshot.Payments, v)
		case "extensions":
			var v compensation.BonusExtensionRecord
			err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.PayloadID, &v.SchemaType, &v.SchemaVersion, &v.Revision, &v.BasisRevision, &v.SupersedesID, &at)
			v.RecordedAt = at.Time
			out.Snapshot.Extensions = append(out.Snapshot.Extensions, v)
		}
		if err != nil {
			return out, safeError(err)
		}
	}
	if err = rows.Err(); err != nil {
		return out, safeError(err)
	}
	switch query.Kind {
	case "targets":
		if len(out.Snapshot.Targets) > query.Limit {
			out.More, out.Snapshot.Targets = true, out.Snapshot.Targets[:query.Limit]
		}
	case "awards":
		if len(out.Snapshot.Awards) > query.Limit {
			out.More, out.Snapshot.Awards = true, out.Snapshot.Awards[:query.Limit]
		}
		for _, award := range out.Snapshot.Awards {
			if award.ApprovalID == nil {
				continue
			}
			var approval compensation.BonusApprovalRecord
			var at dbTime
			err = r.db.QueryRowContext(ctx, r.sql("SELECT org_id,employee_id,id,award_id,award_version_id,approver_subject_id,payload_id,award_revision,basis_revision,bonus_revision,recorded_at FROM bonus_approval WHERE org_id=? AND employee_id=? AND id=?", "SELECT org_id,employee_id,id,award_id,award_version_id,approver_subject_id,payload_id,award_revision,basis_revision,bonus_revision,recorded_at FROM bonus_approval WHERE org_id=$1 AND employee_id=$2 AND id=$3"), org, employee, *award.ApprovalID).Scan(&approval.OrgID, &approval.EmployeeID, &approval.ID, &approval.AwardID, &approval.AwardVersionID, &approval.ApproverSubjectID, &approval.PayloadID, &approval.AwardRevision, &approval.BasisRevision, &approval.BonusRevision, &at)
			if err != nil {
				return out, compensationReadError(err)
			}
			approval.RecordedAt = at.Time
			out.Snapshot.Approvals = append(out.Snapshot.Approvals, approval)
		}
	case "payments":
		if len(out.Snapshot.Payments) > query.Limit {
			out.More, out.Snapshot.Payments = true, out.Snapshot.Payments[:query.Limit]
		}
	case "extensions":
		if len(out.Snapshot.Extensions) > query.Limit {
			out.More, out.Snapshot.Extensions = true, out.Snapshot.Extensions[:query.Limit]
		}
	}
	return out, nil
}

func (r reader) BonusSnapshot(ctx context.Context, org, employee string) (compensation.BonusSnapshot, error) {
	out := compensation.BonusSnapshot{Aggregate: compensation.BonusAggregateRecord{OrgID: org, EmployeeID: employee}, Targets: []compensation.BonusTargetRecord{}, Awards: []compensation.BonusAwardRecord{}, Approvals: []compensation.BonusApprovalRecord{}, Payments: []compensation.BonusPaymentRecord{}, Extensions: []compensation.BonusExtensionRecord{}}
	err := r.db.QueryRowContext(ctx, r.sql("SELECT revision FROM bonus_aggregate WHERE org_id=? AND employee_id=?", "SELECT revision FROM bonus_aggregate WHERE org_id=$1 AND employee_id=$2"), org, employee).Scan(&out.Aggregate.Revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, safeError(err)
	}
	rows, err := r.db.QueryContext(ctx, r.sql("SELECT org_id,employee_id,id,state,version_id,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at FROM bonus_target WHERE org_id=? AND employee_id=? ORDER BY recorded_at,id", "SELECT org_id,employee_id,id,state,version_id,payload_id,period_start::text,period_end::text,actor_subject_id,revision,basis_revision,recorded_at FROM bonus_target WHERE org_id=$1 AND employee_id=$2 ORDER BY recorded_at,id"), org, employee)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var v compensation.BonusTargetRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.PeriodStart, &v.PeriodEnd, &v.ActorSubjectID, &v.Revision, &v.BasisRevision, &at); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		v.RecordedAt = at.Time
		out.Targets = append(out.Targets, v)
	}
	if err = rows.Close(); err != nil {
		return out, safeError(err)
	}
	rows, err = r.db.QueryContext(ctx, r.sql("SELECT org_id,employee_id,id,state,version_id,payload_id,author_subject_id,period_start,period_end,target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at FROM bonus_award WHERE org_id=? AND employee_id=? ORDER BY recorded_at,id", "SELECT org_id,employee_id,id,state,version_id,payload_id,author_subject_id,period_start::text,period_end::text,target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at FROM bonus_award WHERE org_id=$1 AND employee_id=$2 ORDER BY recorded_at,id"), org, employee)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var v compensation.BonusAwardRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.AuthorSubjectID, &v.PeriodStart, &v.PeriodEnd, &v.TargetID, &v.CorrectsAwardID, &v.ApprovalID, &v.Revision, &v.BasisRevision, &at); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		v.RecordedAt = at.Time
		out.Awards = append(out.Awards, v)
	}
	if err = rows.Close(); err != nil {
		return out, safeError(err)
	}
	rows, err = r.db.QueryContext(ctx, r.sql("SELECT org_id,employee_id,id,award_id,award_version_id,approver_subject_id,payload_id,award_revision,basis_revision,bonus_revision,recorded_at FROM bonus_approval WHERE org_id=? AND employee_id=? ORDER BY recorded_at,id", "SELECT org_id,employee_id,id,award_id,award_version_id,approver_subject_id,payload_id,award_revision,basis_revision,bonus_revision,recorded_at FROM bonus_approval WHERE org_id=$1 AND employee_id=$2 ORDER BY recorded_at,id"), org, employee)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var v compensation.BonusApprovalRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.AwardID, &v.AwardVersionID, &v.ApproverSubjectID, &v.PayloadID, &v.AwardRevision, &v.BasisRevision, &v.BonusRevision, &at); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		v.RecordedAt = at.Time
		out.Approvals = append(out.Approvals, v)
	}
	if err = rows.Close(); err != nil {
		return out, safeError(err)
	}
	rows, err = r.db.QueryContext(ctx, r.sql("SELECT org_id,employee_id,id,payload_id,kind,paid_date,business_source,award_id,original_payment_id,business_key_id,business_key_version,basis_revision,business_digest,recorded_at FROM bonus_payment WHERE org_id=? AND employee_id=? ORDER BY paid_date,id", "SELECT org_id,employee_id,id,payload_id,kind,paid_date::text,business_source,award_id,original_payment_id,business_key_id,business_key_version,basis_revision,business_digest,recorded_at FROM bonus_payment WHERE org_id=$1 AND employee_id=$2 ORDER BY paid_date,id"), org, employee)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var v compensation.BonusPaymentRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.PayloadID, &v.Kind, &v.PaidDate, &v.BusinessSource, &v.AwardID, &v.OriginalPaymentID, &v.BusinessKeyID, &v.BusinessKeyVersion, &v.BasisRevision, &v.BusinessDigest, &at); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		v.RecordedAt = at.Time
		out.Payments = append(out.Payments, v)
	}
	if err = rows.Close(); err != nil {
		return out, safeError(err)
	}
	rows, err = r.db.QueryContext(ctx, r.sql("SELECT org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,supersedes_id,recorded_at FROM compensation_extension_version WHERE org_id=? AND employee_id=? ORDER BY recorded_at,id", "SELECT org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,supersedes_id,recorded_at FROM compensation_extension_version WHERE org_id=$1 AND employee_id=$2 ORDER BY recorded_at,id"), org, employee)
	if err != nil {
		return out, safeError(err)
	}
	for rows.Next() {
		var v compensation.BonusExtensionRecord
		var at dbTime
		if err = rows.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.PayloadID, &v.SchemaType, &v.SchemaVersion, &v.Revision, &v.BasisRevision, &v.SupersedesID, &at); err != nil {
			rows.Close()
			return out, safeError(err)
		}
		v.RecordedAt = at.Time
		out.Extensions = append(out.Extensions, v)
	}
	return out, safeError(rows.Close())
}

func (r reader) BonusPayload(ctx context.Context, org, id string) (compensation.Payload, error) {
	var p compensation.Payload
	var at dbTime
	e := &p.Envelope
	c := &e.Context
	err := r.db.QueryRowContext(ctx, r.sql("SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM bonus_payload WHERE org_id=? AND id=?", "SELECT id,org_id,employee_id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at FROM bonus_payload WHERE org_id=$1 AND id=$2"), org, id).Scan(&p.ID, &c.OrgID, &c.EmployeeID, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &c.SchemaVersion, &e.FormatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &e.Key.Version, &e.Key.Data, &e.SealedBytes, &at)
	p.RecordedAt = at.Time
	return p, compensationReadError(err)
}
func (r reader) BonusCommandReceipt(ctx context.Context, org, subject, operation, key string) (compensation.BonusResult, []byte, bool, error) {
	var result compensation.BonusResult
	var digest []byte
	var encoded string
	err := r.db.QueryRowContext(ctx, r.sql("SELECT digest,result_json FROM bonus_command_receipt WHERE org_id=? AND subject_id=? AND operation=? AND key=?", "SELECT digest,result_json FROM bonus_command_receipt WHERE org_id=$1 AND subject_id=$2 AND operation=$3 AND key=$4"), org, subject, operation, key).Scan(&digest, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil, false, nil
	}
	if err != nil {
		return result, nil, false, safeError(err)
	}
	if json.Unmarshal([]byte(encoded), &result) != nil {
		return result, nil, false, fault.Unavailable
	}
	return result, digest, true, nil
}
func scanBonusPayment(row grantScanner) (compensation.BonusPaymentRecord, error) {
	var v compensation.BonusPaymentRecord
	var at dbTime
	err := row.Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.PayloadID, &v.Kind, &v.PaidDate, &v.BusinessSource, &v.AwardID, &v.OriginalPaymentID, &v.BusinessKeyID, &v.BusinessKeyVersion, &v.BasisRevision, &v.BusinessDigest, &at)
	v.RecordedAt = at.Time
	return v, compensationReadError(err)
}
func (r reader) BonusPaymentByDigest(ctx context.Context, org, employee, keyID string, version int64, digest []byte) (compensation.BonusPaymentRecord, bool, error) {
	v, err := scanBonusPayment(r.db.QueryRowContext(ctx, r.sql("SELECT p.org_id,p.employee_id,p.id,p.payload_id,p.kind,p.paid_date,p.business_source,p.award_id,p.original_payment_id,p.business_key_id,p.business_key_version,p.basis_revision,p.business_digest,p.recorded_at FROM bonus_payment_business_index i JOIN bonus_payment p ON p.org_id=i.org_id AND p.employee_id=i.employee_id AND p.id=i.payment_id WHERE i.org_id=? AND i.employee_id=? AND i.key_id=? AND i.key_version=? AND i.digest=?", "SELECT p.org_id,p.employee_id,p.id,p.payload_id,p.kind,p.paid_date::text,p.business_source,p.award_id,p.original_payment_id,p.business_key_id,p.business_key_version,p.basis_revision,p.business_digest,p.recorded_at FROM bonus_payment_business_index i JOIN bonus_payment p ON p.org_id=i.org_id AND p.employee_id=i.employee_id AND p.id=i.payment_id WHERE i.org_id=$1 AND i.employee_id=$2 AND i.key_id=$3 AND i.key_version=$4 AND i.digest=$5"), org, employee, keyID, version, digest))
	if errors.Is(err, fault.NotFound) {
		return v, false, nil
	}
	return v, err == nil, err
}
func (r reader) BonusHMACReady(ctx context.Context, org string) (int64, string, error) {
	var version int64
	var key, state string
	err := r.db.QueryRowContext(ctx, r.sql("SELECT active_version,active_key_id,state FROM hmac_index_state WHERE org_id=? AND domain='bonus_payment'", "SELECT active_version,active_key_id,state FROM hmac_index_state WHERE org_id=$1 AND domain='bonus_payment'"), org).Scan(&version, &key, &state)
	if err != nil || state != "ready" {
		return 0, "", fault.Unavailable
	}
	return version, key, nil
}
func (r reader) BonusTarget(ctx context.Context, org, id string) (compensation.BonusTargetRecord, error) {
	var v compensation.BonusTargetRecord
	var at dbTime
	err := r.db.QueryRowContext(ctx, r.sql("SELECT org_id,employee_id,id,state,version_id,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at FROM bonus_target WHERE org_id=? AND id=?", "SELECT org_id,employee_id,id,state,version_id,payload_id,period_start::text,period_end::text,actor_subject_id,revision,basis_revision,recorded_at FROM bonus_target WHERE org_id=$1 AND id=$2"), org, id).Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.PeriodStart, &v.PeriodEnd, &v.ActorSubjectID, &v.Revision, &v.BasisRevision, &at)
	v.RecordedAt = at.Time
	return v, compensationReadError(err)
}
func (r reader) BonusAward(ctx context.Context, org, id string) (compensation.BonusAwardRecord, error) {
	var v compensation.BonusAwardRecord
	var at dbTime
	err := r.db.QueryRowContext(ctx, r.sql("SELECT org_id,employee_id,id,state,version_id,payload_id,author_subject_id,period_start,period_end,target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at FROM bonus_award WHERE org_id=? AND id=?", "SELECT org_id,employee_id,id,state,version_id,payload_id,author_subject_id,period_start::text,period_end::text,target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at FROM bonus_award WHERE org_id=$1 AND id=$2"), org, id).Scan(&v.OrgID, &v.EmployeeID, &v.ID, &v.State, &v.VersionID, &v.PayloadID, &v.AuthorSubjectID, &v.PeriodStart, &v.PeriodEnd, &v.TargetID, &v.CorrectsAwardID, &v.ApprovalID, &v.Revision, &v.BasisRevision, &at)
	v.RecordedAt = at.Time
	return v, compensationReadError(err)
}
