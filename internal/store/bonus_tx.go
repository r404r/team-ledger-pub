package store

import (
	"context"
	"encoding/json"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

func (t *transaction) LockBonusEmployee(ctx context.Context, org, employee string) error {
	if org != t.org {
		return fault.NotFound
	}
	var revision int64
	if err := t.tx.QueryRowContext(ctx, t.sql("SELECT profile_revision FROM employee WHERE org_id=? AND id=?", "SELECT profile_revision FROM employee WHERE org_id=$1 AND id=$2 FOR UPDATE"), org, employee).Scan(&revision); err != nil {
		return compensationReadError(err)
	}
	if _, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO bonus_aggregate(org_id,employee_id,revision) VALUES(?,?,0) ON CONFLICT(org_id,employee_id) DO NOTHING", "INSERT INTO bonus_aggregate(org_id,employee_id,revision) VALUES($1,$2,0) ON CONFLICT(org_id,employee_id) DO NOTHING"), org, employee); err != nil {
		return safeError(err)
	}
	return compensationReadError(t.tx.QueryRowContext(ctx, t.sql("SELECT revision FROM bonus_aggregate WHERE org_id=? AND employee_id=?", "SELECT revision FROM bonus_aggregate WHERE org_id=$1 AND employee_id=$2 FOR UPDATE"), org, employee).Scan(&revision))
}

func (t *transaction) CommitBonus(ctx context.Context, w compensation.BonusWrite) error {
	a := w.Aggregate
	if a.OrgID != t.org || a.EmployeeID == "" || w.ExpectedBonusRevision < 0 || len(w.CommandDigest) != 32 || w.Operation == "" || w.CommandKey == "" {
		return fault.Invalid
	}
	if w.Extension == nil {
		if a.Revision != w.ExpectedBonusRevision+1 {
			return fault.Invalid
		}
		result, err := t.tx.ExecContext(ctx, t.sql("UPDATE bonus_aggregate SET revision=? WHERE org_id=? AND employee_id=? AND revision=?", "UPDATE bonus_aggregate SET revision=$1 WHERE org_id=$2 AND employee_id=$3 AND revision=$4"), a.Revision, a.OrgID, a.EmployeeID, w.ExpectedBonusRevision)
		if err = interviewAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	} else {
		if a.Revision != w.ExpectedBonusRevision || w.ExpectedCompRevision == nil {
			return fault.Invalid
		}
		result, err := t.tx.ExecContext(ctx, t.sql("UPDATE compensation_aggregate SET revision=revision+1 WHERE org_id=? AND employee_id=? AND revision=?", "UPDATE compensation_aggregate SET revision=revision+1 WHERE org_id=$1 AND employee_id=$2 AND revision=$3"), a.OrgID, a.EmployeeID, *w.ExpectedCompRevision)
		if err = interviewAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	}
	for _, payload := range w.Payloads {
		c, e := payload.Envelope.Context, payload.Envelope
		if c.OrgID != t.org || c.EmployeeID != a.EmployeeID || c.Purpose != "financial" || c.SchemaVersion != 1 || payload.ID != c.VersionID {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), c.OrgID, c.EmployeeID, payload.ID, c.RecordID, c.VersionID, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, t.bindTime(payload.RecordedAt)); err != nil {
			return safeError(err)
		}
	}
	if v := w.Target; v != nil {
		if v.OrgID != t.org || v.EmployeeID != a.EmployeeID || v.BasisRevision != a.Revision || v.Revision != w.ExpectedTargetRevision+1 {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_target_version(org_id,employee_id,id,target_id,state,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.VersionID, v.ID, v.State, v.PayloadID, v.PeriodStart, v.PeriodEnd, v.ActorSubjectID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt)); err != nil {
			return safeError(err)
		}
		if w.ExpectedTargetRevision == 0 {
			if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_target(org_id,employee_id,id,state,version_id,payload_id,period_start,period_end,actor_subject_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.State, v.VersionID, v.PayloadID, v.PeriodStart, v.PeriodEnd, v.ActorSubjectID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt)); err != nil {
				return safeError(err)
			}
		} else {
			result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE bonus_target SET state=?,version_id=?,payload_id=?,actor_subject_id=?,revision=?,basis_revision=?,recorded_at=? WHERE org_id=? AND employee_id=? AND id=? AND revision=?"), v.State, v.VersionID, v.PayloadID, v.ActorSubjectID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt), v.OrgID, v.EmployeeID, v.ID, w.ExpectedTargetRevision)
			if err = interviewAffected(result, err, fault.Conflict); err != nil {
				return err
			}
		}
	}
	if v := w.Award; v != nil {
		if v.OrgID != t.org || v.EmployeeID != a.EmployeeID || v.BasisRevision != a.Revision || v.Revision != w.ExpectedAwardRevision+1 {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_award_revision(org_id,employee_id,id,award_id,state,payload_id,period_start,period_end,target_id,corrects_award_id,actor_subject_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.VersionID, v.ID, v.State, v.PayloadID, v.PeriodStart, v.PeriodEnd, v.TargetID, v.CorrectsAwardID, v.AuthorSubjectID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt)); err != nil {
			return safeError(err)
		}
		if w.ExpectedAwardRevision == 0 {
			if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_award(org_id,employee_id,id,state,version_id,payload_id,author_subject_id,period_start,period_end,target_id,corrects_award_id,approval_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.State, v.VersionID, v.PayloadID, v.AuthorSubjectID, v.PeriodStart, v.PeriodEnd, v.TargetID, v.CorrectsAwardID, v.ApprovalID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt)); err != nil {
				return safeError(err)
			}
		} else {
			result, err := t.tx.ExecContext(ctx, t.structureSQL("UPDATE bonus_award SET state=?,version_id=?,payload_id=?,target_id=?,corrects_award_id=?,approval_id=?,revision=?,basis_revision=?,recorded_at=? WHERE org_id=? AND employee_id=? AND id=? AND revision=?"), v.State, v.VersionID, v.PayloadID, v.TargetID, v.CorrectsAwardID, v.ApprovalID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt), v.OrgID, v.EmployeeID, v.ID, w.ExpectedAwardRevision)
			if err = interviewAffected(result, err, fault.Conflict); err != nil {
				return err
			}
		}
	}
	if v := w.Approval; v != nil {
		if v.OrgID != t.org || v.EmployeeID != a.EmployeeID || v.BonusRevision != a.Revision || v.BasisRevision != w.ExpectedBonusRevision {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_approval(org_id,employee_id,id,award_id,award_version_id,approver_subject_id,payload_id,award_revision,basis_revision,bonus_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.AwardID, v.AwardVersionID, v.ApproverSubjectID, v.PayloadID, v.AwardRevision, v.BasisRevision, v.BonusRevision, t.bindTime(v.RecordedAt)); err != nil {
			return safeError(err)
		}
	}
	if v := w.Payment; v != nil {
		if v.OrgID != t.org || v.EmployeeID != a.EmployeeID || v.BasisRevision != a.Revision || v.BusinessKeyID == "" || v.BusinessKeyVersion <= 0 || len(v.BusinessDigest) != 32 {
			return fault.Invalid
		}
		var ready, activeKeyID string
		var active int64
		if err := t.tx.QueryRowContext(ctx, t.structureSQL("SELECT state,active_key_id,active_version FROM hmac_index_state WHERE org_id=? AND domain='bonus_payment'"), v.OrgID).Scan(&ready, &activeKeyID, &active); err != nil || ready != "ready" || activeKeyID != v.BusinessKeyID || active != v.BusinessKeyVersion {
			return fault.Unavailable
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_payment(org_id,employee_id,id,payload_id,kind,paid_date,business_source,award_id,original_payment_id,business_key_id,business_key_version,basis_revision,business_digest,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.PayloadID, v.Kind, v.PaidDate, v.BusinessSource, v.AwardID, v.OriginalPaymentID, v.BusinessKeyID, v.BusinessKeyVersion, v.BasisRevision, v.BusinessDigest, t.bindTime(v.RecordedAt)); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_payment_business_index(org_id,employee_id,domain,key_id,key_version,digest,payment_id) VALUES(?,?,'bonus_payment',?,?,?,?)"), v.OrgID, v.EmployeeID, v.BusinessKeyID, v.BusinessKeyVersion, v.BusinessDigest, v.ID); err != nil {
			return safeError(err)
		}
	}
	if v := w.Extension; v != nil {
		if v.OrgID != t.org || v.EmployeeID != a.EmployeeID || w.ExpectedCompRevision == nil || v.BasisRevision != *w.ExpectedCompRevision+1 {
			return fault.Invalid
		}
		if _, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_extension_version(org_id,employee_id,id,payload_id,schema_type,schema_version,revision,basis_revision,supersedes_id,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.PayloadID, v.SchemaType, v.SchemaVersion, v.Revision, v.BasisRevision, v.SupersedesID, t.bindTime(v.RecordedAt)); err != nil {
			return safeError(err)
		}
	}
	encoded, err := json.Marshal(w.Result)
	if err != nil {
		return fault.Invalid
	}
	if _, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO bonus_command_receipt(org_id,subject_id,operation,key,digest,result_json,recorded_at,digest_key_id,digest_key_version) VALUES(?,?,?,?,?,?,?,?,?)"), a.OrgID, w.Audit.SubjectID, w.Operation, w.CommandKey, w.CommandDigest, string(encoded), t.bindTime(w.Audit.At), t.commandMACKey.KeyID, t.commandMACKey.Version); err != nil {
		return safeError(err)
	}
	return t.Audit(ctx, w.Audit)
}

var _ organization.Tx = (*transaction)(nil)
