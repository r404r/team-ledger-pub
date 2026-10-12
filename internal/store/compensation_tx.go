package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
)

// WithTx acquires the authorization guard before the callback acquires sorted
// subjects, the employee, and finally its compensation aggregate.
func (r *Repository) WithCompensationTx(ctx context.Context, org string, fn func(compensation.Tx) error) error {
	return r.WithTx(ctx, org, func(tx organization.Tx) error { return fn(tx.(*transaction)) })
}
func (t *transaction) LockCompensationEmployee(ctx context.Context, org, employee string) error {
	if org != t.org {
		return fault.NotFound
	}
	var revision int64
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT profile_revision FROM employee WHERE org_id=? AND id=?", "SELECT profile_revision FROM employee WHERE org_id=$1 AND id=$2 FOR UPDATE"), org, employee).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound
	}
	if err != nil {
		return safeError(err)
	}
	_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO compensation_aggregate(org_id,employee_id,revision) VALUES(?,?,0) ON CONFLICT(org_id,employee_id) DO NOTHING", "INSERT INTO compensation_aggregate(org_id,employee_id,revision) VALUES($1,$2,0) ON CONFLICT(org_id,employee_id) DO NOTHING"), org, employee)
	if err != nil {
		return safeError(err)
	}
	err = t.tx.QueryRowContext(ctx, t.sql("SELECT revision FROM compensation_aggregate WHERE org_id=? AND employee_id=?", "SELECT revision FROM compensation_aggregate WHERE org_id=$1 AND employee_id=$2 FOR UPDATE"), org, employee).Scan(&revision)
	return compensationReadError(err)
}

func (t *transaction) CommitCompensation(ctx context.Context, w compensation.Write) error {
	a, p, v := w.Aggregate, w.Proposal, w.Revision
	if a.OrgID != t.org || p.OrgID != t.org || v.OrgID != t.org || p.EmployeeID != a.EmployeeID || v.EmployeeID != a.EmployeeID || v.ProposalID != p.ID || v.ID != p.RevisionID || v.PayloadID != p.PayloadID || v.Revision != p.Revision || v.BasisRevision != p.BasisRevision || v.Status != p.Status || v.Kind != p.Kind || v.EffectiveDate != p.EffectiveDate || w.ExpectedCompRevision < 0 || !interviewNext(p.Revision, w.ExpectedProposalRevision) {
		return fault.Invalid
	}
	if w.Approval == nil {
		if a.Revision != w.ExpectedCompRevision || w.ReplaceSchedule || len(w.Events) != 0 || len(w.Terms) != 0 || len(w.Schedule) != 0 {
			return fault.Invalid
		}
	} else {
		if !interviewNext(a.Revision, w.ExpectedCompRevision) || !w.ReplaceSchedule || w.ExpectedProposalRevision < 1 || p.Status != "approved" {
			return fault.Invalid
		}
	}
	result, err := t.tx.ExecContext(ctx, t.sql("UPDATE compensation_aggregate SET revision=? WHERE org_id=? AND employee_id=? AND revision=?", "UPDATE compensation_aggregate SET revision=$1 WHERE org_id=$2 AND employee_id=$3 AND revision=$4"), a.Revision, a.OrgID, a.EmployeeID, w.ExpectedCompRevision)
	if err = interviewAffected(result, err, fault.Conflict); err != nil {
		return err
	}
	for _, payload := range w.Payloads {
		if err = t.insertCompensationPayload(ctx, payload, w); err != nil {
			return err
		}
	}
	_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_proposal_revision(org_id,employee_id,id,proposal_id,payload_id,status,kind,effective_date,actor_subject_id,before_term_id,revision,basis_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"), v.OrgID, v.EmployeeID, v.ID, v.ProposalID, v.PayloadID, v.Status, v.Kind, v.EffectiveDate, v.ActorSubjectID, v.BeforeTermID, v.Revision, v.BasisRevision, t.bindTime(v.RecordedAt))
	if err != nil {
		return safeError(err)
	}
	if w.ExpectedProposalRevision == 0 {
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_proposal(org_id,employee_id,id,kind,status,author_subject_id,revision_id,payload_id,effective_date,before_term_id,revision,basis_revision,recorded_at,approval_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), p.OrgID, p.EmployeeID, p.ID, p.Kind, p.Status, p.AuthorSubjectID, p.RevisionID, p.PayloadID, p.EffectiveDate, p.BeforeTermID, p.Revision, p.BasisRevision, t.bindTime(p.RecordedAt), p.ApprovalID)
		if err != nil {
			return safeError(err)
		}
	} else {
		result, err = t.tx.ExecContext(ctx, t.structureSQL("UPDATE compensation_proposal SET kind=?,status=?,revision_id=?,payload_id=?,effective_date=?,before_term_id=?,revision=?,basis_revision=?,approval_id=? WHERE org_id=? AND employee_id=? AND id=? AND revision=? AND author_subject_id=? AND status IN ('draft','submitted')"), p.Kind, p.Status, p.RevisionID, p.PayloadID, p.EffectiveDate, p.BeforeTermID, p.Revision, p.BasisRevision, p.ApprovalID, p.OrgID, p.EmployeeID, p.ID, w.ExpectedProposalRevision, p.AuthorSubjectID)
		if err = interviewAffected(result, err, fault.Conflict); err != nil {
			return err
		}
	}
	if w.Approval != nil {
		approval := w.Approval
		if approval.OrgID != t.org || approval.EmployeeID != a.EmployeeID || approval.ProposalID != p.ID || approval.CompRevision != a.Revision || approval.BasisRevision != w.ExpectedCompRevision || approval.ProposalRevision != w.ExpectedProposalRevision || p.ApprovalID == nil || *p.ApprovalID != approval.ID {
			return fault.Invalid
		}
		_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_approval(org_id,employee_id,id,proposal_id,proposal_revision_id,approver_subject_id,author_subject_id,payload_id,proposal_revision,basis_revision,comp_revision,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), approval.OrgID, approval.EmployeeID, approval.ID, approval.ProposalID, approval.ProposalRevisionID, approval.ApproverSubjectID, approval.AuthorSubjectID, approval.PayloadID, approval.ProposalRevision, approval.BasisRevision, approval.CompRevision, t.bindTime(approval.RecordedAt))
		if err != nil {
			return safeError(err)
		}
		if p.Kind == "correction" {
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_correction_group(org_id,id,employee_id,proposal_id,proposal_revision_id,approval_id,basis_revision) VALUES(?,?,?,?,?,?,?)"), t.org, approval.ID, a.EmployeeID, p.ID, approval.ProposalRevisionID, approval.ID, approval.BasisRevision)
			if err != nil {
				return safeError(err)
			}
		}
		for _, event := range w.Events {
			if event.OrgID != t.org || event.EmployeeID != a.EmployeeID || event.ApprovalID != approval.ID {
				return fault.Invalid
			}
			var group any
			if event.Kind == "correction_replacement" || event.Kind == "correction_reversal" {
				if p.Kind != "correction" || event.CorrectsEventID == nil || event.MemberKey == "" {
					return fault.Invalid
				}
				group = approval.ID
				action := "replace"
				if event.Kind == "correction_reversal" {
					action = "reverse"
				}
				_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_correction_member(org_id,group_id,employee_id,member_key,action,original_event_id,event_id,before_term_id,after_term_id,effective_date) VALUES(?,?,?,?,?,?,?,?,?,?)"), t.org, approval.ID, a.EmployeeID, event.MemberKey, action, event.CorrectsEventID, event.ID, event.BeforeTermID, event.AfterTermID, event.EffectiveDate)
				if err != nil {
					return safeError(err)
				}
			}
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_event(org_id,employee_id,id,approval_id,kind,effective_date,member_key,before_term_id,after_term_id,corrects_event_id,sequence,correction_group_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), event.OrgID, event.EmployeeID, event.ID, event.ApprovalID, event.Kind, event.EffectiveDate, event.MemberKey, event.BeforeTermID, event.AfterTermID, event.CorrectsEventID, event.Sequence, group)
			if err != nil {
				return safeError(err)
			}
		}
		for _, term := range w.Terms {
			if term.OrgID != t.org || term.EmployeeID != a.EmployeeID || term.ApprovalID != approval.ID {
				return fault.Invalid
			}
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_terms_version(org_id,employee_id,id,event_id,approval_id,payload_id,effective_date,version_no) VALUES(?,?,?,?,?,?,?,?)"), term.OrgID, term.EmployeeID, term.ID, term.EventID, term.ApprovalID, term.PayloadID, term.EffectiveDate, term.Version)
			if err != nil {
				return safeError(err)
			}
		}
	}
	if w.ReplaceSchedule {
		_, err = t.tx.ExecContext(ctx, t.sql("DELETE FROM compensation_schedule_projection WHERE org_id=? AND employee_id=?", "DELETE FROM compensation_schedule_projection WHERE org_id=$1 AND employee_id=$2"), a.OrgID, a.EmployeeID)
		if err != nil {
			return safeError(err)
		}
		for _, entry := range w.Schedule {
			if entry.OrgID != t.org || entry.EmployeeID != a.EmployeeID || entry.Revision != a.Revision {
				return fault.Invalid
			}
			_, err = t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_schedule_projection(org_id,employee_id,effective_date,valid_to,term_id,event_id,revision) VALUES(?,?,?,?,?,?,?)"), entry.OrgID, entry.EmployeeID, entry.EffectiveDate, entry.ValidTo, entry.TermID, entry.EventID, entry.Revision)
			if err != nil {
				return safeError(err)
			}
		}
	}
	return nil
}

func (t *transaction) insertCompensationPayload(ctx context.Context, p compensation.Payload, w compensation.Write) error {
	e, c := p.Envelope, p.Envelope.Context
	if c.OrgID != t.org || c.EmployeeID != w.Aggregate.EmployeeID || c.Purpose != "financial" || c.SchemaVersion != 1 {
		return fault.Invalid
	}
	var proposal, revision, term, approval any
	owners := 0
	if p.ID == w.Revision.PayloadID {
		if c.ObjectKind != "compensation_proposal" || c.SchemaType != "compensation.proposal.v1" || c.RecordID != w.Proposal.ID || c.VersionID != w.Revision.ID || p.ID != w.Revision.ID {
			return fault.Invalid
		}
		proposal, revision = w.Proposal.ID, w.Revision.ID
		owners++
	}
	for _, v := range w.Terms {
		if p.ID == v.PayloadID {
			if c.ObjectKind != "compensation_terms" || c.SchemaType != "compensation.terms.v1" || c.RecordID != v.ID || c.VersionID != v.ID || p.ID != v.ID {
				return fault.Invalid
			}
			term = v.ID
			owners++
		}
	}
	if w.Approval != nil && p.ID == w.Approval.PayloadID {
		if c.ObjectKind != "compensation_decision" || c.SchemaType != "compensation.decision.v1" || c.RecordID != w.Approval.ID || c.VersionID != w.Approval.ID || p.ID != w.Approval.ID {
			return fault.Invalid
		}
		approval = w.Approval.ID
		owners++
	}
	if owners != 1 {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.structureSQL("INSERT INTO compensation_payload(org_id,employee_id,id,record_id,version_id,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at,proposal_id,proposal_revision_id,term_id,approval_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"), c.OrgID, c.EmployeeID, p.ID, c.RecordID, c.VersionID, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, t.bindTime(p.RecordedAt), proposal, revision, term, approval)
	return safeError(err)
}
func (t *transaction) SaveCompensationReceipt(ctx context.Context, org, subject, operation, key string, receipt compensation.Receipt) error {
	if org != t.org {
		return fault.Invalid
	}
	// Deliberately project onto safe metadata: Result.Proposal contains decrypted
	// financial content and must never enter the idempotency receipt table.
	result := compensation.Result{ID: receipt.Result.ID, Revision: receipt.Result.Revision, CompRevision: receipt.Result.CompRevision, Status: receipt.Result.Status, Members: receipt.Result.Members}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fault.Invalid
	}
	_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO compensation_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_json,recorded_at) VALUES(?,?,?,?,?,1,?,?)", "INSERT INTO compensation_command_receipt(org_id,subject_id,operation,key,digest,digest_key_version,result_json,recorded_at) VALUES($1,$2,$3,$4,$5,1,$6,$7)"), org, subject, operation, key, receipt.Digest, string(encoded), t.bindTime(time.Now()))
	return safeError(err)
}
