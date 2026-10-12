package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func assessmentSourceEpoch(ctx context.Context, r reader, org, employee string) (int64, error) {
	var epoch int64
	err := r.db.QueryRowContext(ctx, r.sql("SELECT COALESCE((SELECT epoch FROM assessment_source_epoch WHERE org_id=? AND employee_id=?),0)", "SELECT COALESCE((SELECT epoch FROM assessment_source_epoch WHERE org_id=$1 AND employee_id=$2),0)"), org, employee).Scan(&epoch)
	return epoch, safeError(err)
}

func (r *Repository) AssessmentSourceEpoch(ctx context.Context, org, employee string) (int64, error) {
	return assessmentSourceEpoch(ctx, r.read(), org, employee)
}

func (r *Repository) CreateAssessmentInput(ctx context.Context, actor authz.Snapshot, tokenHash []byte, expectedEpoch int64, window assessment.Window, input assessment.StructuredInput, generation, source []byte, now time.Time, audit organization.Audit) (assessment.InputView, error) {
	if actor.OrgID == "" || actor.SubjectID == "" || expectedEpoch < 0 || window.OrgID != actor.OrgID || len(generation) != 32 || len(source) != 32 {
		return assessment.InputView{}, fault.Invalid
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 16*1024 {
		return assessment.InputView{}, fault.Invalid
	}
	out := assessment.InputView{ID: value.NewID(), EmployeeID: window.EmployeeID, WindowID: window.ID, Status: "proposed", RequestedBy: actor.SubjectID, CreatedAt: now, Input: input}
	err = r.WithTx(ctx, actor.OrgID, func(base organization.Tx) error {
		t := base.(*transaction)
		if err := t.LockSubjects(ctx, actor.OrgID, []string{actor.SubjectID}); err != nil {
			return err
		}
		if err := t.LockInterviewEmployee(ctx, actor.OrgID, window.EmployeeID); err != nil {
			return err
		}
		current, authErr := t.Security(ctx, tokenHash, actor.OrgID, window.EmployeeID)
		if authErr != nil || current.SubjectID != actor.SubjectID || !current.Valid(now) || !current.Allows("assessment.request", "metadata", window.EmployeeID, "interview_followup", now) || !current.Allows("assessment.read", "metadata", window.EmployeeID, "interview_followup", now) {
			return fault.NotFound
		}
		currentEpoch, epochErr := assessmentSourceEpoch(ctx, t.reader, actor.OrgID, window.EmployeeID)
		if epochErr != nil {
			return epochErr
		}
		if currentEpoch != expectedEpoch {
			return fault.Conflict
		}
		if _, insertErr := t.tx.ExecContext(ctx, t.sql("INSERT INTO approved_assessment_input(org_id,employee_id,id,window_id,generation_digest,source_digest,facts_json,requested_by,created_at,status) VALUES(?,?,?,?,?,?,?,?,?,'proposed')", "INSERT INTO approved_assessment_input(org_id,employee_id,id,window_id,generation_digest,source_digest,facts_json,requested_by,created_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'proposed')"), actor.OrgID, window.EmployeeID, out.ID, window.ID, generation, source, string(raw), actor.SubjectID, t.bindTime(now)); insertErr != nil {
			return safeError(insertErr)
		}
		return t.Audit(ctx, audit)
	})
	return out, err
}

func (r *Repository) ApproveAssessmentInput(ctx context.Context, actor authz.Snapshot, inputID, provider, audience string, now time.Time, audit organization.Audit) (assessment.Job, error) {
	if actor.OrgID == "" || actor.SubjectID == "" || !value.ValidID(inputID) || !value.ValidID(provider) || (audience != "employee_followup" && audience != "manager_followup") {
		return assessment.Job{}, fault.Invalid
	}
	var out assessment.Job
	err := r.WithTx(ctx, actor.OrgID, func(base organization.Tx) error {
		t := base.(*transaction)
		var requested, status, raw string
		if err := t.tx.QueryRowContext(ctx, t.sql("SELECT employee_id,window_id,requested_by,status,facts_json,source_digest,generation_digest FROM approved_assessment_input WHERE org_id=? AND id=?", "SELECT employee_id,window_id,requested_by,status,facts_json,source_digest,generation_digest FROM approved_assessment_input WHERE org_id=$1 AND id=$2 FOR UPDATE"), actor.OrgID, inputID).Scan(&out.EmployeeID, &out.WindowID, &requested, &status, &raw, &out.SourceDigest, &out.GenerationDigest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fault.NotFound
			}
			return safeError(err)
		}
		if status != "proposed" || requested == actor.SubjectID || !json.Valid([]byte(raw)) {
			return fault.Conflict
		}
		if !actor.Allows("assessment.input.approve", "metadata", out.EmployeeID, "interview_followup", now) {
			return fault.Forbidden
		}
		if err := json.Unmarshal([]byte(raw), &out.Input); err != nil {
			return fault.Unavailable
		}
		out.OrgID, out.ID, out.InputID, out.ProviderPolicyID, out.Audience = actor.OrgID, value.NewID(), inputID, provider, audience
		out.State, out.MaxAttempts, out.DeadlineAt, out.CreatedAt = "queued", 3, now.Add(10*time.Minute), now
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE approved_assessment_input SET status='approved',approved_by=?,approved_at=? WHERE org_id=? AND id=? AND status='proposed'", "UPDATE approved_assessment_input SET status='approved',approved_by=$1,approved_at=$2 WHERE org_id=$3 AND id=$4 AND status='proposed'"), actor.SubjectID, t.bindTime(now), actor.OrgID, inputID); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_job(org_id,employee_id,id,input_id,window_id,generation_digest,source_digest,provider_policy_id,audience,state,max_attempts,deadline_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',?,?,?)", "INSERT INTO assessment_job(org_id,employee_id,id,input_id,window_id,generation_digest,source_digest,provider_policy_id,audience,state,max_attempts,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10,$11,$12)"), actor.OrgID, out.EmployeeID, out.ID, inputID, out.WindowID, out.GenerationDigest, out.SourceDigest, provider, audience, out.MaxAttempts, t.bindTime(out.DeadlineAt), t.bindTime(now)); err != nil {
			return safeError(err)
		}
		return t.Audit(ctx, audit)
	})
	return out, err
}

func assessmentClaimMAC(secret []byte, purpose, worker, key, job string, fence int64) []byte {
	mac := hmac.New(sha256.New, secret)
	for _, part := range []string{"TEAMLEDGER-ASSESSMENT-" + purpose + "\x00V1\x00", worker, key, job, strconv.FormatInt(fence, 10)} {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	return mac.Sum(nil)
}

func (r *Repository) ClaimAssessmentJob(ctx context.Context, org, worker, key string, secret []byte, now time.Time, lease time.Duration) (assessment.Job, string, error) {
	if !value.ValidID(org) || worker == "" || !value.ValidID(key) || len(secret) < sha256.Size || lease < 30*time.Second || lease > 5*time.Minute {
		return assessment.Job{}, "", fault.Invalid
	}
	requestDigest := assessmentClaimMAC(secret, "CLAIM-REQUEST", worker, key, "", 0)
	var out assessment.Job
	var token string
	var claimed bool
	err := r.WithTx(ctx, org, func(base organization.Tx) error {
		t := base.(*transaction)
		var priorJob string
		var priorDigest []byte
		receiptErr := t.tx.QueryRowContext(ctx, t.sql("SELECT job_id,digest FROM assessment_job_receipt WHERE org_id=? AND worker_id=? AND operation='OP-AI-06' AND key=?", "SELECT job_id,digest FROM assessment_job_receipt WHERE org_id=$1 AND worker_id=$2 AND operation='OP-AI-06' AND key=$3"), org, worker, key).Scan(&priorJob, &priorDigest)
		if receiptErr == nil {
			if !hmac.Equal(priorDigest, requestDigest) {
				return fault.Mismatch
			}
			var raw string
			var deadline, created, expires dbTime
			err := t.tx.QueryRowContext(ctx, t.sql("SELECT j.org_id,j.employee_id,j.id,j.input_id,j.window_id,j.generation_digest,j.source_digest,j.provider_policy_id,j.audience,j.attempt,j.max_attempts,j.fence,j.deadline_at,j.created_at,j.lease_expires_at,i.facts_json FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=? AND j.id=? AND j.state='leased' AND j.lease_owner=?", "SELECT j.org_id,j.employee_id,j.id,j.input_id,j.window_id,j.generation_digest,j.source_digest,j.provider_policy_id,j.audience,j.attempt,j.max_attempts,j.fence,j.deadline_at,j.created_at,j.lease_expires_at,i.facts_json FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=$1 AND j.id=$2 AND j.state='leased' AND j.lease_owner=$3 FOR UPDATE"), org, priorJob, worker).Scan(&out.OrgID, &out.EmployeeID, &out.ID, &out.InputID, &out.WindowID, &out.GenerationDigest, &out.SourceDigest, &out.ProviderPolicyID, &out.Audience, &out.Attempt, &out.MaxAttempts, &out.Fence, &deadline, &created, &expires, &raw)
			if err != nil || json.Unmarshal([]byte(raw), &out.Input) != nil {
				return fault.Conflict
			}
			claimed = true
			out.State, out.LeaseOwner, out.DeadlineAt, out.CreatedAt, out.LeaseExpiresAt = "leased", worker, deadline.Time, created.Time, expires.Time
			token = hex.EncodeToString(assessmentClaimMAC(secret, "LEASE-TOKEN", worker, key, out.ID, out.Fence))
			hash := sha256.Sum256([]byte(token))
			out.LeaseTokenHash = hash[:]
			return nil
		}
		if !errors.Is(receiptErr, sql.ErrNoRows) {
			return safeError(receiptErr)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE assessment_job SET state=CASE WHEN attempt>=max_attempts THEN 'failed' ELSE 'queued' END,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,error_code=CASE WHEN attempt>=max_attempts THEN 'lease_expired' ELSE error_code END WHERE org_id=? AND state='leased' AND lease_expires_at<=?", "UPDATE assessment_job SET state=CASE WHEN attempt>=max_attempts THEN 'failed' ELSE 'queued' END,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,error_code=CASE WHEN attempt>=max_attempts THEN 'lease_expired' ELSE error_code END WHERE org_id=$1 AND state='leased' AND lease_expires_at<=$2"), org, t.bindTime(now)); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE approved_assessment_input SET status='invalidated' WHERE org_id=? AND status='approved' AND id IN (SELECT input_id FROM assessment_job WHERE org_id=? AND state='queued' AND deadline_at<=?)", "UPDATE approved_assessment_input SET status='invalidated' WHERE org_id=$1 AND status='approved' AND id IN (SELECT input_id FROM assessment_job WHERE org_id=$2 AND state='queued' AND deadline_at<=$3)"), org, org, t.bindTime(now)); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE assessment_job SET state='failed',error_code='deadline_exceeded' WHERE org_id=? AND state='queued' AND deadline_at<=?", "UPDATE assessment_job SET state='failed',error_code='deadline_exceeded' WHERE org_id=$1 AND state='queued' AND deadline_at<=$2"), org, t.bindTime(now)); err != nil {
			return safeError(err)
		}
		var raw string
		var deadline, created dbTime
		row := t.tx.QueryRowContext(ctx, t.sql("SELECT j.org_id,j.employee_id,j.id,j.input_id,j.window_id,j.generation_digest,j.source_digest,j.provider_policy_id,j.audience,j.attempt,j.max_attempts,j.fence,j.deadline_at,j.created_at,i.facts_json FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=? AND j.state='queued' AND j.deadline_at>? AND i.status='approved' ORDER BY j.created_at,j.id LIMIT 1", "SELECT j.org_id,j.employee_id,j.id,j.input_id,j.window_id,j.generation_digest,j.source_digest,j.provider_policy_id,j.audience,j.attempt,j.max_attempts,j.fence,j.deadline_at,j.created_at,i.facts_json FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=$1 AND j.state='queued' AND j.deadline_at>$2 AND i.status='approved' ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE SKIP LOCKED"), org, t.bindTime(now))
		if err := row.Scan(&out.OrgID, &out.EmployeeID, &out.ID, &out.InputID, &out.WindowID, &out.GenerationDigest, &out.SourceDigest, &out.ProviderPolicyID, &out.Audience, &out.Attempt, &out.MaxAttempts, &out.Fence, &deadline, &created, &raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return safeError(err)
		}
		out.Attempt++
		out.Fence++
		token = hex.EncodeToString(assessmentClaimMAC(secret, "LEASE-TOKEN", worker, key, out.ID, out.Fence))
		hash := sha256.Sum256([]byte(token))
		out.State, out.LeaseOwner, out.LeaseTokenHash = "leased", worker, hash[:]
		out.LeaseExpiresAt, out.DeadlineAt, out.CreatedAt = now.Add(lease), deadline.Time, created.Time
		if json.Unmarshal([]byte(raw), &out.Input) != nil {
			return fault.Unavailable
		}
		result, err := t.tx.ExecContext(ctx, t.sql("UPDATE assessment_job SET state='leased',attempt=?,fence=?,lease_owner=?,lease_token_hash=?,lease_expires_at=? WHERE org_id=? AND id=? AND state='queued'", "UPDATE assessment_job SET state='leased',attempt=$1,fence=$2,lease_owner=$3,lease_token_hash=$4,lease_expires_at=$5 WHERE org_id=$6 AND id=$7 AND state='queued'"), out.Attempt, out.Fence, worker, hash[:], t.bindTime(out.LeaseExpiresAt), out.OrgID, out.ID)
		if err != nil {
			return safeError(err)
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return fault.Conflict
		}
		claimed = true
		_, err = t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_job_receipt(org_id,worker_id,operation,key,digest,job_id,recorded_at) VALUES(?,?,'OP-AI-06',?,?,?,?)", "INSERT INTO assessment_job_receipt(org_id,worker_id,operation,key,digest,job_id,recorded_at) VALUES($1,$2,'OP-AI-06',$3,$4,$5,$6)"), org, worker, key, requestDigest, out.ID, t.bindTime(now))
		return safeError(err)
	})
	if err != nil {
		return assessment.Job{}, "", err
	}
	if !claimed {
		return assessment.Job{}, "", fault.NotFound
	}
	return out, token, nil
}

func (r *Repository) HeartbeatAssessmentJob(ctx context.Context, org, worker, job string, fence int64, tokenHash []byte, now time.Time, lease time.Duration) (time.Time, error) {
	expires := now.Add(lease)
	args := []any{r.read().bindTime(expires), org, job, worker, fence, tokenHash, r.read().bindTime(now)}
	if r.Backend == "sqlite" {
		args = append(args, r.read().bindTime(now))
	}
	result, err := r.DB.ExecContext(ctx, r.read().sql("UPDATE assessment_job SET lease_expires_at=? WHERE org_id=? AND id=? AND state='leased' AND lease_owner=? AND fence=? AND lease_token_hash=? AND lease_expires_at>? AND deadline_at>?", "UPDATE assessment_job SET lease_expires_at=$1 WHERE org_id=$2 AND id=$3 AND state='leased' AND lease_owner=$4 AND fence=$5 AND lease_token_hash=$6 AND lease_expires_at>$7 AND deadline_at>$7"), args...)
	if err != nil {
		return time.Time{}, safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return time.Time{}, fault.Conflict
	}
	return expires, nil
}

func (r *Repository) AssessmentJobResultReceipt(ctx context.Context, org, worker, key string, digest []byte) (assessment.Result, bool, error) {
	var out assessment.Result
	var priorDigest []byte
	var created, updated dbTime
	err := r.DB.QueryRowContext(ctx, r.read().sql("SELECT x.result_id,x.digest,r.employee_id,r.job_id,r.current_revision,r.status,r.created_at,r.updated_at FROM assessment_job_receipt x JOIN assessment_result r ON r.org_id=x.org_id AND r.id=x.result_id WHERE x.org_id=? AND x.worker_id=? AND x.operation='OP-AI-07' AND x.key=?", "SELECT x.result_id,x.digest,r.employee_id,r.job_id,r.current_revision,r.status,r.created_at,r.updated_at FROM assessment_job_receipt x JOIN assessment_result r ON r.org_id=x.org_id AND r.id=x.result_id WHERE x.org_id=$1 AND x.worker_id=$2 AND x.operation='OP-AI-07' AND x.key=$3"), org, worker, key).Scan(&out.ID, &priorDigest, &out.EmployeeID, &out.JobID, &out.Revision, &out.Status, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, safeError(err)
	}
	if !hmac.Equal(priorDigest, digest) {
		return out, false, fault.Mismatch
	}
	out.OrgID, out.CreatedAt, out.UpdatedAt = org, created.Time, updated.Time
	return out, true, nil
}

func (r *Repository) CompleteAssessmentJob(ctx context.Context, worker, key, job string, fence int64, tokenHash, receiptDigest []byte, encrypted assessment.EncryptedResult, now time.Time) (assessment.Result, error) {
	out := encrypted.Result
	if !value.ValidID(key) || len(receiptDigest) != sha256.Size {
		return out, fault.Invalid
	}
	err := r.WithTx(ctx, out.OrgID, func(base organization.Tx) error {
		t := base.(*transaction)
		var priorResult string
		var priorDigest []byte
		receiptErr := t.tx.QueryRowContext(ctx, t.sql("SELECT result_id,digest FROM assessment_job_receipt WHERE org_id=? AND worker_id=? AND operation='OP-AI-07' AND key=?", "SELECT result_id,digest FROM assessment_job_receipt WHERE org_id=$1 AND worker_id=$2 AND operation='OP-AI-07' AND key=$3"), out.OrgID, worker, key).Scan(&priorResult, &priorDigest)
		if receiptErr == nil {
			if !hmac.Equal(priorDigest, receiptDigest) {
				return fault.Mismatch
			}
			var created, updated dbTime
			if readErr := t.tx.QueryRowContext(ctx, t.sql("SELECT employee_id,job_id,current_revision,status,created_at,updated_at FROM assessment_result WHERE org_id=? AND id=?", "SELECT employee_id,job_id,current_revision,status,created_at,updated_at FROM assessment_result WHERE org_id=$1 AND id=$2"), out.OrgID, priorResult).Scan(&out.EmployeeID, &out.JobID, &out.Revision, &out.Status, &created, &updated); readErr != nil {
				return fault.Unavailable
			}
			out.ID, out.CreatedAt, out.UpdatedAt = priorResult, created.Time, updated.Time
			return nil
		}
		if !errors.Is(receiptErr, sql.ErrNoRows) {
			return safeError(receiptErr)
		}
		var employee, inputID string
		var source []byte
		args := []any{out.OrgID, job, worker, fence, tokenHash, t.bindTime(now)}
		if t.backend == "sqlite" {
			args = append(args, t.bindTime(now))
		}
		if err := t.tx.QueryRowContext(ctx, t.sql("SELECT employee_id,input_id,source_digest FROM assessment_job WHERE org_id=? AND id=? AND state='leased' AND lease_owner=? AND fence=? AND lease_token_hash=? AND lease_expires_at>? AND deadline_at>?", "SELECT employee_id,input_id,source_digest FROM assessment_job WHERE org_id=$1 AND id=$2 AND state='leased' AND lease_owner=$3 AND fence=$4 AND lease_token_hash=$5 AND lease_expires_at>$6 AND deadline_at>$6 FOR UPDATE"), args...).Scan(&employee, &inputID, &source); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fault.Conflict
			}
			return safeError(err)
		}
		if employee != out.EmployeeID || !sha256Equal(source, out.SourceDigest) {
			return fault.Conflict
		}
		if err := insertAssessmentPayload(ctx, t, encrypted.Envelope, out, now); err != nil {
			return err
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_result(org_id,employee_id,id,job_id,current_revision,status,created_at,updated_at) VALUES(?,?,?,?,1,'draft',?,?)", "INSERT INTO assessment_result(org_id,employee_id,id,job_id,current_revision,status,created_at,updated_at) VALUES($1,$2,$3,$4,1,'draft',$5,$6)"), out.OrgID, out.EmployeeID, out.ID, job, t.bindTime(now), t.bindTime(now)); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_result_revision(org_id,result_id,revision,payload_id,source_digest,status,created_at) VALUES(?,?,1,?,?,'draft',?)", "INSERT INTO assessment_result_revision(org_id,result_id,revision,payload_id,source_digest,status,created_at) VALUES($1,$2,1,$3,$4,'draft',$5)"), out.OrgID, out.ID, encrypted.Envelope.Context.VersionID, out.SourceDigest, t.bindTime(now)); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE assessment_job SET state='completed',completed_at=?,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE org_id=? AND id=?", "UPDATE assessment_job SET state='completed',completed_at=$1,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE org_id=$2 AND id=$3"), t.bindTime(now), out.OrgID, job); err != nil {
			return safeError(err)
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE approved_assessment_input SET status='consumed' WHERE org_id=? AND id=? AND status='approved'", "UPDATE approved_assessment_input SET status='consumed' WHERE org_id=$1 AND id=$2 AND status='approved'"), out.OrgID, inputID); err != nil {
			return safeError(err)
		}
		_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_job_receipt(org_id,worker_id,operation,key,digest,job_id,result_id,recorded_at) VALUES(?,?,'OP-AI-07',?,?,?,?,?)", "INSERT INTO assessment_job_receipt(org_id,worker_id,operation,key,digest,job_id,result_id,recorded_at) VALUES($1,$2,'OP-AI-07',$3,$4,$5,$6,$7)"), out.OrgID, worker, key, receiptDigest, job, out.ID, t.bindTime(now))
		return safeError(err)
	})
	return out, err
}

func insertAssessmentPayload(ctx context.Context, t *transaction, envelope sensitive.Envelope, result assessment.Result, now time.Time) error {
	c := envelope.Context
	k := envelope.Key
	if c.OrgID != result.OrgID || c.EmployeeID != result.EmployeeID || c.RecordID != result.ID || c.VersionID == "" {
		return fault.Invalid
	}
	_, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_payload(org_id,id,employee_id,result_id,revision,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", "INSERT INTO assessment_payload(org_id,id,employee_id,result_id,revision,object_kind,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)"), c.OrgID, c.VersionID, c.EmployeeID, c.RecordID, result.Revision, c.ObjectKind, c.Purpose, c.SchemaType, c.SchemaVersion, envelope.FormatVersion, envelope.Algorithm, envelope.DEKID, k.KEKID, k.Version, k.Data, envelope.SealedBytes, t.bindTime(now))
	return safeError(err)
}

func (r *Repository) FailAssessmentJob(ctx context.Context, org, worker, job string, fence int64, tokenHash []byte, code string, now time.Time) error {
	if code != "provider_unavailable" && code != "provider_rejected" && code != "invalid_output" {
		return fault.Invalid
	}
	result, err := r.DB.ExecContext(ctx, r.read().sql("UPDATE assessment_job SET state=CASE WHEN attempt>=max_attempts OR deadline_at<=? THEN 'failed' ELSE 'queued' END,error_code=?,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE org_id=? AND id=? AND state='leased' AND lease_owner=? AND fence=? AND lease_token_hash=? AND lease_expires_at>?", "UPDATE assessment_job SET state=CASE WHEN attempt>=max_attempts OR deadline_at<=$1 THEN 'failed' ELSE 'queued' END,error_code=$2,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE org_id=$3 AND id=$4 AND state='leased' AND lease_owner=$5 AND fence=$6 AND lease_token_hash=$7 AND lease_expires_at>$1"), r.read().bindTime(now), code, org, job, worker, fence, tokenHash)
	if err != nil {
		return safeError(err)
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return fault.Conflict
	}
	return nil
}

func (r *Repository) AssessmentResult(ctx context.Context, org, id string) (assessment.Result, sensitive.Envelope, error) {
	return r.read().assessmentResult(ctx, org, id)
}
func (t *transaction) AssessmentResult(ctx context.Context, org, id string) (assessment.Result, sensitive.Envelope, error) {
	return t.reader.assessmentResult(ctx, org, id)
}
func (r reader) assessmentResult(ctx context.Context, org, id string) (assessment.Result, sensitive.Envelope, error) {
	var out assessment.Result
	var env sensitive.Envelope
	var created, updated dbTime
	query := "SELECT r.employee_id,r.job_id,r.current_revision,r.status,r.created_at,r.updated_at,v.source_digest,p.id,p.object_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM assessment_result r JOIN assessment_result_revision v ON v.org_id=r.org_id AND v.result_id=r.id AND v.revision=r.current_revision JOIN assessment_payload p ON p.org_id=v.org_id AND p.id=v.payload_id WHERE r.org_id=? AND r.id=?"
	pg := "SELECT r.employee_id,r.job_id,r.current_revision,r.status,r.created_at,r.updated_at,v.source_digest,p.id,p.object_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM assessment_result r JOIN assessment_result_revision v ON v.org_id=r.org_id AND v.result_id=r.id AND v.revision=r.current_revision JOIN assessment_payload p ON p.org_id=v.org_id AND p.id=v.payload_id WHERE r.org_id=$1 AND r.id=$2"
	err := r.db.QueryRowContext(ctx, r.sql(query, pg), org, id).Scan(&out.EmployeeID, &out.JobID, &out.Revision, &out.Status, &created, &updated, &out.SourceDigest, &env.Context.VersionID, &env.Context.ObjectKind, &env.Context.Purpose, &env.Context.SchemaType, &env.Context.SchemaVersion, &env.FormatVersion, &env.Algorithm, &env.DEKID, &env.Key.KEKID, &env.Key.Version, &env.Key.Data, &env.SealedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return out, env, fault.NotFound
	}
	if err != nil {
		return out, env, safeError(err)
	}
	out.OrgID, out.ID, out.CreatedAt, out.UpdatedAt = org, id, created.Time, updated.Time
	env.Context.OrgID, env.Context.EmployeeID, env.Context.RecordID = org, out.EmployeeID, id
	return out, env, nil
}
func (t *transaction) AssessmentResultCurrent(ctx context.Context, org, employee, id string, revision int64, source []byte) error {
	var current int64
	var status string
	var currentSource []byte
	err := t.tx.QueryRowContext(ctx, t.sql("SELECT r.current_revision,r.status,v.source_digest FROM assessment_result r JOIN assessment_result_revision v ON v.org_id=r.org_id AND v.result_id=r.id AND v.revision=r.current_revision WHERE r.org_id=? AND r.employee_id=? AND r.id=?", "SELECT r.current_revision,r.status,v.source_digest FROM assessment_result r JOIN assessment_result_revision v ON v.org_id=r.org_id AND v.result_id=r.id AND v.revision=r.current_revision WHERE r.org_id=$1 AND r.employee_id=$2 AND r.id=$3 FOR UPDATE"), org, employee, id).Scan(&current, &status, &currentSource)
	if errors.Is(err, sql.ErrNoRows) {
		return fault.NotFound
	}
	if err != nil {
		return safeError(err)
	}
	if current != revision || status == "invalidated" || status == "discarded" || !sha256Equal(currentSource, source) {
		return fault.NotFound
	}
	return nil
}

func (r *Repository) SaveAssessmentResult(ctx context.Context, actor authz.Snapshot, tokenHash []byte, result assessment.Result, envelope sensitive.Envelope, action string, now time.Time, audit organization.Audit) (assessment.Result, error) {
	if action != "edit" && action != "publish" && action != "discard" {
		return result, fault.Invalid
	}
	err := r.WithTx(ctx, actor.OrgID, func(base organization.Tx) error {
		t := base.(*transaction)
		if err := t.LockSubjects(ctx, actor.OrgID, []string{actor.SubjectID}); err != nil {
			return err
		}
		if err := t.LockInterviewEmployee(ctx, actor.OrgID, result.EmployeeID); err != nil {
			return err
		}
		currentActor, authErr := t.Security(ctx, tokenHash, actor.OrgID, result.EmployeeID)
		if authErr != nil || currentActor.SubjectID != actor.SubjectID || !currentActor.Valid(now) || !currentActor.Allows("assessment.publish", "metadata", result.EmployeeID, "interview_followup", now) {
			return fault.NotFound
		}
		var current int64
		var status string
		if err := t.tx.QueryRowContext(ctx, t.sql("SELECT current_revision,status FROM assessment_result WHERE org_id=? AND id=? AND employee_id=?", "SELECT current_revision,status FROM assessment_result WHERE org_id=$1 AND id=$2 AND employee_id=$3 FOR UPDATE"), actor.OrgID, result.ID, result.EmployeeID).Scan(&current, &status); err != nil {
			return safeError(err)
		}
		if current != result.Revision || status != "draft" {
			return fault.Conflict
		}
		if action == "edit" {
			result.Revision++
			if err := insertAssessmentPayload(ctx, t, envelope, result, now); err != nil {
				return err
			}
			if _, err := t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_result_revision(org_id,result_id,revision,payload_id,editor_subject_id,source_digest,status,created_at) VALUES(?,?,?,?,?,?,'draft',?)", "INSERT INTO assessment_result_revision(org_id,result_id,revision,payload_id,editor_subject_id,source_digest,status,created_at) VALUES($1,$2,$3,$4,$5,$6,'draft',$7)"), actor.OrgID, result.ID, result.Revision, envelope.Context.VersionID, actor.SubjectID, result.SourceDigest, t.bindTime(now)); err != nil {
				return safeError(err)
			}
		} else {
			result.Status = map[string]string{"publish": "published", "discard": "discarded"}[action]
		}
		if _, err := t.tx.ExecContext(ctx, t.sql("UPDATE assessment_result SET current_revision=?,status=?,updated_at=? WHERE org_id=? AND id=?", "UPDATE assessment_result SET current_revision=$1,status=$2,updated_at=$3 WHERE org_id=$4 AND id=$5"), result.Revision, result.Status, t.bindTime(now), actor.OrgID, result.ID); err != nil {
			return safeError(err)
		}
		return t.Audit(ctx, audit)
	})
	result.UpdatedAt = now
	return result, err
}

func (r *Repository) ListAssessmentJobs(ctx context.Context, org, employee string) ([]assessment.Job, error) {
	rows, err := r.DB.QueryContext(ctx, r.read().sql("SELECT j.id,j.input_id,j.window_id,COALESCE(r.id,''),j.provider_policy_id,j.audience,j.state,j.attempt,j.max_attempts,j.created_at,j.completed_at IS NOT NULL,COALESCE(j.completed_at,j.created_at),COALESCE(j.error_code,'') FROM assessment_job j LEFT JOIN assessment_result r ON r.org_id=j.org_id AND r.job_id=j.id WHERE j.org_id=? AND j.employee_id=? ORDER BY j.created_at DESC,j.id DESC LIMIT 100", "SELECT j.id,j.input_id,j.window_id,COALESCE(r.id,''),j.provider_policy_id,j.audience,j.state,j.attempt,j.max_attempts,j.created_at,j.completed_at IS NOT NULL,COALESCE(j.completed_at,j.created_at),COALESCE(j.error_code,'') FROM assessment_job j LEFT JOIN assessment_result r ON r.org_id=j.org_id AND r.job_id=j.id WHERE j.org_id=$1 AND j.employee_id=$2 ORDER BY j.created_at DESC,j.id DESC LIMIT 100"), org, employee)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []assessment.Job{}
	for rows.Next() {
		var j assessment.Job
		var created, completed dbTime
		var has bool
		if err = rows.Scan(&j.ID, &j.InputID, &j.WindowID, &j.ResultID, &j.ProviderPolicyID, &j.Audience, &j.State, &j.Attempt, &j.MaxAttempts, &created, &has, &completed, &j.ErrorCode); err != nil {
			return nil, safeError(err)
		}
		j.OrgID, j.EmployeeID, j.CreatedAt = org, employee, created.Time
		if has {
			j.CompletedAt = completed.Time
		}
		out = append(out, j)
	}
	return out, safeError(rows.Err())
}

func sha256Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}

func (r *Repository) DueAssessmentWindows(ctx context.Context, now time.Time) ([]assessment.ScheduledWindow, error) {
	sqlite := "SELECT w.org_id,w.employee_id,w.id,w.policy_revision,w.local_start,w.local_end,w.start_at,w.end_at,w.due_at,w.paused,COALESCE(s.service_subject_id,''),COALESCE(s.approved_by,''),COALESCE(s.audience,''),COALESCE(s.provider_policy_id,''),COALESCE(s.expires_at,w.due_at) FROM followup_window w JOIN interview_policy p ON p.org_id=w.org_id AND p.employee_id=w.employee_id AND p.revision=w.policy_revision LEFT JOIN assessment_standing_policy s ON s.org_id=w.org_id AND s.employee_id=w.employee_id AND s.policy_revision=w.policy_revision WHERE p.ai_mode='periodic_structured_v1' AND w.paused=0 AND w.due_at<=? ORDER BY w.last_scanned_at IS NOT NULL,w.last_scanned_at,w.due_at,w.id LIMIT 100"
	postgres := "SELECT w.org_id,w.employee_id,w.id,w.policy_revision,w.local_start::text,w.local_end::text,w.start_at,w.end_at,w.due_at,w.paused,COALESCE(s.service_subject_id,''),COALESCE(s.approved_by,''),COALESCE(s.audience,''),COALESCE(s.provider_policy_id,''),COALESCE(s.expires_at,w.due_at) FROM followup_window w JOIN interview_policy p ON p.org_id=w.org_id AND p.employee_id=w.employee_id AND p.revision=w.policy_revision LEFT JOIN assessment_standing_policy s ON s.org_id=w.org_id AND s.employee_id=w.employee_id AND s.policy_revision=w.policy_revision WHERE p.ai_mode='periodic_structured_v1' AND w.paused=FALSE AND w.due_at<=$1 ORDER BY w.last_scanned_at IS NOT NULL,w.last_scanned_at,w.due_at,w.id LIMIT 100"
	rows, err := r.DB.QueryContext(ctx, r.read().sql(sqlite, postgres), r.read().bindTime(now))
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []assessment.ScheduledWindow{}
	for rows.Next() {
		var item assessment.ScheduledWindow
		var start, end, due, expires dbTime
		if err = rows.Scan(&item.OrgID, &item.EmployeeID, &item.ID, &item.PolicyRevision, &item.LocalStart, &item.LocalEnd, &start, &end, &due, &item.Paused, &item.ServiceSubjectID, &item.ApprovedBy, &item.Audience, &item.ProviderPolicyID, &expires); err != nil {
			return nil, safeError(err)
		}
		item.StartAt, item.EndAt, item.DueAt, item.ExpiresAt = start.Time, end.Time, due.Time, expires.Time
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
	}
	return out, nil
}

func (r *Repository) CreateScheduledAssessment(ctx context.Context, actor authz.Snapshot, tokenHash []byte, expectedEpoch int64, scheduled assessment.ScheduledWindow, input assessment.StructuredInput, generation, source []byte, now time.Time) (bool, error) {
	if actor.OrgID != scheduled.OrgID || actor.SubjectID != scheduled.ServiceSubjectID || actor.SubjectID == scheduled.ApprovedBy || expectedEpoch < 0 || len(generation) != 32 || len(source) != 32 {
		return false, fault.Invalid
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 16*1024 {
		return false, fault.Invalid
	}
	created := false
	err = r.WithTx(ctx, scheduled.OrgID, func(base organization.Tx) error {
		t := base.(*transaction)
		if err := t.LockSubjects(ctx, actor.OrgID, []string{actor.SubjectID}); err != nil {
			return err
		}
		if err := t.LockInterviewEmployee(ctx, actor.OrgID, scheduled.EmployeeID); err != nil {
			return err
		}
		current, authErr := t.Security(ctx, tokenHash, actor.OrgID, scheduled.EmployeeID)
		if authErr != nil || current.SubjectID != actor.SubjectID || !current.Valid(now) || !current.Allows("assessment.request", "metadata", scheduled.EmployeeID, "interview_followup", now) || !current.Allows("assessment.read", "metadata", scheduled.EmployeeID, "interview_followup", now) {
			return fault.NotFound
		}
		currentEpoch, epochErr := assessmentSourceEpoch(ctx, t.reader, actor.OrgID, scheduled.EmployeeID)
		if epochErr != nil {
			return epochErr
		}
		if currentEpoch != expectedEpoch {
			return fault.Conflict
		}
		inputID := value.NewID()
		result, insertErr := t.tx.ExecContext(ctx, t.sql("INSERT INTO approved_assessment_input(org_id,employee_id,id,window_id,generation_digest,source_digest,facts_json,requested_by,created_at,approved_by,approved_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved') ON CONFLICT(org_id,window_id,generation_digest) WHERE status<>'invalidated' DO NOTHING", "INSERT INTO approved_assessment_input(org_id,employee_id,id,window_id,generation_digest,source_digest,facts_json,requested_by,created_at,approved_by,approved_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'approved') ON CONFLICT(org_id,window_id,generation_digest) WHERE status<>'invalidated' DO NOTHING"), scheduled.OrgID, scheduled.EmployeeID, inputID, scheduled.ID, generation, source, string(raw), actor.SubjectID, t.bindTime(now), scheduled.ApprovedBy, t.bindTime(now))
		if insertErr != nil {
			return safeError(insertErr)
		}
		n, insertErr := result.RowsAffected()
		if insertErr != nil {
			return safeError(insertErr)
		}
		if n == 0 {
			_, insertErr = t.tx.ExecContext(ctx, t.sql("UPDATE followup_window SET automation_state='ready',block_reason=NULL,last_scanned_at=? WHERE org_id=? AND employee_id=? AND id=? AND policy_revision=?", "UPDATE followup_window SET automation_state='ready',block_reason=NULL,last_scanned_at=$1 WHERE org_id=$2 AND employee_id=$3 AND id=$4 AND policy_revision=$5"), t.bindTime(now), scheduled.OrgID, scheduled.EmployeeID, scheduled.ID, scheduled.PolicyRevision)
			return safeError(insertErr)
		}
		jobID := value.NewID()
		_, insertErr = t.tx.ExecContext(ctx, t.sql("INSERT INTO assessment_job(org_id,employee_id,id,input_id,window_id,generation_digest,source_digest,provider_policy_id,audience,state,max_attempts,deadline_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',3,?,?)", "INSERT INTO assessment_job(org_id,employee_id,id,input_id,window_id,generation_digest,source_digest,provider_policy_id,audience,state,max_attempts,deadline_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',3,$10,$11)"), scheduled.OrgID, scheduled.EmployeeID, jobID, inputID, scheduled.ID, generation, source, scheduled.ProviderPolicyID, scheduled.Audience, t.bindTime(now.Add(10*time.Minute)), t.bindTime(now))
		if insertErr != nil {
			return safeError(insertErr)
		}
		_, insertErr = t.tx.ExecContext(ctx, t.sql("UPDATE followup_window SET automation_state='ready',block_reason=NULL,last_scanned_at=? WHERE org_id=? AND id=?", "UPDATE followup_window SET automation_state='ready',block_reason=NULL,last_scanned_at=$1 WHERE org_id=$2 AND id=$3"), t.bindTime(now), scheduled.OrgID, scheduled.ID)
		created = insertErr == nil
		return safeError(insertErr)
	})
	return created, err
}

func (r *Repository) RecordAssessmentScan(ctx context.Context, window assessment.ScheduledWindow, reason string, now time.Time) error {
	if reason != "automation_not_enabled" && reason != "policy_expired" && reason != "authorization_unavailable" && reason != "provider_not_approved" {
		return fault.Invalid
	}
	result, err := r.DB.ExecContext(ctx, r.read().sql("UPDATE followup_window SET automation_state='blocked',block_reason=?,last_scanned_at=? WHERE org_id=? AND employee_id=? AND id=? AND policy_revision=?", "UPDATE followup_window SET automation_state='blocked',block_reason=$1,last_scanned_at=$2 WHERE org_id=$3 AND employee_id=$4 AND id=$5 AND policy_revision=$6"), reason, r.read().bindTime(now), window.OrgID, window.EmployeeID, window.ID, window.PolicyRevision)
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return fault.Conflict
	}
	return nil
}
