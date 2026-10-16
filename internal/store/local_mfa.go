package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func (r *Repository) LocalCredentialBySession(ctx context.Context, hash []byte, now time.Time) (identity.LocalSessionCredential, error) {
	session, err := r.IdentitySession(ctx, hash, now)
	if err != nil {
		return identity.LocalSessionCredential{}, err
	}
	var digest []byte
	err = r.DB.QueryRowContext(ctx, r.read().sql(
		"SELECT a.username_digest FROM session_auth sa JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=sa.org_id AND a.subject_id=sa.subject_id WHERE sa.token_hash=? AND a.active=1",
		"SELECT a.username_digest FROM session_auth sa JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=sa.org_id AND a.subject_id=sa.subject_id WHERE sa.token_hash=$1 AND a.active=true"), hash).Scan(&digest)
	if err != nil {
		return identity.LocalSessionCredential{}, fault.Unauthenticated
	}
	credential, err := r.LookupLocalCredential(ctx, digest)
	if err != nil || credential.OrgID != session.OrgID || credential.SubjectID != session.SubjectID {
		return identity.LocalSessionCredential{}, fault.Unauthenticated
	}
	return identity.LocalSessionCredential{Session: session, Credential: credential}, nil
}

func validMFAEnvelope(enrollment identity.LocalMFAEnrollment) bool {
	e := enrollment.Envelope
	c := e.Context
	return value.ValidID(enrollment.AccountID) && value.ValidID(enrollment.OrgID) && value.ValidID(enrollment.EnrollmentID) &&
		(enrollment.Mode == "initial" || enrollment.Mode == "replace" || enrollment.Mode == "recovery") && enrollment.Generation > 0 && enrollment.Attempts >= 0 && enrollment.Attempts <= 5 &&
		len(enrollment.BoundSessionHash) == 32 && c.OrgID == enrollment.OrgID && c.RecordID == enrollment.AccountID && c.VersionID == enrollment.EnrollmentID && c.EmployeeID == "" &&
		c.ObjectKind == "local_mfa_enrollment" && c.Purpose == "identity" && c.SchemaType == "identity.local_mfa_enrollment.v1" && c.SchemaVersion == 1 &&
		e.FormatVersion == 1 && e.Algorithm == "A256GCM-RANDOMNONCE" && e.DEKID != "" && e.Key.KEKID != "" && e.Key.Version > 0 && len(e.Key.Data) > 0 && len(e.SealedBytes) >= 39
}

func (r *Repository) insertMFAEnrollment(ctx context.Context, q reader, enrollment identity.LocalMFAEnrollment) error {
	e := enrollment.Envelope
	_, err := q.db.ExecContext(ctx, q.sql(
		"INSERT INTO local_mfa_enrollment(account_id,org_id,enrollment_id,mode,generation,attempts,expires_at,bound_session_hash,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		"INSERT INTO local_mfa_enrollment(account_id,org_id,enrollment_id,mode,generation,attempts,expires_at,bound_session_hash,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)"),
		enrollment.AccountID, enrollment.OrgID, enrollment.EnrollmentID, enrollment.Mode, enrollment.Generation, enrollment.Attempts, r.BindTime(enrollment.ExpiresAt), enrollment.BoundSessionHash,
		e.Context.RecordID, e.Context.VersionID, e.Context.Purpose, e.Context.SchemaType, e.Context.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, r.BindTime(enrollment.ExpiresAt.Add(-10*time.Minute)))
	return safeError(err)
}

func (r *Repository) BeginLocalMFAEnrollment(ctx context.Context, input identity.LocalMFAEnrollmentInput) error {
	if !validMFAEnvelope(input.Enrollment) || !bytes.Equal(input.SessionHash, input.Enrollment.BoundSessionHash) || !value.ValidID(input.RequestID) || !input.Enrollment.ExpiresAt.Equal(input.Now.Add(10*time.Minute)) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID, orgID, subjectID, accessKind, status string
	var generation, lastStep int64
	query := q.sql("SELECT a.id,a.org_id,a.subject_id,s.access_kind,m.status,m.generation,COALESCE(f.last_accepted_step,0) FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN local_mfa_account m ON m.account_id=a.id LEFT JOIN local_mfa_factor f ON f.account_id=a.id WHERE s.token_hash=? AND s.revoked=0", "SELECT a.id,a.org_id,a.subject_id,s.access_kind,m.status,m.generation,COALESCE(f.last_accepted_step,0) FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN local_mfa_account m ON m.account_id=a.id LEFT JOIN local_mfa_factor f ON f.account_id=a.id WHERE s.token_hash=$1 AND s.revoked=false FOR UPDATE OF s,m")
	if err = tx.QueryRowContext(ctx, query, input.SessionHash).Scan(&accountID, &orgID, &subjectID, &accessKind, &status, &generation, &lastStep); err != nil || accountID != input.Enrollment.AccountID || orgID != input.Enrollment.OrgID || input.Enrollment.Generation != generation+1 {
		return fault.Unauthenticated
	}
	if input.Enrollment.Mode == "initial" {
		if accessKind != "mfa_enrollment" || status != "enrollment_required" || input.AcceptedStep != 0 {
			return fault.Forbidden
		}
	} else if input.Enrollment.Mode == "replace" {
		if accessKind != "business" || status != "active" || input.AcceptedStep <= lastStep {
			return fault.Unauthenticated
		}
		result, updateErr := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_factor SET last_accepted_step=? WHERE account_id=? AND generation=? AND last_accepted_step<?", "UPDATE local_mfa_factor SET last_accepted_step=$1 WHERE account_id=$2 AND generation=$3 AND last_accepted_step<$4"), input.AcceptedStep, accountID, generation, input.AcceptedStep)
		if updateErr != nil {
			return safeError(updateErr)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Unauthenticated
		}
	} else {
		return fault.Forbidden
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"), accountID); err != nil {
		return safeError(err)
	}
	if err = r.insertMFAEnrollment(ctx, q, input.Enrollment); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func scanEnrollment(row *sql.Row) (identity.LocalMFAEnrollment, error) {
	var out identity.LocalMFAEnrollment
	var expires dbTime
	var schemaVersion, formatVersion, kekVersion int64
	var recordID, versionID, purpose, schemaType, algorithm, dekID string
	err := row.Scan(&out.AccountID, &out.OrgID, &out.EnrollmentID, &out.Mode, &out.Generation, &out.Attempts, &expires, &out.BoundSessionHash, &recordID, &versionID, &purpose, &schemaType, &schemaVersion, &formatVersion, &algorithm, &dekID, &out.Envelope.Key.KEKID, &kekVersion, &out.Envelope.Key.Data, &out.Envelope.SealedBytes)
	if err != nil {
		return identity.LocalMFAEnrollment{}, err
	}
	if schemaVersion != 1 || formatVersion != 1 || kekVersion <= 0 || kekVersion > math.MaxUint32 {
		return identity.LocalMFAEnrollment{}, fault.Unavailable
	}
	out.ExpiresAt = expires.Time
	out.Envelope.Context = sensitive.Context{OrgID: out.OrgID, RecordID: recordID, VersionID: versionID, ObjectKind: "local_mfa_enrollment", Purpose: purpose, SchemaType: schemaType, SchemaVersion: uint32(schemaVersion)}
	out.Envelope.FormatVersion, out.Envelope.Algorithm, out.Envelope.DEKID, out.Envelope.Key.Version = uint16(formatVersion), algorithm, dekID, uint32(kekVersion)
	return out, nil
}

func (r *Repository) LocalMFAEnrollment(ctx context.Context, sessionHash []byte, now time.Time) (identity.LocalMFAEnrollment, error) {
	if len(sessionHash) != 32 {
		return identity.LocalMFAEnrollment{}, fault.Unauthenticated
	}
	q := r.read()
	out, err := scanEnrollment(r.DB.QueryRowContext(ctx, q.sql(
		"SELECT e.account_id,e.org_id,e.enrollment_id,e.mode,e.generation,e.attempts,e.expires_at,e.bound_session_hash,e.record_id,e.version_id,e.purpose,e.schema_type,e.schema_version,e.format_version,e.algorithm,e.dek_id,e.kek_id,e.kek_version,e.wrapped_dek,e.sealed_bytes FROM local_mfa_enrollment e JOIN session s ON s.token_hash=e.bound_session_hash WHERE e.bound_session_hash=? AND s.revoked=0 AND s.access_kind IN('mfa_enrollment','mfa_recovery','business')",
		"SELECT e.account_id,e.org_id,e.enrollment_id,e.mode,e.generation,e.attempts,e.expires_at,e.bound_session_hash,e.record_id,e.version_id,e.purpose,e.schema_type,e.schema_version,e.format_version,e.algorithm,e.dek_id,e.kek_id,e.kek_version,e.wrapped_dek,e.sealed_bytes FROM local_mfa_enrollment e JOIN session s ON s.token_hash=e.bound_session_hash WHERE e.bound_session_hash=$1 AND s.revoked=false AND s.access_kind IN('mfa_enrollment','mfa_recovery','business')"), sessionHash))
	if errors.Is(err, sql.ErrNoRows) || err == nil && !out.ExpiresAt.After(now) {
		return identity.LocalMFAEnrollment{}, fault.Unauthenticated
	}
	if err != nil {
		return identity.LocalMFAEnrollment{}, safeError(err)
	}
	return out, nil
}

func (r *Repository) RecordLocalMFAEnrollmentFailure(ctx context.Context, sessionHash []byte, requestID string, now time.Time) error {
	if len(sessionHash) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID, orgID, subjectID string
	var attempts int64
	if err = tx.QueryRowContext(ctx, q.sql("SELECT e.account_id,a.org_id,a.subject_id,e.attempts FROM local_mfa_enrollment e JOIN local_account a ON a.id=e.account_id WHERE e.bound_session_hash=?", "SELECT e.account_id,a.org_id,a.subject_id,e.attempts FROM local_mfa_enrollment e JOIN local_account a ON a.id=e.account_id WHERE e.bound_session_hash=$1 FOR UPDATE OF e"), sessionHash).Scan(&accountID, &orgID, &subjectID, &attempts); err != nil {
		return fault.Unauthenticated
	}
	attempts++
	if attempts >= 5 {
		if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"), accountID); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE token_hash=?", "UPDATE session SET revoked=true WHERE token_hash=$1"), sessionHash); err != nil {
			return safeError(err)
		}
	} else if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_mfa_enrollment SET attempts=? WHERE account_id=?", "UPDATE local_mfa_enrollment SET attempts=$1 WHERE account_id=$2"), attempts, accountID); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: orgID, SubjectID: subjectID, Operation: "AUTH-LOGIN", RequestID: requestID, Outcome: "denied", At: now}); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func insertSessionForLocal(ctx context.Context, r *Repository, q reader, issue identity.LocalSessionIssue, orgID, subjectID string, epoch int64, digest []byte, keyID string, keyVersion uint32) error {
	if len(issue.TokenHash) != 32 || len(issue.CSRFHash) != 32 || issue.CSRFKeyID == "" || issue.CSRFVersion == 0 || keyID == "" || keyVersion == 0 {
		return fault.Invalid
	}
	if _, err := q.db.ExecContext(ctx, q.sql("INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version,access_kind) VALUES(?,?,?,?,?,?,?,0,?,?,?,?)", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version,access_kind) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,$9,$10,$11)"), issue.TokenHash, orgID, subjectID, epoch, r.BindTime(issue.ExpiresAt), r.BindTime(issue.IdleExpiresAt), r.BindTime(issue.MFAUntil), issue.CSRFHash, issue.CSRFKeyID, issue.CSRFVersion, issue.AccessKind); err != nil {
		return safeError(err)
	}
	amr := `["pwd"]`
	if issue.AccessKind == "business" {
		amr = `["pwd","otp"]`
	}
	_, err := q.db.ExecContext(ctx, q.sql("INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,identity_key_id,key_version,created_at,acr,amr_json) VALUES(?,?,?,?,?,?,?,'',?)", "INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,identity_key_id,key_version,created_at,acr,amr_json) VALUES($1,$2,$3,$4,$5,$6,$7,'',$8)"), issue.TokenHash, orgID, subjectID, digest, keyID, keyVersion, r.BindTime(issue.Now), amr)
	return safeError(err)
}

func insertFactor(ctx context.Context, r *Repository, q reader, factor identity.LocalMFAFactor, now time.Time) error {
	e := factor.Envelope
	c := e.Context
	if c.OrgID != factor.OrgID || c.RecordID != factor.AccountID || c.VersionID != factor.FactorID || c.ObjectKind != "local_mfa_factor" || c.Purpose != "identity" || c.SchemaType != "identity.local_mfa_factor.v1" || c.SchemaVersion != 1 || e.FormatVersion != 1 || e.Key.KEKID == "" || e.Key.Version == 0 {
		return fault.Invalid
	}
	_, err := q.db.ExecContext(ctx, q.sql("INSERT INTO local_mfa_factor(account_id,org_id,factor_id,generation,last_accepted_step,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", "INSERT INTO local_mfa_factor(account_id,org_id,factor_id,generation,last_accepted_step,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"), factor.AccountID, factor.OrgID, factor.FactorID, factor.Generation, factor.LastAcceptedStep, c.RecordID, c.VersionID, c.Purpose, c.SchemaType, c.SchemaVersion, e.FormatVersion, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, r.BindTime(now))
	return safeError(err)
}

func (r *Repository) ConfirmLocalMFAEnrollment(ctx context.Context, input identity.LocalMFAConfirmInput) error {
	factor := input.NewSession.Factor
	if factor == nil || len(input.SessionHash) != 32 || !value.ValidID(input.EnrollmentID) || input.Generation <= 0 || input.AcceptedStep <= 0 || input.Recovery.KeyID == "" || input.Recovery.Version == 0 || len(input.Recovery.Digest) != 32 || !value.ValidID(input.RequestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID, orgID, subjectID, usernameKeyID, mode string
	var usernameDigest []byte
	var usernameVersion, epoch, currentGeneration int64
	query := q.sql("SELECT e.account_id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,e.mode,s.auth_epoch,m.generation FROM local_mfa_enrollment e JOIN local_account a ON a.id=e.account_id JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_mfa_account m ON m.account_id=a.id WHERE e.bound_session_hash=? AND e.enrollment_id=? AND e.generation=? AND e.expires_at>?", "SELECT e.account_id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,e.mode,s.auth_epoch,m.generation FROM local_mfa_enrollment e JOIN local_account a ON a.id=e.account_id JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_mfa_account m ON m.account_id=a.id WHERE e.bound_session_hash=$1 AND e.enrollment_id=$2 AND e.generation=$3 AND e.expires_at>$4 FOR UPDATE OF e,m,s")
	if err = tx.QueryRowContext(ctx, query, input.SessionHash, input.EnrollmentID, input.Generation, r.BindTime(input.Now)).Scan(&accountID, &orgID, &subjectID, &usernameDigest, &usernameKeyID, &usernameVersion, &mode, &epoch, &currentGeneration); err != nil || input.Generation != currentGeneration+1 || factor.AccountID != accountID || factor.OrgID != orgID || factor.Generation != input.Generation || factor.LastAcceptedStep != input.AcceptedStep {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_factor WHERE account_id=?", "DELETE FROM local_mfa_factor WHERE account_id=$1"), accountID); err != nil {
		return safeError(err)
	}
	if err = insertFactor(ctx, r, q, *factor, input.Now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_recovery_code WHERE account_id=?", "DELETE FROM local_mfa_recovery_code WHERE account_id=$1"), accountID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_recovery_code(account_id,generation,key_id,key_version,digest,created_at) VALUES(?,?,?,?,?,?)", "INSERT INTO local_mfa_recovery_code(account_id,generation,key_id,key_version,digest,created_at) VALUES($1,$2,$3,$4,$5,$6)"), accountID, input.Generation, input.Recovery.KeyID, input.Recovery.Version, input.Recovery.Digest, r.BindTime(input.Now)); err != nil {
		return safeError(err)
	}
	result, err := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_account SET status='active',generation=?,updated_at=? WHERE account_id=? AND generation=?", "UPDATE local_mfa_account SET status='active',generation=$1,updated_at=$2 WHERE account_id=$3 AND generation=$4"), input.Generation, r.BindTime(input.Now), accountID, currentGeneration)
	if err != nil {
		return safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"), accountID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if usernameVersion <= 0 || usernameVersion > math.MaxUint32 || mode == "" {
		return fault.Unavailable
	}
	if err = insertSessionForLocal(ctx, r, q, input.NewSession, orgID, subjectID, epoch, usernameDigest, usernameKeyID, uint32(usernameVersion)); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func (r *Repository) BeginLocalMFARecovery(ctx context.Context, input identity.LocalMFARecoveryInput) error {
	if !validMFAEnvelope(input.Enrollment) || input.Enrollment.Mode != "recovery" || len(input.UsernameDigest) != 32 || len(input.RecoveryDigest) != 32 || len(input.InputDigest) != 32 || !value.ValidID(input.RequestID) || !bytes.Equal(input.Enrollment.BoundSessionHash, input.NewSession.TokenHash) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID, orgID, subjectID, usernameKeyID string
	var credentialRevision, generation, epoch, usernameVersion int64
	query := q.sql("SELECT a.id,a.org_id,a.subject_id,a.username_key_id,a.username_key_version,c.revision,m.generation,s.auth_epoch FROM local_account a JOIN local_credential c ON c.account_id=a.id JOIN local_mfa_account m ON m.account_id=a.id JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id WHERE a.username_digest=? AND a.active=1 AND m.status='active'", "SELECT a.id,a.org_id,a.subject_id,a.username_key_id,a.username_key_version,c.revision,m.generation,s.auth_epoch FROM local_account a JOIN local_credential c ON c.account_id=a.id JOIN local_mfa_account m ON m.account_id=a.id JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id WHERE a.username_digest=$1 AND a.active=true AND m.status='active' FOR UPDATE OF a,c,m,s")
	if err = tx.QueryRowContext(ctx, query, input.UsernameDigest).Scan(&accountID, &orgID, &subjectID, &usernameKeyID, &usernameVersion, &credentialRevision, &generation, &epoch); err != nil || credentialRevision != input.CredentialRevision || accountID != input.Enrollment.AccountID || input.Enrollment.Generation != generation+1 {
		return fault.Unauthenticated
	}
	var priorDigest []byte
	var enrollmentID string
	receiptErr := tx.QueryRowContext(ctx, q.sql("SELECT input_digest,enrollment_id FROM local_mfa_recovery_receipt WHERE request_id=?", "SELECT input_digest,enrollment_id FROM local_mfa_recovery_receipt WHERE request_id=$1 FOR UPDATE"), input.RequestID).Scan(&priorDigest, &enrollmentID)
	if receiptErr == nil {
		if !bytes.Equal(priorDigest, input.InputDigest) {
			return fault.Mismatch
		}
		if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
			return safeError(err)
		}
		result, updateErr := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_enrollment SET bound_session_hash=? WHERE account_id=? AND enrollment_id=? AND expires_at>?", "UPDATE local_mfa_enrollment SET bound_session_hash=$1 WHERE account_id=$2 AND enrollment_id=$3 AND expires_at>$4"), input.NewSession.TokenHash, accountID, enrollmentID, r.BindTime(input.Now))
		if updateErr != nil {
			return safeError(updateErr)
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return fault.Unauthenticated
		}
	} else {
		if !errors.Is(receiptErr, sql.ErrNoRows) {
			return safeError(receiptErr)
		}
		var recoveryKeyID string
		var recoveryKeyVersion int64
		var digest []byte
		if err = tx.QueryRowContext(ctx, q.sql("SELECT key_id,key_version,digest FROM local_mfa_recovery_code WHERE account_id=? AND generation=?", "SELECT key_id,key_version,digest FROM local_mfa_recovery_code WHERE account_id=$1 AND generation=$2 FOR UPDATE"), accountID, generation).Scan(&recoveryKeyID, &recoveryKeyVersion, &digest); err != nil || recoveryKeyID != input.RecoveryKey.KeyID || recoveryKeyVersion != int64(input.RecoveryKey.Version) || !bytes.Equal(digest, input.RecoveryDigest) {
			return fault.Unauthenticated
		}
		if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_recovery_code WHERE account_id=?", "DELETE FROM local_mfa_recovery_code WHERE account_id=$1"), accountID); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"), accountID); err != nil {
			return safeError(err)
		}
		if err = r.insertMFAEnrollment(ctx, q, input.Enrollment); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_recovery_receipt(request_id,account_id,input_digest,enrollment_id,expires_at,created_at) VALUES(?,?,?,?,?,?)", "INSERT INTO local_mfa_recovery_receipt(request_id,account_id,input_digest,enrollment_id,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)"), input.RequestID, accountID, input.InputDigest, input.Enrollment.EnrollmentID, r.BindTime(input.Enrollment.ExpiresAt), r.BindTime(input.Now)); err != nil {
			return safeError(err)
		}
	}
	if usernameVersion <= 0 || usernameVersion > math.MaxUint32 {
		return fault.Unavailable
	}
	if err = insertSessionForLocal(ctx, r, q, input.NewSession, orgID, subjectID, epoch, input.UsernameDigest, usernameKeyID, uint32(usernameVersion)); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func (r *Repository) RotateLocalMFASession(ctx context.Context, input identity.LocalMFARotateInput) error {
	if len(input.SessionHash) != 32 || input.Generation <= 0 || input.AcceptedStep <= 0 || !value.ValidID(input.RequestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID, orgID, subjectID, keyID string
	var digest []byte
	var keyVersion, epoch, generation, lastStep int64
	query := q.sql("SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,su.auth_epoch,m.generation,f.last_accepted_step FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject su ON su.org_id=a.org_id AND su.id=a.subject_id JOIN local_mfa_account m ON m.account_id=a.id JOIN local_mfa_factor f ON f.account_id=a.id WHERE s.token_hash=? AND s.revoked=0 AND s.access_kind='business' AND m.status='active'", "SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,su.auth_epoch,m.generation,f.last_accepted_step FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject su ON su.org_id=a.org_id AND su.id=a.subject_id JOIN local_mfa_account m ON m.account_id=a.id JOIN local_mfa_factor f ON f.account_id=a.id WHERE s.token_hash=$1 AND s.revoked=false AND s.access_kind='business' AND m.status='active' FOR UPDATE OF s,m,f,su")
	if err = tx.QueryRowContext(ctx, query, input.SessionHash).Scan(&accountID, &orgID, &subjectID, &digest, &keyID, &keyVersion, &epoch, &generation, &lastStep); err != nil || generation != input.Generation || input.AcceptedStep <= lastStep {
		return fault.Unauthenticated
	}
	result, err := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_factor SET last_accepted_step=? WHERE account_id=? AND generation=? AND last_accepted_step<?", "UPDATE local_mfa_factor SET last_accepted_step=$1 WHERE account_id=$2 AND generation=$3 AND last_accepted_step<$4"), input.AcceptedStep, accountID, generation, input.AcceptedStep)
	if err != nil {
		return safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fault.Unauthenticated
	}
	if input.Recovery != nil {
		if input.Recovery.KeyID == "" || input.Recovery.Version == 0 || len(input.Recovery.Digest) != 32 {
			return fault.Invalid
		}
		if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_recovery_code WHERE account_id=?", "DELETE FROM local_mfa_recovery_code WHERE account_id=$1"), accountID); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_recovery_code(account_id,generation,key_id,key_version,digest,created_at) VALUES(?,?,?,?,?,?)", "INSERT INTO local_mfa_recovery_code(account_id,generation,key_id,key_version,digest,created_at) VALUES($1,$2,$3,$4,$5,$6)"), accountID, generation, input.Recovery.KeyID, input.Recovery.Version, input.Recovery.Digest, r.BindTime(input.Now)); err != nil {
			return safeError(err)
		}
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if keyVersion <= 0 || keyVersion > math.MaxUint32 {
		return fault.Unavailable
	}
	if err = insertSessionForLocal(ctx, r, q, input.NewSession, orgID, subjectID, epoch, digest, keyID, uint32(keyVersion)); err != nil {
		return err
	}
	return safeError(tx.Commit())
}

func (r *Repository) CancelLocalMFAEnrollment(ctx context.Context, sessionHash []byte, requestID string, now time.Time) error {
	if len(sessionHash) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	result, err := tx.ExecContext(ctx, q.sql("DELETE FROM local_mfa_enrollment WHERE bound_session_hash=?", "DELETE FROM local_mfa_enrollment WHERE bound_session_hash=$1"), sessionHash)
	if err != nil {
		return safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fault.NotFound
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE token_hash=?", "UPDATE session SET revoked=true WHERE token_hash=$1"), sessionHash); err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}
