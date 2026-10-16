package store

import (
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

func (r *Repository) IdentityMode(ctx context.Context) (string, error) {
	var mode string
	err := r.DB.QueryRowContext(ctx, "SELECT mode FROM identity_mode_state WHERE id=1").Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fault.Unavailable
	}
	if err != nil || mode != "local" && mode != "oidc" {
		return "", safeError(err)
	}
	return mode, nil
}

func (r *Repository) EnsureIdentityMode(ctx context.Context, mode string, now time.Time) error {
	if mode != "local" && mode != "oidc" {
		return fault.Invalid
	}
	current, err := r.IdentityMode(ctx)
	if err == nil {
		if current != mode {
			return fault.Conflict
		}
		return nil
	}
	if !errors.Is(err, fault.Unavailable) || mode == "local" {
		return err
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	var facts int64
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM organization)+(SELECT count(*) FROM subject)+(SELECT count(*) FROM local_account)").Scan(&facts); err != nil || facts != 0 {
		return fault.Conflict
	}
	q := reader{tx, r.Backend}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,?)", "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,$1)"), r.BindTime(now)); err != nil {
		return safeError(err)
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
func (r *Repository) LookupLocalCredential(ctx context.Context, digest []byte) (identity.LocalCredential, error) {
	var result identity.LocalCredential
	var retry dbTime
	var accountActive, subjectActive bool
	var usernameVersion, pepperVersion, revision int64
	err := r.DB.QueryRowContext(ctx, reader{r.DB, r.Backend}.sql(
		"SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,a.active,a.password_change_required,s.active,c.pepper_key_id,c.pepper_version,c.password_phc,c.revision,COALESCE(t.failures,0),COALESCE(t.retry_after,0) FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id LEFT JOIN local_login_throttle t ON t.username_digest=a.username_digest WHERE a.username_digest=?",
		"SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.username_key_id,a.username_key_version,a.active,a.password_change_required,s.active,c.pepper_key_id,c.pepper_version,c.password_phc,c.revision,COALESCE(t.failures,0),COALESCE(t.retry_after,TIMESTAMPTZ 'epoch') FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id LEFT JOIN local_login_throttle t ON t.username_digest=a.username_digest WHERE a.username_digest=$1"), digest).Scan(&result.AccountID, &result.OrgID, &result.SubjectID, &result.UsernameDigest, &result.UsernameKeyID, &usernameVersion, &accountActive, &result.PasswordChangeRequired, &subjectActive, &result.PepperKeyID, &pepperVersion, &result.PHC, &revision, &result.Failures, &retry)
	if errors.Is(err, sql.ErrNoRows) {
		return result, fault.Unauthenticated
	}
	if err != nil || usernameVersion <= 0 || usernameVersion > math.MaxUint32 || pepperVersion <= 0 || pepperVersion > math.MaxUint32 || revision <= 0 {
		return identity.LocalCredential{}, safeError(err)
	}
	result.UsernameKeyVersion = uint32(usernameVersion)
	result.PepperVersion = uint32(pepperVersion)
	result.CredentialRevision = revision
	result.Active = accountActive && subjectActive
	result.RetryAfter = retry.Time
	var mfaGeneration int64
	if err = r.DB.QueryRowContext(ctx, reader{r.DB, r.Backend}.sql(
		"SELECT status,generation FROM local_mfa_account WHERE account_id=?",
		"SELECT status,generation FROM local_mfa_account WHERE account_id=$1"), result.AccountID).Scan(&result.MFAStatus, &mfaGeneration); err != nil {
		return identity.LocalCredential{}, safeError(err)
	}
	if mfaGeneration <= 0 {
		return identity.LocalCredential{}, fault.Unavailable
	}
	result.MFAGeneration = mfaGeneration
	if result.MFAStatus == "active" {
		var factor identity.LocalMFAFactor
		var schemaVersion, formatVersion, kekVersion int64
		var purpose, schemaType, algorithm, dekID, recordID, versionID string
		err = r.DB.QueryRowContext(ctx, reader{r.DB, r.Backend}.sql(
			"SELECT org_id,factor_id,generation,last_accepted_step,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes FROM local_mfa_factor WHERE account_id=?",
			"SELECT org_id,factor_id,generation,last_accepted_step,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes FROM local_mfa_factor WHERE account_id=$1"),
			result.AccountID).Scan(&factor.OrgID, &factor.FactorID, &factor.Generation, &factor.LastAcceptedStep, &recordID, &versionID, &purpose, &schemaType, &schemaVersion, &formatVersion, &algorithm, &dekID, &factor.Envelope.Key.KEKID, &kekVersion, &factor.Envelope.Key.Data, &factor.Envelope.SealedBytes)
		if err != nil {
			return identity.LocalCredential{}, safeError(err)
		}
		if factor.Generation != result.MFAGeneration || schemaVersion != 1 || formatVersion != 1 || kekVersion <= 0 || kekVersion > math.MaxUint32 {
			return identity.LocalCredential{}, fault.Unavailable
		}
		factor.AccountID = result.AccountID
		factor.Envelope.Context = sensitive.Context{OrgID: factor.OrgID, RecordID: recordID, VersionID: versionID, ObjectKind: "local_mfa_factor", Purpose: purpose, SchemaType: schemaType, SchemaVersion: uint32(schemaVersion)}
		factor.Envelope.FormatVersion, factor.Envelope.Algorithm, factor.Envelope.DEKID, factor.Envelope.Key.Version = uint16(formatVersion), algorithm, dekID, uint32(kekVersion)
		result.Factor = &factor
		var recoveryVersion int64
		err = r.DB.QueryRowContext(ctx, reader{r.DB, r.Backend}.sql(
			"SELECT key_id,key_version,digest FROM local_mfa_recovery_code WHERE account_id=? AND generation=?",
			"SELECT key_id,key_version,digest FROM local_mfa_recovery_code WHERE account_id=$1 AND generation=$2"), result.AccountID, result.MFAGeneration).Scan(&result.RecoveryKeyID, &recoveryVersion, &result.RecoveryDigest)
		if err == nil {
			if recoveryVersion <= 0 || recoveryVersion > math.MaxUint32 || len(result.RecoveryDigest) != 32 {
				return identity.LocalCredential{}, fault.Unavailable
			}
			result.RecoveryKeyVersion = uint32(recoveryVersion)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return identity.LocalCredential{}, safeError(err)
		}
	}
	return result, nil
}

func (r *Repository) RecordLocalFailure(ctx context.Context, digest []byte, requestID string, now time.Time) error {
	if len(digest) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var failures int64
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_login_throttle(username_digest,failures,retry_after) VALUES(?,0,?) ON CONFLICT(username_digest) DO NOTHING", "INSERT INTO local_login_throttle(username_digest,failures,retry_after) VALUES($1,0,$2) ON CONFLICT(username_digest) DO NOTHING"), digest, r.BindTime(now)); err != nil {
		return safeError(err)
	}
	if err = tx.QueryRowContext(ctx, q.sql("SELECT failures FROM local_login_throttle WHERE username_digest=?", "SELECT failures FROM local_login_throttle WHERE username_digest=$1 FOR UPDATE"), digest).Scan(&failures); err != nil {
		return safeError(err)
	}
	if failures < 60 {
		failures++
	}
	delay := int64(1)
	if failures > 1 {
		shift := failures - 1
		if shift > 10 {
			shift = 10
		}
		delay <<= shift
	}
	if delay > 900 {
		delay = 900
	}
	retry := r.BindTime(now.Add(time.Duration(delay) * time.Second))
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_login_throttle SET failures=?,retry_after=? WHERE username_digest=?", "UPDATE local_login_throttle SET failures=$1,retry_after=$2 WHERE username_digest=$3"), failures, retry, digest); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), Operation: "AUTH-LOGIN", RequestID: requestID, Outcome: "denied", At: now}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}

func (r *Repository) IssueLocalSession(ctx context.Context, issue identity.LocalSessionIssue) error {
	validBusiness := issue.AccessKind == "business" && issue.ExpiresAt.Equal(issue.Now.Add(8*time.Hour)) && issue.IdleExpiresAt.Equal(issue.Now.Add(30*time.Minute)) && issue.MFAUntil.Equal(issue.Now.Add(10*time.Minute)) && issue.FactorGeneration > 0 && issue.AcceptedStep > 0
	validRestricted := (issue.AccessKind == "mfa_enrollment" || issue.AccessKind == "password_change") && issue.ExpiresAt.Equal(issue.Now.Add(10*time.Minute)) && issue.IdleExpiresAt.Equal(issue.ExpiresAt) && issue.MFAUntil.Equal(time.Unix(0, 0).UTC()) && issue.AcceptedStep == 0
	if len(issue.UsernameDigest) != 32 || issue.UsernameKeyID == "" || issue.UsernameKeyVersion == 0 || len(issue.TokenHash) != 32 || len(issue.CSRFHash) != 32 || issue.CSRFKeyID == "" || issue.CSRFVersion == 0 || issue.CredentialRevision <= 0 || !value.ValidID(issue.RequestID) || !validBusiness && !validRestricted {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var mode string
	if err = tx.QueryRowContext(ctx, q.sql("SELECT mode FROM identity_mode_state WHERE id=1", "SELECT mode FROM identity_mode_state WHERE id=1 FOR UPDATE")).Scan(&mode); err != nil || mode != "local" {
		return fault.Unauthenticated
	}
	query := q.sql("SELECT a.id,a.org_id,a.subject_id,a.active,a.password_change_required,s.active,s.auth_epoch,c.revision,m.status,m.generation FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id JOIN local_mfa_account m ON m.account_id=a.id WHERE a.username_digest=?", "SELECT a.id,a.org_id,a.subject_id,a.active,a.password_change_required,s.active,s.auth_epoch,c.revision,m.status,m.generation FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id JOIN local_mfa_account m ON m.account_id=a.id WHERE a.username_digest=$1 FOR UPDATE")
	var accountID, orgID, subjectID, status string
	var accountActive, passwordChangeRequired, subjectActive bool
	var epoch, revision, generation int64
	if err = tx.QueryRowContext(ctx, query, issue.UsernameDigest).Scan(&accountID, &orgID, &subjectID, &accountActive, &passwordChangeRequired, &subjectActive, &epoch, &revision, &status, &generation); err != nil || !accountActive || !subjectActive || revision != issue.CredentialRevision {
		return fault.Unauthenticated
	}
	if issue.AccessKind == "password_change" {
		if !passwordChangeRequired || generation != issue.FactorGeneration {
			return fault.Unauthenticated
		}
	} else if passwordChangeRequired {
		return fault.Unauthenticated
	} else if issue.AccessKind == "business" {
		if status != "active" || generation != issue.FactorGeneration {
			return fault.Unauthenticated
		}
		result, updateErr := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_factor SET last_accepted_step=? WHERE account_id=? AND generation=? AND last_accepted_step<?", "UPDATE local_mfa_factor SET last_accepted_step=$1 WHERE account_id=$2 AND generation=$3 AND last_accepted_step<$4"), issue.AcceptedStep, accountID, generation, issue.AcceptedStep)
		if updateErr != nil {
			return safeError(updateErr)
		}
		if n, rowsErr := result.RowsAffected(); rowsErr != nil || n != 1 {
			return fault.Unauthenticated
		}
	} else if status != "enrollment_required" || generation != issue.FactorGeneration {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_login_throttle WHERE username_digest=?", "DELETE FROM local_login_throttle WHERE username_digest=$1"), issue.UsernameDigest); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version,access_kind) VALUES(?,?,?,?,?,?,?,0,?,?,?,?)", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_key_id,csrf_version,access_kind) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,$9,$10,$11)"), issue.TokenHash, orgID, subjectID, epoch, r.BindTime(issue.ExpiresAt), r.BindTime(issue.IdleExpiresAt), r.BindTime(issue.MFAUntil), issue.CSRFHash, issue.CSRFKeyID, issue.CSRFVersion, issue.AccessKind); err != nil {
		return safeError(err)
	}
	amr := `["pwd"]`
	if issue.AccessKind == "business" {
		amr = `["pwd","otp"]`
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,identity_key_id,key_version,created_at,acr,amr_json) VALUES(?,?,?,?,?,?,?,'',?)", "INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,identity_key_id,key_version,created_at,acr,amr_json) VALUES($1,$2,$3,$4,$5,$6,$7,'',$8)"), issue.TokenHash, orgID, subjectID, issue.UsernameDigest, issue.UsernameKeyID, issue.UsernameKeyVersion, r.BindTime(issue.Now), amr); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: orgID, SubjectID: subjectID, Operation: "AUTH-LOGIN", RequestID: issue.RequestID, Outcome: "allowed", At: issue.Now}); err != nil {
		return err
	}
	return safeError(tx.Commit())
}
func (r *Repository) UpgradeLocalCredential(ctx context.Context, usernameDigest []byte, credentialRevision int64, phc string, pepper sensitive.KeyReference, now time.Time) error {
	if len(usernameDigest) != 32 || credentialRevision <= 0 || len(phc) < 80 || len(phc) > 256 || pepper.KeyID == "" || pepper.Version == 0 {
		return fault.Invalid
	}
	result, err := r.DB.ExecContext(ctx, reader{r.DB, r.Backend}.sql(
		"UPDATE local_credential SET pepper_key_id=?,pepper_version=?,password_phc=?,updated_at=? WHERE account_id=(SELECT id FROM local_account WHERE username_digest=? AND active=1) AND revision=?",
		"UPDATE local_credential SET pepper_key_id=$1,pepper_version=$2,password_phc=$3,updated_at=$4 WHERE account_id=(SELECT id FROM local_account WHERE username_digest=$5 AND active=true) AND revision=$6"),
		pepper.KeyID, pepper.Version, phc, r.BindTime(now), usernameDigest, credentialRevision)
	if err != nil {
		return safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return safeError(err)
	}
	if n != 1 {
		return fault.Unauthenticated
	}
	return nil
}

func (r *Repository) ChangeLocalPassword(ctx context.Context, sessionHash []byte, credentialRevision int64, phc string, pepper sensitive.KeyReference, requestID string, now time.Time) error {
	if len(sessionHash) != 32 || credentialRevision <= 0 || len(phc) < 80 || len(phc) > 256 || pepper.KeyID == "" || pepper.Version == 0 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var orgID, subjectID, accountID string
	var epoch, revision int64
	query := q.sql("SELECT s.org_id,s.subject_id,a.id,u.auth_epoch,c.revision FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN local_credential c ON c.account_id=a.id WHERE s.token_hash=? AND s.revoked=0 AND s.subject_epoch=u.auth_epoch AND s.expires_at>? AND s.idle_expires_at>? AND (s.access_kind='business' OR (s.access_kind='password_change' AND a.password_change_required=1)) AND a.active=1 AND u.active=1", "SELECT s.org_id,s.subject_id,a.id,u.auth_epoch,c.revision FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN local_credential c ON c.account_id=a.id WHERE s.token_hash=$1 AND s.revoked=false AND s.subject_epoch=u.auth_epoch AND s.expires_at>$2 AND s.idle_expires_at>$3 AND (s.access_kind='business' OR (s.access_kind='password_change' AND a.password_change_required=true)) AND a.active=true AND u.active=true FOR UPDATE")
	if err = tx.QueryRowContext(ctx, query, sessionHash, r.BindTime(now), r.BindTime(now)).Scan(&orgID, &subjectID, &accountID, &epoch, &revision); err != nil || revision != credentialRevision || epoch == math.MaxInt64 {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_credential SET pepper_key_id=?,pepper_version=?,password_phc=?,revision=revision+1,updated_at=? WHERE account_id=? AND revision=?", "UPDATE local_credential SET pepper_key_id=$1,pepper_version=$2,password_phc=$3,revision=revision+1,updated_at=$4 WHERE account_id=$5 AND revision=$6"), pepper.KeyID, pepper.Version, phc, r.BindTime(now), accountID, credentialRevision); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_account SET password_change_required=0 WHERE id=?", "UPDATE local_account SET password_change_required=false WHERE id=$1"), accountID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1"), orgID); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: orgID, SubjectID: subjectID, Operation: "AUTH-PASSWORD-CHANGE", RequestID: requestID, Outcome: "allowed", At: now}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
