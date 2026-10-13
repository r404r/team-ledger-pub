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
	var active, subjectActive bool
	var pepperVersion, revision int64
	err := r.DB.QueryRowContext(ctx, reader{r.DB, r.Backend}.sql(
		"SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.active,s.active,c.pepper_key_id,c.pepper_version,c.password_phc,c.revision,COALESCE(t.failures,0),COALESCE(t.retry_after,0) FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id LEFT JOIN local_login_throttle t ON t.username_digest=a.username_digest WHERE a.username_digest=?",
		"SELECT a.id,a.org_id,a.subject_id,a.username_digest,a.active,s.active,c.pepper_key_id,c.pepper_version,c.password_phc,c.revision,COALESCE(t.failures,0),COALESCE(t.retry_after,TIMESTAMPTZ 'epoch') FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id LEFT JOIN local_login_throttle t ON t.username_digest=a.username_digest WHERE a.username_digest=$1"), digest).Scan(&result.AccountID, &result.OrgID, &result.SubjectID, &result.UsernameDigest, &active, &subjectActive, &result.PepperKeyID, &pepperVersion, &result.PHC, &revision, &result.Failures, &retry)
	if errors.Is(err, sql.ErrNoRows) {
		return result, fault.Unauthenticated
	}
	if err != nil || pepperVersion <= 0 || pepperVersion > math.MaxUint32 || revision <= 0 {
		return identity.LocalCredential{}, safeError(err)
	}
	result.PepperVersion = uint32(pepperVersion)
	result.CredentialRevision = revision
	result.Active = active && subjectActive
	result.RetryAfter = retry.Time
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
	if len(issue.UsernameDigest) != 32 || len(issue.TokenHash) != 32 || len(issue.CSRFHash) != 32 || issue.CredentialRevision <= 0 || !value.ValidID(issue.RequestID) || !issue.ExpiresAt.Equal(issue.Now.Add(8*time.Hour)) || !issue.IdleExpiresAt.Equal(issue.Now.Add(30*time.Minute)) {
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
	query := q.sql("SELECT a.org_id,a.subject_id,a.active,s.active,s.auth_epoch,c.revision FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id WHERE a.username_digest=?", "SELECT a.org_id,a.subject_id,a.active,s.active,s.auth_epoch,c.revision FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id JOIN local_credential c ON c.account_id=a.id WHERE a.username_digest=$1 FOR UPDATE")
	var orgID, subjectID string
	var accountActive, subjectActive bool
	var epoch, revision int64
	if err = tx.QueryRowContext(ctx, query, issue.UsernameDigest).Scan(&orgID, &subjectID, &accountActive, &subjectActive, &epoch, &revision); err != nil || !accountActive || !subjectActive || revision != issue.CredentialRevision {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("DELETE FROM local_login_throttle WHERE username_digest=?", "DELETE FROM local_login_throttle WHERE username_digest=$1"), issue.UsernameDigest); err != nil {
		return safeError(err)
	}
	zero := r.BindTime(time.Unix(0, 0).UTC())
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES(?,?,?,?,?,?,?,0,?,1)", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,1)"), issue.TokenHash, orgID, subjectID, epoch, r.BindTime(issue.ExpiresAt), r.BindTime(issue.IdleExpiresAt), zero, issue.CSRFHash); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,acr,amr_json) VALUES(?,?,?,?,1,?,'','[\"pwd\"]')", "INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,acr,amr_json) VALUES($1,$2,$3,$4,1,$5,'','[\"pwd\"]')"), issue.TokenHash, orgID, subjectID, issue.UsernameDigest, r.BindTime(issue.Now)); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: orgID, SubjectID: subjectID, Operation: "AUTH-LOGIN", RequestID: issue.RequestID, Outcome: "allowed", At: issue.Now}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
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
	query := q.sql("SELECT s.org_id,s.subject_id,a.id,u.auth_epoch,c.revision FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN local_credential c ON c.account_id=a.id WHERE s.token_hash=? AND s.revoked=0 AND a.active=1 AND u.active=1", "SELECT s.org_id,s.subject_id,a.id,u.auth_epoch,c.revision FROM session s JOIN session_auth sa ON sa.token_hash=s.token_hash JOIN local_account a ON a.username_digest=sa.identity_digest AND a.org_id=s.org_id AND a.subject_id=s.subject_id JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id JOIN local_credential c ON c.account_id=a.id WHERE s.token_hash=$1 AND s.revoked=false AND a.active=true AND u.active=true FOR UPDATE")
	if err = tx.QueryRowContext(ctx, query, sessionHash).Scan(&orgID, &subjectID, &accountID, &epoch, &revision); err != nil || revision != credentialRevision || epoch == math.MaxInt64 {
		return fault.Unauthenticated
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_credential SET pepper_key_id=?,pepper_version=?,password_phc=?,revision=revision+1,updated_at=? WHERE account_id=? AND revision=?", "UPDATE local_credential SET pepper_key_id=$1,pepper_version=$2,password_phc=$3,revision=revision+1,updated_at=$4 WHERE account_id=$5 AND revision=$6"), pepper.KeyID, pepper.Version, phc, r.BindTime(now), accountID, credentialRevision); err != nil {
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
