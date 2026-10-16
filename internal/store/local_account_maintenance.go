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

type LocalAccountProvision struct {
	RequestID, OrgID, SubjectID, AccountID string
	UsernameDigest                         []byte
	UsernameKey                            sensitive.KeyReference
	UsernameEnvelope                       sensitive.Envelope
	PepperKey                              sensitive.KeyReference
	PasswordPHC                            string
	Now                                    time.Time
}

func (r *Repository) CreateLocalAccount(ctx context.Context, input LocalAccountProvision) error {
	bootstrap := LocalBootstrap{RequestID: input.RequestID, OrgID: input.OrgID, SubjectID: input.SubjectID, AccountID: input.AccountID, Timezone: "UTC", InputDigest: make([]byte, 32), UsernameDigest: input.UsernameDigest, UsernameKey: input.UsernameKey, UsernameEnvelope: input.UsernameEnvelope, PepperKey: input.PepperKey, PasswordPHC: input.PasswordPHC, Now: input.Now}
	if !validLocalBootstrap(bootstrap) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var active bool
	if err = tx.QueryRowContext(ctx, q.sql("SELECT active FROM subject WHERE org_id=? AND id=?", "SELECT active FROM subject WHERE org_id=$1 AND id=$2 FOR UPDATE"), input.OrgID, input.SubjectID).Scan(&active); err != nil || !active {
		return fault.Forbidden
	}
	e, at := input.UsernameEnvelope, r.BindTime(input.Now)
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,password_change_required,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,1,1,?,?,'identity','identity.local_username.v1',1,1,?,?,?,?,?,?,?)", "INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,password_change_required,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,true,true,$7,$8,'identity','identity.local_username.v1',1,1,$9,$10,$11,$12,$13,$14,$15)"), input.AccountID, input.OrgID, input.SubjectID, input.UsernameDigest, input.UsernameKey.KeyID, input.UsernameKey.Version, input.AccountID, input.AccountID, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, at); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES(?,?,?,?,1,?)", "INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES($1,$2,$3,$4,1,$5)"), input.AccountID, input.PepperKey.KeyID, input.PepperKey.Version, input.PasswordPHC, at); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_account(account_id,status,generation,updated_at) VALUES(?,'enrollment_required',1,?)", "INSERT INTO local_mfa_account(account_id,status,generation,updated_at) VALUES($1,'enrollment_required',1,$2)"), input.AccountID, at); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES(?,?,?,?,?,1)", "INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES($1,$2,$3,$4,$5,true)"), input.UsernameDigest, input.UsernameKey.KeyID, input.UsernameKey.Version, input.OrgID, input.SubjectID); err != nil {
		return safeError(err)
	}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return err
	}
	if err = insertMaintenanceAudit(ctx, q, identity.Identity{Digest: input.UsernameDigest, KeyVersion: 1, OrgID: input.OrgID, SubjectID: input.SubjectID}, &actor, "AUTH-BIND", input.RequestID, input.Now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}

func (r *Repository) ResetLocalAccount(ctx context.Context, orgID, subjectID string, digest []byte, phc string, pepper sensitive.KeyReference, requestID string, now time.Time) error {
	if !value.ValidID(orgID) || !value.ValidID(subjectID) || len(digest) != 32 || len(phc) < 80 || len(phc) > 256 || pepper.KeyID == "" || pepper.Version == 0 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID string
	var epoch int64
	if err = tx.QueryRowContext(ctx, q.sql("SELECT a.id,s.auth_epoch FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id WHERE a.org_id=? AND a.subject_id=? AND a.username_digest=? AND a.active=1", "SELECT a.id,s.auth_epoch FROM local_account a JOIN subject s ON s.org_id=a.org_id AND s.id=a.subject_id WHERE a.org_id=$1 AND a.subject_id=$2 AND a.username_digest=$3 AND a.active=true FOR UPDATE"), orgID, subjectID, digest).Scan(&accountID, &epoch); err != nil || epoch == math.MaxInt64 {
		return fault.NotFound
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_credential SET pepper_key_id=?,pepper_version=?,password_phc=?,revision=revision+1,updated_at=? WHERE account_id=?", "UPDATE local_credential SET pepper_key_id=$1,pepper_version=$2,password_phc=$3,revision=revision+1,updated_at=$4 WHERE account_id=$5"), pepper.KeyID, pepper.Version, phc, r.BindTime(now), accountID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_account SET password_change_required=1 WHERE id=?", "UPDATE local_account SET password_change_required=true WHERE id=$1"), accountID); err != nil {
		return safeError(err)
	}
	return r.finishLocalAccountRevocation(ctx, tx, q, orgID, subjectID, digest, requestID, now, "AUTH-ACCOUNT-RESET")
}

func (r *Repository) ResetLocalMFA(ctx context.Context, orgID, subjectID string, digest []byte, requestID string, now time.Time) error {
	if !value.ValidID(orgID) || !value.ValidID(subjectID) || len(digest) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var accountID string
	var generation int64
	if err = tx.QueryRowContext(ctx, q.sql("SELECT a.id,m.generation FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=? AND a.subject_id=? AND a.username_digest=? AND a.active=1", "SELECT a.id,m.generation FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=$1 AND a.subject_id=$2 AND a.username_digest=$3 AND a.active=true FOR UPDATE OF a,m"), orgID, subjectID, digest).Scan(&accountID, &generation); err != nil {
		return fault.NotFound
	}
	if generation == math.MaxInt64 {
		return fault.Unavailable
	}
	var receiptAccount string
	var receiptDigest []byte
	receiptErr := tx.QueryRowContext(ctx, q.sql("SELECT account_id,username_digest FROM local_mfa_reset_receipt WHERE request_id=?", "SELECT account_id,username_digest FROM local_mfa_reset_receipt WHERE request_id=$1 FOR UPDATE"), requestID).Scan(&receiptAccount, &receiptDigest)
	if receiptErr == nil {
		if receiptAccount != accountID || !bytes.Equal(receiptDigest, digest) {
			return fault.Mismatch
		}
		return nil
	}
	if !errors.Is(receiptErr, sql.ErrNoRows) {
		return safeError(receiptErr)
	}
	for _, statement := range []string{
		q.sql("DELETE FROM local_mfa_recovery_receipt WHERE account_id=?", "DELETE FROM local_mfa_recovery_receipt WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_recovery_code WHERE account_id=?", "DELETE FROM local_mfa_recovery_code WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_factor WHERE account_id=?", "DELETE FROM local_mfa_factor WHERE account_id=$1"),
	} {
		if _, err = tx.ExecContext(ctx, statement, accountID); err != nil {
			return safeError(err)
		}
	}
	result, err := tx.ExecContext(ctx, q.sql("UPDATE local_mfa_account SET status='enrollment_required',generation=?,updated_at=? WHERE account_id=? AND generation=?", "UPDATE local_mfa_account SET status='enrollment_required',generation=$1,updated_at=$2 WHERE account_id=$3 AND generation=$4"), generation+1, r.BindTime(now), accountID, generation)
	if err != nil {
		return safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fault.Conflict
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_reset_receipt(request_id,account_id,username_digest,created_at) VALUES(?,?,?,?)", "INSERT INTO local_mfa_reset_receipt(request_id,account_id,username_digest,created_at) VALUES($1,$2,$3,$4)"), requestID, accountID, digest, r.BindTime(now)); err != nil {
		return safeError(err)
	}
	return r.finishLocalAccountRevocation(ctx, tx, q, orgID, subjectID, digest, requestID, now, "AUTH-ACCOUNT-RESET")
}

func (r *Repository) DisableLocalAccount(ctx context.Context, orgID, subjectID string, digest []byte, requestID string, now time.Time) error {
	if !value.ValidID(orgID) || !value.ValidID(subjectID) || len(digest) != 32 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	result, err := tx.ExecContext(ctx, q.sql("UPDATE local_account SET active=0 WHERE org_id=? AND subject_id=? AND username_digest=? AND active=1", "UPDATE local_account SET active=false WHERE org_id=$1 AND subject_id=$2 AND username_digest=$3 AND active=true"), orgID, subjectID, digest)
	if err != nil {
		return safeError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fault.NotFound
	}
	var accountID string
	var generation int64
	if err = tx.QueryRowContext(ctx, q.sql("SELECT a.id,m.generation FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=? AND a.subject_id=? AND a.username_digest=?", "SELECT a.id,m.generation FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=$1 AND a.subject_id=$2 AND a.username_digest=$3 FOR UPDATE OF m"), orgID, subjectID, digest).Scan(&accountID, &generation); err != nil || generation == math.MaxInt64 {
		return fault.Unavailable
	}
	for _, statement := range []string{
		q.sql("DELETE FROM local_mfa_reset_receipt WHERE account_id=?", "DELETE FROM local_mfa_reset_receipt WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_recovery_receipt WHERE account_id=?", "DELETE FROM local_mfa_recovery_receipt WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_recovery_code WHERE account_id=?", "DELETE FROM local_mfa_recovery_code WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_enrollment WHERE account_id=?", "DELETE FROM local_mfa_enrollment WHERE account_id=$1"),
		q.sql("DELETE FROM local_mfa_factor WHERE account_id=?", "DELETE FROM local_mfa_factor WHERE account_id=$1"),
	} {
		if _, err = tx.ExecContext(ctx, statement, accountID); err != nil {
			return safeError(err)
		}
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE local_mfa_account SET status='enrollment_required',generation=?,updated_at=? WHERE account_id=?", "UPDATE local_mfa_account SET status='enrollment_required',generation=$1,updated_at=$2 WHERE account_id=$3"), generation+1, r.BindTime(now), accountID); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE subject_identity SET active=0 WHERE digest=? AND org_id=? AND subject_id=?", "UPDATE subject_identity SET active=false WHERE digest=$1 AND org_id=$2 AND subject_id=$3"), digest, orgID, subjectID); err != nil {
		return safeError(err)
	}
	return r.finishLocalAccountRevocation(ctx, tx, q, orgID, subjectID, digest, requestID, now, "AUTH-UNBIND")
}

func (r *Repository) finishLocalAccountRevocation(ctx context.Context, tx *sql.Tx, q reader, orgID, subjectID string, digest []byte, requestID string, now time.Time, operation string) error {
	if _, err := tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE session SET revoked=true WHERE org_id=$1 AND subject_id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if _, err := tx.ExecContext(ctx, q.sql("UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if _, err := tx.ExecContext(ctx, q.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1"), orgID); err != nil {
		return safeError(err)
	}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return err
	}
	if err = insertMaintenanceAudit(ctx, q, identity.Identity{Digest: digest, KeyVersion: 1, OrgID: orgID, SubjectID: subjectID}, &actor, operation, requestID, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}

func (r *Repository) SwitchIdentityMode(ctx context.Context, target, requestID string, now time.Time) error {
	if target != "local" && target != "oidc" || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var current string
	var revision int64
	if err = tx.QueryRowContext(ctx, q.sql("SELECT mode,revision FROM identity_mode_state WHERE id=1", "SELECT mode,revision FROM identity_mode_state WHERE id=1 FOR UPDATE")).Scan(&current, &revision); err != nil || current == target || revision == math.MaxInt64 {
		return fault.Conflict
	}
	rows, err := tx.QueryContext(ctx, "SELECT org_id,id FROM subject ORDER BY org_id,id")
	if err != nil {
		return safeError(err)
	}
	var subjects [][2]string
	for rows.Next() {
		var owner [2]string
		if err = rows.Scan(&owner[0], &owner[1]); err != nil {
			rows.Close()
			return safeError(err)
		}
		subjects = append(subjects, owner)
	}
	if err = rows.Close(); err != nil {
		return safeError(err)
	}
	for _, owner := range subjects {
		if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: owner[0], SubjectID: owner[1], Operation: "AUTH-MODE-SWITCH", RequestID: requestID, Outcome: "allowed", At: now}); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE session SET revoked=1", "UPDATE session SET revoked=true")); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE subject SET auth_epoch=auth_epoch+1"); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch+1"); err != nil {
		return safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("UPDATE identity_mode_state SET mode=?,revision=revision+1,updated_at=? WHERE id=1", "UPDATE identity_mode_state SET mode=$1,revision=revision+1,updated_at=$2 WHERE id=1"), target, r.BindTime(now)); err != nil {
		return safeError(err)
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
func (r *Repository) CreateLocalSubject(ctx context.Context, orgID, subjectID, requestID string, now time.Time) error {
	if !value.ValidID(orgID) || !value.ValidID(subjectID) || !value.ValidID(requestID) {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)"), orgID, subjectID); err != nil {
		return safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: orgID, SubjectID: subjectID, Operation: "OP-SEC-06", Purpose: "security_administration", RequestID: requestID, Outcome: "allowed", At: now}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fault.Unavailable
	}
	return nil
}
