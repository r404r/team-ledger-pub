package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func validLocalUserSnapshot(snapshot authz.Snapshot, expectedOrg, expectedSubject string, expectedEpoch int64) bool {
	return snapshot.OrgID == expectedOrg && snapshot.SubjectID == expectedSubject && snapshot.AuthEpoch == expectedEpoch
}

func authorizeLocalUserSnapshot(snapshot authz.Snapshot, expectedOrg, expectedSubject string, expectedEpoch int64, now time.Time) error {
	if !validLocalUserSnapshot(snapshot, expectedOrg, expectedSubject, expectedEpoch) {
		return fault.Conflict
	}
	if !snapshot.Valid(now) {
		return fault.Unauthenticated
	}
	if !snapshot.Allows("identity.manage", "audit", "", authz.ManagementPurpose, now) {
		return fault.Forbidden
	}
	return nil
}

func (r *Repository) ListLocalUsers(ctx context.Context, query identity.LocalUserStoreQuery) ([]identity.LocalUserRecord, error) {
	if len(query.SessionHash) != 32 || !value.ValidID(query.ExpectedOrgID) || !value.ValidID(query.ExpectedSubjectID) || query.ExpectedAuthEpoch <= 0 || query.Limit < 1 || query.Limit > 100 || !value.ValidID(query.RequestID) || query.Now.IsZero() || query.After != "" && !value.ValidID(query.After) {
		return nil, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	current, err := q.Security(ctx, query.SessionHash, "", "")
	if err != nil {
		return nil, err
	}
	if err = authorizeLocalUserSnapshot(current, query.ExpectedOrgID, query.ExpectedSubjectID, query.ExpectedAuthEpoch, query.Now); err != nil {
		return nil, err
	}
	statement := q.sql("SELECT a.id,a.subject_id,a.active,a.password_change_required,m.status,a.record_id,a.version_id,a.format_version,a.algorithm,a.dek_id,a.kek_id,a.kek_version,a.wrapped_dek,a.sealed_bytes,a.created_at FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=? AND a.id>? ORDER BY a.id LIMIT ?", "SELECT a.id,a.subject_id,a.active,a.password_change_required,m.status,a.record_id,a.version_id,a.format_version,a.algorithm,a.dek_id,a.kek_id,a.kek_version,a.wrapped_dek,a.sealed_bytes,a.created_at FROM local_account a JOIN local_mfa_account m ON m.account_id=a.id WHERE a.org_id=$1 AND a.id>$2 ORDER BY a.id COLLATE \"C\" LIMIT $3")
	rows, err := tx.QueryContext(ctx, statement, current.OrgID, query.After, query.Limit+1)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	items := make([]identity.LocalUserRecord, 0, query.Limit+1)
	for rows.Next() {
		var item identity.LocalUserRecord
		var created dbTime
		var format uint16
		var keyVersion, schemaVersion uint32
		var recordID, versionID string
		envelope := &item.Username
		if err = rows.Scan(&item.AccountID, &item.SubjectID, &item.Active, &item.PasswordChangeRequired, &item.MFAStatus, &recordID, &versionID, &format, &envelope.Algorithm, &envelope.DEKID, &envelope.Key.KEKID, &keyVersion, &envelope.Key.Data, &envelope.SealedBytes, &created); err != nil {
			return nil, safeError(err)
		}
		schemaVersion = 1
		envelope.Context = sensitive.Context{OrgID: current.OrgID, RecordID: recordID, VersionID: versionID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: schemaVersion}
		envelope.FormatVersion, envelope.Key.Version = format, keyVersion
		item.CreatedAt = created.Time
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, safeError(err)
	}
	if err = rows.Close(); err != nil {
		return nil, safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: current.OrgID, SubjectID: current.SubjectID, Operation: "OP-SEC-08", Purpose: authz.ManagementPurpose, RequestID: query.RequestID, Outcome: "allowed", At: query.Now}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, fault.Unavailable
	}
	return items, nil
}

func validLocalUserProvision(input identity.LocalUserProvision) bool {
	binding := input.UsernameEnvelope.Context
	return len(input.SessionHash) == 32 && value.ValidID(input.ExpectedOrgID) && value.ValidID(input.ExpectedSubjectID) && input.ExpectedAuthEpoch > 0 && value.ValidID(input.RequestID) && value.ValidID(input.Key) && value.ValidID(input.AccountID) && value.ValidID(input.SubjectID) && len(input.UsernameDigest) == 32 && len(input.CommandDigest) == 32 && input.UsernameKey.KeyID != "" && input.UsernameKey.Version > 0 && input.CommandKey.KeyID != "" && input.CommandKey.Version > 0 && input.PepperKey.KeyID != "" && input.PepperKey.Version > 0 && len(input.PasswordPHC) >= 80 && len(input.PasswordPHC) <= 256 && binding.OrgID == input.ExpectedOrgID && binding.RecordID == input.AccountID && binding.VersionID == input.AccountID && binding.EmployeeID == "" && binding.ObjectKind == "local_username" && binding.Purpose == "identity" && binding.SchemaType == "identity.local_username.v1" && binding.SchemaVersion == 1 && input.UsernameEnvelope.FormatVersion == 1 && input.UsernameEnvelope.Algorithm == "A256GCM-RANDOMNONCE" && input.UsernameEnvelope.DEKID != "" && input.UsernameEnvelope.Key.KEKID != "" && input.UsernameEnvelope.Key.Version > 0 && len(input.UsernameEnvelope.Key.Data) > 0 && len(input.UsernameEnvelope.SealedBytes) >= 39 && !input.Now.IsZero()
}

func (r *Repository) CreateLocalUser(ctx context.Context, input identity.LocalUserProvision) (identity.LocalUserResult, error) {
	if !validLocalUserProvision(input) {
		return identity.LocalUserResult{}, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return identity.LocalUserResult{}, fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	current, err := q.Security(ctx, input.SessionHash, "", "")
	if err != nil {
		return identity.LocalUserResult{}, err
	}
	if err = authorizeLocalUserSnapshot(current, input.ExpectedOrgID, input.ExpectedSubjectID, input.ExpectedAuthEpoch, input.Now); err != nil {
		return identity.LocalUserResult{}, err
	}
	var digest []byte
	var keyID, subjectID, accountID string
	var keyVersion uint32
	receiptErr := tx.QueryRowContext(ctx, q.sql("SELECT digest,digest_key_id,digest_key_version,result_subject_id,result_account_id FROM local_user_command_receipt WHERE org_id=? AND actor_subject_id=? AND key=?", "SELECT digest,digest_key_id,digest_key_version,result_subject_id,result_account_id FROM local_user_command_receipt WHERE org_id=$1 AND actor_subject_id=$2 AND key=$3 FOR UPDATE"), current.OrgID, current.SubjectID, input.Key).Scan(&digest, &keyID, &keyVersion, &subjectID, &accountID)
	if receiptErr == nil {
		if keyID != input.CommandKey.KeyID || keyVersion != input.CommandKey.Version || subtle.ConstantTimeCompare(digest, input.CommandDigest) != 1 {
			return identity.LocalUserResult{}, fault.Mismatch
		}
		return identity.LocalUserResult{AccountID: accountID, SubjectID: subjectID}, nil
	}
	if !errors.Is(receiptErr, sql.ErrNoRows) {
		return identity.LocalUserResult{}, safeError(receiptErr)
	}
	at := r.BindTime(input.Now)
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)"), current.OrgID, input.SubjectID); err != nil {
		return identity.LocalUserResult{}, safeError(err)
	}
	e := input.UsernameEnvelope
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,password_change_required,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,1,1,?,?,'identity','identity.local_username.v1',1,1,?,?,?,?,?,?,?)", "INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,password_change_required,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,true,true,$7,$8,'identity','identity.local_username.v1',1,1,$9,$10,$11,$12,$13,$14,$15)"), input.AccountID, current.OrgID, input.SubjectID, input.UsernameDigest, input.UsernameKey.KeyID, input.UsernameKey.Version, input.AccountID, input.AccountID, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, at); err != nil {
		return identity.LocalUserResult{}, conflictError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES(?,?,?,?,1,?)", "INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES($1,$2,$3,$4,1,$5)"), input.AccountID, input.PepperKey.KeyID, input.PepperKey.Version, input.PasswordPHC, at); err != nil {
		return identity.LocalUserResult{}, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_mfa_account(account_id,status,generation,updated_at) VALUES(?,'enrollment_required',1,?)", "INSERT INTO local_mfa_account(account_id,status,generation,updated_at) VALUES($1,'enrollment_required',1,$2)"), input.AccountID, at); err != nil {
		return identity.LocalUserResult{}, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES(?,?,?,?,?,1)", "INSERT INTO subject_identity(digest,key_id,key_version,org_id,subject_id,active) VALUES($1,$2,$3,$4,$5,true)"), input.UsernameDigest, input.UsernameKey.KeyID, input.UsernameKey.Version, current.OrgID, input.SubjectID); err != nil {
		return identity.LocalUserResult{}, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.sql("INSERT INTO local_user_command_receipt(org_id,actor_subject_id,key,digest,digest_key_id,digest_key_version,result_subject_id,result_account_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)", "INSERT INTO local_user_command_receipt(org_id,actor_subject_id,key,digest,digest_key_id,digest_key_version,result_subject_id,result_account_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)"), current.OrgID, current.SubjectID, input.Key, input.CommandDigest, input.CommandKey.KeyID, input.CommandKey.Version, input.SubjectID, input.AccountID, at); err != nil {
		return identity.LocalUserResult{}, safeError(err)
	}
	if err = insertAudit(ctx, tx, r.Backend, organization.Audit{ID: value.NewID(), OrgID: current.OrgID, SubjectID: current.SubjectID, Operation: "OP-SEC-07", Purpose: authz.ManagementPurpose, RequestID: input.RequestID, Outcome: "allowed", At: input.Now}); err != nil {
		return identity.LocalUserResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return identity.LocalUserResult{}, fault.Unavailable
	}
	return identity.LocalUserResult{AccountID: input.AccountID, SubjectID: input.SubjectID}, nil
}
