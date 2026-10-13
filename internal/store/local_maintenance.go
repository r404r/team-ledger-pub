package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

type LocalBootstrap struct {
	RequestID, OrgID, SubjectID, AccountID string
	Timezone                               string
	InputDigest, UsernameDigest            []byte
	UsernameKey                            sensitive.KeyReference
	UsernameEnvelope                       sensitive.Envelope
	PepperKey                              sensitive.KeyReference
	PasswordPHC                            string
	Now                                    time.Time
}

type LocalBootstrapResult struct {
	OrgID     string `json:"org_id"`
	SubjectID string `json:"subject_id"`
	AccountID string `json:"account_id"`
}

func validLocalBootstrap(input LocalBootstrap) bool {
	binding := input.UsernameEnvelope.Context
	return value.ValidID(input.RequestID) && value.ValidID(input.OrgID) && value.ValidID(input.SubjectID) && value.ValidID(input.AccountID) &&
		len(input.InputDigest) == 32 && len(input.UsernameDigest) == 32 && input.UsernameKey.Version == 1 && input.UsernameKey.KeyID != "" &&
		input.PepperKey.Version > 0 && input.PepperKey.KeyID != "" && len(input.PasswordPHC) >= 80 && len(input.PasswordPHC) <= 256 &&
		input.Timezone != "" && len(input.Timezone) <= 64 && !strings.ContainsAny(input.Timezone, "\x00\r\n") &&
		binding.OrgID == input.OrgID && binding.RecordID == input.AccountID && binding.VersionID == input.AccountID && binding.EmployeeID == "" &&
		binding.ObjectKind == "local_username" && binding.Purpose == "identity" && binding.SchemaType == "identity.local_username.v1" && binding.SchemaVersion == 1 &&
		input.UsernameEnvelope.FormatVersion == 1 && input.UsernameEnvelope.Algorithm == "A256GCM-RANDOMNONCE" && input.UsernameEnvelope.DEKID != "" &&
		input.UsernameEnvelope.Key.KEKID != "" && input.UsernameEnvelope.Key.Version > 0 && len(input.UsernameEnvelope.Key.Data) > 0 && len(input.UsernameEnvelope.SealedBytes) >= 39 && !input.Now.IsZero()
}

func (r *Repository) BootstrapLocal(ctx context.Context, input LocalBootstrap) (LocalBootstrapResult, error) {
	var empty LocalBootstrapResult
	if !validLocalBootstrap(input) {
		return empty, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return empty, fault.Unavailable
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	var priorDigest []byte
	var prior LocalBootstrapResult
	err = tx.QueryRowContext(ctx, q.sql("SELECT input_digest,org_id,subject_id,account_id FROM local_bootstrap_receipt WHERE request_id=?", "SELECT input_digest,org_id,subject_id,account_id FROM local_bootstrap_receipt WHERE request_id=$1 FOR UPDATE"), input.RequestID).Scan(&priorDigest, &prior.OrgID, &prior.SubjectID, &prior.AccountID)
	if err == nil {
		if !bytes.Equal(priorDigest, input.InputDigest) {
			return empty, fault.Conflict
		}
		return prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, safeError(err)
	}
	var facts int64
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM organization)+(SELECT count(*) FROM subject)+(SELECT count(*) FROM local_account)+(SELECT count(*) FROM identity_mode_state)").Scan(&facts); err != nil {
		return empty, safeError(err)
	}
	if facts != 0 {
		return empty, fault.Conflict
	}
	exec := func(sqlite, postgres string, args ...any) error {
		_, e := tx.ExecContext(ctx, q.sql(sqlite, postgres), args...)
		return safeError(e)
	}
	if err = exec("INSERT INTO organization(id,timezone,graph_revision) VALUES(?,?,1)", "INSERT INTO organization(id,timezone,graph_revision) VALUES($1,$2,1)", input.OrgID, input.Timezone); err != nil {
		return empty, err
	}
	if err = exec("INSERT INTO authorization_guard(org_id,auth_epoch) VALUES(?,1)", "INSERT INTO authorization_guard(org_id,auth_epoch) VALUES($1,1)", input.OrgID); err != nil {
		return empty, err
	}
	if err = exec("INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)", input.OrgID, input.SubjectID); err != nil {
		return empty, err
	}
	at := r.BindTime(input.Now)
	if err = exec("INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,?)", "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,$1)", at); err != nil {
		return empty, err
	}
	e := input.UsernameEnvelope
	if err = exec("INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,?,?,?,?,1,?,?,'identity','identity.local_username.v1',1,1,?,?,?,?,?,?,?)", "INSERT INTO local_account(id,org_id,subject_id,username_digest,username_key_id,username_key_version,active,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,'identity','identity.local_username.v1',1,1,$9,$10,$11,$12,$13,$14,$15)", input.AccountID, input.OrgID, input.SubjectID, input.UsernameDigest, input.UsernameKey.KeyID, input.UsernameKey.Version, input.AccountID, input.AccountID, e.Algorithm, e.DEKID, e.Key.KEKID, e.Key.Version, e.Key.Data, e.SealedBytes, at); err != nil {
		return empty, err
	}
	if err = exec("INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES(?,?,?,?,1,?)", "INSERT INTO local_credential(account_id,pepper_key_id,pepper_version,password_phc,revision,updated_at) VALUES($1,$2,$3,$4,1,$5)", input.AccountID, input.PepperKey.KeyID, input.PepperKey.Version, input.PasswordPHC, at); err != nil {
		return empty, err
	}
	if err = exec("INSERT INTO subject_identity(digest,key_version,org_id,subject_id,active) VALUES(?,1,?,?,1)", "INSERT INTO subject_identity(digest,key_version,org_id,subject_id,active) VALUES($1,1,$2,$3,true)", input.UsernameDigest, input.OrgID, input.SubjectID); err != nil {
		return empty, err
	}
	expires := r.BindTime(input.Now.AddDate(100, 0, 0))
	for _, capability := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
		category := "metadata"
		if strings.HasPrefix(capability, "pii.") {
			category = "pii"
		}
		if err = exec("INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,?,'org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,$3,'org',$4)", input.OrgID, input.SubjectID, capability, input.OrgID); err != nil {
			return empty, err
		}
		if err = exec("INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,?,?,'org',?,'organization_management',?,?,0,0,0)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,$4,$5,'org',$6,'organization_management',$7,$8,false,false,false)", value.NewID(), input.OrgID, input.SubjectID, capability, category, input.OrgID, at, expires); err != nil {
			return empty, err
		}
	}
	mapping := identity.Identity{Digest: input.UsernameDigest, KeyVersion: 1, OrgID: input.OrgID, SubjectID: input.SubjectID}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return empty, err
	}
	if err = insertMaintenanceAudit(ctx, q, mapping, &actor, "AUTH-BIND", input.RequestID, input.Now); err != nil {
		return empty, err
	}
	if err = exec("INSERT INTO local_bootstrap_receipt(request_id,input_digest,org_id,subject_id,account_id,policy_version,created_at) VALUES(?,?,?,?,?,'bootstrap_policy.v1',?)", "INSERT INTO local_bootstrap_receipt(request_id,input_digest,org_id,subject_id,account_id,policy_version,created_at) VALUES($1,$2,$3,$4,$5,'bootstrap_policy.v1',$6)", input.RequestID, input.InputDigest, input.OrgID, input.SubjectID, input.AccountID, at); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, fault.Unavailable
	}
	return LocalBootstrapResult{OrgID: input.OrgID, SubjectID: input.SubjectID, AccountID: input.AccountID}, nil
}
