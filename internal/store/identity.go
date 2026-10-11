package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

var _ identity.Store = (*Repository)(nil)
var _ identity.MappingStore = (*Repository)(nil)

type identityOwner struct{ org, subject string }

// Multi-owner rotation takes every organization guard first in UUID order,
// then each subject guard in (org,subject) order. This is the same authorization
// barrier used by business writers and sensitive release; no I/O occurs inside.
func (r *Repository) withIdentityTx(ctx context.Context, owners []identityOwner, fn func(reader) error) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	sort.Slice(owners, func(i, j int) bool {
		if owners[i].org != owners[j].org {
			return owners[i].org < owners[j].org
		}
		return owners[i].subject < owners[j].subject
	})
	q := reader{db: tx, backend: r.Backend}
	if r.Backend == "postgres" {
		if _, err = tx.ExecContext(ctx, "SET LOCAL statement_timeout='10s'"); err != nil {
			return safeError(err)
		}
		if _, err = tx.ExecContext(ctx, "SET LOCAL lock_timeout='2s'"); err != nil {
			return safeError(err)
		}
	}
	previous := ""
	for _, owner := range owners {
		if owner.org == previous {
			continue
		}
		previous = owner.org
		if r.Backend == "sqlite" {
			result, e := tx.ExecContext(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch WHERE org_id=?", owner.org)
			if e != nil {
				return safeError(e)
			}
			n, e := result.RowsAffected()
			if e != nil {
				return safeError(e)
			}
			if n != 1 {
				return fault.Unauthenticated
			}
		} else {
			var epoch int64
			if err = tx.QueryRowContext(ctx, "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1 FOR UPDATE", owner.org).Scan(&epoch); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fault.Unauthenticated
				}
				return safeError(err)
			}
		}
	}
	var last identityOwner
	for _, owner := range owners {
		if owner == last {
			continue
		}
		last = owner
		var epoch int64
		if err = tx.QueryRowContext(ctx, q.sql("SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2 FOR UPDATE"), owner.org, owner.subject).Scan(&epoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fault.Unauthenticated
			}
			return safeError(err)
		}
	}
	if err = fn(q); err != nil {
		return err
	}
	return safeError(tx.Commit())
}
func binaryNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
func epochNull(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func (r *Repository) SaveOIDCTransaction(ctx context.Context, t identity.Transaction) error {
	if len(t.StateHash) != 32 || len(t.BindingHash) != 32 || len(t.Sealed) < 28 || !identity.AllowedReturn(t.ReturnTo) {
		return fault.Invalid
	}
	// Each successful begin reclaims at most 256 proofs expired at its creation
	// time, oldest first with a stable tie-breaker. Consumed/issued proofs remain
	// until expiry: a callback may still need them after external OIDC I/O.
	// This short transaction locks only proof rows, never authorization guards.
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, r.sql(
		"DELETE FROM oidc_transaction WHERE state_hash IN (SELECT state_hash FROM oidc_transaction WHERE expires_at<=? ORDER BY expires_at,state_hash LIMIT 256)",
		"DELETE FROM oidc_transaction WHERE state_hash IN (SELECT state_hash FROM oidc_transaction WHERE expires_at<=$1 ORDER BY expires_at,state_hash LIMIT 256 FOR UPDATE SKIP LOCKED)"),
		r.BindTime(t.CreatedAt)); err != nil {
		return safeError(err)
	}
	_, err = tx.ExecContext(ctx, r.sql(
		"INSERT INTO oidc_transaction(state_hash,binding_hash,sealed_bytes,key_version,created_at,expires_at,mode,action,return_route,previous_hash,expected_org,expected_subject,expected_epoch,expected_identity) VALUES(?,?,?,1,?,?,?,?,?,?,?,?,?,?)",
		"INSERT INTO oidc_transaction(state_hash,binding_hash,sealed_bytes,key_version,created_at,expires_at,mode,action,return_route,previous_hash,expected_org,expected_subject,expected_epoch,expected_identity) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"),
		t.StateHash, t.BindingHash, t.Sealed, r.BindTime(t.CreatedAt), r.BindTime(t.ExpiresAt), t.Mode, t.Action, t.ReturnTo, binaryNull(t.PreviousHash), nullable(t.ExpectedOrg), nullable(t.ExpectedSubject), epochNull(t.ExpectedEpoch), binaryNull(t.ExpectedIdentity))
	if err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}
func (q reader) oidcTransaction(ctx context.Context, state []byte) (identity.Transaction, bool, bool, error) {
	var t identity.Transaction
	var created, expires dbTime
	var org, subject sql.NullString
	var epoch sql.NullInt64
	var consumed bool
	var issued []byte
	err := q.db.QueryRowContext(ctx, q.sql(
		"SELECT state_hash,binding_hash,sealed_bytes,created_at,expires_at,mode,action,return_route,previous_hash,expected_org,expected_subject,expected_epoch,expected_identity,consumed,issued_hash FROM oidc_transaction WHERE state_hash=?",
		"SELECT state_hash,binding_hash,sealed_bytes,created_at,expires_at,mode,action,return_route,previous_hash,expected_org,expected_subject,expected_epoch,expected_identity,consumed,issued_hash FROM oidc_transaction WHERE state_hash=$1"), state).Scan(&t.StateHash, &t.BindingHash, &t.Sealed, &created, &expires, &t.Mode, &t.Action, &t.ReturnTo, &t.PreviousHash, &org, &subject, &epoch, &t.ExpectedIdentity, &consumed, &issued)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, false, fault.Unauthenticated
	}
	if err != nil {
		return t, false, false, safeError(err)
	}
	t.CreatedAt, t.ExpiresAt = created.Time, expires.Time
	t.ExpectedOrg, t.ExpectedSubject, t.ExpectedEpoch = org.String, subject.String, epoch.Int64
	return t, consumed, len(issued) != 0, nil
}
func (r *Repository) ConsumeOIDCTransaction(ctx context.Context, state, binding []byte, now time.Time) (identity.Transaction, error) {
	var t identity.Transaction
	if len(state) != 32 || len(binding) != 32 {
		return t, fault.Unauthenticated
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return t, safeError(err)
	}
	defer tx.Rollback()
	q := reader{db: tx, backend: r.Backend}
	result, err := tx.ExecContext(ctx, q.sql(
		"UPDATE oidc_transaction SET consumed=1 WHERE state_hash=? AND binding_hash=? AND consumed=0 AND expires_at>? AND created_at<=?",
		"UPDATE oidc_transaction SET consumed=true WHERE state_hash=$1 AND binding_hash=$2 AND consumed=false AND expires_at>$3 AND created_at<=$4"), state, binding, r.BindTime(now), r.BindTime(now))
	if err != nil {
		return t, safeError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return t, safeError(err)
	}
	if n != 1 {
		return t, fault.Unauthenticated
	}
	t, _, _, err = q.oidcTransaction(ctx, state)
	if err != nil {
		return t, err
	}
	if err = tx.Commit(); err != nil {
		return identity.Transaction{}, safeError(err)
	}
	return t, nil
}
func (q reader) identityMapping(ctx context.Context, digest []byte) (identity.Identity, error) {
	var m identity.Identity
	err := q.db.QueryRowContext(ctx, q.sql("SELECT digest,key_version,org_id,subject_id,active FROM subject_identity WHERE digest=?", "SELECT digest,key_version,org_id,subject_id,active FROM subject_identity WHERE digest=$1"), digest).Scan(&m.Digest, &m.KeyVersion, &m.OrgID, &m.SubjectID, &m.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return m, fault.Unauthenticated
	}
	if err != nil {
		return m, safeError(err)
	}
	if m.KeyVersion != 1 || !m.Active {
		return m, fault.Unauthenticated
	}
	return m, nil
}
func (q reader) currentIdentitySession(ctx context.Context, hash []byte, now time.Time) (identity.Session, error) {
	var s identity.Session
	var expires, idle dbTime
	var active, revoked bool
	var epoch int64
	var mappingActive sql.NullBool
	var authVersion sql.NullInt64
	err := q.db.QueryRowContext(ctx, q.sql(
		"SELECT s.token_hash,s.org_id,s.subject_id,s.subject_epoch,s.expires_at,s.idle_expires_at,u.active,u.auth_epoch,s.revoked,a.identity_digest,m.active,a.key_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id LEFT JOIN session_auth a ON a.token_hash=s.token_hash AND a.org_id=s.org_id AND a.subject_id=s.subject_id LEFT JOIN subject_identity m ON m.digest=a.identity_digest AND m.org_id=s.org_id AND m.subject_id=s.subject_id WHERE s.token_hash=?",
		"SELECT s.token_hash,s.org_id,s.subject_id,s.subject_epoch,s.expires_at,s.idle_expires_at,u.active,u.auth_epoch,s.revoked,a.identity_digest,m.active,a.key_version FROM session s JOIN subject u ON u.org_id=s.org_id AND u.id=s.subject_id LEFT JOIN session_auth a ON a.token_hash=s.token_hash AND a.org_id=s.org_id AND a.subject_id=s.subject_id LEFT JOIN subject_identity m ON m.digest=a.identity_digest AND m.org_id=s.org_id AND m.subject_id=s.subject_id WHERE s.token_hash=$1"), hash).Scan(&s.Hash, &s.OrgID, &s.SubjectID, &s.Epoch, &expires, &idle, &active, &epoch, &revoked, &s.IdentityDigest, &mappingActive, &authVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return s, fault.Unauthenticated
	}
	if err != nil {
		return identity.Session{}, safeError(err)
	}
	s.ExpiresAt, s.IdleExpiresAt = expires.Time, idle.Time
	if !active || revoked || s.Epoch != epoch || !s.ExpiresAt.After(now) || !s.IdleExpiresAt.After(now) || len(s.IdentityDigest) != 0 && (!mappingActive.Valid || !mappingActive.Bool || !authVersion.Valid || authVersion.Int64 != 1) {
		return identity.Session{}, fault.Unauthenticated
	}
	return s, nil
}
func (r *Repository) IdentitySession(ctx context.Context, hash []byte, now time.Time) (identity.Session, error) {
	if len(hash) != 32 {
		return identity.Session{}, fault.Unauthenticated
	}
	return r.read().currentIdentitySession(ctx, hash, now)
}
func sameTransaction(a, b identity.Transaction) bool {
	return bytes.Equal(a.StateHash, b.StateHash) && bytes.Equal(a.BindingHash, b.BindingHash) && bytes.Equal(a.Sealed, b.Sealed) && a.CreatedAt.Equal(b.CreatedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.Mode == b.Mode && a.Action == b.Action && a.ReturnTo == b.ReturnTo && bytes.Equal(a.PreviousHash, b.PreviousHash) && a.ExpectedOrg == b.ExpectedOrg && a.ExpectedSubject == b.ExpectedSubject && a.ExpectedEpoch == b.ExpectedEpoch && bytes.Equal(a.ExpectedIdentity, b.ExpectedIdentity)
}
func (r *Repository) IssueSession(ctx context.Context, issue identity.SessionIssue) error {
	if len(issue.TokenHash) != 32 || len(issue.CSRFHash) != 32 || len(issue.IdentityDigest) != 32 || !value.ValidID(issue.RequestID) || !issue.ExpiresAt.Equal(issue.Now.Add(8*time.Hour)) || !issue.IdleExpiresAt.Equal(issue.Now.Add(30*time.Minute)) {
		return fault.Invalid
	}
	mapping, err := r.read().identityMapping(ctx, issue.IdentityDigest)
	if err != nil {
		return err
	}
	owners := []identityOwner{{mapping.OrgID, mapping.SubjectID}}
	t := issue.Transaction
	if t.ExpectedOrg != "" {
		owners = append(owners, identityOwner{t.ExpectedOrg, t.ExpectedSubject})
	}
	return r.withIdentityTx(ctx, owners, func(q reader) error {
		current, err := q.identityMapping(ctx, issue.IdentityDigest)
		if err != nil {
			return err
		}
		if current.OrgID != mapping.OrgID || current.SubjectID != mapping.SubjectID {
			return fault.Unauthenticated
		}
		proof, consumed, issued, err := q.oidcTransaction(ctx, t.StateHash)
		if err != nil {
			return err
		}
		if !consumed || issued || !sameTransaction(proof, t) || !proof.ExpiresAt.After(issue.Now) || proof.CreatedAt.After(issue.Now) {
			return fault.Unauthenticated
		}
		var active bool
		var epoch int64
		if err = q.db.QueryRowContext(ctx, q.sql("SELECT active,auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT active,auth_epoch FROM subject WHERE org_id=$1 AND id=$2"), current.OrgID, current.SubjectID).Scan(&active, &epoch); err != nil {
			return safeError(err)
		}
		if !active {
			return fault.Unauthenticated
		}
		if len(t.PreviousHash) != 0 {
			previous, e := q.currentIdentitySession(ctx, t.PreviousHash, issue.Now)
			if e != nil {
				return e
			}
			if previous.OrgID != t.ExpectedOrg || previous.SubjectID != t.ExpectedSubject || previous.Epoch != t.ExpectedEpoch {
				return fault.Unauthenticated
			}
			if t.Mode == "step_up" && (current.OrgID != previous.OrgID || current.SubjectID != previous.SubjectID || !bytes.Equal(previous.IdentityDigest, issue.IdentityDigest) || !bytes.Equal(t.ExpectedIdentity, issue.IdentityDigest) || !issue.MFAUntil.After(issue.Now)) {
				return identity.MFARequired
			}
			if _, err = q.db.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE token_hash=?", "UPDATE session SET revoked=true WHERE token_hash=$1"), t.PreviousHash); err != nil {
				return safeError(err)
			}
		} else if t.Mode == "step_up" {
			return fault.Unauthenticated
		}
		if _, err = q.db.ExecContext(ctx, q.sql(
			"INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES(?,?,?,?,?,?,?,0,?,1)",
			"INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,1)"), issue.TokenHash, current.OrgID, current.SubjectID, epoch, r.BindTime(issue.ExpiresAt), r.BindTime(issue.IdleExpiresAt), r.BindTime(issue.MFAUntil), issue.CSRFHash); err != nil {
			return safeError(err)
		}
		amr, err := json.Marshal(issue.AMR)
		if err != nil {
			return fault.Invalid
		}
		var authTime any
		if !issue.AuthTime.IsZero() {
			authTime = r.BindTime(issue.AuthTime)
		}
		if _, err = q.db.ExecContext(ctx, q.sql(
			"INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,auth_time,acr,amr_json) VALUES(?,?,?,?,1,?,?,?,?)",
			"INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,auth_time,acr,amr_json) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8)"), issue.TokenHash, current.OrgID, current.SubjectID, issue.IdentityDigest, r.BindTime(issue.Now), authTime, issue.ACR, string(amr)); err != nil {
			return safeError(err)
		}
		result, err := q.db.ExecContext(ctx, q.sql("UPDATE oidc_transaction SET issued_hash=? WHERE state_hash=? AND consumed=1 AND issued_hash IS NULL", "UPDATE oidc_transaction SET issued_hash=$1 WHERE state_hash=$2 AND consumed=true AND issued_hash IS NULL"), issue.TokenHash, t.StateHash)
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
		op := "AUTH-LOGIN"
		if t.Mode == "step_up" {
			op = "AUTH-STEP-UP"
		}
		return insertAudit(ctx, q.db, q.backend, organization.Audit{ID: value.NewID(), OrgID: current.OrgID, SubjectID: current.SubjectID, Operation: op, RequestID: issue.RequestID, Outcome: "allowed", At: issue.Now})
	})
}
func (r *Repository) sessionMutation(ctx context.Context, hash []byte, now time.Time, fn func(reader, identity.Session) error) error {
	initial, err := r.IdentitySession(ctx, hash, now)
	if err != nil {
		return err
	}
	return r.withIdentityTx(ctx, []identityOwner{{initial.OrgID, initial.SubjectID}}, func(q reader) error {
		current, err := q.currentIdentitySession(ctx, hash, now)
		if err != nil {
			return err
		}
		if current.OrgID != initial.OrgID || current.SubjectID != initial.SubjectID {
			return fault.Unauthenticated
		}
		return fn(q, current)
	})
}
func (r *Repository) TouchSession(ctx context.Context, hash []byte, now time.Time) error {
	return r.sessionMutation(ctx, hash, now, func(q reader, s identity.Session) error {
		idle := now.Add(30 * time.Minute)
		if idle.After(s.ExpiresAt) {
			idle = s.ExpiresAt
		}
		_, err := q.db.ExecContext(ctx, q.sql("UPDATE session SET idle_expires_at=? WHERE token_hash=?", "UPDATE session SET idle_expires_at=$1 WHERE token_hash=$2"), r.BindTime(idle), hash)
		return safeError(err)
	})
}
func (r *Repository) LogoutSession(ctx context.Context, hash []byte, requestID string, now time.Time) error {
	return r.sessionMutation(ctx, hash, now, func(q reader, s identity.Session) error {
		if _, err := q.db.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE token_hash=?", "UPDATE session SET revoked=true WHERE token_hash=$1"), hash); err != nil {
			return safeError(err)
		}
		return insertAudit(ctx, q.db, q.backend, organization.Audit{ID: value.NewID(), OrgID: s.OrgID, SubjectID: s.SubjectID, Operation: "AUTH-LOGOUT", RequestID: requestID, Outcome: "allowed", At: now})
	})
}
func (r *Repository) AuditIdentityDenied(ctx context.Context, operation, requestID string, now time.Time) error {
	if operation != "AUTH-LOGIN" && operation != "AUTH-STEP-UP" {
		return fault.Invalid
	}
	return r.AuditDenied(ctx, organization.Audit{ID: value.NewID(), Operation: operation, RequestID: requestID, At: now})
}
func validMapping(m identity.Identity, requestID string) bool {
	return len(m.Digest) == 32 && m.KeyVersion == 1 && value.ValidID(m.OrgID) && value.ValidID(m.SubjectID) && value.ValidID(requestID)
}

type maintenancePrincipal struct {
	uid      int64
	hostHash [32]byte
}

// This is the executing process principal, not a claimed application subject
// or a named human behind a shared/sudo account. Capture outside the DB guard.
func currentMaintenancePrincipal() (maintenancePrincipal, error) {
	uid := os.Geteuid()
	host, err := os.Hostname()
	if err != nil || uid < 0 || uint64(uid) > math.MaxUint32 || host == "" {
		return maintenancePrincipal{}, fault.Unavailable
	}
	return maintenancePrincipal{uid: int64(uid), hostHash: sha256.Sum256([]byte("TEAMLEDGER-MAINTENANCE-HOST\x00\x01" + host))}, nil
}

func insertMaintenanceAudit(ctx context.Context, q reader, m identity.Identity, actor *maintenancePrincipal, operation, requestID string, now time.Time) error {
	var at any = now.UTC().Truncate(time.Microsecond)
	if q.backend == "sqlite" {
		at = now.UTC().UnixMicro()
	}
	_, err := q.db.ExecContext(ctx, q.sql(
		"INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at,actor_kind,actor_uid,actor_host_hash,target_subject_id,identity_digest) VALUES(?,?,NULL,?,'security_administration',?,'allowed',?,'local_maintenance',?,?,?,?)",
		"INSERT INTO audit_event(id,org_id,subject_id,operation,purpose,request_id,outcome,recorded_at,actor_kind,actor_uid,actor_host_hash,target_subject_id,identity_digest) VALUES($1,$2,NULL,$3,'security_administration',$4,'allowed',$5,'local_maintenance',$6,$7,$8,$9)"),
		value.NewID(), m.OrgID, operation, requestID, at, actor.uid, actor.hostHash[:], m.SubjectID, m.Digest)
	if err != nil {
		return fault.AuditUnavailable
	}
	return nil
}
func (r *Repository) BindIdentity(ctx context.Context, m identity.Identity, requestID string, now time.Time) error {
	if !validMapping(m, requestID) {
		return fault.Invalid
	}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return err
	}
	return r.withIdentityTx(ctx, []identityOwner{{m.OrgID, m.SubjectID}}, func(q reader) error {
		var active bool
		if err := q.db.QueryRowContext(ctx, q.sql("SELECT active FROM subject WHERE org_id=? AND id=?", "SELECT active FROM subject WHERE org_id=$1 AND id=$2"), m.OrgID, m.SubjectID).Scan(&active); err != nil {
			return safeError(err)
		}
		if !active {
			return fault.Forbidden
		}
		if _, err := q.db.ExecContext(ctx, q.sql("INSERT INTO subject_identity(digest,key_version,org_id,subject_id,active) VALUES(?,1,?,?,0) ON CONFLICT(digest) DO NOTHING", "INSERT INTO subject_identity(digest,key_version,org_id,subject_id,active) VALUES($1,1,$2,$3,false) ON CONFLICT(digest) DO NOTHING"), m.Digest, m.OrgID, m.SubjectID); err != nil {
			return safeError(err)
		}
		var org, subject string
		if err := q.db.QueryRowContext(ctx, q.sql("SELECT org_id,subject_id,active FROM subject_identity WHERE digest=?", "SELECT org_id,subject_id,active FROM subject_identity WHERE digest=$1 FOR UPDATE"), m.Digest).Scan(&org, &subject, &active); err != nil {
			return safeError(err)
		}
		if org != m.OrgID || subject != m.SubjectID || active {
			return fault.Conflict
		}
		if _, err := q.db.ExecContext(ctx, q.sql("UPDATE subject_identity SET active=1 WHERE digest=?", "UPDATE subject_identity SET active=true WHERE digest=$1"), m.Digest); err != nil {
			return safeError(err)
		}
		return insertMaintenanceAudit(ctx, q, m, &actor, "AUTH-BIND", requestID, now)
	})
}
func (r *Repository) UnbindIdentity(ctx context.Context, m identity.Identity, requestID string, now time.Time) error {
	if !validMapping(m, requestID) {
		return fault.Invalid
	}
	actor, err := currentMaintenancePrincipal()
	if err != nil {
		return err
	}
	return r.withIdentityTx(ctx, []identityOwner{{m.OrgID, m.SubjectID}}, func(q reader) error {
		current, err := q.identityMapping(ctx, m.Digest)
		if err != nil {
			return err
		}
		if current.OrgID != m.OrgID || current.SubjectID != m.SubjectID {
			return fault.Unauthenticated
		}
		var epoch, orgEpoch int64
		if err = q.db.QueryRowContext(ctx, q.sql("SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2"), m.OrgID, m.SubjectID).Scan(&epoch); err != nil {
			return safeError(err)
		}
		if err = q.db.QueryRowContext(ctx, q.sql("SELECT auth_epoch FROM authorization_guard WHERE org_id=?", "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"), m.OrgID).Scan(&orgEpoch); err != nil {
			return safeError(err)
		}
		if epoch == math.MaxInt64 || orgEpoch == math.MaxInt64 {
			return fault.Unavailable
		}
		if _, err = q.db.ExecContext(ctx, q.sql("UPDATE subject_identity SET active=0 WHERE digest=?", "UPDATE subject_identity SET active=false WHERE digest=$1"), m.Digest); err != nil {
			return safeError(err)
		}
		if _, err = q.db.ExecContext(ctx, q.sql("UPDATE session SET revoked=1 WHERE token_hash IN(SELECT token_hash FROM session_auth WHERE identity_digest=?)", "UPDATE session SET revoked=true WHERE token_hash IN(SELECT token_hash FROM session_auth WHERE identity_digest=$1)"), m.Digest); err != nil {
			return safeError(err)
		}
		if _, err = q.db.ExecContext(ctx, q.sql("UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2"), m.OrgID, m.SubjectID); err != nil {
			return safeError(err)
		}
		if _, err = q.db.ExecContext(ctx, q.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1"), m.OrgID); err != nil {
			return safeError(err)
		}
		return insertMaintenanceAudit(ctx, q, m, &actor, "AUTH-UNBIND", requestID, now)
	})
}
