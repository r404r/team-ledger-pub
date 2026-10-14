package store

import (
	"context"
	"math"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

// RevokeCSRFVersion invalidates every live session issued under oldKey before
// keyd is allowed to activate the replacement CSRF key.
func (r *Repository) RevokeCSRFVersion(ctx context.Context, oldKey sensitive.KeyReference, requestID string, now time.Time) error {
	if oldKey.KeyID == "" || oldKey.Version == 0 || !value.ValidID(requestID) {
		return fault.Invalid
	}
	q := r.read()
	rows, err := r.DB.QueryContext(ctx, q.sql(
		"SELECT DISTINCT org_id,subject_id FROM session WHERE csrf_key_id=? AND csrf_version=? AND revoked=0 AND expires_at>? AND idle_expires_at>? ORDER BY org_id,subject_id",
		"SELECT DISTINCT org_id,subject_id FROM session WHERE csrf_key_id=$1 AND csrf_version=$2 AND revoked=false AND expires_at>$3 AND idle_expires_at>$4 ORDER BY org_id,subject_id"), oldKey.KeyID, oldKey.Version, r.BindTime(now), r.BindTime(now))
	if err != nil {
		return safeError(err)
	}
	owners := make([]identityOwner, 0)
	for rows.Next() {
		var owner identityOwner
		if err = rows.Scan(&owner.org, &owner.subject); err != nil {
			rows.Close()
			return safeError(err)
		}
		owners = append(owners, owner)
	}
	if err = rows.Close(); err != nil {
		return safeError(err)
	}
	if len(owners) == 0 {
		return nil
	}
	return r.withIdentityTx(ctx, owners, func(tx reader) error {
		orgs := make(map[string]struct{}, len(owners))
		for _, owner := range owners {
			var epoch int64
			if err := tx.db.QueryRowContext(ctx, tx.sql("SELECT auth_epoch FROM subject WHERE org_id=? AND id=?", "SELECT auth_epoch FROM subject WHERE org_id=$1 AND id=$2"), owner.org, owner.subject).Scan(&epoch); err != nil {
				return safeError(err)
			}
			if epoch == math.MaxInt64 {
				return fault.Unavailable
			}
			if _, err := tx.db.ExecContext(ctx, tx.sql("UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2"), owner.org, owner.subject); err != nil {
				return safeError(err)
			}
			if err := insertAudit(ctx, tx.db, tx.backend, organization.Audit{ID: value.NewID(), OrgID: owner.org, SubjectID: owner.subject, Operation: "AUTH-LOGOUT", RequestID: requestID, Outcome: "allowed", At: now}); err != nil {
				return err
			}
			orgs[owner.org] = struct{}{}
		}
		for org := range orgs {
			result, err := tx.db.ExecContext(ctx, tx.sql("UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=? AND auth_epoch<?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND auth_epoch<$2"), org, int64(math.MaxInt64))
			if err != nil {
				return safeError(err)
			}
			if n, _ := result.RowsAffected(); n != 1 {
				return fault.Unavailable
			}
		}
		_, err := tx.db.ExecContext(ctx, tx.sql("UPDATE session SET revoked=1 WHERE csrf_key_id=? AND csrf_version=? AND revoked=0", "UPDATE session SET revoked=true WHERE csrf_key_id=$1 AND csrf_version=$2 AND revoked=false"), oldKey.KeyID, oldKey.Version)
		return safeError(err)
	})
}
