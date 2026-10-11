package testsupport

import (
	"context"
	"database/sql"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

func (f *Fixture) seedInterviews(ctx context.Context, tx *sql.Tx) error {
	exec := func(sq, pg string, args ...any) error {
		q := sq
		if f.Backend == "postgres" {
			q = pg
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	type pair struct{ capability, category string }
	pairs := make([]pair, 0, 17)
	pairs = append(pairs, pair{"interview.read", "metadata"}, pair{"interview.write", "metadata"}, pair{"action.read", "shared"}, pair{"action.write", "shared"}, pair{"sensitive.export", "metadata"})
	for _, category := range [...]string{"shared", "manager_private", "hr_confidential"} {
		for _, capability := range [...]string{"note.read", "note.write", "note.publish", "sensitive.export"} {
			pairs = append(pairs, pair{capability, category})
		}
	}
	for _, p := range pairs {
		id := value.NewID()
		f.AuthorityIDs[p.capability+"/"+p.category] = id
		if err := exec(
			"INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,?,?,'org',?,'interview_followup',?,?,?,?,?,?)",
			"INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES($1,$2,$3,$4,$5,'org',$6,'interview_followup',$7,$8,$9,$10,$11,$12)",
			id, f.OrgID, f.Manager.SubjectID, p.capability, p.category, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour)), p.capability == "note.publish" || p.capability == "sensitive.export", f.Approver.SubjectID, f.Repo.BindTime(f.Now.Add(-2*time.Hour)), "fixture-policy-r3-explicit"); err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		credential Credential
		org        string
		owner      bool
	}{
		{f.Owner, f.OrgID, true},
		{f.OtherOwner, f.OtherOrgID, true},
		{f.Reader, f.OrgID, false},
		{f.Stranger, f.OrgID, false},
		{f.Manager, f.OrgID, false},
	} {
		assigned := make(map[string]bool, 8)
		for _, p := range pairs {
			if entry.credential.SubjectID == f.Manager.SubjectID && p.capability != "note.read" {
				continue
			}
			if !assigned[p.capability] {
				if err := exec("INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,?,'org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,$3,'org',$4)", entry.org, entry.credential.SubjectID, p.capability, entry.org); err != nil {
					return err
				}
				assigned[p.capability] = true
			}
			if !entry.owner && entry.credential.SubjectID != f.Manager.SubjectID {
				continue
			}
			// These initial fixture facts follow the existing trusted bootstrap
			// convention; explicit sharing still requires a real Issue approval.
			mfa := p.capability == "note.publish" || p.capability == "sensitive.export"
			if err := exec(
				"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,?,?,'org',?,'interview_followup',?,?,0,0,?)",
				"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,$4,$5,'org',$6,'interview_followup',$7,$8,false,false,$9)",
				value.NewID(), entry.org, entry.credential.SubjectID, p.capability, p.category, entry.org, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour)), mfa); err != nil {
				return err
			}
		}
	}
	return nil
}
