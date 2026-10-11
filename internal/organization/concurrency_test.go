package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func TestRevokeCommitPreventsInFlightSensitiveRelease(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id := create(t, f, "SYNTHETIC_INFLIGHT_PRIVATE_MARKER").ID
		arrived, release := make(chan struct{}), make(chan struct{})
		f.KMS.BlockNextDecrypt(arrived, release)
		done := make(chan struct {
			view organization.View
			err  error
		}, 1)
		go func() {
			v, err := f.Service.Read(ctx, f.Request(f.Owner), id, "2026-10-11", true)
			done <- struct {
				view organization.View
				err  error
			}{v, err}
		}()
		select {
		case <-arrived:
		case <-ctx.Done():
			close(release)
			t.Fatal("real KMS request did not reach controlled barrier")
		}
		tx, err := f.Repo.DB.BeginTx(ctx, nil)
		if err != nil {
			close(release)
			t.Fatal(err)
		}
		defer tx.Rollback()
		q := "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?"
		g := "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND category='pii'"
		if f.Backend == "postgres" {
			q = "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1"
			g = "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND category='pii'"
		}
		if _, err = tx.ExecContext(ctx, q, f.OrgID); err == nil {
			_, err = tx.ExecContext(ctx, g, f.OrgID, f.Owner.SubjectID)
		}
		if err == nil {
			err = tx.Commit()
		}
		close(release)
		if err != nil {
			t.Fatal("revoke fixture transaction must commit while KMS is outside write transaction")
		}
		select {
		case out := <-done:
			if !errors.Is(out.err, fault.Forbidden) || out.view.Profile != nil {
				t.Fatal("revoke committed before release but in-flight read disclosed plaintext")
			}
		case <-ctx.Done():
			t.Fatal("in-flight release did not terminate")
		}
	})
}

func TestConcurrentCorrectionsFromSamePreparedRevisionHaveOneWinner(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id := create(t, f, "SYNTHETIC_CONCURRENT_ORIGINAL").ID
		arrived, release := make(chan struct{}, 2), make(chan struct{})
		f.KMS.BlockEncrypt(2, arrived, release)
		type outcome struct {
			result organization.Result
			err    error
		}
		done := make(chan outcome, 2)
		for _, name := range []string{"SYNTHETIC_CONCURRENT_A", "SYNTHETIC_CONCURRENT_B"} {
			go func() {
				r, err := f.Service.Update(ctx, f.Request(f.Owner), id, organization.UpdateCommand{ExpectedRevision: "1", Profile: organization.Profile{DisplayName: name}, EditReason: "synthetic concurrent correction"})
				done <- outcome{r, err}
			}()
		}
		for range 2 {
			select {
			case <-arrived:
			case <-ctx.Done():
				close(release)
				t.Fatal("both real requests must prepare revision1 before competing writes")
			}
		}
		close(release)
		success, conflict := 0, 0
		for range 2 {
			select {
			case out := <-done:
				if out.err == nil && out.result.Revision == "2" {
					success++
				} else if errors.Is(out.err, fault.Conflict) {
					conflict++
				} else {
					t.Fatal("concurrent correction returned unexpected safe result")
				}
			case <-ctx.Done():
				t.Fatal("concurrent writers did not terminate")
			}
		}
		v := read(t, f, id)
		if success != 1 || conflict != 1 || v.Revision != "2" || v.Profile == nil || (v.Profile.DisplayName != "SYNTHETIC_CONCURRENT_A" && v.Profile.DisplayName != "SYNTHETIC_CONCURRENT_B") || f.Count(t, "employee_profile_version") != 2 {
			t.Fatal("same prepared revision must commit one replacement and retain immutable original")
		}
	})
}
