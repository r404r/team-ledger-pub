package authz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func grantBackends(t *testing.T, fn func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { fn(t, testsupport.NewHarness(t, backend)) })
	}
}
func managementRequest(f *testsupport.Fixture) authz.Request {
	return authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}
}
func grantCommand(f *testsupport.Fixture, capability, epoch string) authz.IssueCommand {
	category := "metadata"
	if capability == "pii.read" || capability == "pii.write" {
		category = "pii"
	}
	return authz.IssueCommand{SubjectID: f.Reader.SubjectID, Capability: capability, Category: category, Scope: authz.Scope{Kind: "org", ID: f.OrgID}, Purpose: "organization_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: true, AuthorityID: f.AuthorityIDs[capability], ExpectedRevision: epoch}
}
func makeEmployee(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	r, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_GRANTED_PROFILE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("real encrypted employee creation failed:", err)
	}
	return r.ID
}
func issueGrant(t *testing.T, f *testsupport.Fixture, capability, epoch string) authz.Result {
	t.Helper()
	r, err := f.Authz.Issue(context.Background(), managementRequest(f), grantCommand(f, capability, epoch))
	if err != nil {
		t.Fatal("real grant command failed:", err)
	}
	return r
}

func TestGrantEmployeeManagementSQLFiltersBeforePaging(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		first, second := makeEmployee(t, f), makeEmployee(t, f)
		var eligible, hidden authz.Result
		epoch := "1"
		for _, scope := range []authz.Scope{{Kind: "org", ID: f.OrgID}, {Kind: "employee", ID: second}, {Kind: "employee", ID: first}} {
			cmd := grantCommand(f, "organization.read", epoch)
			cmd.Scope = scope
			r, err := f.Authz.Issue(ctx, managementRequest(f), cmd)
			if err != nil {
				t.Fatal(err)
			}
			epoch = r.AuthEpoch
			if scope.ID == first {
				eligible = r
			} else {
				hidden = r
			}
		}
		for _, table := range []string{"capability_assignment", "access_grant"} {
			if err := f.Exec(ctx, "UPDATE "+table+" SET scope_kind='employee',scope_id=?,employee_id=? WHERE org_id=? AND subject_id=? AND capability='access_grant.manage'", "UPDATE "+table+" SET scope_kind='employee',scope_id=$1,employee_id=$2 WHERE org_id=$3 AND subject_id=$4 AND capability='access_grant.manage'", first, first, f.OrgID, f.Manager.SubjectID); err != nil {
				t.Fatal(err)
			}
		}
		page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{SubjectID: f.Reader.SubjectID, Limit: 1})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != eligible.ID || page.NextCursor != nil {
			t.Fatal("hidden org/other employee grants must not consume page or produce hidden cursor", err)
		}
		before := f.KMS.Calls.Load()
		f.KMS.Fail.Store(true)
		for _, id := range []string{value.NewID(), hidden.ID} {
			if _, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{GrantID: id, Limit: 1}); !errors.Is(err, fault.NotFound) {
				t.Fatal("unmanageable/missing ID must return safe404", err)
			}
			if _, err := f.Authz.Revoke(ctx, managementRequest(f), id, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: epoch, Reason: "policy_change"}); !errors.Is(err, fault.NotFound) {
				t.Fatal("known hidden revoke and missing ID must return same404 before stale revision", err)
			}
		}
		cmd := grantCommand(f, "pii.read", epoch)
		cmd.Scope = authz.Scope{Kind: "employee", ID: first}
		if _, err := f.Authz.Issue(ctx, managementRequest(f), cmd); err != nil {
			t.Fatal("intersection should permit same employee", err)
		}
		cmd = grantCommand(f, "pii.read", epoch)
		cmd.Scope = authz.Scope{Kind: "employee", ID: second}
		if _, err := f.Authz.Issue(ctx, managementRequest(f), cmd); !errors.Is(err, fault.Forbidden) {
			t.Fatal("authority org scope must not override management employee scope", err)
		}
		if f.KMS.Calls.Load() != before {
			t.Fatal("grant management must not reach KMS")
		}
	})
}

func TestGrantRevokeLostQualificationCannotRevive(t *testing.T) {
	for _, loss := range []string{"assignment", "inactive"} {
		t.Run(loss, func(t *testing.T) {
			grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx := context.Background()
				id := makeEmployee(t, f)
				metadata := issueGrant(t, f, "organization.read", "1")
				pii := issueGrant(t, f, "pii.read", metadata.AuthEpoch)
				if view, err := f.Service.Read(ctx, f.Request(f.Reader), id, "2026-01-01", true); err != nil || view.Profile == nil {
					t.Fatal("initially qualified reader must see the actual profile", err)
				}
				if loss == "assignment" {
					if err := f.Exec(ctx, "DELETE FROM capability_assignment WHERE org_id=? AND subject_id=? AND capability='pii.read'", "DELETE FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 AND capability='pii.read'", f.OrgID, f.Reader.SubjectID); err != nil {
						t.Fatal(err)
					}
				} else if err := f.Exec(ctx, "UPDATE subject SET active=0 WHERE org_id=? AND id=?", "UPDATE subject SET active=false WHERE org_id=$1 AND id=$2", f.OrgID, f.Reader.SubjectID); err != nil {
					t.Fatal(err)
				}
				revoked, err := f.Authz.Revoke(ctx, managementRequest(f), pii.ID, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: pii.AuthEpoch, Reason: "access_no_longer_required"})
				if err != nil || revoked.Status != "revoked" || revoked.Revision != "2" {
					t.Fatal("current manager must revoke even after target loses qualification", err)
				}
				if loss == "assignment" {
					if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'pii.read','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'pii.read','org',$3)", f.OrgID, f.Reader.SubjectID, f.OrgID); err != nil {
						t.Fatal(err)
					}
				} else if err := f.Exec(ctx, "UPDATE subject SET active=1 WHERE org_id=? AND id=?", "UPDATE subject SET active=true WHERE org_id=$1 AND id=$2", f.OrgID, f.Reader.SubjectID); err != nil {
					t.Fatal(err)
				}
				before := f.KMS.Calls.Load()
				view, err := f.Service.Read(ctx, f.Request(f.Reader), id, "2026-01-01", true)
				if err != nil || view.Profile != nil || view.Revision != "" || f.KMS.Calls.Load() != before {
					t.Fatal("regained qualification must not revive revoked PII or KMS use", err)
				}
			})
		})
	}
}

func TestGrantCommittedIssueReceiptSurvivesTargetQualificationLoss(t *testing.T) {
	for _, loss := range []string{"assignment", "inactive"} {
		t.Run(loss, func(t *testing.T) {
			grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx := context.Background()
				request := managementRequest(f)
				command := grantCommand(f, "pii.read", "1")
				made, err := f.Authz.Issue(ctx, request, command)
				if err != nil {
					t.Fatal(err)
				}
				if loss == "assignment" {
					if err := f.Exec(ctx, "DELETE FROM capability_assignment WHERE org_id=? AND subject_id=? AND capability='pii.read'", "DELETE FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 AND capability='pii.read'", f.OrgID, f.Reader.SubjectID); err != nil {
						t.Fatal(err)
					}
				} else if err := f.Exec(ctx, "UPDATE subject SET active=0 WHERE org_id=? AND id=?", "UPDATE subject SET active=false WHERE org_id=$1 AND id=$2", f.OrgID, f.Reader.SubjectID); err != nil {
					t.Fatal(err)
				}
				if err := f.Exec(ctx, "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1", f.OrgID); err != nil {
					t.Fatal(err)
				}
				grants, receipts := f.Count(t, "access_grant"), f.Count(t, "grant_command_receipt")
				again, err := f.Authz.Issue(ctx, request, command)
				if err != nil || again != made {
					t.Fatal("current manager must recover original committed receipt after target qualification loss", err)
				}
				command.ExpectedRevision = "3"
				if _, err := f.Authz.Issue(ctx, request, command); !errors.Is(err, fault.Mismatch) {
					t.Fatal("same key with changed body must not return committed receipt", err)
				}
				if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
					t.Fatal("new issue still requires current target qualification", err)
				}
				if f.Count(t, "access_grant") != grants || f.Count(t, "grant_command_receipt") != receipts {
					t.Fatal("receipt recovery or refused new issue created a second grant or receipt")
				}
			})
		})
	}
}

func TestGrantCommandsRecheckCurrentIdentityQualificationAndApproval(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *testsupport.Fixture)
		want   error
	}{
		{"inactive manager", func(t *testing.T, f *testsupport.Fixture) {
			if err := f.Exec(context.Background(), "UPDATE subject SET active=0 WHERE org_id=? AND id=?", "UPDATE subject SET active=false WHERE org_id=$1 AND id=$2", f.OrgID, f.Manager.SubjectID); err != nil {
				t.Fatal(err)
			}
		}, fault.Unauthenticated},
		{"expired MFA exact boundary", func(t *testing.T, f *testsupport.Fixture) {
			if err := f.Exec(context.Background(), "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now), f.Manager.Hash); err != nil {
				t.Fatal(err)
			}
		}, fault.Forbidden},
		{"revoked management before stale epoch", func(t *testing.T, f *testsupport.Fixture) {
			if err := f.Exec(context.Background(), "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=?", "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2", f.OrgID, f.Manager.SubjectID); err != nil {
				t.Fatal(err)
			}
		}, fault.Forbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				request := managementRequest(f)
				command := grantCommand(f, "pii.read", "1")
				made, err := f.Authz.Issue(context.Background(), request, command)
				if err != nil {
					t.Fatal(err)
				}
				tc.mutate(t, f)
				before := f.Count(t, "grant_command_receipt")
				if _, err := f.Authz.Issue(context.Background(), request, command); !errors.Is(err, tc.want) {
					t.Fatal("replay must check current permission before returning old success", err)
				}
				command.ExpectedRevision = made.AuthEpoch
				if _, err := f.Authz.Issue(context.Background(), managementRequest(f), command); !errors.Is(err, tc.want) {
					t.Fatal("new grant must check current qualification", err)
				}
				if f.Count(t, "grant_command_receipt") != before {
					t.Fatal("refused command persisted receipt")
				}
			})
		})
	}
}

func TestGrantCurrentTimeStatesAndApprovalExpiry(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		original := f.Now
		employee := makeEmployee(t, f)
		command := grantCommand(f, "organization.read", "1")
		command.ValidFrom = original.Add(time.Minute).Format(time.RFC3339Nano)
		command.ExpiresAt = original.Add(2 * time.Minute).Format(time.RFC3339Nano)
		made, err := f.Authz.Issue(ctx, managementRequest(f), command)
		if err != nil || made.Status != "future" {
			t.Fatal("future fact must not be current", err)
		}
		for _, tc := range []struct {
			at    time.Time
			state string
		}{{original, "future"}, {original.Add(time.Minute), "current"}, {original.Add(2 * time.Minute), "expired"}} {
			f.Now = tc.at
			page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{GrantID: made.ID, State: tc.state, Limit: 1})
			if err != nil || len(page.Items) != 1 || page.Items[0].Status != tc.state {
				t.Fatal("half-open actual current time state incorrect", err)
			}
			calls := f.KMS.Calls.Load()
			view, err := f.Service.Read(ctx, f.Request(f.Reader), employee, "2026-01-01", true)
			if tc.state == "current" {
				if err != nil || view.Profile != nil || view.Revision != "" {
					t.Fatal("current metadata grant may expose only metadata", err)
				}
			} else if !errors.Is(err, fault.NotFound) || view.Profile != nil {
				t.Fatal("future/expired grant cannot be revived by historical as_of", err)
			}
			if f.KMS.Calls.Load() != calls {
				t.Fatal("metadata/future/expired reads must not reach KMS")
			}
		}
		// Keep session and manager grant current, but approved authority is exactly expired.
		f.Now = original.Add(24 * time.Hour)
		if err := f.Exec(ctx, "UPDATE session SET expires_at=?,idle_expires_at=?,mfa_until=? WHERE token_hash=?", "UPDATE session SET expires_at=$1,idle_expires_at=$2,mfa_until=$3 WHERE token_hash=$4", f.Repo.BindTime(f.Now.Add(time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)), f.Manager.Hash); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(ctx, "UPDATE access_grant SET expires_at=? WHERE subject_id=? AND capability='access_grant.manage'", "UPDATE access_grant SET expires_at=$1 WHERE subject_id=$2 AND capability='access_grant.manage'", f.Repo.BindTime(f.Now.Add(time.Hour)), f.Manager.SubjectID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{Limit: 10}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("expired authority must refuse despite current manager/session", err)
		}
	})
}

func TestGrantEpochAndRevisionCASAuditRollback(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		made := issueGrant(t, f, "organization.read", "1")
		before := f.Count(t, "access_grant")
		receipts := f.Count(t, "grant_command_receipt")
		audits := f.Count(t, "audit_event")
		if _, err := f.Authz.Issue(ctx, managementRequest(f), grantCommand(f, "pii.read", "1")); !errors.Is(err, fault.Conflict) {
			t.Fatal("stale epoch issue must conflict", err)
		}
		for _, cmd := range []authz.RevokeCommand{{ExpectedRevision: "2", ExpectedAuthEpoch: made.AuthEpoch, Reason: "policy_change"}, {ExpectedRevision: "1", ExpectedAuthEpoch: "1", Reason: "policy_change"}} {
			if _, err := f.Authz.Revoke(ctx, managementRequest(f), made.ID, cmd); !errors.Is(err, fault.Conflict) {
				t.Fatal("stale epoch/revision revoke must conflict", err)
			}
		}
		if f.Count(t, "access_grant") != before || f.Count(t, "grant_command_receipt") != receipts || f.Count(t, "audit_event") != audits {
			t.Fatal("CAS conflict persisted state")
		}
		if err := f.Exec(ctx, "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Authz.Revoke(ctx, managementRequest(f), made.ID, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: made.AuthEpoch, Reason: "policy_change"}); !errors.Is(err, fault.AuditUnavailable) {
			t.Fatal("revoke audit failure must fail closed", err)
		}
		row, err := f.Repo.Grant(ctx, f.OrgID, made.ID)
		if err != nil || row.Revision != "1" || row.Status != "current" || row.RevokedBy != nil {
			t.Fatal("failed audit must rollback revoke facts", err)
		}
		snapshot, err := f.Repo.Security(ctx, f.Manager.Hash, "", "")
		if err != nil || snapshot.AuthEpoch != 2 || f.Count(t, "grant_command_receipt") != receipts {
			t.Fatal("failed audit must rollback epoch and receipt", err)
		}
	})
}

func TestGrantTwoConnectionsSameEpochHaveOneWinner(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		second, err := store.Open(ctx, f.Backend, f.DSN)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		other := *f.Authz
		other.Store = second
		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		go func() {
			held <- f.Repo.WithGrantTx(ctx, f.OrgID, func(tx authz.Tx) error {
				close(locked)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		select {
		case <-locked:
		case <-ctx.Done():
			t.Fatal("real guard was not acquired")
		}
		ready, start := make(chan struct{}, 2), make(chan struct{})
		done := make(chan error, 2)
		for _, service := range []*authz.Service{f.Authz, &other} {
			go func(service *authz.Service) {
				request := managementRequest(f)
				cmd := grantCommand(f, "organization.read", "1")
				ready <- struct{}{}
				<-start
				_, err := service.Issue(ctx, request, cmd)
				done <- err
			}(service)
		}
		for range 2 {
			<-ready
		}
		close(start)
		close(release)
		if err := <-held; err != nil {
			t.Fatal(err)
		}
		success, conflict := 0, 0
		for range 2 {
			select {
			case err := <-done:
				if err == nil {
					success++
				} else if errors.Is(err, fault.Conflict) {
					conflict++
				} else {
					t.Fatal("unexpected concurrent result", err)
				}
			case <-ctx.Done():
				t.Fatal("real concurrent grant requests timed out")
			}
		}
		if success != 1 || conflict != 1 || f.Count(t, "grant_command_receipt") != 1 {
			t.Fatal("same epoch must commit exactly one real receipt")
		}
	})
}

func TestGrantRevokeCommitsBeforeOngoingSensitiveRelease(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		id := makeEmployee(t, f)
		metadata := issueGrant(t, f, "organization.read", "1")
		pii := issueGrant(t, f, "pii.read", metadata.AuthEpoch)
		arrived, release := make(chan struct{}), make(chan struct{})
		f.KMS.BlockNextDecrypt(arrived, release)
		type outcome struct {
			view organization.View
			err  error
		}
		done := make(chan outcome, 1)
		go func() {
			v, err := f.Service.Read(ctx, f.Request(f.Reader), id, "2026-01-01", true)
			done <- outcome{v, err}
		}()
		select {
		case <-arrived:
		case <-ctx.Done():
			close(release)
			t.Fatal("actual KMS decrypt did not reach barrier")
		}
		second, err := store.Open(ctx, f.Backend, f.DSN)
		if err != nil {
			close(release)
			t.Fatal(err)
		}
		defer second.Close()
		other := *f.Authz
		other.Store = second
		if _, err := other.Revoke(ctx, managementRequest(f), pii.ID, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: pii.AuthEpoch, Reason: "access_no_longer_required"}); err != nil {
			close(release)
			t.Fatal("real revoke must commit outside KMS transaction", err)
		}
		close(release)
		select {
		case out := <-done:
			if !errors.Is(out.err, fault.Forbidden) || out.view.Profile != nil {
				t.Fatal("revocation linearization must fence already-decrypting sensitive read", out.err)
			}
		case <-ctx.Done():
			t.Fatal("release did not finish")
		}
		var allowedReads int
		if err := f.Repo.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit_event WHERE operation='OP-ORG-06' AND outcome='allowed'").Scan(&allowedReads); err != nil || allowedReads != 0 {
			t.Fatal("refused release must not record successful disclosure", err)
		}
	})
}

func seedManagerFacts(t *testing.T, f *testsupport.Fixture, credential testsupport.Credential, org, approver string, scope authz.Scope) string {
	t.Helper()
	ctx := context.Background()
	var employee any
	if scope.Kind == "employee" {
		employee = scope.ID
	}
	if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES(?,?,'access_grant.manage',?,?,?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id) VALUES($1,$2,'access_grant.manage',$3,$4,$5)", org, credential.SubjectID, scope.Kind, scope.ID, employee); err != nil {
		t.Fatal(err)
	}
	if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,'access_grant.manage','audit',?,?,?,'security_administration',?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,'access_grant.manage','audit',$4,$5,$6,'security_administration',$7,$8,true)", value.NewID(), org, credential.SubjectID, scope.Kind, scope.ID, employee, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	id := value.NewID()
	if err := f.Exec(ctx, "INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,'organization.read','metadata',?,?,?,'organization_management',?,?,1,?,?,'synthetic-test-policy')", "INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES($1,$2,$3,'organization.read','metadata',$4,$5,$6,'organization_management',$7,$8,true,$9,$10,'synthetic-test-policy')", id, org, credential.SubjectID, scope.Kind, scope.ID, employee, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)), approver, f.Repo.BindTime(f.Now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGrantCursorCannotMoveToAnotherCurrentSubjectOrOrganization(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{Limit: 1})
		if err != nil || page.NextCursor == nil {
			t.Fatal("real visible list must produce continuation", err)
		}
		seedManagerFacts(t, f, f.Observer, f.OrgID, f.Approver.SubjectID, authz.Scope{Kind: "org", ID: f.OrgID})
		foreignApprover := value.NewID()
		if err := f.Exec(ctx, "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)", f.OtherOrgID, foreignApprover); err != nil {
			t.Fatal(err)
		}
		seedManagerFacts(t, f, f.OtherOwner, f.OtherOrgID, foreignApprover, authz.Scope{Kind: "org", ID: f.OtherOrgID})
		for _, credential := range []testsupport.Credential{f.Observer, f.OtherOwner} {
			request := authz.Request{TokenHash: credential.Hash, Purpose: authz.ManagementPurpose, RequestID: value.NewID()}
			if _, err := f.Authz.List(ctx, request, authz.Filter{Limit: 1, Cursor: *page.NextCursor}); !errors.Is(err, fault.Conflict) {
				t.Fatal("cursor must bind real current subject and org", err)
			}
		}
	})
}

func TestGrantEmployeeApprovalCannotAuthorizeOrgOrOtherEmployee(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		first, second := makeEmployee(t, f), makeEmployee(t, f)
		authority := seedManagerFacts(t, f, f.Observer, f.OrgID, f.Approver.SubjectID, authz.Scope{Kind: "employee", ID: first})
		request := authz.Request{TokenHash: f.Observer.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}
		command := grantCommand(f, "organization.read", "1")
		command.AuthorityID = authority
		for _, scope := range []authz.Scope{{Kind: "org", ID: f.OrgID}, {Kind: "employee", ID: second}} {
			command.Scope = scope
			if _, err := f.Authz.Issue(ctx, request, command); !errors.Is(err, fault.Forbidden) {
				t.Fatal("employee approved delegation cannot cover broader scope", err)
			}
		}
		command.Scope = authz.Scope{Kind: "employee", ID: first}
		made, err := f.Authz.Issue(ctx, request, command)
		if err != nil || made.Revision != "1" {
			t.Fatal("same canonical employee must be eligible", err)
		}
	})
}

func TestGrantRevokeReplayStillRequiresCurrentManagerAuthority(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		made := issueGrant(t, f, "organization.read", "1")
		request := managementRequest(f)
		command := authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: made.AuthEpoch, Reason: "policy_change"}
		result, err := f.Authz.Revoke(ctx, request, made.ID, command)
		if err != nil || result.Status != "revoked" {
			t.Fatal(err)
		}
		var observed int
		q := "SELECT count(*) FROM audit_event WHERE grant_id=? AND operation='OP-SEC-03' AND outcome='allowed'"
		if f.Backend == "postgres" {
			q = "SELECT count(*) FROM audit_event WHERE grant_id=$1 AND operation='OP-SEC-03' AND outcome='allowed'"
		}
		if err := f.Repo.DB.QueryRowContext(ctx, q, made.ID).Scan(&observed); err != nil || observed != 1 {
			t.Fatal("committed revoke must have typed allowed grant audit", err)
		}
		before := f.Count(t, "grant_command_receipt")
		if err := f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE subject_id=? AND capability='access_grant.manage'", "UPDATE access_grant SET revoked=true WHERE subject_id=$1 AND capability='access_grant.manage'", f.Manager.SubjectID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Authz.Revoke(ctx, request, made.ID, command); !errors.Is(err, fault.Forbidden) {
			t.Fatal("revoke replay cannot return historical success after current management loss", err)
		}
		if f.Count(t, "grant_command_receipt") != before {
			t.Fatal("denied replay must not create receipt")
		}
	})
}

func TestGrantRevisionIntervalAndReferenceBoundaries(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		for _, revision := range []string{"0", "01", "+1", "-1", "9223372036854775808", "1.0", " 1"} {
			cmd := grantCommand(f, "organization.read", revision)
			if _, err := f.Authz.Issue(context.Background(), managementRequest(f), cmd); !errors.Is(err, fault.Invalid) {
				t.Fatal("epoch must be exact canonical positive int64 decimal", err)
			}
		}
		nonNull := "synthetic-ref"
		for _, alter := range []func(*authz.IssueCommand){
			func(c *authz.IssueCommand) { c.ExpiresAt = c.ValidFrom },
			func(c *authz.IssueCommand) { c.ValidFrom = "2026-10-11T00:00:00.1234567Z" },
			func(c *authz.IssueCommand) { c.ValidFrom = "2026-10-11T00:00:00+00:00" },
			func(c *authz.IssueCommand) {
				c.RelationRef = &authz.RelationReference{Kind: "unknown", ID: value.NewID()}
				c.RelationBound = true
			},
			func(c *authz.IssueCommand) { c.ObjectRef = &nonNull },
			func(c *authz.IssueCommand) { c.Category = "financial" },
			func(c *authz.IssueCommand) { c.Purpose = "arbitrary_free_text" },
			func(c *authz.IssueCommand) { c.Scope.ID = "not-a-canonical-uuid" },
		} {
			cmd := grantCommand(f, "organization.read", "1")
			alter(&cmd)
			if _, err := f.Authz.Issue(context.Background(), managementRequest(f), cmd); !errors.Is(err, fault.Invalid) {
				t.Fatal("invalid command must reject without receipt", err)
			}
		}
		if f.Count(t, "grant_command_receipt") != 0 {
			t.Fatal("invalid boundary cases wrote receipt")
		}
	})
}

func TestGrantTwoConnectionsSameRevokeHaveOneWinner(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		made := issueGrant(t, f, "organization.read", "1")
		second, err := store.Open(ctx, f.Backend, f.DSN)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		other := *f.Authz
		other.Store = second
		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		go func() {
			held <- f.Repo.WithGrantTx(ctx, f.OrgID, func(tx authz.Tx) error {
				close(locked)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		select {
		case <-locked:
		case <-ctx.Done():
			t.Fatal("real guard was not acquired")
		}
		ready, start := make(chan struct{}, 2), make(chan struct{})
		done := make(chan error, 2)
		for _, service := range []*authz.Service{f.Authz, &other} {
			go func(service *authz.Service) {
				request := managementRequest(f)
				command := authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: made.AuthEpoch, Reason: "policy_change"}
				ready <- struct{}{}
				<-start
				_, err := service.Revoke(ctx, request, made.ID, command)
				done <- err
			}(service)
		}
		for range 2 {
			<-ready
		}
		close(start)
		close(release)
		if err := <-held; err != nil {
			t.Fatal(err)
		}
		success, conflict := 0, 0
		for range 2 {
			select {
			case err := <-done:
				if err == nil {
					success++
				} else if errors.Is(err, fault.Conflict) {
					conflict++
				} else {
					t.Fatal("unexpected concurrent revoke result", err)
				}
			case <-ctx.Done():
				t.Fatal("real concurrent revoke requests timed out")
			}
		}
		grant, err := f.Repo.Grant(ctx, f.OrgID, made.ID)
		if err != nil || success != 1 || conflict != 1 || grant.Revision != "2" || grant.Status != "revoked" || f.Count(t, "grant_command_receipt") != 2 {
			t.Fatal("same revision/epoch must commit exactly one revoke", err)
		}
	})
}

func TestGrantReadReleaseBeforeRevokeKeepsAlreadyDisclosedBoundary(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		id := makeEmployee(t, f)
		metadata := issueGrant(t, f, "organization.read", "1")
		pii := issueGrant(t, f, "pii.read", metadata.AuthEpoch)
		disclosed, err := f.Service.Read(ctx, f.Request(f.Reader), id, "2026-01-01", true)
		if err != nil || disclosed.Profile == nil {
			t.Fatal("real authorized release must finish", err)
		}
		if _, err := f.Authz.Revoke(ctx, managementRequest(f), pii.ID, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: pii.AuthEpoch, Reason: "policy_change"}); err != nil {
			t.Fatal(err)
		}
		calls := f.KMS.Calls.Load()
		f.KMS.Fail.Store(true)
		current, err := f.Service.Read(ctx, f.Request(f.Reader), id, "2026-01-01", true)
		if err != nil || current.Profile != nil || current.Revision != "" || f.KMS.Calls.Load() != calls {
			t.Fatal("new read must retain only authorized metadata after PII revoke", err)
		}
		if disclosed.Profile.DisplayName != "SYNTHETIC_GRANTED_PROFILE" {
			t.Fatal("system cannot retroactively erase already released consumer data")
		}
	})
}
