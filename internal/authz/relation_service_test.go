package authz_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func currentEpoch(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	s, err := f.Repo.Security(context.Background(), f.Manager.Hash, f.OrgID, "")
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(s.AuthEpoch, 10)
}

func changeReporting(t *testing.T, f *testsupport.Fixture, org string, actor testsupport.Credential, item organization.WorkforceChangeItem) organization.WorkforceChangeResult {
	t.Helper()
	ctx := context.Background()
	catalogs, err := f.Repo.WorkforceCatalogs(ctx, org, f.Now.Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	query := "SELECT workforce_revision FROM employee WHERE org_id=? AND id=?"
	if f.Backend == "postgres" {
		query = "SELECT workforce_revision FROM employee WHERE org_id=$1 AND id=$2"
	}
	var revision int64
	if err = f.Repo.DB.QueryRowContext(ctx, query, org, item.EmployeeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	result, err := f.Service.ChangeWorkforce(ctx, f.Request(actor), org, organization.WorkforceChangeCommand{
		ExpectedCatalogRevision:  catalogs.CatalogRevision,
		ExpectedGraphRevision:    catalogs.GraphRevision,
		ExpectedEmployeeRevision: map[string]string{item.EmployeeID: strconv.FormatInt(revision, 10)},
		Changes:                  []organization.WorkforceChangeItem{item},
	})
	if err != nil {
		t.Fatal("real atomic workforce relation change:", err)
	}
	return result
}

func bindRelationActor(t *testing.T, f *testsupport.Fixture, actor string) {
	t.Helper()
	if err := f.Exec(context.Background(), "INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES(?,?,?)", "INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES($1,$2,$3)", f.OrgID, f.Reader.SubjectID, actor); err != nil {
		t.Fatal(err)
	}
}

func TestRelationGrantOriginalReceiptSurvivesEndAndReplacementWithoutRevival(t *testing.T) {
	for _, action := range []string{"end", "replace"} {
		t.Run(action, func(t *testing.T) {
			grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx := context.Background()
				actor, employee := makeEmployee(t, f), makeEmployee(t, f)
				day := f.Now.Format("2006-01-02")
				from := f.Now.AddDate(0, 0, -2).Format("2006-01-02")
				reporting := "administrative"
				item := organization.WorkforceChangeItem{Action: "add", Kind: "reporting", EmployeeID: employee, ManagerEmployeeID: &actor, ReportingKind: &reporting, ValidFrom: &from}
				added := changeReporting(t, f, f.OrgID, f.Owner, item)
				ref := added.Items[0].ID
				bindRelationActor(t, f, actor)
				metadata := issueGrant(t, f, "organization.read", currentEpoch(t, f))
				independentCommand := grantCommand(f, "pii.read", metadata.AuthEpoch)
				independentCommand.Scope = authz.Scope{Kind: "employee", ID: employee}
				independent, err := f.Authz.Issue(ctx, managementRequest(f), independentCommand)
				if err != nil {
					t.Fatal(err)
				}
				command := grantCommand(f, "pii.read", independent.AuthEpoch)
				command.Scope, command.RelationBound, command.RelationRef = authz.Scope{Kind: "employee", ID: employee}, true, &authz.RelationReference{Kind: "reporting_line", ID: ref}
				request := managementRequest(f)
				issued, err := f.Authz.Issue(ctx, request, command)
				if err != nil {
					t.Fatal("qualified explicit relation issue:", err)
				}
				before, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
				if err != nil {
					t.Fatal(err)
				}
				var original authz.Grant
				for _, grant := range before.Grants {
					if grant.RelationBound {
						original = grant
					}
				}
				before.Grants = []authz.Grant{original}
				if !before.Allows("pii.read", "pii", employee, "organization_management", f.Now) {
					t.Fatal("real loaded relation did not authorize")
				}
				if action == "end" {
					changeReporting(t, f, f.OrgID, f.Owner, organization.WorkforceChangeItem{Action: "end", Kind: "reporting", Ref: &ref, EmployeeID: employee, EffectiveTo: &day})
				} else {
					item.Action, item.Ref, item.ValidFrom, item.EffectiveTo = "replace", &ref, &day, &day
					changeReporting(t, f, f.OrgID, f.Owner, item)
				}
				after, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
				if err != nil {
					t.Fatal(err)
				}
				after.Grants = []authz.Grant{original}
				if after.Allows("pii.read", "pii", employee, "organization_management", f.Now) {
					t.Fatal("old exact tenure revived after end/replacement")
				}
				view, err := f.Service.Read(ctx, f.Request(f.Reader), employee, from, true)
				if err != nil || view.Profile == nil {
					t.Fatal("independent original grant changed by reporting change", err)
				}
				if _, err = f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
					t.Fatal("new issue accepted ended or superseded tenure", err)
				}
				again, err := f.Authz.Issue(ctx, request, command)
				if err != nil || again != issued {
					t.Fatal("original receipt required current target relation", err)
				}
				command.ExpiresAt = f.Now.Add(2 * time.Hour).Format(time.RFC3339Nano)
				if _, err = f.Authz.Issue(ctx, request, command); !errors.Is(err, fault.Mismatch) {
					t.Fatal("changed command bypassed receipt digest before qualification", err)
				}
				revoked, err := f.Authz.Revoke(ctx, managementRequest(f), issued.ID, authz.RevokeCommand{ExpectedRevision: "1", ExpectedAuthEpoch: currentEpoch(t, f), Reason: "policy_change"})
				if err != nil || revoked.Status != "revoked" {
					t.Fatal("revoke incorrectly required current relation", err)
				}
				stored, err := f.Repo.Grant(ctx, f.OrgID, issued.ID)
				if err != nil || stored.RelationRef == nil || *stored.RelationRef != *original.RelationRef || stored.RelationActorEmployeeID != actor {
					t.Fatal("typed immutable relation provenance missing", err)
				}
			})
		})
	}
}

func TestRelationGrantNeedsApprovedExactActorAndRejectsForeignReferences(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		actor, employee := makeEmployee(t, f), makeEmployee(t, f)
		kind := "administrative"
		from := f.Now.AddDate(0, 0, -1).Format("2006-01-02")
		added := changeReporting(t, f, f.OrgID, f.Owner, organization.WorkforceChangeItem{Action: "add", Kind: "reporting", EmployeeID: employee, ManagerEmployeeID: &actor, ReportingKind: &kind, ValidFrom: &from})
		command := grantCommand(f, "pii.read", currentEpoch(t, f))
		command.Scope, command.RelationBound, command.RelationRef = authz.Scope{Kind: "employee", ID: employee}, true, &authz.RelationReference{Kind: "reporting_line", ID: added.Items[0].ID}
		if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
			t.Fatal("missing subject_employee correspondence accepted", err)
		}
		bindRelationActor(t, f, actor)
		wrong := command
		wrong.Scope.ID = actor
		if _, err := f.Authz.Issue(ctx, managementRequest(f), wrong); !errors.Is(err, fault.Forbidden) {
			t.Fatal("relation employee endpoint mismatch accepted", err)
		}
		foreignEmployee, err := f.Service.Create(ctx, f.Request(f.OtherOwner), f.OtherOrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "SYNTHETIC_FOREIGN"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
		if err != nil {
			t.Fatal(err)
		}
		foreignManager, err := f.Service.Create(ctx, f.Request(f.OtherOwner), f.OtherOrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "SYNTHETIC_FOREIGN_MANAGER"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
		if err != nil {
			t.Fatal(err)
		}
		foreign := changeReporting(t, f, f.OtherOrgID, f.OtherOwner, organization.WorkforceChangeItem{Action: "add", Kind: "reporting", EmployeeID: foreignEmployee.ID, ManagerEmployeeID: &foreignManager.ID, ReportingKind: &kind, ValidFrom: &from})
		wrong = command
		wrong.RelationRef = &authz.RelationReference{Kind: "reporting_line", ID: foreign.Items[0].ID}
		if _, err := f.Authz.Issue(ctx, managementRequest(f), wrong); !errors.Is(err, fault.Forbidden) {
			t.Fatal("foreign organization relation accepted", err)
		}
		if _, err := f.Authz.Issue(ctx, managementRequest(f), command); err != nil {
			t.Fatal("exact approved manager qualification rejected", err)
		}
	})
}

func TestScheduledRelationEndUsesServiceClockWithoutSQLCurrentTimestamp(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		f.Now = time.Date(f.Now.Year(), f.Now.Month(), f.Now.Day(), 23, 59, 0, 0, time.UTC)
		fromTime, toTime := f.Repo.BindTime(f.Now.Add(-24*time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour))
		if err := f.Exec(ctx, "UPDATE session SET expires_at=?,idle_expires_at=?,mfa_until=? WHERE org_id=?", "UPDATE session SET expires_at=$1,idle_expires_at=$2,mfa_until=$3 WHERE org_id=$4", toTime, toTime, toTime, f.OrgID); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(ctx, "UPDATE access_grant SET valid_from=?,expires_at=? WHERE org_id=?", "UPDATE access_grant SET valid_from=$1,expires_at=$2 WHERE org_id=$3", fromTime, toTime, f.OrgID); err != nil {
			t.Fatal(err)
		}
		for _, capability := range []string{"organization.read", "pii.read"} {
			id, category := value.NewID(), "metadata"
			if capability == "pii.read" {
				category = "pii"
			}
			if err := f.Exec(ctx,
				"INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,?,?,'org',?,'organization_management',?,?,1,?,?,'synthetic-midnight-policy')",
				"INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES($1,$2,$3,$4,$5,'org',$6,'organization_management',$7,$8,true,$9,$10,'synthetic-midnight-policy')",
				id, f.OrgID, f.Manager.SubjectID, capability, category, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), toTime, f.Approver.SubjectID, f.Repo.BindTime(f.Now.Add(-2*time.Hour))); err != nil {
				t.Fatal(err)
			}
			f.AuthorityIDs[capability] = id
		}
		actor, employee := makeEmployee(t, f), makeEmployee(t, f)
		reporting := "administrative"
		from := f.Now.AddDate(0, 0, -1).Format("2006-01-02")
		end := f.Now.AddDate(0, 0, 1).Format("2006-01-02")
		added := changeReporting(t, f, f.OrgID, f.Owner, organization.WorkforceChangeItem{Action: "add", Kind: "reporting", EmployeeID: employee, ManagerEmployeeID: &actor, ReportingKind: &reporting, ValidFrom: &from})
		ref := added.Items[0].ID
		bindRelationActor(t, f, actor)
		metadata := issueGrant(t, f, "organization.read", currentEpoch(t, f))
		command := grantCommand(f, "pii.read", metadata.AuthEpoch)
		command.Scope, command.RelationBound, command.RelationRef = authz.Scope{Kind: "employee", ID: employee}, true, &authz.RelationReference{Kind: "reporting_line", ID: ref}
		request := managementRequest(f)
		issued, err := f.Authz.Issue(ctx, request, command)
		if err != nil {
			t.Fatal(err)
		}
		changeReporting(t, f, f.OrgID, f.Owner, organization.WorkforceChangeItem{Action: "end", Kind: "reporting", Ref: &ref, EmployeeID: employee, EffectiveTo: &end})
		view, err := f.Service.Read(ctx, f.Request(f.Reader), employee, from, true)
		if err != nil || view.Profile == nil {
			t.Fatal("scheduled future relation end revoked too early", err)
		}
		f.Now = f.Now.Add(time.Minute)
		before := f.KMS.Calls.Load()
		view, err = f.Service.Read(ctx, f.Request(f.Reader), employee, from, true)
		if err != nil || view.Profile != nil || view.Revision != "" || f.KMS.Calls.Load() != before {
			t.Fatal("date boundary retained historical PII or reached KMS despite current end", err)
		}
		again, err := f.Authz.Issue(ctx, request, command)
		if err != nil || again != issued {
			t.Fatal("scheduled end boundary invalidated original issue receipt", err)
		}
		snapshot, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
		if err != nil {
			t.Fatal(err)
		}
		for _, tenure := range snapshot.Relations {
			if tenure.ID == ref && (tenure.ValidTo != nil || tenure.EffectiveTo == nil || *tenure.EffectiveTo != end) {
				t.Fatal("nominal approval interval was not retained separately from effective end")
			}
		}
	})
}
