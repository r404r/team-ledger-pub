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

func createRelationTeam(t *testing.T, f *testsupport.Fixture, org string, actor testsupport.Credential) string {
	t.Helper()
	r, err := f.Service.CreateTeam(context.Background(), f.Request(actor), org, organization.CreateTeamCommand{Code: "relation_" + value.NewID(), Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("real team creation:", err)
	}
	return r.ID
}

func changeRelations(t *testing.T, f *testsupport.Fixture, items ...organization.StructureItem) organization.StructureResult {
	t.Helper()
	g, err := f.Repo.Graph(context.Background(), f.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.Service.ChangeStructure(context.Background(), f.Request(f.Owner), f.OrgID, organization.StructureCommand{ExpectedGraphRevision: strconv.FormatInt(g.Revision, 10), Changes: items})
	if err != nil {
		t.Fatal("real atomic relation change:", err)
	}
	return r
}

func bindRelationActor(t *testing.T, f *testsupport.Fixture, actor string) {
	t.Helper()
	if err := f.Exec(context.Background(), "INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES(?,?,?)", "INSERT INTO subject_employee(org_id,subject_id,employee_id) VALUES($1,$2,$3)", f.OrgID, f.Reader.SubjectID, actor); err != nil {
		t.Fatal(err)
	}
}

func TestRelationGrantOriginalReceiptSurvivesEndAndReplacementWithoutRevival(t *testing.T) {
	for _, kind := range []string{"reporting_line", "team_membership"} {
		for _, action := range []string{"end", "replace"} {
			t.Run(kind+"/"+action, func(t *testing.T) {
				grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
					ctx := context.Background()
					actor, employee := makeEmployee(t, f), makeEmployee(t, f)
					team := createRelationTeam(t, f, f.OrgID, f.Owner)
					day := f.Now.Format("2006-01-02")
					from := f.Now.AddDate(0, 0, -2).Format("2006-01-02")
					primary, reporting := true, "administrative"
					item := organization.StructureItem{Action: "add", Kind: "reporting_line", EmployeeID: &employee, ManagerEmployeeID: &actor, ReportingKind: &reporting, Lifecycle: &organization.Lifecycle{ValidFrom: from}}
					scope := authz.Scope{Kind: "employee", ID: employee}
					if kind == "team_membership" {
						employee = actor
						item = organization.StructureItem{Action: "add", Kind: "membership", EmployeeID: &actor, TeamID: &team, IsPrimary: &primary, Lifecycle: &organization.Lifecycle{ValidFrom: from}}
						scope = authz.Scope{Kind: "team", ID: team}
					}
					added := changeRelations(t, f, item)
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
					command.Scope, command.RelationBound, command.RelationRef = scope, true, &authz.RelationReference{Kind: kind, ID: ref}
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
					for _, g := range before.Grants {
						if g.RelationBound {
							original = g
						}
					}
					before.Grants = []authz.Grant{original}
					if !before.Allows("pii.read", "pii", employee, "organization_management", f.Now) {
						t.Fatal("real loaded relation did not authorize")
					}
					if action == "end" {
						changeRelations(t, f, organization.StructureItem{Action: "end", Kind: item.Kind, Ref: &ref, EndDate: &day})
					} else {
						item.Action, item.Ref = "replace", &ref
						changeRelations(t, f, item)
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
						t.Fatal("independent original grant changed by structural relation change", err)
					}
					if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
						t.Fatal("NEW issue accepted ended/superseded tenure", err)
					}
					again, err := f.Authz.Issue(ctx, request, command)
					if err != nil || again != issued {
						t.Fatal("original receipt required current target relation", err)
					}
					command.ExpiresAt = f.Now.Add(2 * time.Hour).Format(time.RFC3339Nano)
					if _, err := f.Authz.Issue(ctx, request, command); !errors.Is(err, fault.Mismatch) {
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
}

func TestRelationGrantNeedsApprovedExactActorAndRejectsForeignReferences(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		actor, employee := makeEmployee(t, f), makeEmployee(t, f)
		kind := "administrative"
		from := f.Now.AddDate(0, 0, -1).Format("2006-01-02")
		added := changeRelations(t, f, organization.StructureItem{Action: "add", Kind: "reporting_line", EmployeeID: &employee, ManagerEmployeeID: &actor, ReportingKind: &kind, Lifecycle: &organization.Lifecycle{ValidFrom: from}})
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
		foreignEmployee, err := f.Service.Create(ctx, f.Request(f.OtherOwner), f.OtherOrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_FOREIGN"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
		if err != nil {
			t.Fatal(err)
		}
		foreignManager, err := f.Service.Create(ctx, f.Request(f.OtherOwner), f.OtherOrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_FOREIGN_MANAGER"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
		if err != nil {
			t.Fatal(err)
		}
		graph, err := f.Repo.Graph(ctx, f.OtherOrgID)
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := f.Service.ChangeStructure(ctx, f.Request(f.OtherOwner), f.OtherOrgID, organization.StructureCommand{ExpectedGraphRevision: strconv.FormatInt(graph.Revision, 10), Changes: []organization.StructureItem{{Action: "add", Kind: "reporting_line", EmployeeID: &foreignEmployee.ID, ManagerEmployeeID: &foreignManager.ID, ReportingKind: &kind, Lifecycle: &organization.Lifecycle{ValidFrom: from}}}})
		if err != nil {
			t.Fatal(err)
		}
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

func TestTeamManagementIntersectionsFilterCurrentMembershipBeforeSQLLimit(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		member, outsider := makeEmployee(t, f), makeEmployee(t, f)
		team, otherTeam := createRelationTeam(t, f, f.OrgID, f.Owner), createRelationTeam(t, f, f.OrgID, f.Owner)
		primary := true
		from := f.Now.AddDate(0, 0, -2).Format("2006-01-02")
		added := changeRelations(t, f, organization.StructureItem{Action: "add", Kind: "membership", EmployeeID: &member, TeamID: &team, IsPrimary: &primary, Lifecycle: &organization.Lifecycle{ValidFrom: from}})
		var eligible authz.Result
		for _, scope := range []authz.Scope{{Kind: "org", ID: f.OrgID}, {Kind: "employee", ID: outsider}, {Kind: "team", ID: otherTeam}, {Kind: "employee", ID: member}} {
			command := grantCommand(f, "organization.read", currentEpoch(t, f))
			command.Scope = scope
			made, err := f.Authz.Issue(ctx, managementRequest(f), command)
			if err != nil {
				t.Fatal(err)
			}
			if scope.ID == member {
				eligible = made
			}
		}
		// Narrow current management grants, never rewrite immutable approvals.
		if err := f.Exec(ctx,
			"UPDATE access_grant SET revoked=1,revision=revision+1,revoked_by=?,revoked_at=?,revoke_reason='policy_change' WHERE org_id=? AND subject_id=? AND capability='access_grant.manage'",
			"UPDATE access_grant SET revoked=true,revision=revision+1,revoked_by=$1,revoked_at=$2,revoke_reason='policy_change' WHERE org_id=$3 AND subject_id=$4 AND capability='access_grant.manage'",
			f.Manager.SubjectID, f.Repo.BindTime(f.Now), f.OrgID, f.Manager.SubjectID); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(ctx,
			"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required,team_id) VALUES(?,?,?,'access_grant.manage','audit','team',?,'security_administration',?,?,0,0,1,?)",
			"INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required,team_id) VALUES($1,$2,$3,'access_grant.manage','audit','team',$4,'security_administration',$5,$6,false,false,true,$7)",
			value.NewID(), f.OrgID, f.Manager.SubjectID, team, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour)), team); err != nil {
			t.Fatal(err)
		}
		page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{SubjectID: f.Reader.SubjectID, Category: "metadata", Limit: 1})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != eligible.ID || page.NextCursor != nil {
			t.Fatal("hidden org/other team/nonmember rows affected exact current-member page", err)
		}
		if err := f.Exec(ctx, "UPDATE capability_assignment SET scope_kind='team',scope_id=?,team_id=?,employee_id=NULL WHERE org_id=? AND subject_id=? AND capability='pii.read'", "UPDATE capability_assignment SET scope_kind='team',scope_id=$1,team_id=$2,employee_id=NULL WHERE org_id=$3 AND subject_id=$4 AND capability='pii.read'", team, team, f.OrgID, f.Reader.SubjectID); err != nil {
			t.Fatal(err)
		}
		command := grantCommand(f, "pii.read", currentEpoch(t, f))
		command.Scope = authz.Scope{Kind: "employee", ID: member}
		made, err := f.Authz.Issue(ctx, managementRequest(f), command)
		if err != nil {
			t.Fatal("current membership must qualify employee subset of exact team standing/approval", err)
		}
		command.ExpectedRevision, command.Scope.ID = made.AuthEpoch, outsider
		if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, fault.Forbidden) {
			t.Fatal("team authorization covered nonmember employee", err)
		}
		day, ref := f.Now.Format("2006-01-02"), added.Items[0].ID
		changeRelations(t, f, organization.StructureItem{Action: "end", Kind: "membership", Ref: &ref, EndDate: &day})
		page, err = f.Authz.List(ctx, managementRequest(f), authz.Filter{SubjectID: f.Reader.SubjectID, Category: "metadata", Limit: 1})
		if err != nil || len(page.Items) != 0 || page.NextCursor != nil {
			t.Fatal("ended historical membership remained visible or affected cursor", err)
		}
		grant, err := f.Repo.Grant(ctx, f.OrgID, eligible.ID)
		if err != nil || grant.Status != "current" || grant.Scope.Kind != "employee" {
			t.Fatal("membership projection permanently rewrote independent approved grant", err)
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
		added := changeRelations(t, f, organization.StructureItem{Action: "add", Kind: "reporting_line", EmployeeID: &employee, ManagerEmployeeID: &actor, ReportingKind: &reporting, Lifecycle: &organization.Lifecycle{ValidFrom: from}})
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
		changeRelations(t, f, organization.StructureItem{Action: "end", Kind: "reporting_line", Ref: &ref, EndDate: &end})
		view, err := f.Service.Read(ctx, f.Request(f.Reader), employee, from, true)
		if err != nil || view.Profile == nil {
			t.Fatal("scheduled future relation end revoked too early", err)
		}
		f.Now = f.Now.Add(time.Minute)
		before := f.KMS.Calls.Load()
		view, err = f.Service.Read(ctx, f.Request(f.Reader), employee, from, true)
		if err != nil || view.Profile != nil || view.Revision != "" || f.KMS.Calls.Load() != before {
			t.Fatal("date boundary retained historical PII/reached KMS despite current end", err)
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
