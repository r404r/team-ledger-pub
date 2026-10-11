package organization_test

import (
	"errors"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
	"testing"
)

func graphFixture() organization.Graph {
	org := value.NewID()
	g := organization.Graph{OrgID: org, Revision: 1, AuthEpoch: 1}
	for range 3 {
		g.Teams = append(g.Teams, organization.Team{ID: value.NewID(), OrgID: org, Lifecycle: organization.Lifecycle{ValidFrom: "2020-01-01"}})
		g.Employees = append(g.Employees, organization.Employee{ID: value.NewID(), OrgID: org, Lifecycle: organization.Lifecycle{ValidFrom: "2020-01-01"}})
	}
	return g
}
func parentFact(g organization.Graph, child, parent int, from, to string) organization.Relation {
	l := organization.Lifecycle{ValidFrom: from}
	if to != "" {
		l.ValidTo = &to
	}
	return organization.Relation{ID: value.NewID(), OrgID: g.OrgID, Kind: "team_parent", TeamID: g.Teams[child].ID, ParentTeamID: g.Teams[parent].ID, Lifecycle: l}
}
func reportingFact(g organization.Graph, employee, manager int, kind, from, to string) organization.Relation {
	l := organization.Lifecycle{ValidFrom: from}
	if to != "" {
		l.ValidTo = &to
	}
	return organization.Relation{ID: value.NewID(), OrgID: g.OrgID, Kind: "reporting_line", EmployeeID: g.Employees[employee].ID, ManagerEmployeeID: g.Employees[manager].ID, ReportingKind: kind, Lifecycle: l}
}
func TestGraphChecksExistingIntermediateBoundaryAndFinalInfinity(t *testing.T) {
	for _, kind := range []string{"team_parent", "reporting_line"} {
		t.Run(kind, func(t *testing.T) {
			g := graphFixture()
			makeFact := func(a, b int, from, to string) organization.Relation {
				if kind == "team_parent" {
					return parentFact(g, a, b, from, to)
				}
				return reportingFact(g, a, b, "administrative", from, to)
			}
			g.Relations = []organization.Relation{makeFact(0, 1, "2026-01-01", "2030-01-01"), makeFact(1, 2, "2027-01-01", "2028-01-01"), makeFact(2, 0, "2026-01-01", "2030-01-01")}
			if !errors.Is(organization.ValidateGraph(g), fault.Invalid) {
				t.Fatal("intermediate pre-existing interval cycle accepted")
			}
			g.Relations = []organization.Relation{makeFact(0, 1, "2026-01-01", ""), makeFact(1, 2, "2027-01-01", ""), makeFact(2, 0, "2028-01-01", "")}
			if !errors.Is(organization.ValidateGraph(g), fault.Invalid) {
				t.Fatal("last unbounded segment cycle accepted")
			}
			g.Relations[2].Superseded = true
			if err := organization.ValidateGraph(g); err != nil {
				t.Fatal("immutable superseded tenure must not participate:", err)
			}
		})
	}
}
func TestGraphHalfOpenHandoffDottedPolicyAndEffectiveLifecycleContainment(t *testing.T) {
	g := graphFixture()
	g.Relations = []organization.Relation{reportingFact(g, 0, 1, "administrative", "2026-01-01", "2027-01-01"), reportingFact(g, 0, 2, "administrative", "2027-01-01", "")}
	if err := organization.ValidateGraph(g); err != nil {
		t.Fatal("half-open exact handoff rejected", err)
	}
	g.Relations = append(g.Relations, reportingFact(g, 1, 2, "dotted", "2026-01-01", ""), reportingFact(g, 2, 1, "dotted", "2026-01-01", ""))
	if err := organization.ValidateGraph(g); err != nil {
		t.Fatal("dotted cycle is not an administrative cycle", err)
	}
	g = graphFixture()
	r := organization.Relation{ID: value.NewID(), OrgID: g.OrgID, Kind: "membership", EmployeeID: g.Employees[0].ID, TeamID: g.Teams[0].ID, IsPrimary: true, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}, EffectiveTo: new("2027-01-01")}
	g.Teams[0].Lifecycle.ValidTo = new("2027-01-01")
	g.Relations = []organization.Relation{r}
	if err := organization.ValidateGraph(g); err != nil {
		t.Fatal("effective future end should allow matching lifecycle end", err)
	}
	g.Teams[0].Lifecycle.ValidTo = new("2026-12-31")
	if !errors.Is(organization.ValidateGraph(g), fault.Invalid) {
		t.Fatal("lifecycle cuts a still-effective relation")
	}
}
func TestGraphPrimaryOverlapAndOwnershipNeverRelaxed(t *testing.T) {
	for _, kind := range []string{"membership", "position"} {
		g := graphFixture()
		a := organization.Relation{ID: value.NewID(), OrgID: g.OrgID, Kind: kind, EmployeeID: g.Employees[0].ID, TeamID: g.Teams[0].ID, IsPrimary: true, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}
		b := a
		b.ID = value.NewID()
		b.TeamID = g.Teams[1].ID
		b.Lifecycle.ValidFrom = "2027-01-01"
		g.Relations = []organization.Relation{a, b}
		if !errors.Is(organization.ValidateGraph(g), fault.Invalid) {
			t.Fatal("overlapping primary accepted", kind)
		}
		g.Relations[0].EffectiveTo = new("2027-01-01")
		if err := organization.ValidateGraph(g); err != nil {
			t.Fatal("end/add transfer rejected", kind, err)
		}
		g.Relations[1].OrgID = value.NewID()
		if !errors.Is(organization.ValidateGraph(g), fault.Invalid) {
			t.Fatal("cross-org relation accepted", kind)
		}
	}
}
