package organization_test

import (
	"context"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestORG05CreateProtectedEmployee(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			request := f.Request(f.Owner)
			snapshot, err := f.Service.Session(context.Background(), request, "")
			if err != nil || !snapshot.Allows("pii.write", "pii", "", request.Purpose, f.Now) {
				t.Fatal("real authenticated, explicitly authorized fixture is required")
			}
			result, err := f.Service.Create(context.Background(), request, f.OrgID, organization.CreateCommand{
				Profile:   organization.Profile{LocalName: "SYNTHETIC_PROFILE_CREATE"},
				Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"},
			})
			if err != nil {
				t.Fatalf("authorized profile creation must commit and return revision 1: %v", err)
			}
			if !value.ValidID(result.ID) || result.Revision != "1" {
				t.Fatal("creation must return a stable UUID and revision 1")
			}
			if f.Count(t, "employee") != 1 || f.Count(t, "employee_profile_version") != 1 || f.Count(t, "command_receipt") != 1 {
				t.Fatal("creation must persist a complete employee, immutable version and receipt")
			}
		})
	}
}
