package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func grantPIIExport(t *testing.T, f *testsupport.Fixture, employee string) string {
	t.Helper()
	var exportID string
	for _, capability := range []string{"pii.read", "sensitive.export"} {
		id := value.NewID()
		if err := f.Exec(context.Background(), "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id,team_id) VALUES(?,?,?,?,?,?,NULL)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id,employee_id,team_id) VALUES($1,$2,$3,$4,$5,$6,NULL) ON CONFLICT DO NOTHING", f.OrgID, f.Reader.SubjectID, capability, "employee", employee, employee); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(context.Background(), "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,employee_id,purpose,valid_from,expires_at,mfa_required) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)", id, f.OrgID, f.Reader.SubjectID, capability, "pii", "employee", employee, employee, "organization_management", f.Repo.BindTime(f.Now.Add(-time.Minute)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		if capability == "sensitive.export" {
			exportID = id
		}
	}
	return exportID
}

func TestPIIExportRequiresIndependentCurrentGrantAndExactRevisionAtRelease(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			created, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_EXPORT_PROFILE", WorkContact: &organization.Contact{Email: "only@example.test"}}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			grant := grantPIIExport(t, f, created.ID)
			request := f.Request(f.Reader)
			command := organization.ExportCommand{Format: "ndjson", Objects: []organization.ExportObject{{Kind: "employee_profile", ID: created.ID, ExpectedRevision: created.Revision}}}
			var events []map[string]any
			_, err = f.Service.ExportProfiles(ctx, request, command, func(event organization.ExportEvent) error {
				var decoded map[string]any
				if e := json.Unmarshal(event.EncodedJSON, &decoded); e != nil {
					return e
				}
				events = append(events, decoded)
				return nil
			})
			if err != nil || len(events) != 3 || events[1]["kind"] != "employee_profile" {
				t.Fatal("bounded pii export", events, err)
			}
			encoded, _ := json.Marshal(events)
			if !bytes.Contains(encoded, []byte("SYNTHETIC_EXPORT_PROFILE")) || !bytes.Contains(encoded, []byte("only@example.test")) {
				t.Fatal("selected profile missing", string(encoded))
			}
			request = f.Request(f.Reader)
			released := 0
			_, err = f.Service.ExportProfiles(ctx, request, command, func(event organization.ExportEvent) error {
				released++
				if released == 1 {
					return f.Exec(ctx, "UPDATE access_grant SET revoked=1,revision=revision+1,revoked_by=?,revoked_at=?,revoke_reason='policy_change' WHERE id=?", "UPDATE access_grant SET revoked=true,revision=revision+1,revoked_by=$1,revoked_at=$2,revoke_reason='policy_change' WHERE id=$3", f.Manager.SubjectID, f.Repo.BindTime(f.Now), grant)
				}
				return nil
			})
			if !errors.Is(err, fault.Forbidden) || released != 1 {
				t.Fatal("revoked export released profile", released, err)
			}
		})
	}
}
