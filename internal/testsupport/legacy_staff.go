package testsupport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func LegacyStaffMAC(f *Fixture) store.StaffCodeMAC {
	if f.Service.StaffCodeMAC != nil {
		return f.Service.StaffCodeMAC
	}
	return func(_ context.Context, b []byte) (sensitive.MACValue, error) {
		h := hmac.New(sha256.New, f.DigestKey)
		h.Write(b)
		return sensitive.MACValue{KeyID: "legacy-process-key", Version: 1, Digest: h.Sum(nil)}, nil
	}
}

func SeedLegacyStaffIdentifier(t testing.TB, f *Fixture, employee, code, from string, to *string) string {
	t.Helper()
	ctx := context.Background()
	if employee == "" {
		r, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "Synthetic Migration Employee"}, Lifecycle: organization.Lifecycle{ValidFrom: "2020-01-01"}})
		if err != nil {
			t.Fatal(err)
		}
		employee = r.ID
	}
	id, payloadID, changeID := value.NewID(), value.NewID(), value.NewID()
	binding := sensitive.Context{OrgID: f.OrgID, EmployeeID: employee, RecordID: id, VersionID: payloadID, ObjectKind: "employee_identifier", Purpose: "pii", SchemaType: "pii.employee_identifier.v1", SchemaVersion: 1}
	plain, _ := json.Marshal(map[string]string{"staff_code": code})
	env, err := f.Service.Cipher.Seal(ctx, binding, plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := LegacyStaffMAC(f)(ctx, []byte("staff-code\x00"+f.OrgID+"\x00"+code))
	exec := func(q string, args ...any) {
		t.Helper()
		if f.Backend == "postgres" {
			q = PostgresPlaceholders(q)
		}
		if _, e := f.Repo.DB.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	at := f.Repo.BindTime(f.Now)
	exec("INSERT INTO structure_change(org_id,id,subject_id,recorded_at,graph_before,graph_after,catalog_before,catalog_after) VALUES(?,?,?,?,1,1,1,1)", f.OrgID, changeID, f.Owner.SubjectID, at)
	exec("INSERT INTO workforce_payload(org_id,id,owner_kind,owner_id,employee_id,record_id,version_id,purpose,schema_type,schema_version,format_version,algorithm,dek_id,kek_id,kek_version,wrapped_dek,sealed_bytes,created_at) VALUES(?,?,'employee_identifier',?,?,?,?,'pii','pii.employee_identifier.v1',1,?,?,?,?,?,?,?,?)", f.OrgID, payloadID, id, employee, id, payloadID, env.FormatVersion, env.Algorithm, env.DEKID, env.Key.KEKID, env.Key.Version, env.Key.Data, env.SealedBytes, at)
	exec("INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) VALUES(?,'staff_code',?,?,?,?,?) ON CONFLICT DO NOTHING", f.OrgID, mac.KeyID, mac.Version, mac.Digest, employee, at)
	exec("INSERT INTO employee_business_identifier(org_id,id,employee_id,lookup_key_id,lookup_key_version,lookup_digest,payload_id,valid_from,valid_to,recorded_at,change_id,revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)", f.OrgID, id, employee, mac.KeyID, mac.Version, mac.Digest, payloadID, from, to, at, changeID)
	return employee
}

func PostgresPlaceholders(q string) string {
	out := ""
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			out += "$" + strconv.Itoa(n)
		} else {
			out += string(c)
		}
	}
	return out
}

func BuildSyntheticV19Fixture(t testing.TB, f *Fixture, migrationDir string) {
	t.Helper()
	ctx := context.Background()
	statements := []string{}
	if f.Backend == "sqlite" {
		statements = append(statements, "DROP TRIGGER staff_normalization_pending_insert", "DROP TRIGGER staff_normalization_pending_update", "DROP TRIGGER staff_normalization_immutable_update", "DROP TRIGGER staff_normalization_immutable_delete")
	} else {
		statements = append(statements, "DROP TRIGGER staff_normalization_pending ON employee_business_identifier", "DROP TRIGGER staff_normalization_immutable ON staff_code_normalization", "DROP FUNCTION staff_normalization_guard()")
	}
	statements = append(statements, "DROP VIEW staff_code_identifier", "DROP TABLE staff_code_normalization", "DROP TABLE staff_code_normalization_state", "DROP TABLE staff_code_normalization_receipt", "DELETE FROM schema_version WHERE version=20")
	ddl, err := os.ReadFile(filepath.Join(migrationDir, f.Backend+"_v19.sql"))
	if err != nil {
		t.Fatal(err)
	}
	statements = append(statements, strings.Split(string(ddl), "\n")[:4]...)
	tx, err := f.Repo.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
