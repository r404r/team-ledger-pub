package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func backends(t *testing.T, run func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, testsupport.NewHarness(t, backend)) })
	}
}
func create(t *testing.T, f *testsupport.Fixture, name string) organization.Result {
	t.Helper()
	result, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: name, WorkContact: &organization.Contact{Email: "synthetic@example.invalid"}}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("authorized setup creation failed:", err)
	}
	return result
}
func read(t *testing.T, f *testsupport.Fixture, id string) organization.View {
	t.Helper()
	v, err := f.Service.Read(context.Background(), f.Request(f.Owner), id, "2026-10-11", true)
	if err != nil {
		t.Fatal("authorized profile reload failed:", err)
	}
	return v
}

func TestProfileImmutableVersionsCASAndIdempotency(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		made := create(t, f, "SYNTHETIC_PROFILE_OLD")
		before := read(t, f, made.ID)
		if before.Profile == nil || before.Profile.DisplayName != "SYNTHETIC_PROFILE_OLD" || before.Revision != "1" {
			t.Fatal("created profile must reload exact saved fields and revision")
		}
		oldEmployee, err := f.Repo.Employee(ctx, made.ID)
		if err != nil {
			t.Fatal(err)
		}
		oldVersion, err := f.Repo.Version(ctx, f.OrgID, made.ID, oldEmployee.HeadID)
		if err != nil {
			t.Fatal(err)
		}
		request := f.Request(f.Owner)
		command := organization.UpdateCommand{ExpectedRevision: "1", Profile: organization.Profile{DisplayName: "SYNTHETIC_PROFILE_NEW"}, EditReason: "SYNTHETIC_PRIVATE_EDIT_REASON"}
		updated, err := f.Service.Update(ctx, request, made.ID, command)
		if err != nil || updated.Revision != "2" {
			t.Fatal("complete authorized replacement must commit revision2")
		}
		after := read(t, f, made.ID)
		if after.Profile == nil || after.Profile.DisplayName != command.Profile.DisplayName || after.Profile.WorkContact != nil || after.Revision != "2" {
			t.Fatal("complete replacement must reload new fields and clear omitted contact")
		}
		current, err := f.Repo.Employee(ctx, made.ID)
		if err != nil {
			t.Fatal(err)
		}
		newVersion, err := f.Repo.Version(ctx, f.OrgID, made.ID, current.HeadID)
		if err != nil || newVersion.SupersedesID != oldVersion.ID {
			t.Fatal("new immutable version must reference original same-employee version")
		}
		retained, err := f.Repo.Version(ctx, f.OrgID, made.ID, oldVersion.ID)
		if err != nil || !bytes.Equal(oldVersion.Envelope.SealedBytes, retained.Envelope.SealedBytes) {
			t.Fatal("original encrypted history was overwritten")
		}
		plain, err := f.Service.Cipher.Open(ctx, oldVersion.Envelope.Context, retained.Envelope)
		if err != nil {
			t.Fatal("authorized historic envelope must remain readable")
		}
		defer clear(plain)
		var old organization.ProfilePayload
		if json.Unmarshal(plain, &old) != nil || old.Profile.DisplayName != "SYNTHETIC_PROFILE_OLD" {
			t.Fatal("original history must retain old profile, not current replacement")
		}
		versions, audits := f.Count(t, "employee_profile_version"), f.Count(t, "audit_event")
		calls := f.KMS.Calls.Load()
		replay, err := f.Service.Update(ctx, request, made.ID, command)
		if err != nil || replay != updated {
			t.Fatal("same command key must confirm original commit before stale-revision rejection")
		}
		if f.Count(t, "employee_profile_version") != versions || f.Count(t, "audit_event") != audits || f.KMS.Calls.Load() != calls {
			t.Fatal("confirmed replay must not create another version/audit fact or touch KMS")
		}
		changed := command
		changed.Profile.DisplayName = "SYNTHETIC_CONFLICTING_REPLAY"
		if _, err = f.Service.Update(ctx, request, made.ID, changed); !errors.Is(err, fault.Mismatch) {
			t.Fatal("same key with different command must conflict")
		}
		if _, err = f.Service.Update(ctx, f.Request(f.Owner), made.ID, command); !errors.Is(err, fault.Conflict) {
			t.Fatal("independent command with stale revision must not overwrite")
		}
		if read(t, f, made.ID).Profile.DisplayName != "SYNTHETIC_PROFILE_NEW" || f.Count(t, "employee_profile_version") != 2 {
			t.Fatal("conflicts changed accepted profile/history")
		}
	})
}

func TestCreateReplayDoesNotCreateAnotherEmployee(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		request := f.Request(f.Owner)
		cmd := organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_CREATE_REPLAY"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}}
		first, err := f.Service.Create(ctx, request, f.OrgID, cmd)
		if err != nil {
			t.Fatal(err)
		}
		calls := f.KMS.Calls.Load()
		second, err := f.Service.Create(ctx, request, f.OrgID, cmd)
		if err != nil || first != second || f.Count(t, "employee") != 1 || f.KMS.Calls.Load() != calls {
			t.Fatal("creation replay must confirm original employee without another encrypted object")
		}
		cmd.Profile.DisplayName = "SYNTHETIC_DIFFERENT_COMMAND"
		if _, err = f.Service.Create(ctx, request, f.OrgID, cmd); !errors.Is(err, fault.Mismatch) {
			t.Fatal("creation key reused for different profile must conflict")
		}
	})
}

func TestCurrentAuthorizationPrecedesUnavailableKMS(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		id := create(t, f, "SYNTHETIC_AUTHORIZATION_MARKER").ID
		f.KMS.Fail.Store(true)
		before := f.KMS.Calls.Load()
		for _, c := range []testsupport.Credential{f.Stranger, f.OtherOwner} {
			if _, err := f.Service.Read(context.Background(), f.Request(c), id, "2026-10-11", true); !errors.Is(err, fault.NotFound) {
				t.Fatal("unreadable scope and cross-org object must return same safe rejection")
			}
		}
		observer, err := f.Service.Read(context.Background(), f.Request(f.Observer), id, "2026-10-11", true)
		if err != nil || observer.Profile != nil {
			t.Fatal("metadata reader cannot receive PII or trigger unavailable KMS")
		}
		if _, err = f.Service.Update(context.Background(), f.Request(f.Observer), id, organization.UpdateCommand{ExpectedRevision: "1", Profile: organization.Profile{DisplayName: "SYNTHETIC_DENIED_WRITE"}, EditReason: "synthetic"}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("metadata read never implies PII read/write")
		}
		missing := f.Request(f.Owner)
		missing.TokenHash = nil
		if _, err = f.Service.Read(context.Background(), missing, id, "2026-10-11", true); !errors.Is(err, fault.Unauthenticated) {
			t.Fatal("missing session must reject before KMS")
		}
		if f.KMS.Calls.Load() != before {
			t.Fatal("unauthorized request reached external KMS")
		}
		if _, err = f.Service.Read(context.Background(), f.Request(f.Owner), id, "2026-10-11", true); !errors.Is(err, fault.Unavailable) {
			t.Fatal("authorized read with unavailable KMS must fail closed")
		}
		if f.Count(t, "employee_profile_version") != 1 {
			t.Fatal("rejected accesses changed accepted history")
		}
	})
}

func TestExpiredGrantAndRevokedSessionCannotRestoreHistory(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		id := create(t, f, "SYNTHETIC_EXPIRY_MARKER").ID
		before := f.KMS.Calls.Load()
		ctx := context.Background()
		if err := f.Exec(ctx, "UPDATE access_grant SET expires_at=? WHERE subject_id=? AND category='pii'", "UPDATE access_grant SET expires_at=$1 WHERE subject_id=$2 AND category='pii'", f.Repo.BindTime(f.Now), f.Owner.SubjectID); err != nil {
			t.Fatal(err)
		}
		v, err := f.Service.Read(ctx, f.Request(f.Owner), id, "2026-01-01", true)
		if err != nil || v.Profile != nil {
			t.Fatal("historical as_of cannot revive currently expired PII grant")
		}
		if f.KMS.Calls.Load() != before {
			t.Fatal("expired grant reached KMS")
		}
		if err = f.Exec(ctx, "UPDATE session SET revoked=1 WHERE token_hash=?", "UPDATE session SET revoked=true WHERE token_hash=$1", f.Owner.Hash); err != nil {
			t.Fatal(err)
		}
		if _, err = f.Service.Read(ctx, f.Request(f.Owner), id, "2026-01-01", true); !errors.Is(err, fault.Unauthenticated) {
			t.Fatal("revoked opaque session cannot authorize historic object")
		}
	})
}

func TestPayloadTamperAndAuditFailureNeverReleasePlaintext(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		id := create(t, f, "SYNTHETIC_TAMPER_MARKER").ID
		emp, err := f.Repo.Employee(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		version, err := f.Repo.Version(ctx, f.OrgID, id, emp.HeadID)
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(version.Envelope.SealedBytes)
		tampered := bytes.Clone(original)
		tampered[len(tampered)-1] ^= 1
		if err = f.Exec(ctx, "UPDATE encrypted_payload SET sealed_bytes=? WHERE id=?", "UPDATE encrypted_payload SET sealed_bytes=$1 WHERE id=$2", tampered, version.ID); err != nil {
			t.Fatal(err)
		}
		v, err := f.Service.Read(ctx, f.Request(f.Owner), id, "2026-10-11", true)
		if !errors.Is(err, fault.Unavailable) || v.Profile != nil {
			t.Fatal("AEAD tamper must fail without partial profile")
		}
		if err = f.Exec(ctx, "UPDATE encrypted_payload SET sealed_bytes=? WHERE id=?", "UPDATE encrypted_payload SET sealed_bytes=$1 WHERE id=$2", original, version.ID); err != nil {
			t.Fatal(err)
		}
		if err = f.DisableAudit(ctx); err != nil {
			t.Fatal(err)
		}
		v, err = f.Service.Read(ctx, f.Request(f.Owner), id, "2026-10-11", true)
		if !errors.Is(err, fault.AuditUnavailable) || v.Profile != nil {
			t.Fatal("mandatory audit failure must prevent sensitive release")
		}
		_, err = f.Service.Update(ctx, f.Request(f.Owner), id, organization.UpdateCommand{ExpectedRevision: "1", Profile: organization.Profile{DisplayName: "SYNTHETIC_ROLLED_BACK"}, EditReason: "synthetic"})
		if !errors.Is(err, fault.AuditUnavailable) {
			t.Fatal("write audit failure must be explicit")
		}
		current, err := f.Repo.Employee(ctx, id)
		if err != nil || current.HeadID != emp.HeadID || current.Revision != 1 || f.Count(t, "employee_profile_version") != 1 || f.Count(t, "command_receipt") != 1 {
			t.Fatal("failed write audit left partial head/version/receipt")
		}
	})
}

func TestInvalidProfileAndLifecycleNeverPersistPartialEmployee(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		for _, cmd := range []organization.CreateCommand{
			{Profile: organization.Profile{}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}},
			{Profile: organization.Profile{DisplayName: "synthetic"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-02-30"}},
			{Profile: organization.Profile{DisplayName: "synthetic"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01", ValidTo: new("2026-01-01")}},
		} {
			if _, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, cmd); !errors.Is(err, fault.Invalid) {
				t.Fatal("invalid profile/date must reject with safe input error")
			}
		}
		if f.Count(t, "employee") != 0 || f.Count(t, "employee_profile_version") != 0 || f.Count(t, "command_receipt") != 0 {
			t.Fatal("invalid command created partial employee/history/receipt")
		}
	})
}

func TestSQLiteFileAndWALDoNotContainSyntheticProfile(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	id := create(t, f, "SYNTHETIC_PII_FILE_STORAGE_MARKER").ID
	_ = read(t, f, id)
	for _, path := range []string{f.DSN, f.DSN + "-wal"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("real SQLite storage observation failed")
		}
		if bytes.Contains(data, []byte("SYNTHETIC_PII_FILE_STORAGE_MARKER")) {
			t.Fatal("synthetic plaintext leaked into actual SQLite file/WAL")
		}
	}
}

func TestCurrentMFAPolicyIsEvaluatedBeforeDecrypt(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		id := create(t, f, "SYNTHETIC_MFA_MARKER").ID
		before := f.KMS.Calls.Load()
		if err := f.Exec(ctx, "UPDATE access_grant SET mfa_required=1 WHERE subject_id=? AND category='pii'", "UPDATE access_grant SET mfa_required=true WHERE subject_id=$1 AND category='pii'", f.Owner.SubjectID); err != nil {
			t.Fatal(err)
		}
		if err := f.Exec(ctx, "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now.Add(-time.Microsecond)), f.Owner.Hash); err != nil {
			t.Fatal(err)
		}
		v, err := f.Service.Read(ctx, f.Request(f.Owner), id, "2026-10-11", true)
		if err != nil || v.Profile != nil || f.KMS.Calls.Load() != before {
			t.Fatal("missing trusted fresh MFA cannot decrypt PII")
		}
	})
}

func TestWrongPurposeDenialRetainsOnlySafeAuditMetadata(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		id := create(t, f, "SYNTHETIC_PURPOSE_PROTECTED")
		request := f.Request(f.Owner)
		request.Purpose = "UNTRUSTED_PURPOSE_MUST_NOT_BE_STORED"
		before := f.Count(t, "audit_event")
		calls := f.KMS.Calls.Load()
		view, err := f.Service.Read(context.Background(), request, id.ID, "2026-10-11", true)
		if !errors.Is(err, fault.NotFound) || view.Profile != nil || f.KMS.Calls.Load() != calls {
			t.Fatal("wrong purpose must deny without releasing PII or reaching KMS")
		}
		if f.Count(t, "audit_event") != before+1 {
			t.Fatal("authorization denial lost its safe audit event")
		}
		var n int
		query := "SELECT count(*) FROM audit_event WHERE outcome='denied' AND operation='OP-ORG-06' AND purpose='' AND employee_id IS NULL"
		if err := f.Repo.DB.QueryRow(query).Scan(&n); err != nil || n != 1 {
			t.Fatal("denial audit must omit unknown purpose and hidden employee")
		}
	})
}
