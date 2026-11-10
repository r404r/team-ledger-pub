package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
)

func legacyStaffMAC(f *testsupport.Fixture) store.StaffCodeMAC { return testsupport.LegacyStaffMAC(f) }
func seedLegacyStaff(t *testing.T, f *testsupport.Fixture, employee, code, from string, to *string) string {
	return testsupport.SeedLegacyStaffIdentifier(t, f, employee, code, from, to)
}
func syntheticV19(t *testing.T, f *testsupport.Fixture) {
	testsupport.BuildSyntheticV19Fixture(t, f, "migrations")
}

func TestStaffNormalizationProjectsWithoutChangingHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			employee := seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
			seedLegacyStaff(t, f, "", "1234567", "2020-01-01", nil)
			seedLegacyStaff(t, f, "", "A123", "2020-01-01", nil)
			before := f.Count(t, "workforce_payload")
			report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil || report.Identifiers != 3 || report.ShortNumeric != 1 || report.NonNumeric != 1 {
				t.Fatalf("preflight: %+v %v", report, err)
			}
			if f.Count(t, "workforce_payload") != before {
				t.Fatal("dry run wrote payloads")
			}
			_, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot})
			if err != nil {
				t.Fatal(err)
			}
			mac, _ := legacyStaffMAC(f)(ctx, []byte("staff-code\x00"+f.OrgID+"\x00"+"002213"))
			found, err := f.Repo.StaffCodeEmployeeID(ctx, f.OrgID, mac.KeyID, mac.Version, mac.Digest, "2026-01-01")
			if err != nil || found != employee {
				t.Fatal("canonical lookup failed", err)
			}
			facts, err := f.Repo.EmployeeWorkforceFacts(ctx, f.OrgID, employee, "2026-01-01")
			if err != nil {
				t.Fatal(err)
			}
			payload, err := f.Repo.WorkforcePayload(ctx, f.OrgID, facts.Identifiers[0].PayloadID)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := f.Service.Cipher.Open(ctx, payload.Envelope.Context, payload.Envelope)
			if err != nil || string(plain) != "{\"staff_code\":\"002213\"}" {
				t.Fatal("canonical encrypted payload mismatch")
			}
			clear(plain)
			if f.Count(t, "employee_business_identifier") != 3 || f.Count(t, "employee_identifier_owner") != 4 {
				t.Fatal("history or old ownership lost")
			}
			if _, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot}); err != nil {
				t.Fatal("exact retry rejected", err)
			}
			after, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			count := f.Count(t, "workforce_payload")
			if _, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: after.Snapshot}); err != nil {
				t.Fatal(err)
			}
			if f.Count(t, "staff_code_normalization_receipt") != 1 {
				t.Fatal("missing immutable migration audit or repeat audit duplicated")
			}
			if f.Count(t, "workforce_payload") != count {
				t.Fatal("repeat apply not idempotent")
			}
		})
	}
}

func TestStaffNormalizationRejectsWholeBatch(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		for _, scenario := range []string{"conflict", "long", "overlap", "orphan", "corrupt", "drift"} {
			t.Run(backend+"/"+scenario, func(t *testing.T) {
				f := testsupport.NewHarness(t, backend)
				ctx := context.Background()
				emp := seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
				switch scenario {
				case "conflict":
					seedLegacyStaff(t, f, "", "002213", "2020-01-01", nil)
				case "long":
					seedLegacyStaff(t, f, "", "12345678901", "2020-01-01", nil)
				case "overlap":
					to := "2025-01-01"
					seedLegacyStaff(t, f, emp, "002213", "2021-01-01", &to)
				case "orphan":
					q := "INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) VALUES(?,'staff_code','legacy-process-key',1,?,?,?)"
					if backend == "postgres" {
						q = testsupport.PostgresPlaceholders(q)
					}
					if _, err := f.Repo.DB.ExecContext(ctx, q, f.OrgID, make([]byte, 32), emp, f.Repo.BindTime(f.Now)); err != nil {
						t.Fatal(err)
					}
				case "corrupt":
					if _, err := f.Repo.DB.ExecContext(ctx, "UPDATE workforce_payload SET sealed_bytes="+map[string]string{"sqlite": "zeroblob(40)", "postgres": "decode(repeat('00',40),'hex')"}[backend]+" WHERE owner_kind='employee_identifier'"); err != nil {
						t.Fatal(err)
					}
				}
				n := f.Count(t, "workforce_payload")
				report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
				if scenario == "drift" {
					if err != nil {
						t.Fatal(err)
					}
					seedLegacyStaff(t, f, "", "A12", "2020-01-01", nil)
					n++
				}
				_, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot})
				if err == nil {
					t.Fatal("unsafe migration accepted")
				}
				if f.Count(t, "workforce_payload") != n {
					t.Fatal("partial migration committed")
				}
			})
		}
	}
}

// syntheticV19 removes only v20 fixture objects from a disposable test database.
// It constructs the exact released v19 catalog before testing the forward path;
// it is never an operator downgrade or a production migration.

func TestStaffNormalizationUpgradesV19AndKeepsHistoricalReferences(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			end := "2023-01-01"
			emp := seedLegacyStaff(t, f, "", "2213", "2020-01-01", &end)
			seedLegacyStaff(t, f, emp, "002213", "2023-01-01", nil)
			syntheticV19(t, f)
			report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil || report.SchemaVersion != 19 {
				t.Fatal("valid v19 preflight", err)
			}
			before := f.Count(t, "structure_change")
			_, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot})
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.CheckSchema(ctx); err != nil {
				t.Fatal("upgraded schema not ready", err)
			}
			if f.Count(t, "structure_change") != before || f.Count(t, "employee_business_identifier") != 2 {
				t.Fatal("history references rewritten")
			}
			for _, day := range []string{"2021-01-01", "2024-01-01"} {
				facts, e := f.Repo.EmployeeWorkforceFacts(ctx, f.OrgID, emp, day)
				if e != nil || len(facts.Identifiers) != 1 {
					t.Fatal("history interval lost", e)
				}
				payload, e := f.Repo.WorkforcePayload(ctx, f.OrgID, facts.Identifiers[0].PayloadID)
				if e != nil {
					t.Fatal(e)
				}
				plain, e := f.Service.Cipher.Open(ctx, payload.Envelope.Context, payload.Envelope)
				if e != nil || !bytes.Contains(plain, []byte("002213")) {
					t.Fatal("historical projection not normalized")
				}
				clear(plain)
			}
		})
	}
}

func TestStaffNormalizationPendingFencesWritesAndRejectsUnknownChecksum(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
			syntheticV19(t, f)
			if err := f.Repo.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.CheckSchema(ctx); err == nil {
				t.Fatal("pending database accepted by API")
			}
			if _, err := f.Repo.DB.ExecContext(ctx, "UPDATE employee_business_identifier SET revision=revision"); err == nil {
				t.Fatal("pending database allowed writes")
			}
			report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.Repo.DB.ExecContext(ctx, "UPDATE schema_version SET checksum='unknown' WHERE version=19"); err != nil {
				t.Fatal(err)
			}
			if _, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{}); err == nil {
				t.Fatal("unknown source checksum accepted")
			}
		})
	}
}

type controlledStaffWrapper struct {
	sensitive.Wrapper
	wraps   int
	failAt  int
	entered chan struct{}
	release chan struct{}
	cancel  context.CancelFunc
}

func (w *controlledStaffWrapper) Wrap(ctx context.Context, key []byte) (sensitive.WrappedKey, error) {
	w.wraps++
	if w.wraps == 1 && w.entered != nil {
		close(w.entered)
		<-w.release
	}
	if w.wraps == w.failAt {
		if w.cancel != nil {
			w.cancel()
		}
		return sensitive.WrappedKey{}, sensitive.ErrUnavailable
	}
	return w.Wrapper.Wrap(ctx, key)
}

func TestStaffNormalizationCancellationRollsBackAndCanResume(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
			seedLegacyStaff(t, f, "", "2214", "2020-01-01", nil)
			syntheticV19(t, f)
			report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			before := f.Count(t, "workforce_payload")
			cancelled, cancel := context.WithCancel(ctx)
			defer cancel()
			wrapper := &controlledStaffWrapper{Wrapper: f.Service.Cipher.Wrapper, failAt: 2, cancel: cancel}
			if _, err = f.Repo.NormalizeStaffCodes(cancelled, sensitive.Cipher{Wrapper: wrapper}, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot}); err == nil {
				t.Fatal("interrupted apply succeeded")
			}
			// Close and reopen to exercise recovery through the actual database engine.
			if err = f.Repo.Close(); err != nil {
				t.Fatal(err)
			}
			f.Repo, err = store.Open(ctx, backend, f.DSN)
			if err != nil {
				t.Fatal(err)
			}
			version, checkErr := f.Repo.CheckMaintenanceSchema(ctx)
			if checkErr != nil || version != 19 || f.Count(t, "workforce_payload") != before {
				t.Fatal("cancelled transaction left partial writes")
			}
			if _, err = f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot}); err != nil {
				t.Fatal("resume failed", err)
			}
			if f.Count(t, "staff_code_normalization") != 2 {
				t.Fatal("resume incomplete")
			}
		})
	}
}

func TestStaffNormalizationRejectsConcurrentApply(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
			report, err := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{})
			if err != nil {
				t.Fatal(err)
			}
			wrapper := &controlledStaffWrapper{Wrapper: f.Service.Cipher.Wrapper, entered: make(chan struct{}), release: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				_, e := f.Repo.NormalizeStaffCodes(ctx, sensitive.Cipher{Wrapper: wrapper}, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot})
				result <- e
			}()
			select {
			case <-wrapper.entered:
			case err = <-result:
				t.Fatal("first apply never reached write boundary", err)
			}
			_, second := f.Repo.NormalizeStaffCodes(ctx, f.Service.Cipher, legacyStaffMAC(f), store.StaffNormalizationOptions{Apply: true, ExpectedSnapshot: report.Snapshot})
			close(wrapper.release)
			err = <-result
			if second == nil || err != nil {
				t.Fatal("concurrent apply guard failed", second, err)
			}
			if f.Count(t, "staff_code_normalization_receipt") != 1 {
				t.Fatal("duplicate audit receipt")
			}
		})
	}
}

func TestStaffUpgradeBackupManifestRetainsSourceSchemaVersion(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			seedLegacyStaff(t, f, "", "2213", "2020-01-01", nil)
			syntheticV19(t, f)
			manifest, err := f.Repo.BackupManifest(context.Background(), f.Now, 0, strings.Repeat("0", 64))
			if err != nil || manifest.SchemaVersion != 19 {
				t.Fatal("source backup mislabeled as target schema", manifest.SchemaVersion, err)
			}
		})
	}
}
