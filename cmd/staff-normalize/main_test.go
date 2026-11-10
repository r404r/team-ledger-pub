package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNormalizeCLIRejectsMissingOrUnsupportedSourceBeforeOpeningDatabase(t *testing.T) {
	for _, args := range [][]string{nil, {"-source-commit", "unknown"}, {"-source-commit", supportedSourceCommit, "-apply"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out); err == nil {
			t.Fatal("unsafe invocation accepted")
		}
		if out.Len() != 0 {
			t.Fatal("invalid invocation exposed output")
		}
	}
}

func serveNormalizationKeyd(t *testing.T, dir, socket string) *sensitive.KeydClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sensitive.ServeKeyd(ctx, sensitive.KeydServerConfig{KeyDirectory: dir, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}, MaintenanceUIDs: []uint32{uint32(os.Geteuid())}})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("keyd shutdown failed")
		}
	})
	client := &sensitive.KeydClient{Socket: socket, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Ready(context.Background()); err == nil {
			return client
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("keyd readiness failed")
	return nil
}

func TestBuiltNormalizeCLIUpgradesRestoredV19WithRestoredOfflineKeys(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "staff-normalize")
	if data, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s", data)
	}
	apiBinary := filepath.Join(t.TempDir(), "api")
	if data, err := exec.Command("go", "build", "-o", apiBinary, "../api").CombinedOutput(); err != nil {
		t.Fatalf("API build failed: %s", data)
	}
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			f := testsupport.NewHarness(t, backend)
			if err := f.Exec(ctx, "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,?)", "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,$1)", f.Repo.BindTime(f.Now)); err != nil {
				t.Fatal("identity fixture", err)
			}

			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			parent, err := os.MkdirTemp(home, ".tl-norm-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(parent) })
			dir, restoreDir := filepath.Join(parent, "keys"), filepath.Join(parent, "restore-keys")
			if err = sensitive.InitKeyDirectory(dir); err != nil {
				t.Fatal(err)
			}
			mediaA := filepath.Join(parent, "media-a")
			if err = os.Mkdir(mediaA, 0700); err != nil {
				t.Fatal(err)
			}
			if mediaRoot := os.Getenv("TEAMLEDGER_TEST_OFFLINE_MEDIA_DIR"); mediaRoot != "" {
				mediaB, e := os.MkdirTemp(mediaRoot, "tl-norm-")
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { os.RemoveAll(mediaB) })
				keyA, keyB := make([]byte, 32), make([]byte, 32)
				_, _ = rand.Read(keyA)
				_, _ = rand.Read(keyB)
				defer clear(keyA)
				defer clear(keyB)
				archiveA, archiveB := filepath.Join(mediaA, "keys.tlk"), filepath.Join(mediaB, "keys.tlk")
				if _, err = sensitive.ExportOfflinePair(dir, archiveA, archiveB, keyA, keyB, []byte("synthetic-normalization-host"), time.Now().UTC()); err != nil {
					t.Fatal("key export", err)
				}
				if _, err = sensitive.VerifyOfflinePair(archiveA, archiveB, keyA, keyB); err != nil {
					t.Fatal("key pair verify", err)
				}
				if _, err = sensitive.RestoreOfflineArchive(archiveA, restoreDir, keyA); err != nil {
					t.Fatal("key restore", err)
				}
			} else {
				// A protected synthetic key-directory backup exercises restore in
				// CI without pretending two directories are separate media.
				backupDir := filepath.Join(mediaA, "key-backup")
				copyFixtureKeys(t, dir, backupDir)
				copyFixtureKeys(t, backupDir, restoreDir)
			}
			keys := serveNormalizationKeyd(t, dir, filepath.Join(parent, "source.sock"))
			restoreKeys := serveNormalizationKeyd(t, restoreDir, filepath.Join(parent, "restore.sock"))
			wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainPIIPayload)
			if err != nil {
				t.Fatal(err)
			}
			f.Service.Cipher = sensitive.Cipher{Wrapper: wrapper}
			f.Service.StaffCodeMAC = func(ctx context.Context, b []byte) (sensitive.MACValue, error) {
				return keys.MAC(ctx, sensitive.DomainStaffCodeLookup, b)
			}
			employee := testsupport.SeedLegacyStaffIdentifier(t, f, "", "2213", "2020-01-01", nil)
			state, err := keys.Ready(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.VerifyOrInitializeCryptoState(ctx, state, f.Now); err != nil {
				t.Fatal(err)
			}
			testsupport.BuildSyntheticV19Fixture(t, f, "../../internal/store/migrations")
			restoredDSN := restoreNormalizationDatabase(t, f)
			dsnFile, restoreFile := filepath.Join(parent, "source.dsn"), filepath.Join(parent, "restore.dsn")
			if os.WriteFile(dsnFile, []byte(f.DSN), 0600) != nil || os.WriteFile(restoreFile, []byte(restoredDSN), 0600) != nil {
				t.Fatal("write DSN files")
			}
			args := []string{"-backend", backend, "-dsn-file", dsnFile, "-keyd-socket", keys.Socket, "-source-commit", supportedSourceCommit}
			if backend == "postgres" {
				u, _ := url.Parse(f.DSN)
				args = append(args, "-postgres-ca-file", u.Query().Get("sslrootcert"))
			}
			invoke := func(arguments []string, wantSuccess bool) store.StaffNormalizationReport {
				t.Helper()
				cmd := exec.Command(binary, arguments...)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				data, e := cmd.Output()
				if (e == nil) != wantSuccess {
					t.Fatalf("CLI result mismatch: %s report=%s", stderr.String(), data)
				}
				for _, marker := range []string{`"2213"`, "Synthetic Migration Employee", "synthetic-ci-test"} {
					if bytes.Contains(data, []byte(marker)) || bytes.Contains(stderr.Bytes(), []byte(marker)) {
						t.Fatal("CLI leaked private marker")
					}
				}
				var report store.StaffNormalizationReport
				if json.Unmarshal(data, &report) != nil {
					t.Fatal("invalid aggregate report")
				}
				return report
			}
			report := invoke(args, true)
			if report.Identifiers != 1 || report.ShortNumeric != 1 || report.Applied {
				t.Fatal("wrong preflight")
			}
			caPath := ""
			if backend == "postgres" {
				u, _ := url.Parse(f.DSN)
				caPath = u.Query().Get("sslrootcert")
			}
			restored, _, e := open(ctx, backend, restoreFile, caPath, true)
			if e != nil {
				t.Fatal("restore open", e)
			}
			restoredCipher, restoredMAC, e := maintenanceKeys(ctx, restored, restoreKeys)
			if e != nil {
				restored.Close()
				t.Fatal("restore keys", e)
			}
			proof, e := restored.NormalizeStaffCodes(ctx, restoredCipher, restoredMAC, store.StaffNormalizationOptions{})
			restored.Close()
			if e != nil || proof.Snapshot != report.Snapshot {
				t.Fatalf("restore proof failed: %v, %+v, source snapshot matches=%v", e, proof, proof.Snapshot == report.Snapshot)
			}
			applyArgs := append(append([]string{}, args...), "-apply", "-maintenance-confirmed", "-expected-snapshot", report.Snapshot, "-request-id", value.NewID(), "-restored-dsn-file", restoreFile, "-restored-keyd-socket", restoreKeys.Socket)
			if !invoke(applyArgs, true).Applied {
				t.Fatal("apply not acknowledged")
			}
			if !invoke(applyArgs, true).Applied {
				t.Fatal("exact retry failed")
			}
			if f.Count(t, "staff_code_normalization_receipt") != 1 {
				t.Fatal("repeat apply duplicated receipt")
			}
			canonical, _ := keys.MAC(ctx, sensitive.DomainStaffCodeLookup, []byte("staff-code\x00"+f.OrgID+"\x00"+"002213"))
			found, e := f.Repo.StaffCodeEmployeeID(ctx, f.OrgID, canonical.KeyID, canonical.Version, canonical.Digest, "2026-01-01")
			if e != nil || found != employee {
				t.Fatal("upgraded lookup failed")
			}
			if err = f.Repo.CheckSchema(ctx); err != nil {
				t.Fatal("upgraded API schema not ready")
			}
			smokeUpgradedStaffAccount(t, f, keys, employee)
			smokeUpgradedAPI(t, f, keys, apiBinary, parent, employee)

		})
	}
}

func restoreNormalizationDatabase(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	ctx := context.Background()
	if f.Backend == "sqlite" {
		snapshot := filepath.Join(t.TempDir(), "restored.db")
		if err := f.Repo.SQLiteSnapshot(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
		restored, err := store.Open(ctx, "sqlite", snapshot)
		if err != nil {
			t.Fatal(err)
		}
		restored.Close()
		for _, name := range []string{f.DSN, f.DSN + "-wal", snapshot} {
			raw, e := os.ReadFile(name)
			if e != nil && !os.IsNotExist(e) {
				t.Fatal("ciphertext leak inspection failed")
			}
			if bytes.Contains(raw, []byte("Synthetic Migration Employee")) || bytes.Contains(raw, []byte(`"staff_code":"2213"`)) {
				t.Fatal("database or WAL contains decrypted markers")
			}
		}
		return snapshot
	}
	container := os.Getenv("TEAMLEDGER_TEST_POSTGRES_CONTAINER")
	if container == "" {
		t.Fatal("disposable PostgreSQL container required for real dump/restore")
	}
	u, err := url.Parse(f.DSN)
	if err != nil {
		t.Fatal(err)
	}
	source := u.Query().Get("search_path")
	target := "restore_" + strings.ReplaceAll(value.NewID(), "-", "")
	database := strings.TrimPrefix(u.Path, "/")
	user := u.User.Username()
	dump, err := exec.Command("docker", "exec", container, "pg_dump", "-U", user, "-d", database, "--schema", source, "--no-owner", "--no-privileges").Output()
	if err != nil {
		t.Fatal("real pg_dump failed")
	}
	if bytes.Contains(dump, []byte("Synthetic Migration Employee")) || bytes.Contains(dump, []byte(`"staff_code":"2213"`)) {
		t.Fatal("database dump contains decrypted markers")
	}
	dump = bytes.ReplaceAll(dump, []byte(source), []byte(target))
	command := exec.Command("docker", "exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-U", user, "-d", database)
	command.Stdin = bytes.NewReader(dump)
	if _, err = command.Output(); err != nil {
		t.Fatal("real PostgreSQL restore failed")
	}
	t.Cleanup(func() { _, _ = f.Repo.DB.ExecContext(ctx, "DROP SCHEMA "+target+" CASCADE") })
	query := u.Query()
	query.Set("search_path", target)
	u.RawQuery = query.Encode()
	return u.String()
}

func copyFixtureKeys(t *testing.T, source, target string) {
	t.Helper()
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root.key", "keyring.bin", ".lock"} {
		raw, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0600)
		if name == "root.key" {
			mode = 0400
		}
		err = os.WriteFile(filepath.Join(target, name), raw, mode)
		clear(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func smokeUpgradedAPI(t *testing.T, f *testsupport.Fixture, keys *sensitive.KeydClient, binary, parent, employee string) {
	t.Helper()
	ctx := context.Background()
	if err := f.Repo.EnsureIdentityMode(ctx, "local", f.Now); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(f.Owner.Token)
	if err != nil {
		t.Fatal(err)
	}
	csrf, reference, err := identity.CSRFToken(ctx, keys, raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	csrfHash := sha256.Sum256([]byte(csrf))
	if err = f.Exec(ctx, "UPDATE session SET csrf_hash=?,csrf_key_id=?,csrf_version=? WHERE token_hash=?", "UPDATE session SET csrf_hash=$1,csrf_key_id=$2,csrf_version=$3 WHERE token_hash=$4", csrfHash[:], reference.KeyID, reference.Version, f.Owner.Hash); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(parent, "api.crt"), filepath.Join(parent, "api.key")
	cert := f.KMS.Server.TLS.Certificates[0]
	private, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600) != nil || os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600) != nil {
		t.Fatal("TLS fixture")
	}
	clear(private)
	web := filepath.Join(parent, "web")
	if err = os.Mkdir(web, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(web, "index.html"), []byte("<!doctype html><title>Synthetic Upgrade Smoke</title>"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "https://" + address
	childContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(childContext, binary)
	command.Env = os.Environ()
	for key, val := range map[string]string{"BACKEND": f.Backend, "DSN": f.DSN, "LISTEN": address, "PUBLIC_ORIGIN": origin, "TLS_CERT_FILE": certFile, "TLS_KEY_FILE": keyFile, "KEYD_SOCKET": keys.Socket, "WEB_DIR": web, "DEPLOYMENT_ID": "synthetic-upgrade", "COMPENSATION_POLICY_FILE": "", "IDENTITY_MODE": "local"} {
		command.Env = append(command.Env, "TEAMLEDGER_"+key+"="+val)
	}
	var logs bytes.Buffer
	command.Stdout = &logs
	command.Stderr = &logs
	if err = command.Start(); err != nil {
		t.Fatal("API start failed")
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("API diagnostic: %s", logs.String())
		}
		if bytes.Contains(logs.Bytes(), []byte("staff_code\":\"2213")) || bytes.Contains(logs.Bytes(), []byte("Synthetic Migration Employee")) {
			t.Error("API log leaked identifiers")
		}
	}()
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second} // isolated synthetic loopback TLS
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		res, e := client.Get(origin + "/health/live")
		if e == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("upgraded binary did not become ready")
	}
	send := func(method, path, body string, want int) []byte {
		t.Helper()
		request, e := http.NewRequest(method, origin+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		request.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: f.Owner.Token})
		request.Header.Set("Origin", origin)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		request.Header.Set("X-Access-Purpose", "organization_management")
		request.Header.Set("Idempotency-Key", value.NewID())
		res, e := client.Do(request)
		if e != nil {
			t.Fatal("API request failed")
		}
		defer res.Body.Close()
		data, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if e != nil || res.StatusCode != want {
			t.Fatalf("API smoke %s returned %d, expected %d", path, res.StatusCode, want)
		}
		return data
	}
	detail := send("GET", "/api/v1/employees/"+employee+"?as_of=2026-01-01&include_profile=true", "", 200)
	var view organization.View
	if json.Unmarshal(detail, &view) != nil || len(view.Identifiers) != 1 || view.Identifiers[0].StaffCode != "002213" {
		t.Fatal("API did not display migrated value")
	}
	migratedIdentifier := view.Identifiers[0].ID
	body := `{"profile":{"local_name":"Synthetic New Employee"},"lifecycle":{"valid_from":"2020-01-01","valid_to":null},"staff_code":"2214","expected_catalog_revision":"1","expected_graph_revision":"1"}`
	created := send("POST", "/api/v1/orgs/"+f.OrgID+"/employees", body, 201)
	var result organization.Result
	if json.Unmarshal(created, &result) != nil {
		t.Fatal("create result invalid")
	}
	detail = send("GET", "/api/v1/employees/"+result.ID+"?as_of=2026-01-01&include_profile=true", "", 200)
	if json.Unmarshal(detail, &view) != nil || view.Identifiers[0].StaffCode != "002214" {
		t.Fatal("new employee not normalized")
	}
	data := send("POST", "/api/v1/orgs/"+f.OrgID+"/employees/query", `{"as_of":"2026-01-01","include_profile":true,"q":"2213","limit":10}`, 200)
	var page organization.DirectoryPage
	if json.Unmarshal(data, &page) != nil || len(page.Items) != 1 || page.Items[0].ID != employee {
		t.Fatal("upgraded directory short search failed")
	}
	send("POST", "/api/v1/orgs/"+f.OrgID+"/employees", strings.Replace(body, "2214", "12345678901", 1), 422)
	day := f.Now.Format("2006-01-02")
	change := map[string]any{"expected_catalog_revision": "1", "expected_graph_revision": "1", "expected_employee_revisions": map[string]string{employee: "1"}, "changes": []map[string]string{{"action": "replace", "kind": "identifier", "ref": migratedIdentifier, "employee_id": employee, "staff_code": "2215", "valid_from": day, "effective_to": day}}}
	encoded, _ := json.Marshal(change)
	send("POST", "/api/v1/orgs/"+f.OrgID+"/workforce-changes", string(encoded), 201)
	detail = send("GET", "/api/v1/employees/"+employee+"?as_of="+day+"&include_profile=true", "", 200)
	if json.Unmarshal(detail, &view) != nil || view.Identifiers[0].StaffCode != "002215" {
		t.Fatal("post-upgrade staff replacement not normalized")
	}

}

func smokeUpgradedStaffAccount(t *testing.T, f *testsupport.Fixture, keys *sensitive.KeydClient, employee string) {
	t.Helper()
	ctx := context.Background()
	if err := f.Exec(ctx, "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'identity.manage','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'identity.manage','org',$3)", f.OrgID, f.Owner.SubjectID, f.OrgID); err != nil {
		t.Fatal(err)
	}
	if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,'identity.manage','audit','org',?,'security_administration',?,?,0,0,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,'identity.manage','audit','org',$4,'security_administration',$5,$6,false,false,true)", value.NewID(), f.OrgID, f.Owner.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	mfa, err := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMFA)
	if err != nil {
		t.Fatal(err)
	}
	username, err := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMapping)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewLocal(ctx, f.Repo, f.Repo, keys, sensitive.Cipher{Wrapper: mfa}, sensitive.Cipher{Wrapper: username})
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return f.Now }
	result, err := service.CreateLocalUser(ctx, identity.LocalUserRequest{SessionHash: f.Owner.Hash, Username: "synthetic.staff", InitialPassword: "synthetic temporary password", AccountType: "staff", StaffCode: "2213", Key: value.NewID(), RequestID: value.NewID()})
	if err != nil || result.EmployeeID != employee {
		t.Fatal("post-upgrade Staff account short lookup failed", err)
	}
}
