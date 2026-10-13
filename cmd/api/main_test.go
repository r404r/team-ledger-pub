package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
)

type fixedIdentityMode struct {
	mode string
	err  error
}

func (f fixedIdentityMode) IdentityMode(context.Context) (string, error) {
	return f.mode, f.err
}

// Only the test executable dispatches this helper; the product has no test mode.
func TestAPIStartupChildProcess(t *testing.T) {
	if os.Getenv("TEAMLEDGER_TEST_API_CHILD") == "1" {
		main()
	}
}

func TestValidListenerScopes(t *testing.T) {
	for _, test := range []struct {
		name, address, scope string
		want                 bool
	}{
		{"host_loopback_ipv4", "127.0.0.1:8443", "", true},
		{"host_loopback_ipv6", "[::1]:8443", "", true},
		{"host_wildcard_rejected", "0.0.0.0:8443", "", false},
		{"container_wildcard_ipv4", "0.0.0.0:8443", "container", true},
		{"container_wildcard_ipv6", "[::]:8443", "container", true},
		{"container_interface_rejected", "192.0.2.10:8443", "container", false},
		{"container_loopback_rejected", "127.0.0.1:8443", "container", false},
		{"unknown_scope", "127.0.0.1:8443", "public", false},
		{"hostname_rejected", "localhost:8443", "", false},
		{"missing_port", "127.0.0.1", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validListener(test.address, test.scope); got != test.want {
				t.Fatalf("validListener(%q, %q) = %v, want %v", test.address, test.scope, got, test.want)
			}
		})
	}
}

func TestIdentityModeMatchesRuntimeDatabaseState(t *testing.T) {
	ctx := context.Background()
	if !identityModeMatches(ctx, fixedIdentityMode{mode: "local"}, "local") {
		t.Fatal("matching runtime identity mode rejected")
	}
	if identityModeMatches(ctx, fixedIdentityMode{mode: "oidc"}, "local") {
		t.Fatal("runtime identity mode drift accepted")
	}
	if identityModeMatches(ctx, fixedIdentityMode{err: context.Canceled}, "local") {
		t.Fatal("identity mode read failure accepted")
	}
}

func TestAPIStartupRequiresProtectedTLSAndLocalKeyd(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			modeTime := any(time.Now().UTC().UnixMicro())
			modeSQL := "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,?)"
			if backend == "postgres" {
				modeTime = time.Now().UTC()
				modeSQL = "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'local',1,$1)"
			}
			if _, err := f.Repo.DB.ExecContext(context.Background(), modeSQL, modeTime); err != nil {
				t.Fatal("identity mode fixture failed", err)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			keyParent, err := os.MkdirTemp(home, ".teamledger-api-keyd-test-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(keyParent)
			if err = os.Chmod(keyParent, 0700); err != nil {
				t.Fatal(err)
			}
			keyDirectory, socket := filepath.Join(keyParent, "keys"), filepath.Join(keyParent, "keyd.sock")
			if err = sensitive.InitKeyDirectory(keyDirectory); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name      string
				keyMode   os.FileMode
				startKeyd bool
				accepts   bool
			}{
				{"protected_local_keyd", 0600, true, true},
				{"owner_read_only_tls_key", 0400, true, true},
				{"public_tls_private_key", 0644, true, false},
				{"missing_local_keyd", 0600, false, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					dir := t.TempDir()
					certificate := f.KMS.Server.TLS.Certificates[0]
					key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
					if err != nil {
						t.Fatal("fixture private key encoding failed")
					}
					defer clear(key)
					cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
					if err = os.WriteFile(filepath.Join(dir, "api.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), tc.keyMode); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(filepath.Join(dir, "cert.pem"), cert, 0644); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Fixture</title>"), 0644); err != nil {
						t.Fatal(err)
					}
					// Every startup for this database uses the same persisted keyring.
					keyContext, stopKeys := context.WithCancel(context.Background())
					defer stopKeys()
					keyDone := make(chan error, 1)
					if tc.startKeyd {
						go func() {
							keyDone <- sensitive.ServeKeyd(keyContext, sensitive.KeydServerConfig{KeyDirectory: keyDirectory, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}})
						}()
						client := &sensitive.KeydClient{Socket: socket, Timeout: time.Second}
						deadline := time.Now().Add(3 * time.Second)
						for time.Now().Before(deadline) {
							if _, err = client.Ready(context.Background()); err == nil {
								break
							}
							time.Sleep(10 * time.Millisecond)
						}
						if err != nil {
							stopKeys()
							<-keyDone
							t.Fatal("keyd did not become ready", err)
						}
						defer func() { stopKeys(); <-keyDone }()
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					address := listener.Addr().String()
					_ = listener.Close()
					origin := "https://" + address
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, executable, "-test.run=^TestAPIStartupChildProcess$")
					env := map[string]string{"BACKEND": backend, "DSN": f.DSN, "LISTEN": address, "PUBLIC_ORIGIN": origin, "TLS_CERT_FILE": filepath.Join(dir, "cert.pem"), "TLS_KEY_FILE": filepath.Join(dir, "api.key"), "KEYD_SOCKET": socket, "WEB_DIR": dir, "TEST_API_CHILD": "1", "COMPENSATION_POLICY_FILE": "", "IDENTITY_MODE": "local"}
					command.Env = os.Environ()
					for name, value := range env {
						command.Env = append(command.Env, "TEAMLEDGER_"+name+"="+value)
					}
					var output bytes.Buffer
					command.Stdout, command.Stderr = &output, &output
					if err = command.Start(); err != nil {
						t.Fatal("actual API child launch failed")
					}
					exited := make(chan error, 1)
					go func() { exited <- command.Wait() }()
					finished := false
					defer func() {
						if !finished {
							_ = command.Process.Signal(syscall.SIGTERM)
							select {
							case <-exited:
							case <-time.After(3 * time.Second):
								_ = command.Process.Kill()
								<-exited
							}
						}
					}()
					client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 300 * time.Millisecond} // controlled loopback fixture
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case childErr := <-exited:
							finished = true
							if tc.accepts {
								t.Fatalf("protected local-keyd configuration did not start API: %s", output.String())
							}
							if childErr == nil || command.ProcessState.ExitCode() == 0 {
								t.Fatal("invalid startup configuration exited successfully")
							}
							for _, private := range []string{dir, f.DSN, keyDirectory, "-----BEGIN PRIVATE KEY-----"} {
								if strings.Contains(output.String(), private) {
									t.Fatal("startup error disclosed private configuration")
								}
							}
							return
						case <-ctx.Done():
							t.Fatal("API startup observation deadline exceeded")
						case <-ticker.C:
							request, requestErr := http.NewRequestWithContext(ctx, "GET", origin+"/health/live", nil)
							if requestErr != nil {
								t.Fatal(requestErr)
							}
							response, requestErr := client.Do(request)
							if requestErr != nil {
								continue
							}
							_ = response.Body.Close()
							if !tc.accepts {
								t.Fatal("API accepted invalid startup configuration")
							}
							if response.StatusCode != 200 {
								t.Fatalf("protected startup readiness status = %d", response.StatusCode)
							}
							return
						}
					}
				})
			}
		})
	}
}

func TestCompensationPolicyRejectsUnapprovedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"duplicate_approval", `{"enabled":true,"enabled":false}`},
		{"duplicate_currency", `{"enabled":false,"currencies":{"USD":2,"USD":0}}`},
		{"unknown_policy", `{"enabled":false,"allow_self_approval":true}`},
		{"missing_approval", `{}`},
		{"null_approval", `{"enabled":null}`},
		{"null_currency_scale", `{"enabled":false,"currencies":{"USD":null}}`},
		{"incomplete_active_policy", `{"enabled":true}`},
		{"trailing_policy", `{"enabled":false}{"enabled":true}`},
		{"invalid_utf8", "{\"enabled\":false,\"units\":[\"\xff\"]}"},
		{"invalid_currency_scale", `{"enabled":false,"currencies":{"USD":10}}`},
		{"unknown_tax_basis", `{"enabled":false,"tax_bases":["invented_tax"]}`},
		{"unknown_rounding_mode", `{"enabled":false,"rounding_modes":["invented_rounding"]}`},
		{"duplicate_units", `{"enabled":false,"units":["month","month"]}`},
		{"oversize", strings.Repeat(" ", 64<<10) + `{"enabled":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEAMLEDGER_COMPENSATION_POLICY_FILE", path)
			if _, err := compensationPolicy(); err == nil {
				t.Fatal("unapproved or malformed configuration accepted")
			}
		})
	}
	t.Run("writable_policy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(`{"enabled":false}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TEAMLEDGER_COMPENSATION_POLICY_FILE", path)
		if _, err := compensationPolicy(); err == nil {
			t.Fatal("mutable untrusted policy accepted")
		}
	})
}
