package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
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

	"github.com/r404r/team-ledger/internal/testsupport"
)

// Only the test executable dispatches this helper; the product has no test mode.
func TestAPIStartupChildProcess(t *testing.T) {
	if os.Getenv("TEAMLEDGER_TEST_API_CHILD") == "1" {
		main()
	}
}

func TestAPIStartupRequiresProtectedCredentialFiles(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			for _, tc := range []struct {
				name, unsafeFile string
				mode             os.FileMode
				accepts          bool
			}{
				{"owner_read_only", "", 0400, true},
				{"owner_read_write", "", 0600, true},
				{"public_csrf", "csrf.key", 0644, false},
				{"group_digest", "digest.key", 0640, false},
				{"public_cursor", "cursor.key", 0644, false},
				{"missing_cursor", "cursor.key", 0600, false},
				{"nonregular_cursor", "cursor.key", 0600, false},
				{"cursor_equals_csrf", "cursor.key", 0600, false},
				{"cursor_equals_digest", "cursor.key", 0600, false},
				{"public_kms_token", "kms.token", 0666, false},
				{"public_tls_private_key", "api.key", 0644, false},
				{"public_interview_token", "interview.token", 0644, false},
				{"missing_interview_token", "", 0600, false},
				{"interview_token_equals_pii", "", 0600, false},
				{"interview_key_equals_pii", "", 0600, false},
				{"public_writable_interview_ca", "interview-cert.pem", 0666, false},
				{"public_readable_interview_ca", "interview-cert.pem", 0644, true},
				{"public_read_only_ca", "cert.pem", 0444, true},
				{"public_readable_ca", "cert.pem", 0644, true},
				{"group_writable_ca", "cert.pem", 0660, false},
				{"public_writable_ca", "cert.pem", 0666, false},
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
					interviewCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.InterviewKMS.Server.TLS.Certificates[0].Certificate[0]})
					files := map[string][]byte{"csrf.key": f.CSRFKey, "digest.key": f.DigestKey, "cursor.key": f.CursorKey, "kms.token": []byte(f.KMS.Token), "interview.token": []byte(f.InterviewKMS.Token), "interview-cert.pem": interviewCert, "api.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "cert.pem": cert, "index.html": []byte("<!doctype html><title>Fixture</title>")}
					for name, data := range files {
						if name == "interview.token" {
							if tc.name == "missing_interview_token" {
								continue
							}
							if tc.name == "interview_token_equals_pii" {
								data = []byte(f.KMS.Token)
							}
						}
						if name == "cursor.key" {
							switch tc.name {
							case "missing_cursor":
								continue
							case "nonregular_cursor":
								if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
									t.Fatal(err)
								}
								continue
							case "cursor_equals_csrf":
								data = f.CSRFKey
							case "cursor_equals_digest":
								data = f.DigestKey
							}
						}
						mode := os.FileMode(0600)
						if tc.unsafeFile == "" {
							mode = tc.mode
						}
						if name == tc.unsafeFile {
							mode = tc.mode
						}
						path := filepath.Join(dir, name)
						if err := os.WriteFile(path, data, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, mode); err != nil {
							t.Fatal(err)
						}
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					address := listener.Addr().String()
					if err = listener.Close(); err != nil {
						t.Fatal(err)
					}
					origin := "https://" + address
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, executable, "-test.run=^TestAPIStartupChildProcess$")
					env := map[string]string{"BACKEND": backend, "DSN": f.DSN, "LISTEN": address, "PUBLIC_ORIGIN": origin, "TLS_CERT_FILE": filepath.Join(dir, "cert.pem"), "TLS_KEY_FILE": filepath.Join(dir, "api.key"), "CSRF_KEY_FILE": filepath.Join(dir, "csrf.key"), "DIGEST_KEY_FILE": filepath.Join(dir, "digest.key"), "KMS_URL": f.KMS.Server.URL, "KMS_KEY": "dev002-pii", "KMS_TOKEN_FILE": filepath.Join(dir, "kms.token"), "KMS_CA_FILE": filepath.Join(dir, "cert.pem"), "WEB_DIR": dir, "TEST_API_CHILD": "1"}
					env["CURSOR_KEY_FILE"] = filepath.Join(dir, "cursor.key")
					env["INTERVIEW_KMS_URL"] = f.InterviewKMS.Server.URL
					env["INTERVIEW_KMS_KEY"] = f.InterviewKMS.KeyName
					env["INTERVIEW_KMS_TOKEN_FILE"] = filepath.Join(dir, "interview.token")
					env["INTERVIEW_KMS_CA_FILE"] = filepath.Join(dir, "interview-cert.pem")
					if tc.name == "interview_key_equals_pii" {
						env["INTERVIEW_KMS_KEY"] = f.KMS.KeyName
					}
					command.Env = os.Environ()
					for name, value := range env {
						command.Env = append(command.Env, "TEAMLEDGER_"+name+"="+value)
					}
					var output bytes.Buffer
					command.Stdout = &output
					command.Stderr = &output
					if err := command.Start(); err != nil {
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
					client := *f.KMS.Server.Client()
					client.Timeout = 300 * time.Millisecond
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case err := <-exited:
							finished = true
							if tc.accepts {
								t.Fatal("protected configuration did not start actual API")
							}
							if err == nil || command.ProcessState.ExitCode() == 0 {
								t.Fatal("insecure file must fail startup")
							}
							for _, private := range []string{dir, f.DSN, f.KMS.Token, f.InterviewKMS.Token, string(f.CSRFKey), string(f.DigestKey), string(f.CursorKey), "-----BEGIN PRIVATE KEY-----"} {
								if strings.Contains(output.String(), private) {
									t.Fatal("startup error disclosed private configuration")
								}
							}
							return
						case <-ctx.Done():
							t.Fatal("API startup observation deadline exceeded")
						case <-ticker.C:
							request, err := http.NewRequestWithContext(ctx, "GET", origin+"/api/v1/session", nil)
							if err != nil {
								t.Fatal(err)
							}
							request.AddCookie(&http.Cookie{Name: "__Host-teamledger_session", Value: f.Owner.Token})
							response, err := client.Do(request)
							if err != nil {
								continue
							}
							var session struct {
								SubjectID string `json:"subject_id"`
							}
							decode := json.NewDecoder(response.Body).Decode(&session)
							_ = response.Body.Close()
							if !tc.accepts {
								t.Fatal("actual API accepted insecure credential-file permissions")
							}
							if response.StatusCode != 200 || decode != nil || session.SubjectID != f.Owner.SubjectID {
								t.Fatal("protected startup must serve actual authenticated session")
							}
							return
						}
					}
				})
			}
		})
	}
}
