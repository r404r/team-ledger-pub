package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func maintenanceFile(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestIdentityCLIReallyBindsApprovedExistingSubjectAndRevokesOnUnbind(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			client, socket := startIdentityKeyd(t)
			issuer, sub := "https://approved-synthetic.invalid", "synthetic-cli-approved-sub"
			args := []string{"bind", "-backend", backend, "-dsn-file", maintenanceFile(t, "dsn", []byte(f.DSN), 0600), "-issuer", issuer, "-keyd-socket", socket, "-sub-file", maintenanceFile(t, "sub", []byte(sub), 0600), "-org-id", f.OrgID, "-subject-id", f.Owner.SubjectID, "-request-id", value.NewID()}
			if backend == "postgres" {
				u, err := url.Parse(f.DSN)
				if err != nil {
					t.Fatal(err)
				}
				args = append(args, "-postgres-ca-file", u.Query().Get("sslrootcert"))
			}
			subjects, grants := f.Count(t, "subject"), f.Count(t, "access_grant")
			if err := run(args); err != nil {
				t.Fatal("real maintenance bind failed:", err)
			}
			if f.Count(t, "subject") != subjects || f.Count(t, "access_grant") != grants {
				t.Fatal("binding cannot provision new subjects/grants")
			}
			if sources := f.Count(t, "identity_mapping_source"); sources != 1 {
				t.Fatalf("canonical identity source rows=%d", sources)
			}
			digestValue, err := identity.IdentityMAC(context.Background(), client, issuer, sub)
			if err != nil {
				t.Fatal(err)
			}
			digest := digestValue.Digest
			if err = f.Exec(context.Background(), "INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,acr,amr_json) VALUES(?,?,?,?,1,?,'','[]')", "INSERT INTO session_auth(token_hash,org_id,subject_id,identity_digest,key_version,created_at,acr,amr_json) VALUES($1,$2,$3,$4,1,$5,'','[]')", f.Owner.Hash, f.OrgID, f.Owner.SubjectID, digest, f.Repo.BindTime(f.Now)); err != nil {
				t.Fatal(err)
			}
			if _, err = f.Service.Session(context.Background(), f.Request(f.Owner), ""); err != nil {
				t.Fatal(err)
			}
			args[0] = "unbind"
			if err = run(args); err != nil {
				t.Fatal("real maintenance unbind failed:", err)
			}
			if _, err = f.Service.Session(context.Background(), f.Request(f.Owner), ""); err == nil {
				t.Fatal("CLI unbind must revoke existing actual consumers")
			}
			args[0] = "bind"
			if err = run(args); err != nil {
				t.Fatal(err)
			}
			if _, err = f.Service.Session(context.Background(), f.Request(f.Owner), ""); err == nil {
				t.Fatal("rebind cannot revive revoked historical session")
			}
			if f.Count(t, "subject") != subjects || f.Count(t, "access_grant") != grants {
				t.Fatal("maintenance cannot change business authority")
			}
		})
	}
}
func TestIdentityCLIRejectsMissingKeydAndUnknownOrInactiveSubject(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	_, socket := startIdentityKeyd(t)
	args := []string{"bind", "-backend", "sqlite", "-dsn-file", maintenanceFile(t, "dsn", []byte(f.DSN), 0600), "-issuer", "https://approved-synthetic.invalid", "-keyd-socket", socket, "-sub-file", maintenanceFile(t, "sub", []byte("synthetic-private-sub"), 0600), "-org-id", f.OrgID, "-subject-id", value.NewID(), "-request-id", value.NewID()}
	before := f.Count(t, "subject")
	missing := append([]string(nil), args...)
	missing[8] = filepath.Join(t.TempDir(), "missing.sock")
	if err := run(missing); err == nil {
		t.Fatal("missing local key service was accepted")
	}
	if err := run(args); err == nil {
		t.Fatal("unknown subject cannot be auto-provisioned")
	}
	if f.Count(t, "subject") != before || f.Count(t, "subject_identity") != 0 {
		t.Fatal("refused maintenance must preserve identities")
	}
	args[14] = f.Owner.SubjectID
	if err := f.Exec(context.Background(), "UPDATE subject SET active=0 WHERE org_id=? AND id=?", "UPDATE subject SET active=false WHERE org_id=$1 AND id=$2", f.OrgID, f.Owner.SubjectID); err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil {
		t.Fatal("inactive subject cannot be bound")
	}
	if f.Count(t, "subject_identity") != 0 {
		t.Fatal("inactive bind must not persist identity")
	}
}

func TestIdentityCLIRejectsUnsafePostgresTrustWithoutChangingIdentityFacts(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	u, err := url.Parse(f.DSN)
	if err != nil {
		t.Fatal("test DSN must be a PostgreSQL URL")
	}
	valid, err := configfile.Read(u.Query().Get("sslrootcert"), 1<<20, false)
	if err != nil {
		t.Fatal("test CA must satisfy the protected public-file policy")
	}
	caPath := maintenanceFile(t, "postgres-ca.pem", valid, 0600)
	_, socket := startIdentityKeyd(t)
	subPath := maintenanceFile(t, "sub", []byte("synthetic-cli-trust-subject"), 0600)
	for _, change := range []string{"mode", "mismatch", "writable", "malformed_bundle", "duplicate_mode", "ssl_alias"} {
		t.Run(change, func(t *testing.T) {
			if err := os.WriteFile(caPath, valid, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(caPath, 0600); err != nil {
				t.Fatal(err)
			}
			copyURL := *u
			q := copyURL.Query()
			q.Set("sslrootcert", caPath)
			switch change {
			case "mode":
				q.Set("sslmode", "verify-ca")
			case "mismatch":
				q.Set("sslrootcert", caPath+".undeclared")
			case "writable":
				if err := os.Chmod(caPath, 0666); err != nil {
					t.Fatal(err)
				}
			case "malformed_bundle":
				if err := os.WriteFile(caPath, append(append([]byte(nil), valid...), []byte("unapproved trust suffix")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate_mode":
				q.Add("sslmode", "verify-full")
			case "ssl_alias":
				q.Set("ssl", "true")
			}
			copyURL.RawQuery = q.Encode()
			args := []string{"bind", "-backend", "postgres", "-dsn-file", maintenanceFile(t, "dsn", []byte(copyURL.String()), 0600), "-postgres-ca-file", caPath, "-issuer", "https://approved-synthetic.invalid", "-keyd-socket", socket, "-sub-file", subPath, "-org-id", f.OrgID, "-subject-id", f.Owner.SubjectID, "-request-id", value.NewID()}
			identities, subjects, grants, audits := f.Count(t, "subject_identity"), f.Count(t, "subject"), f.Count(t, "access_grant"), f.Count(t, "audit_event")
			if err := run(args); err == nil {
				t.Fatal("unsafe PostgreSQL trust must prevent identity maintenance")
			}
			if f.Count(t, "subject_identity") != identities || f.Count(t, "subject") != subjects || f.Count(t, "access_grant") != grants || f.Count(t, "audit_event") != audits {
				t.Fatal("trust rejection must not change identities, business authority, or commit an audit")
			}
		})
	}
}
