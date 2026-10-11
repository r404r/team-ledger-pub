package testsupport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

type Credential struct {
	SubjectID, Token, CSRF string
	Hash                   []byte
}
type Fixture struct {
	Repo                                  *store.Repository
	Service                               *organization.Service
	Authz                                 *authz.Service
	AuthorityIDs                          map[string]string
	Manager, Reader, Approver             Credential
	CursorKey                             []byte
	KMS                                   *VaultFixture
	Server                                *httptest.Server
	OrgID, OtherOrgID, DSN, Backend       string
	CSRFKey, DigestKey                    []byte
	Owner, Observer, Stranger, OtherOwner Credential
	Now                                   time.Time
}

func randomBytes(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func credential(key []byte) (Credential, error) {
	raw, err := randomBytes(32)
	if err != nil {
		return Credential{}, err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("TEAMLEDGER-CSRF\x00"))
	mac.Write(raw)
	return Credential{SubjectID: value.NewID(), Token: base64.RawURLEncoding.EncodeToString(raw), CSRF: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), Hash: hash[:]}, nil
}

func NewFixture(ctx context.Context, backend, dsn string) (_ *Fixture, err error) {
	f := &Fixture{OrgID: value.NewID(), OtherOrgID: value.NewID(), Backend: backend, DSN: dsn, Now: time.Now().UTC().Truncate(time.Microsecond)}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	f.Repo, err = store.Open(ctx, backend, dsn)
	if err != nil {
		return nil, err
	}
	if err = f.Repo.Migrate(ctx); err != nil {
		return nil, err
	}
	f.CSRFKey, err = randomBytes(32)
	if err != nil {
		return nil, err
	}
	f.DigestKey, err = randomBytes(32)
	if err != nil {
		return nil, err
	}
	f.CursorKey, err = randomBytes(32)
	if err != nil {
		return nil, err
	}
	f.Manager, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.Reader, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.Approver, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.AuthorityIDs = make(map[string]string, 4)
	f.Owner, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.Observer, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.Stranger, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	f.OtherOwner, err = credential(f.CSRFKey)
	if err != nil {
		return nil, err
	}
	if err = f.seed(ctx); err != nil {
		return nil, err
	}
	f.KMS, err = NewVaultFixture()
	if err != nil {
		return nil, err
	}
	wrapper, err := f.KMS.Wrapper()
	if err != nil {
		return nil, err
	}
	f.Service = &organization.Service{Store: f.Repo, Cipher: sensitive.Cipher{Wrapper: wrapper}, DigestKey: f.DigestKey, Now: func() time.Time { return f.Now }}
	f.Authz = &authz.Service{Store: f.Repo, DigestKey: f.DigestKey, CursorKey: f.CursorKey, Now: func() time.Time { return f.Now }}
	return f, nil
}
func (f *Fixture) Close() {
	if f.Server != nil {
		f.Server.Close()
	}
	if f.KMS != nil {
		f.KMS.Close()
	}
	if f.Repo != nil {
		f.Repo.Close()
	}
	clear(f.CSRFKey)
	clear(f.DigestKey)
	clear(f.CursorKey)
}
func (f *Fixture) seed(ctx context.Context) error {
	tx, err := f.Repo.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exec := func(sq, pg string, args ...any) error {
		q := sq
		if f.Backend == "postgres" {
			q = pg
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	for _, org := range []string{f.OrgID, f.OtherOrgID} {
		if err = exec("INSERT INTO organization(id,timezone,graph_revision) VALUES(?,'UTC',1)", "INSERT INTO organization(id,timezone,graph_revision) VALUES($1,'UTC',1)", org); err != nil {
			return err
		}
		if err = exec("INSERT INTO authorization_guard(org_id,auth_epoch) VALUES(?,1)", "INSERT INTO authorization_guard(org_id,auth_epoch) VALUES($1,1)", org); err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		c    Credential
		org  string
		mode int
	}{{f.Owner, f.OrgID, 2}, {f.Observer, f.OrgID, 1}, {f.Stranger, f.OrgID, 0}, {f.OtherOwner, f.OtherOrgID, 2}, {f.Manager, f.OrgID, -1}, {f.Reader, f.OrgID, 0}, {f.Approver, f.OrgID, -1}} {
		if err = exec("INSERT INTO subject(org_id,id,active,auth_epoch) VALUES(?,?,1,1)", "INSERT INTO subject(org_id,id,active,auth_epoch) VALUES($1,$2,true,1)", entry.org, entry.c.SubjectID); err != nil {
			return err
		}
		csrfHash := sha256.Sum256([]byte(entry.c.CSRF))
		if err = exec("INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES(?,?,?,?,?,?,?,0,?,1)", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,1)", entry.c.Hash, entry.org, entry.c.SubjectID, int64(1), f.Repo.BindTime(f.Now.Add(8*time.Hour)), f.Repo.BindTime(f.Now.Add(30*time.Minute)), f.Repo.BindTime(f.Now.Add(10*time.Minute)), csrfHash[:]); err != nil {
			return err
		}
		if entry.mode == -1 {
			continue
		}
		for _, cap := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
			if err = exec("INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,?,'org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,$3,'org',$4)", entry.org, entry.c.SubjectID, cap, entry.org); err != nil {
				return err
			}
			if entry.mode == 0 || entry.mode == 1 && cap != "organization.read" {
				continue
			}
			category := "metadata"
			if strings.HasPrefix(cap, "pii.") {
				category = "pii"
			}
			if err = exec("INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,?,?,'org',?,'organization_management',?,?,0,0,0)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,$4,$5,'org',$6,'organization_management',$7,$8,false,false,false)", value.NewID(), entry.org, entry.c.SubjectID, cap, category, entry.org, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour))); err != nil {
				return err
			}
		}
	}
	if err = exec("INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES(?,?,'access_grant.manage','org',?)", "INSERT INTO capability_assignment(org_id,subject_id,capability,scope_kind,scope_id) VALUES($1,$2,'access_grant.manage','org',$3)", f.OrgID, f.Manager.SubjectID, f.OrgID); err != nil {
		return err
	}
	if err = exec("INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,'access_grant.manage','audit','org',?,'security_administration',?,?,0,0,1)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,'access_grant.manage','audit','org',$4,'security_administration',$5,$6,false,false,true)", value.NewID(), f.OrgID, f.Manager.SubjectID, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour))); err != nil {
		return err
	}
	for _, cap := range []string{"organization.read", "organization.write", "pii.read", "pii.write"} {
		category := "metadata"
		if strings.HasPrefix(cap, "pii.") {
			category = "pii"
		}
		id := value.NewID()
		f.AuthorityIDs[cap] = id
		if err = exec("INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES(?,?,?,?,?,'org',?,'organization_management',?,?,1,?,?,?)", "INSERT INTO delegation_authority(id,org_id,manager_subject_id,capability,category,scope_kind,scope_id,purpose,valid_from,expires_at,mfa_required,approved_by,approved_at,policy_version) VALUES($1,$2,$3,$4,$5,'org',$6,'organization_management',$7,$8,true,$9,$10,$11)", id, f.OrgID, f.Manager.SubjectID, cap, category, f.OrgID, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(24*time.Hour)), f.Approver.SubjectID, f.Repo.BindTime(f.Now.Add(-2*time.Hour)), "fixture-policy-1"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func NewHarness(t testing.TB, backend string) *Fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dsn := filepath.Join(t.TempDir(), "fixture.db")
	var base *store.Repository
	var schema string
	if backend == "postgres" {
		original := os.Getenv("TEAMLEDGER_TEST_POSTGRES_DSN")
		if original == "" {
			t.Fatal("real PostgreSQL DSN is required; no skip/fallback")
		}
		var err error
		base, err = store.Open(ctx, "postgres", original)
		if err != nil {
			t.Fatal("isolated PostgreSQL connection failed")
		}
		schema = "dev002_" + strings.ReplaceAll(value.NewID(), "-", "")
		if _, err = base.DB.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
			base.Close()
			t.Fatal("isolated PostgreSQL schema creation failed")
		}
		u, err := url.Parse(original)
		if err != nil {
			t.Fatal("test DSN must be a PostgreSQL URL")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
		t.Cleanup(func() {
			_, _ = base.DB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			_ = base.Close()
		})
	}
	f, err := NewFixture(ctx, backend, dsn)
	if err != nil {
		t.Fatal("real fixture initialization failed:", err)
	}
	t.Cleanup(f.Close)
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Synthetic fixture</title><main></main>"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	identities, err := identity.New(ctx, f.Repo, f.CSRFKey, nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	identities.Now = f.Service.Now
	handler, err := httpapi.New(f.Service, f.Authz, identities, f.CSRFKey, "https://"+server.Listener.Addr().String(), dir)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	f.Server = server
	if backend == "postgres" {
		var super, bypass bool
		if err = f.Repo.DB.QueryRowContext(ctx, "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").Scan(&super, &bypass); err != nil || super || bypass {
			t.Fatal("PostgreSQL contract requires non-superuser/non-BYPASSRLS role")
		}
		var tls bool
		if err = f.Repo.DB.QueryRowContext(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&tls); err != nil || !tls {
			t.Fatal("PostgreSQL contract requires verified TLS")
		}
	}
	return f
}
func (f *Fixture) Request(c Credential) organization.Request {
	return organization.Request{TokenHash: c.Hash, Purpose: "organization_management", Key: value.NewID(), RequestID: value.NewID()}
}
func (f *Fixture) Exec(ctx context.Context, sq, pg string, args ...any) error {
	q := sq
	if f.Backend == "postgres" {
		q = pg
	}
	_, err := f.Repo.DB.ExecContext(ctx, q, args...)
	return err
}
func (f *Fixture) Count(t testing.TB, table string) int {
	t.Helper()
	var n int
	if err := f.Repo.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal("fixture state query failed")
	}
	return n
}
