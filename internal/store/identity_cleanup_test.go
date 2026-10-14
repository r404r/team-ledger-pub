package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func cleanupFixture(t *testing.T, backend string) *testsupport.Fixture {
	t.Helper()
	f := testsupport.NewHarness(t, backend)
	f.Now = time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	at := any(f.Now.UnixMicro())
	statement := "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,?)"
	if backend == "postgres" {
		at = f.Now
		statement = "INSERT INTO identity_mode_state(id,mode,revision,updated_at) VALUES(1,'oidc',1,$1)"
	}
	if _, err := f.Repo.DB.ExecContext(context.Background(), statement, at); err != nil {
		t.Fatal("set OIDC fixture mode:", err)
	}
	return f
}

func cleanupProof(id uint64, created, expires time.Time) identity.Transaction {
	state := make([]byte, 32)
	binary.BigEndian.PutUint64(state[24:], id)
	return identity.Transaction{StateHash: state, BindingHash: bytes.Repeat([]byte{71}, 32), Sealed: bytes.Repeat([]byte{72}, 28), CreatedAt: created, ExpiresAt: expires, Mode: "login", ReturnTo: "/"}
}

func cleanupSave(t *testing.T, f *testsupport.Fixture, proof identity.Transaction) {
	t.Helper()
	if err := f.Repo.SaveOIDCTransaction(context.Background(), proof); err != nil {
		t.Fatal("save genuine OIDC proof:", err)
	}
}

func cleanupSeedExpired(t *testing.T, f *testsupport.Fixture, count int) {
	t.Helper()
	// Reverse insertion order makes equal-expiry ordering observable. Historical
	// writes have the same creation time, so seeding cannot clean its own rows.
	for i := count; i > 0; i-- {
		cleanupSave(t, f, cleanupProof(uint64(i), f.Now.Add(-20*time.Minute), f.Now.Add(-10*time.Minute)))
	}
}

func cleanupExpiredCount(t *testing.T, f *testsupport.Fixture) int {
	t.Helper()
	query := "SELECT count(*) FROM oidc_transaction WHERE expires_at<=?"
	if f.Backend == "postgres" {
		query = "SELECT count(*) FROM oidc_transaction WHERE expires_at<=$1"
	}
	var count int
	if err := f.Repo.DB.QueryRowContext(context.Background(), query, f.Repo.BindTime(f.Now)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func cleanupProofExists(t *testing.T, f *testsupport.Fixture, proof identity.Transaction) bool {
	t.Helper()
	query := "SELECT count(*) FROM oidc_transaction WHERE state_hash=?"
	if f.Backend == "postgres" {
		query = "SELECT count(*) FROM oidc_transaction WHERE state_hash=$1"
	}
	var count int
	if err := f.Repo.DB.QueryRowContext(context.Background(), query, proof.StateHash).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

func TestOIDCTransactionCleanupBoundedAndStable(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := cleanupFixture(t, backend)
			cleanupSeedExpired(t, f, 600)
			for batch, remaining := range []int{344, 88, 0} {
				cleanupSave(t, f, cleanupProof(uint64(1000+batch), f.Now, f.Now.Add(10*time.Minute)))
				if got := cleanupExpiredCount(t, f); got != remaining {
					t.Fatalf("one begin must remove at most 256 oldest expired proofs: batch=%d remaining=%d want=%d", batch, got, remaining)
				}
				if remaining > 0 {
					first := uint64(600 - remaining + 1)
					if cleanupProofExists(t, f, cleanupProof(first-1, time.Time{}, time.Time{})) || !cleanupProofExists(t, f, cleanupProof(first, time.Time{}, time.Time{})) {
						t.Fatal("equal-expiry cleanup must use stable state-hash order, not insertion order")
					}
				}
			}
			if got := f.Count(t, "oidc_transaction"); got != 3 {
				t.Fatalf("only the three newly created live proofs must remain: %d", got)
			}
		})
	}
}

func TestOIDCTransactionCleanupAndInsertRollBackTogether(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := cleanupFixture(t, backend)
			live := cleanupProof(1000, f.Now, f.Now.Add(10*time.Minute))
			cleanupSave(t, f, live)
			cleanupSeedExpired(t, f, 300)
			if err := f.Repo.SaveOIDCTransaction(context.Background(), live); err == nil {
				t.Fatal("duplicate state must not overwrite an existing proof")
			}
			if got := cleanupExpiredCount(t, f); got != 300 {
				t.Fatalf("failed begin must roll back expiry cleanup: remaining=%d", got)
			}
			cleanupSave(t, f, cleanupProof(1001, f.Now, f.Now.Add(10*time.Minute)))
			if got := cleanupExpiredCount(t, f); got != 44 {
				t.Fatalf("next successful begin must clean one bounded batch: remaining=%d", got)
			}
			if _, err := f.Repo.ConsumeOIDCTransaction(context.Background(), live.StateHash, live.BindingHash, f.Now); err != nil {
				t.Fatal("failed duplicate begin must preserve usable original proof:", err)
			}
		})
	}
}

func TestOIDCTransactionCleanupExactExpiryPreservesConsumedProofAndIssuance(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := cleanupFixture(t, backend)
			ctx := context.Background()
			created := f.Now.Add(-9 * time.Minute)
			old := cleanupProof(1, created, f.Now.Add(-time.Microsecond))
			exact := cleanupProof(2, created, f.Now)
			live := cleanupProof(3, created, f.Now.Add(time.Microsecond))
			for _, proof := range []identity.Transaction{old, exact, live} {
				cleanupSave(t, f, proof)
			}
			proof, err := f.Repo.ConsumeOIDCTransaction(ctx, live.StateHash, live.BindingHash, f.Now.Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			cleanupSave(t, f, cleanupProof(4, f.Now, f.Now.Add(10*time.Minute)))
			if cleanupProofExists(t, f, old) || cleanupProofExists(t, f, exact) {
				t.Fatal("proofs expiring before or exactly at begin must be removed")
			}
			if !cleanupProofExists(t, f, live) {
				t.Fatal("consumed proof expiring one microsecond later must survive")
			}
			for _, expired := range []identity.Transaction{old, exact} {
				if _, err = f.Repo.ConsumeOIDCTransaction(ctx, expired.StateHash, expired.BindingHash, f.Now); !errors.Is(err, fault.Unauthenticated) {
					t.Fatal("expired proof must stay unusable:", err)
				}
			}
			digest := bytes.Repeat([]byte{73}, 32)
			mapping := identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID}
			if err = f.Repo.BindIdentity(ctx, mapping, value.NewID(), f.Now); err != nil {
				t.Fatal(err)
			}
			issue := identity.SessionIssue{Transaction: proof, IdentityDigest: digest, IdentityKeyID: "legacy-process-key", IdentityVersion: 1, TokenHash: bytes.Repeat([]byte{74}, 32), CSRFHash: bytes.Repeat([]byte{75}, 32), CSRFKeyID: "00000000-0000-7000-8000-000000000001", CSRFVersion: 1, Now: f.Now, ExpiresAt: f.Now.Add(8 * time.Hour), IdleExpiresAt: f.Now.Add(30 * time.Minute), RequestID: value.NewID()}
			if err = f.Repo.IssueSession(ctx, issue); err != nil {
				t.Fatal("surviving consumed proof must still issue a mapped session:", err)
			}
			cleanupSave(t, f, cleanupProof(5, f.Now, f.Now.Add(10*time.Minute)))
			if !cleanupProofExists(t, f, live) {
				t.Fatal("issued proof must remain until expiration to enforce replay guards")
			}
			if _, err = f.Repo.ConsumeOIDCTransaction(ctx, live.StateHash, live.BindingHash, f.Now); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("cleanup cannot reset consumed proof:", err)
			}
			issue.TokenHash = bytes.Repeat([]byte{76}, 32)
			if err = f.Repo.IssueSession(ctx, issue); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("cleanup cannot allow a second session from issued proof:", err)
			}
			session, err := f.Repo.IdentitySession(ctx, bytes.Repeat([]byte{74}, 32), f.Now)
			if err != nil || session.OrgID != f.OrgID || session.SubjectID != f.Owner.SubjectID {
				t.Fatal("issued session must authenticate its real mapped owner:", err)
			}
			cleanupSave(t, f, cleanupProof(6, live.ExpiresAt, live.ExpiresAt.Add(10*time.Minute)))
			if cleanupProofExists(t, f, live) {
				t.Fatal("consumed/issued proof must become reclaimable exactly at expiration")
			}
			if _, err = f.Repo.IdentitySession(ctx, bytes.Repeat([]byte{74}, 32), live.ExpiresAt); err != nil {
				t.Fatal("cleaning expired proof must not revoke its valid issued session:", err)
			}
			drifted := cleanupProof(7, f.Now, f.Now.Add(10*time.Minute))
			cleanupSave(t, f, drifted)
			drifted, err = f.Repo.ConsumeOIDCTransaction(ctx, drifted.StateHash, drifted.BindingHash, f.Now)
			if err != nil {
				t.Fatal("consume pre-switch OIDC proof:", err)
			}
			if err = f.Repo.SwitchIdentityMode(ctx, "local", value.NewID(), f.Now.Add(time.Second)); err != nil {
				t.Fatal("switch identity mode:", err)
			}
			driftedIssue := issue
			driftedIssue.Transaction = drifted
			driftedIssue.TokenHash = bytes.Repeat([]byte{77}, 32)
			driftedIssue.RequestID = value.NewID()
			if err = f.Repo.IssueSession(ctx, driftedIssue); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("old-mode OIDC callback issued a session after mode switch:", err)
			}
		})
	}
}

func TestOIDCTransactionConcurrentBeginsCleanBoundedBatches(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := cleanupFixture(t, backend)
			cleanupSeedExpired(t, f, 600)
			start := make(chan struct{})
			results := make(chan error, 2)
			for i := range 2 {
				proof := cleanupProof(uint64(1000+i), f.Now, f.Now.Add(10*time.Minute))
				go func() {
					<-start
					results <- f.Repo.SaveOIDCTransaction(context.Background(), proof)
				}()
			}
			close(start)
			for range 2 {
				if err := <-results; err != nil {
					t.Fatal("independent concurrent begins must commit:", err)
				}
			}
			if got := cleanupExpiredCount(t, f); got != 88 {
				t.Fatalf("two begins must each reclaim 256 expired proofs: remaining=%d want=88", got)
			}
			for i := range 2 {
				proof := cleanupProof(uint64(1000+i), f.Now, f.Now.Add(10*time.Minute))
				if _, err := f.Repo.ConsumeOIDCTransaction(context.Background(), proof.StateHash, proof.BindingHash, f.Now); err != nil {
					t.Fatal("concurrent cleanup must retain both fresh proofs:", err)
				}
			}
		})
	}
}

func TestOIDCTransactionBeginCleanupPreservesInFlightSignedCallbackAndSealedNonce(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := cleanupFixture(t, backend)
			ctx := context.Background()
			idp, err := testsupport.NewOIDCFixture()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(idp.Close)
			idp.Now = func() time.Time { return f.Now }
			cfg := identity.OIDCConfig{Issuer: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, RedirectURI: f.Server.URL + "/api/v1/auth/callback", HTTPClient: idp.Client(), IdentityKey: bytes.Repeat([]byte{77}, 32), TransactionKey: bytes.Repeat([]byte{78}, 32)}
			svc, err := identity.New(ctx, f.Repo, testsupport.MACKeys{Key: f.CSRFKey, DomainKeys: map[sensitive.KeyDomain][]byte{sensitive.DomainIdentitySubjectLookup: cfg.IdentityKey}}, &cfg)
			if err != nil {
				t.Fatal(err)
			}
			svc.Now = func() time.Time { return f.Now }
			digest, err := identity.IdentityDigest(cfg.IdentityKey, cfg.Issuer, idp.Subject)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Repo.BindIdentity(ctx, identity.Identity{Digest: digest, KeyVersion: 1, OrgID: f.OrgID, SubjectID: f.Owner.SubjectID}, value.NewID(), f.Now); err != nil {
				t.Fatal(err)
			}
			begin := func() identity.Authorization {
				authorization, e := svc.Begin(ctx, identity.BeginRequest{Mode: "login", ReturnTo: "/", RequestID: value.NewID()})
				if e != nil {
					t.Fatal(e)
				}
				return authorization
			}
			live := begin()
			cleanupSeedExpired(t, f, 300)
			callback, err := idp.Authorize(live.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			idp.ExchangeStarted = make(chan struct{}, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			idp.ExchangeRelease = release
			request := identity.CallbackRequest{Code: callback.Code, State: callback.State, BrowserCookie: live.BrowserCookie, RequestID: value.NewID()}
			type completion struct {
				result identity.LoginResult
				err    error
			}
			done := make(chan completion, 1)
			go func() {
				result, e := svc.Complete(ctx, request)
				done <- completion{result, e}
			}()
			select {
			case <-idp.ExchangeStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("callback must reach real TLS exchange after consuming its proof")
			}
			other := begin()
			if got := cleanupExpiredCount(t, f); got != 44 {
				t.Fatalf("begin during live callback must reclaim only one expired batch: remaining=%d", got)
			}
			cleanupAssertNoRawSecrets(t, f, live)
			cleanupAssertNoRawSecrets(t, f, other)
			unblock()
			var completed completion
			select {
			case completed = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("live signed callback must finish after interleaved cleanup")
			}
			if completed.err != nil {
				t.Fatal("cleanup must preserve consumed in-flight proof for signed completion:", completed.err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(completed.result.SessionCookie)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(raw)
			clear(raw)
			if session, e := f.Repo.IdentitySession(ctx, hash[:], f.Now); e != nil || session.OrgID != f.OrgID || session.SubjectID != f.Owner.SubjectID {
				t.Fatal("completed signed callback must authenticate approved mapped owner:", e)
			}
			begin()
			if got := cleanupExpiredCount(t, f); got != 0 {
				t.Fatalf("subsequent begin must reclaim the remaining expired proofs: %d", got)
			}
			if _, err = svc.Complete(ctx, request); !errors.Is(err, fault.Unauthenticated) {
				t.Fatal("cleanup must not permit replay of completed callback:", err)
			}
		})
	}
}

func cleanupAssertNoRawSecrets(t *testing.T, f *testsupport.Fixture, authorization identity.Authorization) {
	t.Helper()
	u, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	var secrets [][]byte
	for _, secret := range []string{u.Query().Get("nonce"), u.Query().Get("state"), authorization.BrowserCookie} {
		raw, e := base64.RawURLEncoding.DecodeString(secret)
		if e != nil || len(raw) != 32 {
			t.Fatal("authorization must contain genuine 256-bit browser proofs")
		}
		secrets = append(secrets, []byte(secret), raw)
	}
	rows, err := f.Repo.DB.QueryContext(context.Background(), "SELECT * FROM oidc_transaction")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	for rows.Next() {
		if err = rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		for _, val := range values {
			var stored []byte
			switch v := val.(type) {
			case []byte:
				stored = v
			case string:
				stored = []byte(v)
			default:
				continue
			}
			for _, secret := range secrets {
				if bytes.Contains(stored, secret) {
					t.Fatal("persisted proof must not expose raw nonce, state or browser binding")
				}
			}
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}
