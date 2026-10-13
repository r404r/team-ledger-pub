package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func receiverFixture(t *testing.T, f *testsupport.Fixture) (*audit.Receiver, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := audit.NewReceiver(f.Repo, "synthetic-deployment", "receipt-2026-10", private, func() time.Time { return f.Now })
	if err != nil {
		t.Fatal(err)
	}
	return receiver, public
}

func receiverDelivery(t *testing.T, receiver *audit.Receiver, now time.Time, event string) ([]byte, [32]byte) {
	t.Helper()
	item := audit.Delivery{Event: audit.Event{ID: event, Operation: "OP-SEC-04", Purpose: audit.Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}}
	body, digest, err := audit.DeliveryRequestBytes("synthetic-deployment", item)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiver.Receive(context.Background(), event, body)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, digest
}

func TestAuditReceiverLedgerIsAtomicReplayableAndAppendOnly(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			receiver, public := receiverFixture(t, f)
			event := value.NewID()
			first, digest := receiverDelivery(t, receiver, f.Now, event)
			// Reusing the exact canonical body is tested by the receiver package;
			// the repository must return the same persisted bytes without rebuilding.
			called := false
			replay, err := f.Repo.CommitAuditReceipt(ctx, "synthetic-deployment", event, digest[:], func(int64, []byte) ([]byte, []byte, error) {
				called = true
				return nil, nil, errors.New("must not rebuild replay")
			})
			if err != nil || called || !bytes.Equal(first, replay) {
				t.Fatal("exact replay changed persisted receipt", called, err)
			}
			if _, err = audit.VerifyDeliveryReceipt(first, "synthetic-deployment", event, digest, audit.ReceiptKeys{"receipt-2026-10": public}, f.Now); err != nil {
				t.Fatal("persisted receipt is not trusted", err)
			}
			changed := sha256.Sum256([]byte("different"))
			if _, err = f.Repo.CommitAuditReceipt(ctx, "synthetic-deployment", event, changed[:], nil); !errors.Is(err, audit.ErrAuditEventConflict) {
				t.Fatal("digest conflict was not rejected", err)
			}
			failedEvent := value.NewID()
			if _, err = f.Repo.CommitAuditReceipt(ctx, "synthetic-deployment", failedEvent, changed[:], func(sequence int64, previous []byte) ([]byte, []byte, error) {
				if sequence != 2 || len(previous) != sha256.Size {
					t.Fatal("failed build observed wrong chain head", sequence, previous)
				}
				return nil, nil, errors.New("synthetic signer failure")
			}); err == nil {
				t.Fatal("signer failure committed")
			}
			if got := f.Count(t, "audit_receiver_ledger"); got != 1 {
				t.Fatal("failed commit left partial ledger", got)
			}
			badEvent := value.NewID()
			if _, err = f.Repo.CommitAuditReceipt(ctx, "synthetic-deployment", badEvent, changed[:], func(int64, []byte) ([]byte, []byte, error) {
				return first, make([]byte, sha256.Size), nil
			}); err == nil {
				t.Fatal("receipt for a different event was persisted")
			}
			for _, statement := range []string{"UPDATE audit_receiver_ledger SET sequence=9", "DELETE FROM audit_receiver_ledger"} {
				if _, err = f.Repo.DB.ExecContext(ctx, statement); err == nil {
					t.Fatal("append-only trigger accepted mutation", statement)
				}
			}
			corruptHead := make([]byte, sha256.Size)
			query := "UPDATE audit_receiver_chain SET head_hash=? WHERE deployment_id=?"
			if backend == "postgres" {
				query = "UPDATE audit_receiver_chain SET head_hash=$1 WHERE deployment_id=$2"
			}
			if _, err = f.Repo.DB.ExecContext(ctx, query, corruptHead, "synthetic-deployment"); err != nil {
				t.Fatal(err)
			}
			called = false
			if _, err = f.Repo.CommitAuditReceipt(ctx, "synthetic-deployment", value.NewID(), changed[:], func(int64, []byte) ([]byte, []byte, error) {
				called = true
				return nil, nil, nil
			}); err == nil || called {
				t.Fatal("corrupt chain head was accepted", called, err)
			}
			if err = f.Repo.AuditReceiverReady(ctx); err == nil {
				t.Fatal("readiness accepted a corrupt chain head")
			}
		})
	}
}

func TestAuditReceiverConcurrentEventsFormOneContinuousChain(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			receiver, _ := receiverFixture(t, f)
			const count = 8
			var wg sync.WaitGroup
			errs := make(chan error, count)
			for range count {
				wg.Add(1)
				go func() {
					defer wg.Done()
					event := value.NewID()
					item := audit.Delivery{Event: audit.Event{ID: event, Operation: "OP-SEC-04", Purpose: audit.Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: f.Now, ActorKind: "application"}}
					body, _, err := audit.DeliveryRequestBytes("synthetic-deployment", item)
					if err == nil {
						_, err = receiver.Receive(context.Background(), event, body)
					}
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			query := "SELECT count(*),min(sequence),max(sequence),count(DISTINCT sequence) FROM audit_receiver_ledger WHERE deployment_id=?"
			if backend == "postgres" {
				query = "SELECT count(*),min(sequence),max(sequence),count(DISTINCT sequence) FROM audit_receiver_ledger WHERE deployment_id=$1"
			}
			var ledgerCount, minSequence, maxSequence, distinctSequence int
			if err := f.Repo.DB.QueryRowContext(context.Background(), query, "synthetic-deployment").Scan(&ledgerCount, &minSequence, &maxSequence, &distinctSequence); err != nil || ledgerCount != count || minSequence != 1 || maxSequence != count || distinctSequence != count {
				t.Fatal("receiver chain forked", ledgerCount, minSequence, maxSequence, distinctSequence, err)
			}
		})
	}
}

func TestAuditReceiverStatusIsFreshFailClosedAndPortable(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			if err := f.Repo.AuditReceiverAvailable(ctx, "synthetic-deployment", now, 15*time.Second); err == nil {
				t.Fatal("missing receiver status was available")
			}
			if err := f.Repo.RecordAuditReceiverStatus(ctx, "synthetic-deployment", true, now); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.AuditReceiverAvailable(ctx, "other-deployment", now.Add(14*time.Second), 15*time.Second); err == nil {
				t.Fatal("another deployment's receiver status was available")
			}
			if err := f.Repo.AuditReceiverAvailable(ctx, "synthetic-deployment", now.Add(14*time.Second), 15*time.Second); err != nil {
				t.Fatal("fresh receiver status was unavailable", err)
			}
			if err := f.Repo.AuditReceiverAvailable(ctx, "synthetic-deployment", now.Add(16*time.Second), 15*time.Second); err == nil {
				t.Fatal("stale receiver status was available")
			}
			if err := f.Repo.RecordAuditReceiverStatus(ctx, "synthetic-deployment", false, now.Add(17*time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := f.Repo.AuditReceiverAvailable(ctx, "synthetic-deployment", now.Add(17*time.Second), 15*time.Second); err == nil {
				t.Fatal("failed receiver status was available")
			}
		})
	}
}
