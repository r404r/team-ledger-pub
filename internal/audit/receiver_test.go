package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

type receiverMemory struct {
	records map[string]ReceiverRecord
	seq     int64
	head    []byte
	fail    bool
}

func (m *receiverMemory) CommitAuditReceipt(_ context.Context, deployment, event string, digest []byte, build ReceiptBuilder) ([]byte, error) {
	if prior, ok := m.records[event]; ok {
		if !bytes.Equal(prior.Digest, digest) {
			return nil, ErrAuditEventConflict
		}
		return append([]byte(nil), prior.Receipt...), nil
	}
	sequence := m.seq + 1
	receipt, entryHash, err := build(sequence, append([]byte(nil), m.head...))
	if err != nil || m.fail {
		return nil, errors.New("synthetic commit failure")
	}
	m.seq, m.head = sequence, append([]byte(nil), entryHash...)
	m.records[event] = ReceiverRecord{Digest: append([]byte(nil), digest...), Receipt: append([]byte(nil), receipt...)}
	return append([]byte(nil), receipt...), nil
}

func TestReceiverCommitsSignedChainReceiptAndReplaysExactBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 14, 3, 4, 5, 6000, time.UTC)
	store := &receiverMemory{records: map[string]ReceiverRecord{}}
	receiver, err := NewReceiver(store, "synthetic-deployment", "receipt-2026-10", private, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	item := Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}}
	body, digest, err := DeliveryRequestBytes("synthetic-deployment", item)
	if err != nil {
		t.Fatal(err)
	}
	first, err := receiver.Receive(context.Background(), item.ID, body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := receiver.Receive(context.Background(), item.ID, body)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("exact replay did not return persisted receipt bytes", err)
	}
	receipt, err := VerifyDeliveryReceipt(first, "synthetic-deployment", item.ID, digest, ReceiptKeys{"receipt-2026-10": public}, now)
	if err != nil || receipt.Sequence != 1 || receipt.EntryHash == "" || receipt.PreviousHash != "" {
		t.Fatal("invalid signed chain receipt", receipt, err)
	}
}

func TestReceiverRejectsDigestConflictAndNeverReturnsUncommittedReceipt(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Microsecond)
	store := &receiverMemory{records: map[string]ReceiverRecord{}}
	receiver, err := NewReceiver(store, "synthetic-deployment", "receipt-1", private, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	item := Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}}
	body, _, _ := DeliveryRequestBytes("synthetic-deployment", item)
	if _, err = receiver.Receive(context.Background(), item.ID, body); err != nil {
		t.Fatal(err)
	}
	body[len(body)-2] ^= 1
	if _, err = receiver.Receive(context.Background(), item.ID, body); !errors.Is(err, ErrInvalidAuditDelivery) && !errors.Is(err, ErrAuditEventConflict) {
		t.Fatal("changed replay was accepted", err)
	}
	fresh := item
	fresh.ID = value.NewID()
	fresh.RequestID = value.NewID()
	body, _, _ = DeliveryRequestBytes("synthetic-deployment", fresh)
	store.fail = true
	if receipt, commitErr := receiver.Receive(context.Background(), fresh.ID, body); commitErr == nil || len(receipt) != 0 {
		t.Fatal("uncommitted receipt escaped", len(receipt), commitErr)
	}
}
