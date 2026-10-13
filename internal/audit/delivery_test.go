package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

type deliveryMemory struct {
	item                    Delivery
	claimed, acked, retried bool
	receipt                 DeliveryReceipt
	retryAt                 time.Time
}

func (m *deliveryMemory) ClaimAuditDelivery(context.Context, time.Time, time.Duration) (Delivery, bool, error) {
	if m.claimed {
		return Delivery{}, false, nil
	}
	m.claimed = true
	return m.item, true, nil
}
func (m *deliveryMemory) AckAuditDelivery(_ context.Context, id, token string, r DeliveryReceipt, _ time.Time) error {
	if id != m.item.ID || token != m.item.ClaimToken {
		return context.Canceled
	}
	m.acked = true
	m.receipt = r
	return nil
}
func (m *deliveryMemory) RetryAuditDelivery(_ context.Context, id, token string, at time.Time) error {
	if id != m.item.ID || token != m.item.ClaimToken {
		return context.Canceled
	}
	m.retried = true
	m.retryAt = at
	return nil
}
func (*deliveryMemory) AuditDeliveryBacklog(context.Context, time.Time) (int64, *time.Time, error) {
	return 0, nil, nil
}

func receiverServer(t *testing.T, receiver *Receiver) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health/ready" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
		if err != nil || r.Method != http.MethodPost || r.URL.Path != "/v1/events" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		receipt, err := receiver.Receive(r.Context(), r.Header.Get("Idempotency-Key"), body)
		if err != nil {
			http.Error(w, "rejected", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(receipt)
	}))
}

func TestAuditRetryIsDeterministicJitteredAndBounded(t *testing.T) {
	now := time.Date(2026, 10, 14, 1, 2, 3, 0, time.UTC)
	first := retryAt(now, 1, "event-a")
	if first.Before(now.Add(time.Second)) || !first.Before(now.Add(1126*time.Millisecond)) || first != retryAt(now, 1, "event-a") {
		t.Fatal("first retry is outside its deterministic jitter window", first)
	}
	last := retryAt(now, 100, "event-b")
	if last.Before(now.Add(256*time.Second)) || last.After(now.Add(288*time.Second)) {
		t.Fatal("retry exceeded the five-minute bound", last)
	}
}

func TestProbeReceiverRequiresExactHealthyResponse(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	receiver, _ := NewReceiver(&receiverMemory{records: map[string]ReceiverRecord{}}, "synthetic-deployment", "receipt-2026-10", private, time.Now)
	server := receiverServer(t, receiver)
	defer server.Close()
	if err := ProbeReceiver(context.Background(), server.Client(), server.URL+"/v1/events"); err != nil {
		t.Fatal("healthy receiver probe failed", err)
	}
	unhealthy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()
	if err := ProbeReceiver(context.Background(), unhealthy.Client(), unhealthy.URL+"/v1/events"); err == nil {
		t.Fatal("unhealthy receiver probe succeeded")
	}
}

func TestDeliverOneAcceptsDelayedSignedTLSReceiptForExactSafePayload(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 1, 2, 3, 0, time.UTC)
	memory := &deliveryMemory{item: Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}, ClaimToken: value.NewID(), Attempt: 1}}
	ledger := &receiverMemory{records: map[string]ReceiverRecord{}}
	receiver, err := NewReceiver(ledger, "synthetic-deployment", "receipt-2026-10", private, func() time.Time { return now.Add(-24 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	server := receiverServer(t, receiver)
	defer server.Close()
	found, err := DeliverOne(context.Background(), memory, server.Client(), server.URL+"/v1/events", "synthetic-deployment", ReceiptKeys{"receipt-2026-10": public}, now)
	if err != nil || !found || !memory.acked || memory.retried || !value.ValidID(memory.receipt.ReceiptID) || len(memory.receipt.Digest) != sha256.Size {
		t.Fatal("signed independent receipt was not persisted", found, memory, err)
	}
}

func TestDeliverOneRejectsUntrustedReceiptAndSchedulesRetry(t *testing.T) {
	trusted, _, _ := ed25519.GenerateKey(rand.Reader)
	_, untrustedPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Microsecond)
	memory := &deliveryMemory{item: Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}, ClaimToken: value.NewID(), Attempt: 1}}
	ledger := &receiverMemory{records: map[string]ReceiverRecord{}}
	receiver, _ := NewReceiver(ledger, "synthetic-deployment", "receipt-2026-10", untrustedPrivate, func() time.Time { return now })
	server := receiverServer(t, receiver)
	defer server.Close()
	found, err := DeliverOne(context.Background(), memory, server.Client(), server.URL+"/v1/events", "synthetic-deployment", ReceiptKeys{"receipt-2026-10": trusted}, now)
	if err == nil || !found || memory.acked || !memory.retried || memory.retryAt.Before(now.Add(time.Second)) {
		t.Fatal("untrusted receipt was accepted or retry was not deferred", found, memory, err)
	}
}
