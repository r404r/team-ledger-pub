package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
func (m *deliveryMemory) RetryAuditDelivery(_ context.Context, id, token string, _ time.Time) error {
	if id != m.item.ID || token != m.item.ClaimToken {
		return context.Canceled
	}
	m.retried = true
	return nil
}
func (*deliveryMemory) AuditDeliveryBacklog(context.Context, time.Time) (int64, *time.Time, error) {
	return 0, nil, nil
}

func TestDeliverOneAcceptsDelayedSignedTLSReceiptForExactSafePayload(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 1, 2, 3, 0, time.UTC)
	memory := &deliveryMemory{item: Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}, ClaimToken: value.NewID(), Attempt: 1}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != memory.item.ID || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unsafe delivery request")
		}
		var payload deliveryPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.EventID != memory.item.ID || payload.Version != 1 {
			t.Error("wrong safe payload", err)
		}
		body, digest, err := deliveryBytes(memory.item)
		if err != nil {
			t.Error(err)
		}
		clear(body)
		digestText := base64.RawURLEncoding.EncodeToString(digest[:])
		receiptID := value.NewID()
		received := now.Add(-24 * time.Hour).Format(time.RFC3339Nano)
		signature := ed25519.Sign(private, receiptMessage(receiptID, memory.item.ID, digestText, received))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(deliveryReceiptWire{receiptID, memory.item.ID, digestText, received, base64.RawURLEncoding.EncodeToString(signature)})
	}))
	defer server.Close()
	found, err := DeliverOne(context.Background(), memory, server.Client(), server.URL, public, now)
	if err != nil || !found || !memory.acked || memory.retried || !value.ValidID(memory.receipt.ReceiptID) || len(memory.receipt.Digest) != sha256.Size {
		t.Fatal("signed independent receipt was not persisted", found, memory, err)
	}
}

func TestDeliverOneRejectsUntrustedReceiptAndSchedulesRetry(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Microsecond)
	memory := &deliveryMemory{item: Delivery{Event: Event{ID: value.NewID(), Operation: "OP-SEC-04", Purpose: Purpose, RequestID: value.NewID(), Outcome: "allowed", RecordedAt: now, ActorKind: "application"}, ClaimToken: value.NewID(), Attempt: 1}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, digest, _ := deliveryBytes(memory.item)
		clear(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(deliveryReceiptWire{value.NewID(), memory.item.ID, base64.RawURLEncoding.EncodeToString(digest[:]), now.Format(time.RFC3339Nano), base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))})
	}))
	defer server.Close()
	found, err := DeliverOne(context.Background(), memory, server.Client(), server.URL, public, now)
	if err == nil || !found || memory.acked || !memory.retried {
		t.Fatal("untrusted receipt was accepted", found, memory, err)
	}
}
