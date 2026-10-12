package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

const deliveryDomain = "TEAMLEDGER-AUDIT-RECEIPT\x00V1\x00"

type deliveryPayload struct {
	Version          int       `json:"version"`
	EventID          string    `json:"event_id"`
	OrgID            *string   `json:"org_id"`
	SubjectID        *string   `json:"subject_id"`
	EmployeeID       *string   `json:"employee_id"`
	GrantID          *string   `json:"grant_id"`
	Operation        string    `json:"operation"`
	Purpose          string    `json:"purpose"`
	RequestID        string    `json:"request_id"`
	Outcome          string    `json:"outcome"`
	RecordedAt       time.Time `json:"recorded_at"`
	ActorKind        string    `json:"actor_kind"`
	TargetSubjectID  *string   `json:"target_subject_id"`
	TargetEmployeeID *string   `json:"target_employee_id"`
}

type deliveryReceiptWire struct {
	ReceiptID     string `json:"receipt_id"`
	EventID       string `json:"event_id"`
	PayloadDigest string `json:"payload_digest"`
	ReceivedAt    string `json:"received_at"`
	Signature     string `json:"signature"`
}

func deliveryBytes(item Delivery) ([]byte, [32]byte, error) {
	payload := deliveryPayload{1, item.ID, item.OrgID, item.SubjectID, item.EmployeeID, item.GrantID, item.Operation, item.Purpose, item.RequestID, item.Outcome, item.RecordedAt.UTC().Truncate(time.Microsecond), item.ActorKind, item.TargetSubjectID, item.TargetEmployeeID}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 16<<10 {
		return nil, [32]byte{}, errors.New("invalid audit delivery")
	}
	return encoded, sha256.Sum256(encoded), nil
}

func receiptMessage(receiptID, eventID, digest, receivedAt string) []byte {
	parts := []string{receiptID, eventID, digest, receivedAt}
	message := []byte(deliveryDomain)
	for _, part := range parts {
		message = strconv.AppendInt(message, int64(len(part)), 10)
		message = append(message, ':')
		message = append(message, part...)
	}
	return message
}

func retryAt(now time.Time, attempt int64) time.Time {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return now.Add(time.Second * time.Duration(1<<uint(attempt-1)))
}

// DeliverOne transfers one body-free audit event and accepts only a receipt
// signed by the separately configured audit facility.
func DeliverOne(ctx context.Context, store DeliveryStore, client *http.Client, endpoint string, receiptKey ed25519.PublicKey, now time.Time) (bool, error) {
	if store == nil || client == nil || len(receiptKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid audit delivery configuration")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false, errors.New("invalid audit delivery endpoint")
	}
	item, found, err := store.ClaimAuditDelivery(ctx, now, time.Minute)
	if err != nil || !found {
		return found, err
	}
	release := func(cause error) (bool, error) {
		retryErr := store.RetryAuditDelivery(context.WithoutCancel(ctx), item.ID, item.ClaimToken, retryAt(now, item.Attempt))
		if retryErr != nil {
			return true, retryErr
		}
		return true, cause
	}
	body, digest, err := deliveryBytes(item)
	if err != nil {
		return release(err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return release(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", item.ID)
	response, err := client.Do(request)
	if err != nil {
		return release(err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 16<<10+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > 16<<10 || response.StatusCode != http.StatusCreated || response.Header.Get("Content-Type") != "application/json" {
		return release(errors.New("audit facility rejected delivery"))
	}
	var wire deliveryReceiptWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || !value.ValidID(wire.ReceiptID) || wire.EventID != item.ID || wire.PayloadDigest != base64.RawURLEncoding.EncodeToString(digest[:]) {
		return release(errors.New("invalid audit receipt"))
	}
	received, timeErr := time.Parse(time.RFC3339Nano, wire.ReceivedAt)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(wire.Signature)
	if timeErr != nil || received.Location() != time.UTC || received.After(now.Add(time.Minute)) || signatureErr != nil || !ed25519.Verify(receiptKey, receiptMessage(wire.ReceiptID, wire.EventID, wire.PayloadDigest, wire.ReceivedAt), signature) {
		return release(errors.New("untrusted audit receipt"))
	}
	if err = store.AckAuditDelivery(ctx, item.ID, item.ClaimToken, DeliveryReceipt{ReceiptID: wire.ReceiptID, Digest: digest[:]}, now); err != nil {
		return true, err
	}
	return true, nil
}
