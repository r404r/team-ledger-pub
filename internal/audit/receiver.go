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
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

const (
	receiptVersion = 1
	chainDomain    = "TEAMLEDGER-AUDIT-CHAIN\x00V1\x00"
)

var (
	ErrInvalidAuditDelivery = errors.New("invalid audit delivery")
	ErrAuditEventConflict   = errors.New("audit event conflict")
)

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

type deliveryRequestWire struct {
	Version      int             `json:"version"`
	DeploymentID string          `json:"deployment_id"`
	EventID      string          `json:"event_id"`
	EventDigest  string          `json:"event_digest"`
	Event        deliveryPayload `json:"event"`
}
type receiptFrame struct {
	Version       int    `json:"version"`
	KeyID         string `json:"key_id"`
	DeploymentID  string `json:"deployment_id"`
	ReceiptID     string `json:"receipt_id"`
	EventID       string `json:"event_id"`
	PayloadDigest string `json:"payload_digest"`
	Sequence      int64  `json:"sequence"`
	PreviousHash  string `json:"previous_hash"`
	EntryHash     string `json:"entry_hash"`
	ReceivedAt    string `json:"received_at"`
}

type deliveryReceiptWire struct {
	receiptFrame
	Signature string `json:"signature"`
}

type ReceiverRecord struct {
	Digest  []byte
	Receipt []byte
}

type ReceiptBuilder func(sequence int64, previousHash []byte) (receipt []byte, entryHash []byte, err error)

type ReceiverStore interface {
	CommitAuditReceipt(context.Context, string, string, []byte, ReceiptBuilder) ([]byte, error)
}

type ReceiptKeys map[string]ed25519.PublicKey

type VerifiedReceipt struct {
	ReceiptID, KeyID, PreviousHash, EntryHash string
	Sequence                                  int64
}

type Receiver struct {
	store      ReceiverStore
	deployment string
	keyID      string
	private    ed25519.PrivateKey
	now        func() time.Time
}

func validName(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidDeploymentID(s string) bool {
	return validName(s)
}

func NewReceiver(store ReceiverStore, deployment, keyID string, private ed25519.PrivateKey, now func() time.Time) (*Receiver, error) {
	if store == nil || !validName(deployment) || !validName(keyID) || len(private) != ed25519.PrivateKeySize || now == nil {
		return nil, errors.New("invalid audit receiver configuration")
	}
	return &Receiver{store: store, deployment: deployment, keyID: keyID, private: private, now: now}, nil
}

func payloadFor(item Delivery) deliveryPayload {
	return deliveryPayload{1, item.ID, item.OrgID, item.SubjectID, item.EmployeeID, item.GrantID, item.Operation, item.Purpose, item.RequestID, item.Outcome, item.RecordedAt.UTC().Truncate(time.Microsecond), item.ActorKind, item.TargetSubjectID, item.TargetEmployeeID}
}

func DeliveryRequestBytes(deployment string, item Delivery) ([]byte, [32]byte, error) {
	var zero [32]byte
	if !validName(deployment) {
		return nil, zero, ErrInvalidAuditDelivery
	}
	event := payloadFor(item)
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return nil, zero, ErrInvalidAuditDelivery
	}
	digest := sha256.Sum256(eventBytes)
	clear(eventBytes)
	wire := deliveryRequestWire{receiptVersion, deployment, item.ID, base64.RawURLEncoding.EncodeToString(digest[:]), event}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > 16<<10 {
		clear(encoded)
		return nil, zero, ErrInvalidAuditDelivery
	}
	return encoded, digest, nil
}

func decodeDelivery(body []byte, idempotency, deployment string) (deliveryRequestWire, [32]byte, error) {
	var wire deliveryRequestWire
	var zero [32]byte
	if len(body) == 0 || len(body) > 16<<10 || !value.ValidID(idempotency) {
		return wire, zero, ErrInvalidAuditDelivery
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != receiptVersion || wire.DeploymentID != deployment || wire.EventID != idempotency || wire.Event.EventID != idempotency {
		return wire, zero, ErrInvalidAuditDelivery
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		clear(canonical)
		return wire, zero, ErrInvalidAuditDelivery
	}
	clear(canonical)
	eventBytes, err := json.Marshal(wire.Event)
	if err != nil {
		return wire, zero, ErrInvalidAuditDelivery
	}
	digest := sha256.Sum256(eventBytes)
	clear(eventBytes)
	declared, err := base64.RawURLEncoding.DecodeString(wire.EventDigest)
	if err != nil || len(declared) != sha256.Size || !bytes.Equal(declared, digest[:]) || !validPayload(wire.Event) {
		clear(declared)
		return wire, zero, ErrInvalidAuditDelivery
	}
	clear(declared)
	return wire, digest, nil
}

func validPayload(p deliveryPayload) bool {
	if p.Version != 1 || !value.ValidID(p.EventID) || !value.ValidID(p.RequestID) || p.RecordedAt.IsZero() || p.RecordedAt.Location() != time.UTC || len(p.Operation) < 1 || len(p.Operation) > 64 || len(p.Purpose) > 64 || len(p.Outcome) < 1 || len(p.Outcome) > 16 || len(p.ActorKind) < 1 || len(p.ActorKind) > 32 {
		return false
	}
	for _, id := range []*string{p.OrgID, p.SubjectID, p.EmployeeID, p.GrantID, p.TargetSubjectID, p.TargetEmployeeID} {
		if id != nil && !value.ValidID(*id) {
			return false
		}
	}
	return true
}

func framed(domain string, parts ...string) []byte {
	out := make([]byte, 0, len(domain)+len(parts)*8)
	out = append(out, domain...)
	for _, part := range parts {
		out = strconv.AppendInt(out, int64(len(part)), 10)
		out = append(out, ':')
		out = append(out, part...)
	}
	return out
}

func (r *Receiver) Receive(ctx context.Context, idempotency string, body []byte) ([]byte, error) {
	wire, digest, err := decodeDelivery(body, idempotency, r.deployment)
	if err != nil {
		return nil, err
	}
	return r.store.CommitAuditReceipt(ctx, r.deployment, wire.EventID, digest[:], func(sequence int64, previous []byte) ([]byte, []byte, error) {
		received := r.now().UTC().Truncate(time.Microsecond)
		if received.IsZero() || sequence < 1 || len(previous) != 0 && len(previous) != sha256.Size {
			return nil, nil, ErrInvalidAuditDelivery
		}
		previousText := base64.RawURLEncoding.EncodeToString(previous)
		digestText := base64.RawURLEncoding.EncodeToString(digest[:])
		receiptID := value.NewID()
		sequenceText := strconv.FormatInt(sequence, 10)
		receivedText := received.Format(time.RFC3339Nano)
		entryMessage := framed(chainDomain, r.deployment, wire.EventID, digestText, sequenceText, previousText, receiptID, r.keyID, receivedText)
		entryHash := sha256.Sum256(entryMessage)
		clear(entryMessage)
		frame := receiptFrame{receiptVersion, r.keyID, r.deployment, receiptID, wire.EventID, digestText, sequence, previousText, base64.RawURLEncoding.EncodeToString(entryHash[:]), receivedText}
		message, marshalErr := json.Marshal(frame)
		if marshalErr != nil {
			return nil, nil, marshalErr
		}
		signature := ed25519.Sign(r.private, message)
		clear(message)
		receipt, marshalErr := json.Marshal(deliveryReceiptWire{frame, base64.RawURLEncoding.EncodeToString(signature)})
		clear(signature)
		if marshalErr != nil || len(receipt) > 16<<10 {
			clear(receipt)
			return nil, nil, ErrInvalidAuditDelivery
		}
		return receipt, entryHash[:], nil
	})
}

func VerifyDeliveryReceipt(encoded []byte, deployment, event string, digest [32]byte, keys ReceiptKeys, now time.Time) (VerifiedReceipt, error) {
	var wire deliveryReceiptWire
	if len(encoded) == 0 || len(encoded) > 16<<10 || !validName(deployment) || !value.ValidID(event) {
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	clear(canonical)
	frame := wire.receiptFrame
	if frame.Version != receiptVersion || frame.DeploymentID != deployment || frame.EventID != event || frame.PayloadDigest != base64.RawURLEncoding.EncodeToString(digest[:]) || !value.ValidID(frame.ReceiptID) || !validName(frame.KeyID) || frame.Sequence < 1 {
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	previous, previousErr := base64.RawURLEncoding.DecodeString(frame.PreviousHash)
	entry, entryErr := base64.RawURLEncoding.DecodeString(frame.EntryHash)
	received, timeErr := time.Parse(time.RFC3339Nano, frame.ReceivedAt)
	public := keys[frame.KeyID]
	signature, signatureErr := base64.RawURLEncoding.DecodeString(wire.Signature)
	if previousErr != nil || len(previous) != 0 && len(previous) != sha256.Size || entryErr != nil || len(entry) != sha256.Size || timeErr != nil || received.Location() != time.UTC || received.After(now.UTC().Add(time.Minute)) || len(public) != ed25519.PublicKeySize || signatureErr != nil {
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	entryMessage := framed(chainDomain, deployment, event, frame.PayloadDigest, strconv.FormatInt(frame.Sequence, 10), frame.PreviousHash, frame.ReceiptID, frame.KeyID, frame.ReceivedAt)
	expectedEntry := sha256.Sum256(entryMessage)
	clear(entryMessage)
	if !bytes.Equal(entry, expectedEntry[:]) {
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	message, err := json.Marshal(frame)
	if err != nil || !ed25519.Verify(public, message, signature) {
		clear(message)
		return VerifiedReceipt{}, ErrInvalidAuditDelivery
	}
	clear(message)
	return VerifiedReceipt{frame.ReceiptID, frame.KeyID, frame.PreviousHash, frame.EntryHash, frame.Sequence}, nil
}

// ValidateReceiptStorage checks that a canonical receipt exactly describes
// the ledger row before its indexed fields are persisted. Signature trust is
// checked independently by the forwarder.
func ValidateReceiptStorage(encoded []byte, deployment, event string, digest []byte, sequence int64, previous, entry []byte) (receiptID, keyID string, receivedAt time.Time, err error) {
	var wire deliveryReceiptWire
	if len(encoded) == 0 || len(encoded) > 16<<10 || len(digest) != sha256.Size || sequence < 1 || len(entry) != sha256.Size || len(previous) != 0 && len(previous) != sha256.Size {
		return "", "", time.Time{}, ErrInvalidAuditDelivery
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", "", time.Time{}, ErrInvalidAuditDelivery
	}
	canonical, marshalErr := json.Marshal(wire)
	frame := wire.receiptFrame
	if marshalErr != nil || !bytes.Equal(canonical, encoded) || frame.Version != receiptVersion || frame.DeploymentID != deployment || frame.EventID != event || frame.PayloadDigest != base64.RawURLEncoding.EncodeToString(digest) || frame.Sequence != sequence || frame.PreviousHash != base64.RawURLEncoding.EncodeToString(previous) || frame.EntryHash != base64.RawURLEncoding.EncodeToString(entry) || !value.ValidID(frame.ReceiptID) || !validName(frame.KeyID) {
		clear(canonical)
		return "", "", time.Time{}, ErrInvalidAuditDelivery
	}
	clear(canonical)
	receivedAt, err = time.Parse(time.RFC3339Nano, frame.ReceivedAt)
	if err != nil || receivedAt.Location() != time.UTC {
		return "", "", time.Time{}, ErrInvalidAuditDelivery
	}
	entryMessage := framed(chainDomain, deployment, event, frame.PayloadDigest, strconv.FormatInt(sequence, 10), frame.PreviousHash, frame.ReceiptID, frame.KeyID, frame.ReceivedAt)
	expectedEntry := sha256.Sum256(entryMessage)
	clear(entryMessage)
	if !bytes.Equal(entry, expectedEntry[:]) {
		return "", "", time.Time{}, ErrInvalidAuditDelivery
	}
	return frame.ReceiptID, frame.KeyID, receivedAt, nil
}

type receiptTrustDocument struct {
	Version int               `json:"version"`
	Keys    map[string]string `json:"keys"`
}

func ParseReceiptKeys(encoded []byte) (ReceiptKeys, error) {
	var document receiptTrustDocument
	if len(encoded) == 0 || len(encoded) > 16<<10 {
		return nil, ErrInvalidAuditDelivery
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Version != 1 || len(document.Keys) == 0 || len(document.Keys) > 8 {
		return nil, ErrInvalidAuditDelivery
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return nil, ErrInvalidAuditDelivery
	}
	clear(canonical)
	keys := make(ReceiptKeys, len(document.Keys))
	for id, text := range document.Keys {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(text)
		if decodeErr != nil || !validName(id) || len(raw) != ed25519.PublicKeySize {
			for _, key := range keys {
				clear(key)
			}
			return nil, ErrInvalidAuditDelivery
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

func ReceiptKeysBytes(keys ReceiptKeys) ([]byte, error) {
	if len(keys) == 0 || len(keys) > 8 {
		return nil, ErrInvalidAuditDelivery
	}
	document := receiptTrustDocument{Version: 1, Keys: make(map[string]string, len(keys))}
	for id, key := range keys {
		if !validName(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidAuditDelivery
		}
		document.Keys[id] = base64.RawURLEncoding.EncodeToString(key)
	}
	return json.Marshal(document)
}
