package sensitive

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

const keydFrameLimit = 64 << 10

type KeyDomain string

const (
	DomainPIIPayload            KeyDomain = "pii_payload"
	DomainInterviewPayload      KeyDomain = "interview_payload"
	DomainAssessmentPayload     KeyDomain = "assessment_payload"
	DomainFinancialPayload      KeyDomain = "financial_payload"
	DomainIdentityTransaction   KeyDomain = "identity_transaction"
	DomainIdentityMapping       KeyDomain = "identity_mapping"
	DomainBackupArchive         KeyDomain = "backup_archive"
	DomainStaffCodeLookup       KeyDomain = "staff_code_lookup"
	DomainBonusPaymentLookup    KeyDomain = "bonus_payment_lookup"
	DomainIdentitySubjectLookup KeyDomain = "identity_subject_lookup"
	DomainCommandReceipt        KeyDomain = "command_receipt"
	DomainAssessmentGeneration  KeyDomain = "assessment_generation"
	DomainCSRFToken             KeyDomain = "csrf_token"
	DomainCursorToken           KeyDomain = "cursor_token"
	DomainLocalUsernameLookup   KeyDomain = "local_username_lookup"
	DomainLocalPasswordPepper   KeyDomain = "local_password_pepper"
)

type KeyReference struct {
	KeyID   string `json:"key_id"`
	Version uint32 `json:"version"`
}

type ReadyState struct {
	MaterialGeneration uint64                     `json:"material_generation"`
	Digest             string                     `json:"digest"`
	Active             map[KeyDomain]uint32       `json:"active"`
	ActiveKeys         map[KeyDomain]KeyReference `json:"active_keys"`
	Staged             map[KeyDomain]KeyReference `json:"staged,omitempty"`
	WriteEnabled       bool                       `json:"write_enabled"`
}

type MACValue struct {
	KeyID   string `json:"key_id"`
	Version uint32 `json:"version"`
	Digest  []byte `json:"digest"`
}

type keydRequest struct {
	Operation string      `json:"operation"`
	KeyID     string      `json:"key_id,omitempty"`
	Domain    KeyDomain   `json:"domain,omitempty"`
	Context   *Context    `json:"context,omitempty"`
	DEKID     string      `json:"dek_id,omitempty"`
	Data      []byte      `json:"data,omitempty"`
	Key       *WrappedKey `json:"key,omitempty"`
	Message   []byte      `json:"message,omitempty"`
	Version   uint32      `json:"version,omitempty"`
	MAC       []byte      `json:"mac,omitempty"`
}

type keydResponse struct {
	OK       bool        `json:"ok"`
	Code     string      `json:"code,omitempty"`
	Key      *WrappedKey `json:"key,omitempty"`
	Data     []byte      `json:"data,omitempty"`
	MAC      *MACValue   `json:"mac,omitempty"`
	Ready    *ReadyState `json:"ready,omitempty"`
	Verified bool        `json:"verified,omitempty"`
}

type KeydClient struct {
	Socket  string
	Timeout time.Duration
}

func (c *KeydClient) call(ctx context.Context, request keydRequest) (keydResponse, error) {
	if c == nil || c.Socket == "" || ctx.Err() != nil {
		return keydResponse{}, ErrUnavailable
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return keydResponse{}, ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	raw, err := json.Marshal(request)
	if err != nil || len(raw) == 0 || len(raw) > keydFrameLimit {
		return keydResponse{}, ErrInvalid
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	if _, err = conn.Write(size[:]); err == nil {
		_, err = conn.Write(raw)
	}
	clear(raw)
	if err != nil {
		return keydResponse{}, ErrUnavailable
	}
	reader := bufio.NewReaderSize(conn, keydFrameLimit+4)
	if _, err = io.ReadFull(reader, size[:]); err != nil {
		return keydResponse{}, ErrUnavailable
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > keydFrameLimit {
		return keydResponse{}, ErrUnavailable
	}
	raw = make([]byte, n)
	if _, err = io.ReadFull(reader, raw); err != nil {
		return keydResponse{}, ErrUnavailable
	}
	decoder := json.NewDecoder(newExactReader(raw))
	decoder.DisallowUnknownFields()
	var response keydResponse
	if decoder.Decode(&response) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(raw)
		return keydResponse{}, ErrUnavailable
	}
	clear(raw)
	if !response.OK {
		if response.Code == "invalid" {
			return keydResponse{}, ErrInvalid
		}
		return keydResponse{}, ErrUnavailable
	}
	return response, nil
}

type exactReader struct {
	data   []byte
	offset int
}

func newExactReader(data []byte) *exactReader { return &exactReader{data: data} }
func (r *exactReader) Read(p []byte) (int, error) {
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (c *KeydClient) Ready(ctx context.Context) (ReadyState, error) {
	response, err := c.call(ctx, keydRequest{Operation: "ready"})
	if err != nil || response.Ready == nil || response.Ready.MaterialGeneration == 0 || len(response.Ready.Active) != 16 || len(response.Ready.ActiveKeys) != 16 {
		return ReadyState{}, ErrUnavailable
	}
	return *response.Ready, nil
}

func (c *KeydClient) MAC(ctx context.Context, domain KeyDomain, message []byte) (MACValue, error) {
	response, err := c.call(ctx, keydRequest{Operation: "mac", Domain: domain, Message: message})
	if err != nil || response.MAC == nil || response.MAC.Version == 0 || len(response.MAC.Digest) != 32 {
		return MACValue{}, keyError(err)
	}
	return *response.MAC, nil
}

func (c *KeydClient) Verify(ctx context.Context, domain KeyDomain, reference KeyReference, message, digest []byte) (bool, error) {
	response, err := c.call(ctx, keydRequest{Operation: "verify", Domain: domain, KeyID: reference.KeyID, Version: reference.Version, Message: message, MAC: digest})
	if err != nil {
		return false, err
	}
	return response.Verified, nil
}

// ProcessKey returns a purpose-separated process key only for the transient
// OIDC transaction encryption domain. Root and keyring material stay in keyd.
func (c *KeydClient) ProcessKey(ctx context.Context, domain KeyDomain, label string) ([]byte, error) {
	if domain != DomainIdentityTransaction || label == "" {
		return nil, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "derive", Domain: domain, Message: []byte(label)})
	if err != nil || response.MAC == nil || len(response.MAC.Digest) != 32 {
		return nil, keyError(err)
	}
	return response.MAC.Digest, nil
}

type keydWrapper struct {
	client *KeydClient
	domain KeyDomain
}

func (c *KeydClient) Stage(ctx context.Context, domain KeyDomain, target KeyReference, manifest []byte) (ReadyState, error) {
	if _, ok := domainNumber(domain); !ok || target.KeyID == "" || target.Version == 0 || len(manifest) != 32 {
		return ReadyState{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "stage", Domain: domain, KeyID: target.KeyID, Version: target.Version, Message: manifest})
	if err != nil || response.Ready == nil || response.Ready.Staged[domain] != target {
		return ReadyState{}, keyError(err)
	}
	return *response.Ready, nil
}

func (c *KeydClient) Activate(ctx context.Context, domain KeyDomain, manifest []byte) (ReadyState, error) {
	if _, ok := domainNumber(domain); !ok || len(manifest) != 32 {
		return ReadyState{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "activate", Domain: domain, Message: manifest})
	if err != nil || response.Ready == nil {
		return ReadyState{}, keyError(err)
	}
	return *response.Ready, nil
}

func (c *KeydClient) Acknowledge(ctx context.Context, domain KeyDomain, manifest []byte) (ReadyState, error) {
	if _, ok := domainNumber(domain); !ok || len(manifest) != 32 {
		return ReadyState{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "acknowledge", Domain: domain, Message: manifest})
	if err != nil || response.Ready == nil || !response.Ready.WriteEnabled {
		return ReadyState{}, keyError(err)
	}
	return *response.Ready, nil
}

func (c *KeydClient) Retire(ctx context.Context, domain KeyDomain, key KeyReference, proof []byte) (ReadyState, error) {
	if _, ok := domainNumber(domain); !ok || key.KeyID == "" || key.Version == 0 || len(proof) != 32 {
		return ReadyState{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "retire", Domain: domain, KeyID: key.KeyID, Version: key.Version, Message: proof})
	if err != nil || response.Ready == nil || !response.Ready.WriteEnabled {
		return ReadyState{}, keyError(err)
	}
	return *response.Ready, nil
}

func (c *KeydClient) MACStaging(ctx context.Context, domain KeyDomain, manifest, message []byte) (MACValue, error) {
	if !macDomain(domain) || len(manifest) != 32 {
		return MACValue{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "mac_staging", Domain: domain, Message: append(append([]byte(nil), manifest...), message...)})
	if err != nil || response.MAC == nil || len(response.MAC.Digest) != 32 {
		return MACValue{}, keyError(err)
	}
	return *response.MAC, nil
}

func (c *KeydClient) Rewrap(ctx context.Context, domain KeyDomain, key WrappedKey) (WrappedKey, error) {
	if !wrapperDomain(domain) || !validWrappedKey(key) {
		return WrappedKey{}, ErrInvalid
	}
	response, err := c.call(ctx, keydRequest{Operation: "rewrap", Domain: domain, Key: &key})
	if err != nil || response.Key == nil || !validWrappedKey(*response.Key) {
		return WrappedKey{}, keyError(err)
	}
	return *response.Key, nil
}

// WrapBackup wraps one random archive DEK in the maintenance-only backup
// domain. The archive identifier is the DEK UUID and is recoverable from TLW1.
func (c *KeydClient) WrapBackup(ctx context.Context, dek []byte) (WrappedKey, error) {
	if len(dek) != 32 {
		return WrappedKey{}, ErrInvalid
	}
	dekID, err := newDEKID()
	if err != nil {
		return WrappedKey{}, ErrUnavailable
	}
	binding := backupBinding(dekID)
	response, err := c.call(ctx, keydRequest{Operation: "wrap", Domain: DomainBackupArchive, Context: &binding, DEKID: dekID, Data: dek})
	if err != nil || response.Key == nil || !validWrappedKey(*response.Key) {
		return WrappedKey{}, keyError(err)
	}
	return *response.Key, nil
}

func backupBinding(dekID string) Context {
	const zero = "00000000-0000-0000-0000-000000000000"
	return Context{OrgID: zero, RecordID: dekID, VersionID: zero, ObjectKind: "backup_archive", Purpose: "backup", SchemaType: "backup.archive.v1", SchemaVersion: 1}
}

// ParseBackupWrappedKey validates the public TLW1 header without unwrapping it.
func ParseBackupWrappedKey(packet []byte) (WrappedKey, error) {
	if len(packet) != 150 || string(packet[:4]) != "TLW1" || binary.BigEndian.Uint16(packet[4:6]) != 1 ||
		binary.BigEndian.Uint16(packet[6:8]) != 7 || binary.BigEndian.Uint32(packet[24:28]) == 0 ||
		binary.BigEndian.Uint16(packet[76:78]) != 72 {
		return WrappedKey{}, ErrInvalid
	}
	keyID := formatUUID(packet[8:24])
	dekID := formatUUID(packet[28:44])
	if keyID == "" || dekID == "" {
		return WrappedKey{}, ErrInvalid
	}
	return WrappedKey{KEKID: keyID, Version: binary.BigEndian.Uint32(packet[24:28]), Data: append([]byte(nil), packet...)}, nil
}

func (c *KeydClient) UnwrapBackup(ctx context.Context, key WrappedKey) ([]byte, error) {
	parsed, err := ParseBackupWrappedKey(key.Data)
	if err != nil || parsed.KEKID != key.KEKID || parsed.Version != key.Version {
		return nil, ErrInvalid
	}
	dekID := formatUUID(key.Data[28:44])
	binding := backupBinding(dekID)
	response, err := c.call(ctx, keydRequest{Operation: "unwrap", Domain: DomainBackupArchive, Context: &binding, DEKID: dekID, Key: &key})
	if err != nil || len(response.Data) != 32 {
		clear(response.Data)
		return nil, keyError(err)
	}
	return response.Data, nil
}

func NewKeydWrapper(client *KeydClient, domain KeyDomain) (Wrapper, error) {
	if client == nil || !wrapperDomain(domain) {
		return nil, ErrInvalid
	}
	return &keydWrapper{client: client, domain: domain}, nil
}
func (w *keydWrapper) Ready(ctx context.Context) error {
	state, err := w.client.Ready(ctx)
	if err != nil || state.Active[w.domain] == 0 {
		return ErrUnavailable
	}
	return nil
}

func (w *keydWrapper) Wrap(ctx context.Context, dek []byte) (WrappedKey, error) {
	return WrappedKey{}, ErrInvalid
}
func (w *keydWrapper) Unwrap(ctx context.Context, key WrappedKey) ([]byte, error) {
	response, err := w.client.call(ctx, keydRequest{Operation: "probe", Domain: w.domain, Key: &key})
	if err != nil || len(response.Data) != 32 {
		clear(response.Data)
		return nil, keyError(err)
	}
	return response.Data, nil
}
func (w *keydWrapper) WrapBound(ctx context.Context, binding Context, dekID string, dek []byte) (WrappedKey, error) {
	response, err := w.client.call(ctx, keydRequest{Operation: "wrap", Domain: w.domain, Context: &binding, DEKID: dekID, Data: dek})
	if err != nil || response.Key == nil || !validWrappedKey(*response.Key) {
		return WrappedKey{}, keyError(err)
	}
	return *response.Key, nil
}
func (w *keydWrapper) UnwrapBound(ctx context.Context, binding Context, dekID string, key WrappedKey) ([]byte, error) {
	response, err := w.client.call(ctx, keydRequest{Operation: "unwrap", Domain: w.domain, Context: &binding, DEKID: dekID, Key: &key})
	if err != nil || len(response.Data) != 32 {
		clear(response.Data)
		return nil, keyError(err)
	}
	return response.Data, nil
}

func equalMAC(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }

var errKeydProtocol = errors.New("invalid keyd protocol")
