//go:build linux

package sensitive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type KeydServerConfig struct {
	KeyDirectory    string
	Socket          string
	APIUIDs         []uint32
	MaintenanceUIDs []uint32
}

type keydServer struct {
	mu           sync.Mutex
	ring         keyring
	root         []byte
	keyDirectory string
	api          map[uint32]bool
	maintenance  map[uint32]bool
}

func ServeKeyd(ctx context.Context, cfg KeydServerConfig) error {
	if ctx == nil || !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || len(cfg.APIUIDs) == 0 {
		return errors.New("invalid keyd configuration")
	}
	lockfd, root, ring, err := loadKeyDirectory(cfg.KeyDirectory)
	if err != nil {
		return err
	}
	defer unix.Close(lockfd)
	defer clear(root)
	defer clearKeyring(&ring)
	api := map[uint32]bool{}
	for _, uid := range cfg.APIUIDs {
		api[uid] = true
	}
	maintenance := map[uint32]bool{}
	for _, uid := range cfg.MaintenanceUIDs {
		maintenance[uid] = true
	}
	if info, statErr := os.Lstat(cfg.Socket); statErr == nil {
		st, ok := info.Sys().(*unix.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) {
			return errors.New("unsafe existing keyd socket")
		}
		if err = os.Remove(cfg.Socket); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(cfg.Socket)
	if err = os.Chmod(cfg.Socket, 0660); err != nil {
		return err
	}
	server := &keydServer{ring: ring, root: root, keyDirectory: cfg.KeyDirectory, api: api, maintenance: maintenance}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			server.serveConnection(conn)
		}()
	}
}

func (s *keydServer) serveConnection(conn *net.UnixConn) {
	uid, err := peerUID(conn)
	if err != nil || (!s.api[uid] && !s.maintenance[uid]) {
		return
	}
	reader := bufio.NewReaderSize(conn, keydFrameLimit+4)
	var size [4]byte
	if _, err = io.ReadFull(reader, size[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > keydFrameLimit {
		return
	}
	raw := make([]byte, n)
	if _, err = io.ReadFull(reader, raw); err != nil {
		clear(raw)
		return
	}
	response := keydResponse{OK: false, Code: "invalid"}
	var request keydRequest
	if validJSON(raw) {
		decoder := json.NewDecoder(newExactReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) == nil && decoder.Decode(&struct{}{}) == io.EOF {
			response = s.dispatch(uid, request)
		}
	}
	clear(raw)
	encoded, _ := json.Marshal(response)
	if len(encoded) == 0 || len(encoded) > keydFrameLimit {
		return
	}
	binary.BigEndian.PutUint32(size[:], uint32(len(encoded)))
	_, _ = conn.Write(size[:])
	_, _ = conn.Write(encoded)
	clear(encoded)
}

func validJSON(raw []byte) bool {
	decoder := json.NewDecoder(newExactReader(raw))
	decoder.UseNumber()
	stack := []map[string]bool{}
	expectKey := []bool{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, map[string]bool{})
				expectKey = append(expectKey, true)
			case '}':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectKey = expectKey[:len(expectKey)-1]
			case '[':
				stack = append(stack, nil)
				expectKey = append(expectKey, false)
			case ']':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectKey = expectKey[:len(expectKey)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1] != nil && expectKey[len(expectKey)-1] {
				if stack[len(stack)-1][value] {
					return false
				}
				stack[len(stack)-1][value] = true
				expectKey[len(expectKey)-1] = false
			} else if len(stack) > 0 && stack[len(stack)-1] != nil {
				expectKey[len(expectKey)-1] = true
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1] != nil {
				expectKey[len(expectKey)-1] = true
			}
		}
	}
}

func (s *keydServer) dispatch(uid uint32, request keydRequest) keydResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.Operation == "ready" {
		if request.KeyID != "" || request.Domain != "" || request.Context != nil || request.DEKID != "" || len(request.Data) != 0 || request.Key != nil || len(request.Message) != 0 || request.Version != 0 || len(request.MAC) != 0 {
			return keydResponse{Code: "invalid"}
		}
		return s.readyResponse()
	}
	if request.Operation != "retire" && request.Operation != "stage" && request.Operation != "verify" && request.KeyID != "" {
		return keydResponse{Code: "invalid"}
	}
	if !s.api[uid] && !s.maintenance[uid] {
		return keydResponse{Code: "unavailable"}
	}
	switch request.Operation {
	case "wrap":
		if request.Domain == DomainBackupArchive && !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.wrap(request)
	case "unwrap":
		if request.Domain == DomainBackupArchive && !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.unwrap(request)
	case "probe":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.probe(request)
	case "rewrap":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.rewrap(request)
	case "mac":
		return s.mac(request)
	case "derive":
		return s.derive(request)
	case "verify":
		return s.verify(request)
	case "stage":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.stage(request)
	case "activate":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.activate(request)
	case "acknowledge":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.acknowledge(request)
	case "retire":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.retire(request)
	case "mac_staging":
		if !s.maintenance[uid] {
			return keydResponse{Code: "unavailable"}
		}
		return s.macStaging(request)
	default:
		return keydResponse{Code: "invalid"}
	}
}

func expectedDomain(binding Context, dekID string) (KeyDomain, error) {
	if _, err := canonicalAAD(binding, dekID); err != nil {
		return "", err
	}
	if binding.ObjectKind == "assessment_result" {
		return DomainAssessmentPayload, nil
	}
	switch binding.Purpose {
	case "pii":
		return DomainPIIPayload, nil
	case "interview":
		return DomainInterviewPayload, nil
	case "assessment":
		return DomainAssessmentPayload, nil
	case "financial":
		return DomainFinancialPayload, nil
	case "identity":
		switch binding.ObjectKind {
		case "identity_transaction":
			return DomainIdentityTransaction, nil
		case "local_mfa_factor", "local_mfa_enrollment":
			return DomainIdentityMFA, nil
		default:
			return DomainIdentityMapping, nil
		}
	case "backup":
		return DomainBackupArchive, nil
	default:
		return "", ErrInvalid
	}
}
func (s *keydServer) entry(domain KeyDomain, keyID string, version uint32, write bool) (*keyEntry, bool) {
	for i := range s.ring.Entries {
		e := &s.ring.Entries[i]
		if e.Domain != domain {
			continue
		}
		if keyID != "" && (e.KeyID != keyID || e.Version != version) {
			continue
		}
		if keyID == "" && version != 0 && e.Version != version {
			continue
		}
		if write && e.Status != "active" && e.Status != "active_write_verify" {
			continue
		}
		if !write && e.Status != "active" && e.Status != "active_write_verify" && e.Status != "decrypt_only" && e.Status != "verify_only" {
			continue
		}
		return e, true
	}
	return nil, false
}
func (s *keydServer) wrap(r keydRequest) keydResponse {
	if !s.writeEnabled() || !wrapperDomain(r.Domain) || r.Context == nil || len(r.Data) != 32 || r.Key != nil || len(r.Message) != 0 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	domain, err := expectedDomain(*r.Context, r.DEKID)
	if err != nil || domain != r.Domain {
		return keydResponse{Code: "invalid"}
	}
	aad, err := canonicalAAD(*r.Context, r.DEKID)
	if err != nil {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, "", 0, true)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	packet, err := encodeTLW(r.Domain, entry.KeyID, entry.Version, r.DEKID, aad, r.Data, entry.Material)
	if err != nil {
		return keydResponse{Code: "unavailable"}
	}
	key := WrappedKey{KEKID: entry.KeyID, Version: entry.Version, Data: packet}
	return keydResponse{OK: true, Key: &key}
}
func (s *keydServer) unwrap(r keydRequest) keydResponse {
	if !wrapperDomain(r.Domain) || r.Context == nil || r.Key == nil || len(r.Data) != 0 || len(r.Message) != 0 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	domain, err := expectedDomain(*r.Context, r.DEKID)
	if err != nil || domain != r.Domain {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, r.Key.KEKID, r.Key.Version, false)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	aad, _ := canonicalAAD(*r.Context, r.DEKID)
	dek, err := decodeTLW(r.Key.Data, r.Domain, entry.KeyID, entry.Version, r.DEKID, aad, entry.Material)
	if err != nil {
		return keydResponse{Code: "invalid"}
	}
	return keydResponse{OK: true, Data: dek}
}
func macInput(domain KeyDomain, message []byte) []byte {
	raw := make([]byte, 0, 32+len(domain)+len(message))
	raw = append(raw, "TEAMLEDGER-KEYD-MAC\x00"...)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(domain)))
	raw = append(raw, domain...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(message)))
	raw = append(raw, message...)
	return raw
}
func (s *keydServer) mac(r keydRequest) keydResponse {
	if !s.writeEnabled() || !macDomain(r.Domain) || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || r.Version != 0 || len(r.MAC) != 0 || len(r.Message) > 32<<10 {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, "", 0, true)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	input := macInput(r.Domain, r.Message)
	mac := hmac.New(sha256.New, entry.Material)
	_, _ = mac.Write(input)
	clear(input)
	value := MACValue{KeyID: entry.KeyID, Version: entry.Version, Digest: mac.Sum(nil)}
	return keydResponse{OK: true, MAC: &value}
}
func (s *keydServer) derive(r keydRequest) keydResponse {
	if !s.writeEnabled() || r.Domain != DomainIdentityTransaction || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || r.Version != 0 || len(r.MAC) != 0 || len(r.Message) == 0 || len(r.Message) > 256 {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, "", 0, true)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	mac := hmac.New(sha256.New, entry.Material)
	_, _ = mac.Write([]byte("TEAMLEDGER-KEYD-DERIVE\x00V1\x00"))
	_, _ = mac.Write(r.Message)
	value := MACValue{KeyID: entry.KeyID, Version: entry.Version, Digest: mac.Sum(nil)}
	return keydResponse{OK: true, MAC: &value}
}

func (s *keydServer) verify(r keydRequest) keydResponse {
	if !macDomain(r.Domain) || r.KeyID == "" || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || r.Version == 0 || len(r.MAC) != 32 || len(r.Message) > 32<<10 {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, r.KeyID, r.Version, false)
	if !ok || entry.KeyID != r.KeyID || entry.Version != r.Version {
		return keydResponse{Code: "unavailable"}
	}
	input := macInput(r.Domain, r.Message)
	mac := hmac.New(sha256.New, entry.Material)
	_, _ = mac.Write(input)
	clear(input)
	return keydResponse{OK: true, Verified: equalMAC(r.MAC, mac.Sum(nil))}
}

func (s *keydServer) probe(r keydRequest) keydResponse {
	if !wrapperDomain(r.Domain) || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key == nil || len(r.Message) != 0 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	entry, ok := s.entry(r.Domain, r.Key.KEKID, r.Key.Version, false)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	dek, err := probeTLW(r.Key.Data, r.Domain, entry.KeyID, entry.Version, entry.Material)
	if err != nil {
		return keydResponse{Code: "invalid"}
	}
	return keydResponse{OK: true, Data: dek}
}

func (s *keydServer) rewrap(r keydRequest) keydResponse {
	if !wrapperDomain(r.Domain) || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key == nil || len(r.Message) != 0 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	source, ok := s.entry(r.Domain, r.Key.KEKID, r.Key.Version, false)
	if !ok {
		return keydResponse{Code: "unavailable"}
	}
	var target *keyEntry
	for i := range s.ring.Entries {
		if s.ring.Entries[i].Domain == r.Domain && s.ring.Entries[i].Status == "staged" {
			target = &s.ring.Entries[i]
			break
		}
	}
	if target == nil {
		return keydResponse{Code: "unavailable"}
	}
	dek, err := probeTLW(r.Key.Data, r.Domain, source.KeyID, source.Version, source.Material)
	if err != nil {
		return keydResponse{Code: "invalid"}
	}
	defer clear(dek)
	dekID := formatUUID(r.Key.Data[28:44])
	packet, err := encodeTLWDigest(r.Domain, target.KeyID, target.Version, dekID, r.Key.Data[44:76], dek, target.Material)
	if err != nil {
		return keydResponse{Code: "unavailable"}
	}
	next := WrappedKey{KEKID: target.KeyID, Version: target.Version, Data: packet}
	return keydResponse{OK: true, Key: &next}
}

func (s *keydServer) writeEnabled() bool {
	for i := range s.ring.Entries {
		if len(s.ring.Entries[i].Manifest) != 0 {
			return false
		}
	}
	return true
}

func keyringReadyState(ring keyring) ReadyState {
	active := map[KeyDomain]uint32{}
	activeKeys := map[KeyDomain]KeyReference{}
	staged := map[KeyDomain]KeyReference{}
	for _, entry := range ring.Entries {
		if entry.Status == "active" || entry.Status == "active_write_verify" {
			active[entry.Domain] = entry.Version
			activeKeys[entry.Domain] = KeyReference{KeyID: entry.KeyID, Version: entry.Version}
		}
		if len(entry.Manifest) == 32 {
			staged[entry.Domain] = KeyReference{KeyID: entry.KeyID, Version: entry.Version}
		}
	}
	return ReadyState{MaterialGeneration: ring.Generation, Digest: ring.Digest, Active: active, ActiveKeys: activeKeys, Staged: staged, WriteEnabled: len(staged) == 0}
}

func (s *keydServer) readyResponse() keydResponse {
	state := keyringReadyState(s.ring)
	return keydResponse{OK: true, Ready: &state}
}

func (s *keydServer) stage(r keydRequest) keydResponse {
	if _, ok := domainNumber(r.Domain); !ok || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || !validKeyName(r.KeyID) || len(r.Message) != 32 || r.Version == 0 || len(r.MAC) != 0 || !s.writeEnabled() {
		return keydResponse{Code: "invalid"}
	}
	var maximum uint32
	for _, entry := range s.ring.Entries {
		if entry.Domain == r.Domain {
			if entry.Status == "staged" {
				return keydResponse{Code: "unavailable"}
			}
			if entry.Version > maximum {
				maximum = entry.Version
			}
		}
	}
	if maximum == ^uint32(0) || r.Version != maximum+1 {
		return keydResponse{Code: "unavailable"}
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		clear(material)
		return keydResponse{Code: "unavailable"}
	}
	next := s.ring
	next.Entries = append([]keyEntry(nil), s.ring.Entries...)
	kind := "wrap"
	if macDomain(r.Domain) {
		kind = "mac"
	}
	next.Entries = append(next.Entries, keyEntry{Domain: r.Domain, Kind: kind, KeyID: r.KeyID, Version: r.Version, Status: "staged", Material: material, Manifest: bytes.Clone(r.Message)})
	next.Generation++
	if err := persistKeyring(s.keyDirectory, s.root, &next); err != nil {
		clear(material)
		return keydResponse{Code: "unavailable"}
	}
	s.ring = next
	return s.readyResponse()
}

func (s *keydServer) activate(r keydRequest) keydResponse {
	if _, ok := domainNumber(r.Domain); !ok || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || len(r.Message) != 32 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	next := s.ring
	next.Entries = append([]keyEntry(nil), s.ring.Entries...)
	staged := false
	for i := range next.Entries {
		entry := &next.Entries[i]
		if entry.Domain != r.Domain {
			continue
		}
		switch entry.Status {
		case "staged":
			if !bytes.Equal(entry.Manifest, r.Message) {
				return keydResponse{Code: "unavailable"}
			}
			if wrapperDomain(r.Domain) {
				entry.Status = "active"
			} else {
				entry.Status = "active_write_verify"
			}
			staged = true
		case "active":
			entry.Status = "decrypt_only"
		case "active_write_verify":
			entry.Status = "verify_only"
		}
	}
	if !staged {
		return keydResponse{Code: "unavailable"}
	}
	next.Generation++
	if err := persistKeyring(s.keyDirectory, s.root, &next); err != nil {
		return keydResponse{Code: "unavailable"}
	}
	s.ring = next
	return s.readyResponse()
}

func (s *keydServer) acknowledge(r keydRequest) keydResponse {
	if _, ok := domainNumber(r.Domain); !ok || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || len(r.Message) != 32 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	next := s.ring
	next.Entries = append([]keyEntry(nil), s.ring.Entries...)
	found := false
	for i := range next.Entries {
		entry := &next.Entries[i]
		if entry.Domain == r.Domain && (entry.Status == "active" || entry.Status == "active_write_verify") && bytes.Equal(entry.Manifest, r.Message) {
			entry.Manifest = nil
			found = true
		}
	}
	if !found {
		return keydResponse{Code: "unavailable"}
	}
	next.Generation++
	if err := persistKeyring(s.keyDirectory, s.root, &next); err != nil {
		return keydResponse{Code: "unavailable"}
	}
	s.ring = next
	return s.readyResponse()
}

func (s *keydServer) retire(r keydRequest) keydResponse {
	if _, ok := domainNumber(r.Domain); !ok || r.Domain == DomainBackupArchive || !s.writeEnabled() || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || r.KeyID == "" || r.Version == 0 || len(r.Message) != 32 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	next := s.ring
	next.Entries = make([]keyEntry, 0, len(s.ring.Entries)-1)
	found := false
	for i := range s.ring.Entries {
		entry := s.ring.Entries[i]
		if entry.Domain == r.Domain && entry.KeyID == r.KeyID && entry.Version == r.Version {
			if entry.Status != "decrypt_only" && entry.Status != "verify_only" {
				return keydResponse{Code: "unavailable"}
			}
			found = true
			continue
		}
		next.Entries = append(next.Entries, entry)
	}
	if !found {
		return s.readyResponse()
	}
	next.Generation++
	if err := persistKeyring(s.keyDirectory, s.root, &next); err != nil {
		return keydResponse{Code: "unavailable"}
	}
	for i := range s.ring.Entries {
		if s.ring.Entries[i].Domain == r.Domain && s.ring.Entries[i].KeyID == r.KeyID && s.ring.Entries[i].Version == r.Version {
			clear(s.ring.Entries[i].Material)
			break
		}
	}
	s.ring = next
	return s.readyResponse()
}

func (s *keydServer) macStaging(r keydRequest) keydResponse {
	if !macDomain(r.Domain) || r.Context != nil || r.DEKID != "" || len(r.Data) != 0 || r.Key != nil || len(r.Message) < 32 || len(r.Message) > 32<<10 || r.Version != 0 || len(r.MAC) != 0 {
		return keydResponse{Code: "invalid"}
	}
	var entry *keyEntry
	for i := range s.ring.Entries {
		candidate := &s.ring.Entries[i]
		if candidate.Domain == r.Domain && candidate.Status == "staged" && bytes.Equal(candidate.Manifest, r.Message[:32]) {
			entry = candidate
			break
		}
	}
	if entry == nil {
		return keydResponse{Code: "unavailable"}
	}
	input := macInput(r.Domain, r.Message[32:])
	mac := hmac.New(sha256.New, entry.Material)
	_, _ = mac.Write(input)
	clear(input)
	value := MACValue{KeyID: entry.KeyID, Version: entry.Version, Digest: mac.Sum(nil)}
	return keydResponse{OK: true, MAC: &value}
}

func ParseUIDList(value string) ([]uint32, error) {
	if value == "" {
		return nil, errors.New("empty UID list")
	}
	seen := map[uint32]bool{}
	var out []uint32
	for _, part := range strings.Split(value, ",") {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part || seen[uint32(number)] {
			return nil, errors.New("invalid UID list")
		}
		seen[uint32(number)] = true
		out = append(out, uint32(number))
	}
	return out, nil
}
