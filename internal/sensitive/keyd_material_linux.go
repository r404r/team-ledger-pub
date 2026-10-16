//go:build linux

package sensitive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type keyEntry struct {
	Domain   KeyDomain `json:"domain"`
	Kind     string    `json:"kind"`
	KeyID    string    `json:"key_id"`
	Version  uint32    `json:"version"`
	Status   string    `json:"status"`
	Material []byte    `json:"material"`
	Manifest []byte    `json:"manifest,omitempty"`
}
type keyring struct {
	Generation uint64     `json:"generation"`
	Entries    []keyEntry `json:"entries"`
	Digest     string     `json:"-"`
}

func secureOpenDirectory(path string, exactFinal bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, errors.New("invalid key directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	uid := uint32(os.Geteuid())
	for i, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return -1, errors.New("invalid key directory")
		}
		next, openErr := unix.Openat2(fd, part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || st.Mode&0022 != 0 {
			unix.Close(fd)
			return -1, errors.New("unsafe key directory ancestry")
		}
		if exactFinal && i == len(strings.Split(strings.TrimPrefix(path, "/"), "/"))-1 && (st.Uid != uid || st.Mode&0777 != 0700 || st.Nlink != 2) {
			unix.Close(fd)
			return -1, errors.New("invalid key directory metadata")
		}
	}
	return fd, nil
}

func openCheckedFile(dirfd int, name string, flags int, mode uint32, size int64) (int, error) {
	fd, err := unix.Openat(dirfd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st, entry unix.Stat_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatat(dirfd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != mode || st.Nlink != 1 || (size >= 0 && st.Size != size) || st.Dev != entry.Dev || st.Ino != entry.Ino {
		unix.Close(fd)
		return -1, errors.New("invalid key file metadata")
	}
	return fd, nil
}

func lockDirectory(dirfd int) (int, error) {
	fd, err := openCheckedFile(dirfd, ".lock", unix.O_RDWR, 0600, 0)
	if err != nil {
		return -1, err
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
	if err = unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock); err != nil {
		unix.Close(fd)
		return -1, errors.New("key directory locked")
	}
	return fd, nil
}

func readExactFD(fd int, size int) ([]byte, error) {
	before := unix.Stat_t{}
	if unix.Fstat(fd, &before) != nil {
		return nil, errors.New("key file stat failed")
	}
	raw := make([]byte, size)
	offset := 0
	for offset < size {
		n, err := unix.Pread(fd, raw[offset:], int64(offset))
		if err != nil {
			clear(raw)
			return nil, err
		}
		if n == 0 {
			clear(raw)
			return nil, io.ErrUnexpectedEOF
		}
		offset += n
	}
	after := unix.Stat_t{}
	if unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		clear(raw)
		return nil, errors.New("key file changed during read")
	}
	return raw, nil
}

func makeInitialKeyring(root []byte) ([]byte, error) {
	entries := make([]keyEntry, 0, len(allKeyDomains()))
	for _, domain := range allKeyDomains() {
		id, err := newDEKID()
		if err != nil {
			return nil, err
		}
		material := make([]byte, 32)
		if _, err = rand.Read(material); err != nil {
			clear(material)
			return nil, err
		}
		status := "active"
		kind := "wrap"
		if macDomain(domain) {
			status = "active_write_verify"
			kind = "mac"
		}
		entries = append(entries, keyEntry{Domain: domain, Kind: kind, KeyID: id, Version: 1, Status: status, Material: material})
	}
	ring := keyring{Generation: 1, Entries: entries}
	raw, err := sealKeyring(root, ring, [32]byte{})
	for i := range entries {
		clear(entries[i].Material)
	}
	return raw, err
}

func sealKeyring(root []byte, ring keyring, previous [32]byte) ([]byte, error) {
	if len(root) != 32 || ring.Generation == 0 || len(ring.Entries) < 16 || len(ring.Entries) > 32 {
		return nil, ErrInvalid
	}
	sort.Slice(ring.Entries, func(i, j int) bool {
		a, _ := domainNumber(ring.Entries[i].Domain)
		b, _ := domainNumber(ring.Entries[j].Domain)
		return a < b || a == b && ring.Entries[i].Version < ring.Entries[j].Version
	})
	plain, err := json.Marshal(struct {
		Generation uint64     `json:"generation"`
		Entries    []keyEntry `json:"entries"`
	}{ring.Generation, ring.Entries})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var salt [16]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	header := make([]byte, 0, 4+2+8+32+16+4)
	header = append(header, "TLKR"...)
	header = binary.BigEndian.AppendUint16(header, 1)
	header = binary.BigEndian.AppendUint64(header, ring.Generation)
	header = append(header, previous[:]...)
	header = append(header, salt[:]...)
	header = binary.BigEndian.AppendUint32(header, uint32(len(plain)+16))
	info := make([]byte, 0, len("TEAMLEDGER-KEYRING")+10)
	info = append(info, "TEAMLEDGER-KEYRING"...)
	info = binary.BigEndian.AppendUint16(info, 1)
	info = binary.BigEndian.AppendUint64(info, ring.Generation)
	derived := hkdfKey(root, salt[:], info)
	clear(info)
	block, _ := aes.NewCipher(derived[:])
	clear(derived[:])
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, plain, header)
	return append(header, sealed...), nil
}

func openKeyringInventory(root, raw []byte, allowLegacy bool) (keyring, error) {
	var empty keyring
	if len(root) != 32 || len(raw) < 66+16 || string(raw[:4]) != "TLKR" || binary.BigEndian.Uint16(raw[4:6]) != 1 || int(binary.BigEndian.Uint32(raw[62:66])) != len(raw)-66 {
		return empty, ErrInvalid
	}
	generation := binary.BigEndian.Uint64(raw[6:14])
	if generation == 0 {
		return empty, ErrInvalid
	}
	salt := raw[46:62]
	info := make([]byte, 0, len("TEAMLEDGER-KEYRING")+10)
	info = append(info, "TEAMLEDGER-KEYRING"...)
	info = binary.BigEndian.AppendUint16(info, 1)
	info = binary.BigEndian.AppendUint64(info, generation)
	derived := hkdfKey(root, salt, info)
	clear(info)
	block, _ := aes.NewCipher(derived[:])
	clear(derived[:])
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	plain, err := aead.Open(nil, nonce, raw[66:], raw[:66])
	if err != nil {
		return empty, ErrInvalid
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var body struct {
		Generation uint64     `json:"generation"`
		Entries    []keyEntry `json:"entries"`
	}
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || body.Generation != generation || len(body.Entries) < 16 || len(body.Entries) > 32 {
		return empty, ErrInvalid
	}
	type domainState struct {
		active, staged int
		versions       map[uint32]bool
	}
	pending := 0
	states := map[KeyDomain]*domainState{}
	lastDomain, lastVersion := uint16(0), uint32(0)
	for i := range body.Entries {
		e := &body.Entries[i]
		number, ok := domainNumber(e.Domain)
		state := states[e.Domain]
		if state == nil {
			state = &domainState{versions: map[uint32]bool{}}
			states[e.Domain] = state
		}
		validStatus := wrapperDomain(e.Domain) && e.Kind == "wrap" && (e.Status == "active" || e.Status == "decrypt_only" || e.Status == "staged") ||
			macDomain(e.Domain) && e.Kind == "mac" && (e.Status == "active_write_verify" || e.Status == "verify_only" || e.Status == "staged")
		hasManifest := len(e.Manifest) == 32
		if !ok || number < lastDomain || number == lastDomain && e.Version <= lastVersion || e.Version == 0 || state.versions[e.Version] || len(e.Material) != 32 || !validKeyName(e.KeyID) || !validStatus || len(e.Manifest) != 0 && !hasManifest || hasManifest && e.Status != "staged" && e.Status != "active" && e.Status != "active_write_verify" {
			for j := range body.Entries {
				clear(body.Entries[j].Material)
			}
			return empty, ErrInvalid
		}
		if e.Status == "active" || e.Status == "active_write_verify" {
			state.active++
		}
		if e.Status == "staged" {
			state.staged++
		}
		if hasManifest {
			pending++
		}
		state.versions[e.Version] = true
		lastDomain, lastVersion = number, e.Version
	}
	if pending > 1 {
		for j := range body.Entries {
			clear(body.Entries[j].Material)
		}
		return empty, ErrInvalid
	}
	expected := allKeyDomains()
	if allowLegacy && len(states) == len(legacyKeyDomains()) {
		expected = legacyKeyDomains()
	}
	if len(states) != len(expected) {
		for j := range body.Entries {
			clear(body.Entries[j].Material)
		}
		return empty, ErrInvalid
	}
	for _, domain := range expected {
		state := states[domain]
		if state == nil || state.active != 1 || state.staged > 1 {
			for j := range body.Entries {
				clear(body.Entries[j].Material)
			}
			return empty, ErrInvalid
		}
	}
	digest := sha256.Sum256(raw)
	return keyring{Generation: generation, Entries: body.Entries, Digest: hex.EncodeToString(digest[:])}, nil
}

func openKeyring(root, raw []byte) (keyring, error) {
	return openKeyringInventory(root, raw, false)
}

func InitKeyDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("invalid key directory")
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	parentFD, err := secureOpenDirectory(parent, false)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var suffix [12]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := ".teamledger-keyd-init-" + hex.EncodeToString(suffix[:])
	if err = unix.Mkdirat(parentFD, tmp, 0700); err != nil {
		return err
	}
	tmpPath := filepath.Join(parent, tmp)
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tmpPath)
		}
	}()
	dirfd, err := unix.Openat(parentFD, tmp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	root := make([]byte, 32)
	if _, err = rand.Read(root); err != nil {
		return err
	}
	defer clear(root)
	if err = writeNewFile(dirfd, "root.key", 0400, root); err != nil {
		return err
	}
	ring, err := makeInitialKeyring(root)
	if err != nil {
		return err
	}
	defer clear(ring)
	if err = writeNewFile(dirfd, "keyring.bin", 0600, ring); err != nil {
		return err
	}
	if err = writeNewFile(dirfd, ".lock", 0600, nil); err != nil {
		return err
	}
	if err = unix.Fsync(dirfd); err != nil {
		return err
	}
	if err = unix.Renameat2(parentFD, tmp, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publishing key directory: %w", err)
	}
	published = true
	return unix.Fsync(parentFD)
}

func writeNewFile(dirfd int, name string, mode uint32, data []byte) error {
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	for len(data) > 0 {
		n, e := unix.Write(fd, data)
		if e != nil {
			return e
		}
		data = data[n:]
	}
	return unix.Fsync(fd)
}

func loadKeyDirectoryMode(path string, allowLegacy bool) (int, []byte, keyring, error) {
	dirfd, err := secureOpenDirectory(path, true)
	if err != nil {
		return -1, nil, keyring{}, err
	}
	lockfd, err := lockDirectory(dirfd)
	if err != nil {
		unix.Close(dirfd)
		return -1, nil, keyring{}, err
	}
	rootfd, err := openCheckedFile(dirfd, "root.key", unix.O_RDONLY, 0400, 32)
	if err != nil {
		unix.Close(lockfd)
		unix.Close(dirfd)
		return -1, nil, keyring{}, err
	}
	root, err := readExactFD(rootfd, 32)
	unix.Close(rootfd)
	if err != nil {
		unix.Close(lockfd)
		unix.Close(dirfd)
		return -1, nil, keyring{}, err
	}
	ringfd, err := openCheckedFile(dirfd, "keyring.bin", unix.O_RDONLY, 0600, -1)
	if err != nil {
		clear(root)
		unix.Close(lockfd)
		unix.Close(dirfd)
		return -1, nil, keyring{}, err
	}
	var st unix.Stat_t
	_ = unix.Fstat(ringfd, &st)
	if st.Size < 82 || st.Size > 1<<20 {
		unix.Close(ringfd)
		clear(root)
		unix.Close(lockfd)
		unix.Close(dirfd)
		return -1, nil, keyring{}, ErrInvalid
	}
	raw, err := readExactFD(ringfd, int(st.Size))
	unix.Close(ringfd)
	if err != nil {
		clear(root)
		unix.Close(lockfd)
		unix.Close(dirfd)
		return -1, nil, keyring{}, err
	}
	ring, err := openKeyringInventory(root, raw, allowLegacy)
	clear(raw)
	unix.Close(dirfd)
	if err != nil {
		clear(root)
		unix.Close(lockfd)
		return -1, nil, keyring{}, err
	}
	return lockfd, root, ring, nil
}

func loadKeyDirectory(path string) (int, []byte, keyring, error) {
	return loadKeyDirectoryMode(path, false)
}

// UpgradeKeyDomains adds only the two v14 MFA domains to a complete legacy
// keyring. Callers must stop keyd first; the same persistent lock prevents a
// concurrent server or second upgrader from modifying material.
func UpgradeKeyDomains(path string) (ReadyState, error) {
	lockfd, root, ring, err := loadKeyDirectoryMode(path, true)
	if err != nil {
		return ReadyState{}, err
	}
	defer unix.Close(lockfd)
	defer clear(root)
	defer clearKeyring(&ring)
	current := len(ring.Entries) == len(allKeyDomains())
	if current {
		return keyringReadyState(ring), nil
	}
	if len(ring.Entries) != len(legacyKeyDomains()) {
		return ReadyState{}, ErrInvalid
	}
	for _, domain := range []KeyDomain{DomainIdentityMFA, DomainLocalRecoveryCode} {
		id, keyErr := newDEKID()
		if keyErr != nil {
			return ReadyState{}, keyErr
		}
		material := make([]byte, 32)
		if _, keyErr = rand.Read(material); keyErr != nil {
			clear(material)
			return ReadyState{}, keyErr
		}
		kind, status := "wrap", "active"
		if macDomain(domain) {
			kind, status = "mac", "active_write_verify"
		}
		ring.Entries = append(ring.Entries, keyEntry{Domain: domain, Kind: kind, KeyID: id, Version: 1, Status: status, Material: material})
	}
	if ring.Generation == ^uint64(0) {
		return ReadyState{}, ErrInvalid
	}
	ring.Generation++
	if err = persistKeyring(path, root, &ring); err != nil {
		return ReadyState{}, err
	}
	return keyringReadyState(ring), nil
}

func persistKeyring(path string, root []byte, ring *keyring) error {
	previous, err := hex.DecodeString(ring.Digest)
	if err != nil || len(previous) != 32 {
		return ErrInvalid
	}
	var previousDigest [32]byte
	copy(previousDigest[:], previous)
	clear(previous)
	raw, err := sealKeyring(root, *ring, previousDigest)
	if err != nil {
		return err
	}
	defer clear(raw)
	dirfd, err := secureOpenDirectory(path, true)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var suffix [12]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := ".keyring-" + hex.EncodeToString(suffix[:])
	if err = writeNewFile(dirfd, temp, 0600, raw); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(dirfd, temp, 0)
		}
	}()
	if err = unix.Renameat(dirfd, temp, dirfd, "keyring.bin"); err != nil {
		return err
	}
	if err = unix.Fsync(dirfd); err != nil {
		return err
	}
	published = true
	digest := sha256.Sum256(raw)
	ring.Digest = hex.EncodeToString(digest[:])
	return nil
}
func clearKeyring(r *keyring) {
	for i := range r.Entries {
		clear(r.Entries[i].Material)
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return 0, err
	}
	if controlErr != nil || cred == nil {
		return 0, controlErr
	}
	return cred.Uid, nil
}
