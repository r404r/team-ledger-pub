//go:build linux

package sensitive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

var offlineMagic = [16]byte{'T', 'L', 'K', 'E', 'Y', 'O', 'F', 'F', 'L', 'I', 'N', 'E', 0, 1, 0, 0}

const offlineHeaderSize = len(offlineMagic) + 2 + 1 + 12 + 4

var ErrOfflinePublishRolledBack = errors.New("offline publish rolled back")
var ErrOfflinePublishIndeterminate = errors.New("offline publish indeterminate")

var offlineFsync = unix.Fsync
var offlineRenameat2 = unix.Renameat2
var offlineOutputDevice = func(path string) (uint64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, ErrInvalid
	}
	dirfd, err := secureOpenDirectory(filepath.Dir(path), true)
	if err != nil {
		return 0, err
	}
	defer unix.Close(dirfd)
	var st unix.Stat_t
	if err = unix.Fstat(dirfd, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

func rollbackOfflinePublish(dirfd int, publishedName, tempName string, commitErr error) error {
	if rollbackErr := offlineRenameat2(dirfd, publishedName, dirfd, tempName, unix.RENAME_NOREPLACE); rollbackErr != nil {
		return fmt.Errorf("%w: rollback rename failed (commit: %v): %v", ErrOfflinePublishIndeterminate, commitErr, rollbackErr)
	}
	if rollbackSyncErr := offlineFsync(dirfd); rollbackSyncErr != nil {
		return fmt.Errorf("%w: target is absent but rollback persistence failed (commit: %v): %v", ErrOfflinePublishIndeterminate, commitErr, rollbackSyncErr)
	}
	return fmt.Errorf("%w: %v", ErrOfflinePublishRolledBack, commitErr)
}

type OfflineKeyEntry struct {
	Domain      string `json:"domain"`
	Kind        string `json:"kind"`
	KeyID       string `json:"key_id"`
	Version     uint32 `json:"version"`
	State       string `json:"state"`
	ProbeSHA256 string `json:"probe_sha256"`
}

type OfflineActivePointer struct {
	Domain  string `json:"domain"`
	KeyID   string `json:"key_id"`
	Version uint32 `json:"version"`
}

type OfflineFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

type OfflineInventory struct {
	FormatVersion            uint16                 `json:"format_version"`
	ExportUUID               string                 `json:"export_uuid"`
	MaterialGeneration       uint64                 `json:"material_generation"`
	RootSHA256               string                 `json:"root_sha256"`
	KeyringSHA256            string                 `json:"keyring_sha256"`
	Entries                  []OfflineKeyEntry      `json:"entries"`
	ActivePointers           []OfflineActivePointer `json:"active_pointers"`
	Files                    []OfflineFile          `json:"files"`
	ExportedAt               time.Time              `json:"exported_at"`
	ProcessUID               uint32                 `json:"process_uid"`
	SourceHostIdentitySHA256 string                 `json:"source_host_identity_sha256"`
}

type offlinePayload struct {
	Inventory       json.RawMessage `json:"inventory"`
	InventorySHA256 string          `json:"inventory_sha256"`
	Root            []byte          `json:"root"`
	Keyring         []byte          `json:"keyring"`
	Lock            []byte          `json:"lock"`
}

type offlineMaterial struct {
	Inventory OfflineInventory
	Canonical []byte
	Root      []byte
	Keyring   []byte
	Lock      []byte
	Media     byte
}

func offlineProbe(entry keyEntry) string {
	mac := hmac.New(sha256.New, entry.Material)
	_, _ = mac.Write([]byte("TEAMLEDGER-OFFLINE-KNOWN-ANSWER"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(entry.Domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(entry.Kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(entry.KeyID))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], entry.Version)
	_, _ = mac.Write(version[:])
	return hex.EncodeToString(mac.Sum(nil))
}

func buildOfflineInventory(root, raw []byte, ring keyring, exportUUID string, exportedAt time.Time, processUID uint32, hostIdentityDigest string) (OfflineInventory, error) {
	hostDigest, digestErr := hex.DecodeString(hostIdentityDigest)
	if !validKeyName(exportUUID) || exportedAt.IsZero() || exportedAt.Location() != time.UTC || digestErr != nil || len(hostDigest) != sha256.Size || hex.EncodeToString(hostDigest) != hostIdentityDigest {
		clear(hostDigest)
		return OfflineInventory{}, ErrInvalid
	}
	clear(hostDigest)
	rootDigest, ringDigest := sha256.Sum256(root), sha256.Sum256(raw)
	inventory := OfflineInventory{
		FormatVersion: 1, ExportUUID: exportUUID, MaterialGeneration: ring.Generation,
		RootSHA256: hex.EncodeToString(rootDigest[:]), KeyringSHA256: hex.EncodeToString(ringDigest[:]),
		ExportedAt: exportedAt.UTC().Truncate(time.Microsecond), ProcessUID: processUID,
		SourceHostIdentitySHA256: hostIdentityDigest,
		Files:                    []OfflineFile{{".lock", 0, 0600}, {"keyring.bin", int64(len(raw)), 0600}, {"root.key", int64(len(root)), 0400}},
	}
	for _, entry := range ring.Entries {
		inventory.Entries = append(inventory.Entries, OfflineKeyEntry{
			Domain: string(entry.Domain), Kind: entry.Kind, KeyID: entry.KeyID, Version: entry.Version, State: entry.Status, ProbeSHA256: offlineProbe(entry),
		})
		if entry.Status == "active" || entry.Status == "active_write_verify" {
			inventory.ActivePointers = append(inventory.ActivePointers, OfflineActivePointer{string(entry.Domain), entry.KeyID, entry.Version})
		}
	}
	if len(inventory.ActivePointers) != len(allKeyDomains()) {
		return OfflineInventory{}, ErrInvalid
	}
	return inventory, nil
}

func offlineAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	return cipher.NewGCM(block)
}

func encodeOfflineArchive(media byte, inventory OfflineInventory, root, keyringRaw, lock, mediaKey []byte) ([]byte, error) {
	if media != 'A' && media != 'B' {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(inventory)
	if err != nil {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(canonical)
	payload := offlinePayload{canonical, hex.EncodeToString(digest[:]), root, keyringRaw, lock}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plain)
	aead, err := offlineAEAD(mediaKey)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if len(plain)+aead.Overhead() > math.MaxUint32 {
		return nil, ErrInvalid
	}
	header := make([]byte, 0, offlineHeaderSize)
	header = append(header, offlineMagic[:]...)
	header = binary.BigEndian.AppendUint16(header, 1)
	header = append(header, media)
	header = append(header, nonce[:]...)
	header = binary.BigEndian.AppendUint32(header, uint32(len(plain)+aead.Overhead()))
	return append(header, aead.Seal(nil, nonce[:], plain, header)...), nil
}

func writeOfflineArchive(path string, raw []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return ErrInvalid
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	dirfd, err := secureOpenDirectory(parent, true)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var suffix [12]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := ".teamledger-offline-" + hex.EncodeToString(suffix[:])
	if err = writeNewFile(dirfd, temp, 0400, raw); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(dirfd, temp, 0)
		}
	}()
	if err = offlineFsync(dirfd); err != nil {
		return err
	}
	if err = offlineRenameat2(dirfd, temp, dirfd, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err = offlineFsync(dirfd); err != nil {
		return rollbackOfflinePublish(dirfd, name, temp, err)
	}
	published = true
	return nil
}

func snapshotOfflineMaterial(keyDir string, hostIdentity []byte, now time.Time) (OfflineInventory, []byte, []byte, []byte, error) {
	dirfd, err := secureOpenDirectory(keyDir, true)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	defer unix.Close(dirfd)
	lockfd, err := lockDirectory(dirfd)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	defer unix.Close(lockfd)
	rootfd, err := openCheckedFile(dirfd, "root.key", unix.O_RDONLY, 0400, 32)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	root, err := readExactFD(rootfd, 32)
	unix.Close(rootfd)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			clear(root)
		}
	}()
	ringfd, err := openCheckedFile(dirfd, "keyring.bin", unix.O_RDONLY, 0600, -1)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(ringfd, &st) != nil || st.Size < 82 || st.Size > 1<<20 {
		unix.Close(ringfd)
		return OfflineInventory{}, nil, nil, nil, ErrInvalid
	}
	raw, err := readExactFD(ringfd, int(st.Size))
	unix.Close(ringfd)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	defer func() {
		if failed {
			clear(raw)
		}
	}()
	ring, err := openKeyring(root, raw)
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	defer clearKeyring(&ring)
	exportUUID, err := newDEKID()
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	hostDigest := sha256.Sum256(hostIdentity)
	inventory, err := buildOfflineInventory(root, raw, ring, exportUUID, now, uint32(os.Geteuid()), hex.EncodeToString(hostDigest[:]))
	if err != nil {
		return OfflineInventory{}, nil, nil, nil, err
	}
	failed = false
	return inventory, root, raw, []byte{}, nil
}

func ExportOfflinePair(keyDir, outputA, outputB string, keyA, keyB, hostIdentity []byte, now time.Time) (OfflineInventory, error) {
	if outputA == outputB || hmac.Equal(keyA, keyB) {
		return OfflineInventory{}, ErrInvalid
	}
	deviceA, err := offlineOutputDevice(outputA)
	if err != nil {
		return OfflineInventory{}, err
	}
	deviceB, err := offlineOutputDevice(outputB)
	if err != nil || deviceA == deviceB {
		return OfflineInventory{}, ErrInvalid
	}
	inventory, root, ring, lock, err := snapshotOfflineMaterial(keyDir, hostIdentity, now)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clear(root)
	defer clear(ring)
	a, err := encodeOfflineArchive('A', inventory, root, ring, lock, keyA)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clear(a)
	b, err := encodeOfflineArchive('B', inventory, root, ring, lock, keyB)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clear(b)
	if err = writeOfflineArchive(outputA, a); err != nil {
		return OfflineInventory{}, err
	}
	if err = writeOfflineArchive(outputB, b); err != nil {
		return OfflineInventory{}, err
	}
	return inventory, nil
}

func readOfflineFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 || st.Size < int64(offlineHeaderSize+16) || st.Size > 2<<20 {
		return nil, ErrInvalid
	}
	return readExactFD(fd, int(st.Size))
}

func decodeOfflineArchive(path string, mediaKey []byte) (offlineMaterial, error) {
	raw, err := readOfflineFile(path)
	if err != nil {
		return offlineMaterial{}, err
	}
	defer clear(raw)
	if len(raw) < offlineHeaderSize+16 || !bytes.Equal(raw[:len(offlineMagic)], offlineMagic[:]) || binary.BigEndian.Uint16(raw[16:18]) != 1 || int(binary.BigEndian.Uint32(raw[31:35])) != len(raw)-offlineHeaderSize {
		return offlineMaterial{}, ErrInvalid
	}
	media := raw[18]
	if media != 'A' && media != 'B' {
		return offlineMaterial{}, ErrInvalid
	}
	aead, err := offlineAEAD(mediaKey)
	if err != nil {
		return offlineMaterial{}, err
	}
	plain, err := aead.Open(nil, raw[19:31], raw[offlineHeaderSize:], raw[:offlineHeaderSize])
	if err != nil {
		return offlineMaterial{}, ErrInvalid
	}
	failed := true
	var payload offlinePayload
	defer func() {
		clear(plain)
		if failed {
			clear(payload.Root)
			clear(payload.Keyring)
			clear(payload.Lock)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(payload.Root) != 32 || len(payload.Keyring) < 82 || len(payload.Keyring) > 1<<20 || len(payload.Lock) != 0 {
		return offlineMaterial{}, ErrInvalid
	}
	digest := sha256.Sum256(payload.Inventory)
	if payload.InventorySHA256 != hex.EncodeToString(digest[:]) {
		return offlineMaterial{}, ErrInvalid
	}
	var inventory OfflineInventory
	inventoryDecoder := json.NewDecoder(bytes.NewReader(payload.Inventory))
	inventoryDecoder.DisallowUnknownFields()
	if inventoryDecoder.Decode(&inventory) != nil || inventoryDecoder.Decode(&struct{}{}) != io.EOF {
		return offlineMaterial{}, ErrInvalid
	}
	canonical, err := json.Marshal(inventory)
	if err != nil || !bytes.Equal(canonical, payload.Inventory) {
		clear(canonical)
		return offlineMaterial{}, ErrInvalid
	}
	ring, err := openKeyring(payload.Root, payload.Keyring)
	if err != nil {
		clear(canonical)
		return offlineMaterial{}, ErrInvalid
	}
	defer clearKeyring(&ring)
	expected, err := buildOfflineInventory(payload.Root, payload.Keyring, ring, inventory.ExportUUID, inventory.ExportedAt, inventory.ProcessUID, inventory.SourceHostIdentitySHA256)
	if err != nil {
		clear(canonical)
		return offlineMaterial{}, ErrInvalid
	}
	expectedCanonical, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(expectedCanonical, canonical) {
		clear(canonical)
		clear(expectedCanonical)
		return offlineMaterial{}, ErrInvalid
	}
	clear(expectedCanonical)
	failed = false
	return offlineMaterial{inventory, canonical, payload.Root, payload.Keyring, payload.Lock, media}, nil
}

func clearOfflineMaterial(material *offlineMaterial) {
	clear(material.Canonical)
	clear(material.Root)
	clear(material.Keyring)
	clear(material.Lock)
}

func VerifyOfflineArchive(path string, mediaKey []byte) (OfflineInventory, byte, error) {
	material, err := decodeOfflineArchive(path, mediaKey)
	if err != nil {
		return OfflineInventory{}, 0, err
	}
	defer clearOfflineMaterial(&material)
	return material.Inventory, material.Media, nil
}

func VerifyOfflinePair(pathA, pathB string, keyA, keyB []byte) (OfflineInventory, error) {
	if pathA == pathB || hmac.Equal(keyA, keyB) {
		return OfflineInventory{}, ErrInvalid
	}
	a, err := decodeOfflineArchive(pathA, keyA)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clearOfflineMaterial(&a)
	b, err := decodeOfflineArchive(pathB, keyB)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clearOfflineMaterial(&b)
	if a.Media != 'A' || b.Media != 'B' || !bytes.Equal(a.Canonical, b.Canonical) || !bytes.Equal(a.Root, b.Root) || !bytes.Equal(a.Keyring, b.Keyring) || !bytes.Equal(a.Lock, b.Lock) {
		return OfflineInventory{}, ErrInvalid
	}
	return a.Inventory, nil
}

func RestoreOfflineArchive(path, targetDir string, mediaKey []byte) (OfflineInventory, error) {
	material, err := decodeOfflineArchive(path, mediaKey)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer clearOfflineMaterial(&material)
	if !filepath.IsAbs(targetDir) || filepath.Clean(targetDir) != targetDir || targetDir == "/" {
		return OfflineInventory{}, ErrInvalid
	}
	parent, name := filepath.Dir(targetDir), filepath.Base(targetDir)
	parentFD, err := secureOpenDirectory(parent, false)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer unix.Close(parentFD)
	var suffix [12]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return OfflineInventory{}, err
	}
	temp := ".teamledger-keyd-restore-" + hex.EncodeToString(suffix[:])
	if err = unix.Mkdirat(parentFD, temp, 0700); err != nil {
		return OfflineInventory{}, err
	}
	tempPath := filepath.Join(parent, temp)
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tempPath)
		}
	}()
	dirfd, err := unix.Openat(parentFD, temp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return OfflineInventory{}, err
	}
	defer unix.Close(dirfd)
	if err = writeNewFile(dirfd, "root.key", 0400, material.Root); err == nil {
		err = writeNewFile(dirfd, "keyring.bin", 0600, material.Keyring)
	}
	if err == nil {
		err = writeNewFile(dirfd, ".lock", 0600, material.Lock)
	}
	if err == nil {
		err = offlineFsync(dirfd)
	}
	if err != nil {
		return OfflineInventory{}, err
	}
	if err = offlineRenameat2(parentFD, temp, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
		return OfflineInventory{}, fmt.Errorf("publishing restored key directory: %w", err)
	}
	if err = offlineFsync(parentFD); err != nil {
		return OfflineInventory{}, rollbackOfflinePublish(parentFD, name, temp, err)
	}
	published = true
	return material.Inventory, nil
}
