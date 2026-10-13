//go:build linux

package sensitive

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func offlineTestRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".teamledger-offline-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func random32(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func addOfflineStateHistory(t *testing.T, keyDir string) {
	t.Helper()
	lockfd, root, ring, err := loadKeyDirectory(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(lockfd)
	defer clear(root)
	defer clearKeyring(&ring)
	for i := range ring.Entries {
		switch ring.Entries[i].Domain {
		case DomainPIIPayload:
			ring.Entries[i].Status = "decrypt_only"
			ring.Entries = append(ring.Entries, keyEntry{Domain: DomainPIIPayload, Kind: "wrap", KeyID: mustNewID(t), Version: 2, Status: "active", Material: random32(t)})
		case DomainFinancialPayload:
			ring.Entries = append(ring.Entries, keyEntry{Domain: DomainFinancialPayload, Kind: "wrap", KeyID: mustNewID(t), Version: 2, Status: "staged", Material: random32(t), Manifest: random32(t)})
		case DomainStaffCodeLookup:
			ring.Entries[i].Status = "verify_only"
			ring.Entries = append(ring.Entries, keyEntry{Domain: DomainStaffCodeLookup, Kind: "mac", KeyID: mustNewID(t), Version: 2, Status: "active_write_verify", Material: random32(t)})
		}
	}
	ring.Generation++
	if err = persistKeyring(keyDir, root, &ring); err != nil {
		t.Fatal(err)
	}
}

func mustNewID(t *testing.T) string {
	t.Helper()
	id, err := newDEKID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOfflinePairCoversEveryStateVerifiesAndRestoresExactMaterial(t *testing.T) {
	root := offlineTestRoot(t)
	keyDir := filepath.Join(root, "source-keys")
	if err := InitKeyDirectory(keyDir); err != nil {
		t.Fatal(err)
	}
	addOfflineStateHistory(t, keyDir)
	mediaA, mediaB := filepath.Join(root, "media-a"), filepath.Join(root, "media-b")
	if err := os.Mkdir(mediaA, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mediaB, 0700); err != nil {
		t.Fatal(err)
	}
	originalDevice := offlineOutputDevice
	offlineOutputDevice = func(path string) (uint64, error) {
		if filepath.Dir(path) == mediaA {
			return 1, nil
		}
		if filepath.Dir(path) == mediaB {
			return 2, nil
		}
		return originalDevice(path)
	}
	t.Cleanup(func() { offlineOutputDevice = originalDevice })
	archiveA, archiveB := filepath.Join(mediaA, "keys.tlk"), filepath.Join(mediaB, "keys.tlk")
	keyA, keyB := random32(t), random32(t)
	defer clear(keyA)
	defer clear(keyB)
	now := time.Date(2026, 10, 14, 12, 0, 0, 123000000, time.UTC)
	inventory, err := ExportOfflinePair(keyDir, archiveA, archiveB, keyA, keyB, []byte("synthetic-host-identity"), now)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.FormatVersion != 1 || inventory.MaterialGeneration != 2 || len(inventory.Entries) != 19 || len(inventory.ActivePointers) != 16 || len(inventory.Files) != 3 {
		t.Fatal("incomplete inventory", inventory.MaterialGeneration, len(inventory.Entries), len(inventory.ActivePointers), len(inventory.Files))
	}
	states := map[string]bool{}
	for _, entry := range inventory.Entries {
		states[entry.State] = true
		if entry.ProbeSHA256 == "" {
			t.Fatal("missing known-answer probe")
		}
	}
	for _, state := range []string{"active", "staged", "decrypt_only", "active_write_verify", "verify_only"} {
		if !states[state] {
			t.Fatal("missing key state", state)
		}
	}
	for _, path := range []string{archiveA, archiveB} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0400 {
			t.Fatal("archive was not protected", path, statErr)
		}
	}
	rawA, err := os.ReadFile(archiveA)
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := os.ReadFile(archiveB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawA, rawB) {
		t.Fatal("independently encrypted archives were identical")
	}
	verified, err := VerifyOfflinePair(archiveA, archiveB, keyA, keyB)
	if err != nil || !EqualOfflineInventoryForTest(inventory, verified) {
		t.Fatal("pair verification failed", err)
	}
	if _, err = VerifyOfflinePair(archiveA, archiveB, keyB, keyA); err == nil {
		t.Fatal("wrong media keys were accepted")
	}
	tampered := filepath.Join(mediaA, "tampered.tlk")
	rawA[len(rawA)-1] ^= 1
	if err = os.WriteFile(tampered, rawA, 0400); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyOfflineArchive(tampered, keyA); err == nil {
		t.Fatal("tampered archive was accepted")
	}
	restored := filepath.Join(root, "restored-keys")
	restoredInventory, err := RestoreOfflineArchive(archiveA, restored, keyA)
	if err != nil || !EqualOfflineInventoryForTest(inventory, restoredInventory) {
		t.Fatal("isolated restore failed", err)
	}
	for name, mode := range map[string]os.FileMode{"root.key": 0400, "keyring.bin": 0600, ".lock": 0600} {
		source, readErr := os.ReadFile(filepath.Join(keyDir, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		target, readErr := os.ReadFile(filepath.Join(restored, name))
		info, statErr := os.Stat(filepath.Join(restored, name))
		if readErr != nil || statErr != nil || !bytes.Equal(source, target) || info.Mode().Perm() != mode {
			t.Fatal("restored material differs", name, readErr, statErr)
		}
	}
	lockfd, restoredRoot, restoredRing, err := loadKeyDirectory(restored)
	if err != nil || restoredRing.Generation != inventory.MaterialGeneration {
		t.Fatal("restored key directory was not usable", err)
	}
	unix.Close(lockfd)
	clear(restoredRoot)
	clearKeyring(&restoredRing)
	rollbackTarget := filepath.Join(root, "rollback-target")
	originalFsync := offlineFsync
	fsyncCalls := 0
	offlineFsync = func(fd int) error {
		fsyncCalls++
		if fsyncCalls == 2 {
			return unix.EIO
		}
		return originalFsync(fd)
	}
	if _, err = RestoreOfflineArchive(archiveA, rollbackTarget, keyA); err == nil || !errors.Is(err, ErrOfflinePublishRolledBack) {
		t.Fatal("restore did not report a completed rollback", err)
	}
	offlineFsync = originalFsync
	if _, statErr := os.Lstat(rollbackTarget); !os.IsNotExist(statErr) {
		t.Fatal("failed restore left a published key directory", statErr)
	}
	indeterminateTarget := filepath.Join(root, "indeterminate-target")
	fsyncCalls = 0
	renameCalls := 0
	originalRename := offlineRenameat2
	offlineFsync = func(fd int) error {
		fsyncCalls++
		if fsyncCalls == 2 {
			return unix.EIO
		}
		return originalFsync(fd)
	}
	offlineRenameat2 = func(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
		renameCalls++
		if renameCalls == 2 {
			return unix.EIO
		}
		return originalRename(olddirfd, oldpath, newdirfd, newpath, flags)
	}
	_, err = RestoreOfflineArchive(archiveA, indeterminateTarget, keyA)
	offlineFsync = originalFsync
	offlineRenameat2 = originalRename
	if err == nil || !errors.Is(err, ErrOfflinePublishIndeterminate) {
		t.Fatal("restore did not report an indeterminate rollback", err)
	}
	if _, statErr := os.Lstat(indeterminateTarget); statErr != nil {
		t.Fatal("fault injection did not leave the explicitly indeterminate target", statErr)
	}
	if err = os.RemoveAll(indeterminateTarget); err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreOfflineArchive(archiveA, restored, keyA); err == nil {
		t.Fatal("restore overwrote an existing target")
	}
	if _, err = ExportOfflinePair(keyDir, archiveA, archiveB, keyA, keyB, []byte("synthetic-host-identity"), now); err == nil {
		t.Fatal("export overwrote existing archives")
	}
}

func TestOfflineExportRequiresExclusiveWriterLockAndMatchingPair(t *testing.T) {
	root := offlineTestRoot(t)
	keyDir := filepath.Join(root, "source-keys")
	if err := InitKeyDirectory(keyDir); err != nil {
		t.Fatal(err)
	}
	mediaA, mediaB, otherA, otherB := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "a2"), filepath.Join(root, "b2")
	for _, dir := range []string{mediaA, mediaB, otherA, otherB} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	originalDevice := offlineOutputDevice
	offlineOutputDevice = func(path string) (uint64, error) {
		switch filepath.Dir(path) {
		case mediaA, otherA:
			return 1, nil
		case mediaB, otherB:
			return 2, nil
		default:
			return originalDevice(path)
		}
	}
	t.Cleanup(func() { offlineOutputDevice = originalDevice })
	keyA, keyB := random32(t), random32(t)
	defer clear(keyA)
	defer clear(keyB)
	lockfd, loadedRoot, ring, err := loadKeyDirectory(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ExportOfflinePair(keyDir, filepath.Join(mediaA, "blocked.tlk"), filepath.Join(mediaB, "blocked.tlk"), keyA, keyB, []byte("host"), time.Now().UTC()); err == nil {
		t.Fatal("export succeeded while key writer lock was held")
	}
	unix.Close(lockfd)
	clear(loadedRoot)
	clearKeyring(&ring)
	firstA, firstB := filepath.Join(mediaA, "first.tlk"), filepath.Join(mediaB, "first.tlk")
	secondA, secondB := filepath.Join(otherA, "second.tlk"), filepath.Join(otherB, "second.tlk")
	if _, err = ExportOfflinePair(keyDir, firstA, firstB, keyA, keyB, []byte("host"), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err = ExportOfflinePair(keyDir, secondA, secondB, keyA, keyB, []byte("host"), time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOfflinePair(firstA, secondB, keyA, keyB); err == nil {
		t.Fatal("archives from different exports formed a valid pair")
	}
	if _, err = ExportOfflinePair(keyDir, filepath.Join(mediaA, "same-key.tlk"), filepath.Join(mediaB, "same-key.tlk"), keyA, keyA, []byte("host"), time.Now().UTC()); err == nil {
		t.Fatal("same media key was accepted for A and B")
	}
}

func TestOfflineExportRejectsSameFilesystem(t *testing.T) {
	root := offlineTestRoot(t)
	keyDir := filepath.Join(root, "source-keys")
	if err := InitKeyDirectory(keyDir); err != nil {
		t.Fatal(err)
	}
	mediaA, mediaB := filepath.Join(root, "same-filesystem-a"), filepath.Join(root, "same-filesystem-b")
	if err := os.Mkdir(mediaA, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mediaB, 0700); err != nil {
		t.Fatal(err)
	}
	keyA, keyB := random32(t), random32(t)
	defer clear(keyA)
	defer clear(keyB)
	if _, err := ExportOfflinePair(keyDir, filepath.Join(mediaA, "keys.tlk"), filepath.Join(mediaB, "keys.tlk"), keyA, keyB, []byte("host"), time.Now().UTC()); err == nil {
		t.Fatal("same filesystem was accepted as two media")
	}
}

func EqualOfflineInventoryForTest(a, b OfflineInventory) bool {
	aRaw, _ := json.Marshal(a)
	bRaw, _ := json.Marshal(b)
	return bytes.Equal(aRaw, bRaw)
}
