package backup_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/r404r/team-ledger/internal/backup"
	"testing"
	"time"
)

func TestEncryptedArchiveRoundTripAndTamperFailure(t *testing.T) {
	database := bytes.Repeat([]byte("SYNTHETIC_DB_BYTES\x00"), 70000)
	digest := sha256.Sum256(database)
	manifest := backup.Manifest{FormatVersion: 1, Backend: "sqlite", SchemaVersion: 11, CreatedAt: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), DatabaseSize: int64(len(database)), DatabaseSHA256: hex.EncodeToString(digest[:]), OrganizationIDs: []string{"10000000-0000-4000-8000-000000000001"}, KeyDependencies: []backup.KeyDependency{{Domain: "pii", KeyID: "pii-v1", Version: 1}, {Domain: "assessment", KeyID: "assessment-v1", Version: 1}}}
	key := bytes.Repeat([]byte{7}, 32)
	var archive bytes.Buffer
	if err := backup.WriteArchive(&archive, bytes.NewReader(database), manifest, key); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive.Bytes(), []byte("SYNTHETIC_DB_BYTES")) {
		t.Fatal("plaintext present in encrypted archive")
	}
	var restored bytes.Buffer
	decoded, err := backup.ReadArchive(bytes.NewReader(archive.Bytes()), &restored, key)
	if err != nil || !bytes.Equal(restored.Bytes(), database) || decoded.DatabaseSHA256 != manifest.DatabaseSHA256 {
		t.Fatal("restore", decoded, err)
	}
	tampered := bytes.Clone(archive.Bytes())
	tampered[len(tampered)/2] ^= 1
	if _, err = backup.ReadArchive(bytes.NewReader(tampered), &bytes.Buffer{}, key); err == nil {
		t.Fatal("tampered archive accepted")
	}
	withSuffix := append(bytes.Clone(archive.Bytes()), []byte("UNAUTHENTICATED_SUFFIX")...)
	if _, err = backup.ReadArchive(bytes.NewReader(withSuffix), &bytes.Buffer{}, key); err == nil {
		t.Fatal("archive with trailing bytes accepted")
	}
	wrong := bytes.Repeat([]byte{8}, 32)
	if _, err = backup.ReadArchive(bytes.NewReader(archive.Bytes()), &bytes.Buffer{}, wrong); err == nil {
		t.Fatal("wrong independent backup key accepted")
	}
}
