package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/r404r/team-ledger/internal/backup"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteEncryptedSnapshotRestoresSchemaAndFacts(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := f.Repo.SQLiteSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	snapRepo, err := store.Open(ctx, "sqlite", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := snapRepo.BackupManifest(ctx, f.Now, int64(len(raw)), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	snapRepo.Close()
	key := bytes.Repeat([]byte{17}, 32)
	var archive bytes.Buffer
	if err = backup.WriteArchive(&archive, bytes.NewReader(raw), manifest, key); err != nil {
		t.Fatal(err)
	}
	clear(raw)
	restored := filepath.Join(t.TempDir(), "restored.sqlite")
	out, err := os.OpenFile(restored, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backup.ReadArchive(bytes.NewReader(archive.Bytes()), out, key)
	closeErr := out.Close()
	if err != nil || closeErr != nil || decoded.SchemaVersion != 15 {
		t.Fatal(decoded, err, closeErr)
	}
	restoredRepo, err := store.Open(ctx, "sqlite", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredRepo.Close()
	if err = restoredRepo.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = restoredRepo.DB.QueryRowContext(ctx, "SELECT count(*) FROM organization WHERE id=?", f.OrgID).Scan(&count); err != nil || count != 1 {
		t.Fatal("restored live fact missing", count, err)
	}
}
