package configfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRootTrustRejectsOperatorOwnedReplacement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root service identity")
	}
	path := filepath.Join(t.TempDir(), "approval-authorities.json")
	if err := os.WriteFile(path, []byte(`{"authorities":[]}`), 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRootTrust(path, 1024); err == nil {
		t.Fatal("operator-owned replacement accepted as deployment trust root")
	}
}

func TestReadRejectsHardLinkedConfidentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	linked := filepath.Join(t.TempDir(), "linked.json")
	if err := os.WriteFile(path, []byte(`{"password":"not-a-real-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 1024, true); err == nil {
		t.Fatal("hard-linked confidential file accepted")
	}
}

func TestReadRejectsSymbolicLinkedConfidentialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	linked := filepath.Join(dir, "linked.json")
	if err := os.WriteFile(path, []byte(`{"password":"not-a-real-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(linked, 1024, true); err == nil {
		t.Fatal("symbolic-linked confidential file accepted")
	}
}
