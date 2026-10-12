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
