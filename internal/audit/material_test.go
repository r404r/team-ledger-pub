package audit

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"syscall"
)

func testMaterialOwners() MaterialOwners {
	return MaterialOwners{BootstrapUID: os.Geteuid(), ReceiverUID: os.Geteuid(), ForwarderUID: os.Geteuid(), GID: os.Getegid()}
}

func readCertificateFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestAuditMaterialBootstrapAndRotationAreProtectedAndOneTime(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "audit-material")
	owners := testMaterialOwners()
	now := time.Date(2026, 10, 14, 5, 6, 7, 0, time.UTC)
	if err := BootstrapMaterial(directory, "audit-receiver", owners, now); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapMaterial(directory, "audit-receiver", owners, now); err == nil {
		t.Fatal("second bootstrap replaced audit identities")
	}
	for path, mode := range map[string]os.FileMode{
		"bootstrap/ca.pem":            0400,
		"receiver/server-key.pem":     0400,
		"receiver/signer.json":        0400,
		"forwarder/client-key.pem":    0400,
		"forwarder/receipt-keys.json": 0444,
	} {
		info, err := os.Lstat(filepath.Join(directory, path))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatalf("unsafe %s metadata: %v %v", path, info, err)
		}
	}
	oldKeyID, oldPrivate, err := LoadSigner(filepath.Join(directory, "receiver", "signer.json"))
	if err != nil {
		t.Fatal(err)
	}
	clear(oldPrivate)
	oldServer := readCertificateFile(t, filepath.Join(directory, "receiver", "server-cert.pem"))
	if err = RotateLeaves(directory, "audit-receiver", owners, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	newServer := readCertificateFile(t, filepath.Join(directory, "receiver", "server-cert.pem"))
	if oldServer.SerialNumber.Cmp(newServer.SerialNumber) == 0 || len(newServer.DNSNames) != 1 || newServer.DNSNames[0] != "audit-receiver" {
		t.Fatal("leaf rotation did not publish a new constrained server identity")
	}
	caRaw, err := os.ReadFile(filepath.Join(directory, "bootstrap", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	oldCA, oldCAKey, _, err := parseCurrentCA(caRaw)
	clear(caRaw)
	if err != nil {
		t.Fatal(err)
	}
	clear(oldCAKey)
	if err = RotateCA(directory, "audit-receiver", owners, now.Add(90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	caRaw, err = os.ReadFile(filepath.Join(directory, "bootstrap", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	currentCA, currentCAKey, _, err := parseCurrentCA(caRaw)
	clear(caRaw)
	if err != nil {
		t.Fatal(err)
	}
	clear(currentCAKey)
	bundleRaw, err := os.ReadFile(filepath.Join(directory, "receiver", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := parseCABundle(bundleRaw)
	if err != nil || len(bundle) != 2 || !bytes.Equal(bundle[0].Raw, oldCA.Raw) || !bytes.Equal(bundle[1].Raw, currentCA.Raw) {
		t.Fatal("CA rotation did not publish dual trust", err)
	}
	if err = readCertificateFile(t, filepath.Join(directory, "receiver", "server-cert.pem")).CheckSignatureFrom(currentCA); err != nil {
		t.Fatal("new receiver leaf is not signed by the active CA", err)
	}
	if err = RotateCA(directory, "audit-receiver", owners, now.Add(100*time.Minute)); err == nil {
		t.Fatal("second CA rotation started before retirement")
	}
	if err = RetireOldCA(directory, owners); err != nil {
		t.Fatal(err)
	}
	bundleRaw, err = os.ReadFile(filepath.Join(directory, "receiver", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = parseCABundle(bundleRaw)
	if err != nil || len(bundle) != 1 || !bytes.Equal(bundle[0].Raw, currentCA.Raw) {
		t.Fatal("old CA trust was not retired", err)
	}
	newKeyID, err := RotateSigner(directory, owners, now.Add(2*time.Hour))
	if err != nil || newKeyID == oldKeyID {
		t.Fatal("signer rotation failed", newKeyID, err)
	}
	trustRaw, err := configfile.Read(filepath.Join(directory, "forwarder", "receipt-keys.json"), 16<<10, false)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseReceiptKeys(trustRaw)
	if err != nil || len(keys) != 2 || len(keys[oldKeyID]) == 0 || len(keys[newKeyID]) == 0 {
		t.Fatal("rotation did not publish dual signer trust", err)
	}
	if err = RetireSigner(directory, owners, newKeyID, true); err == nil {
		t.Fatal("active signer was retired")
	}
	if err = RetireSigner(directory, owners, oldKeyID, false); err == nil {
		t.Fatal("old signer retired without dependency proof")
	}
	if err = RetireSigner(directory, owners, oldKeyID, true); err != nil {
		t.Fatal(err)
	}
	trustRaw, err = configfile.Read(filepath.Join(directory, "forwarder", "receipt-keys.json"), 16<<10, false)
	if err == nil {
		keys, err = ParseReceiptKeys(trustRaw)
	}
	if err != nil || len(keys) != 1 || len(keys[newKeyID]) == 0 {
		t.Fatal("old signer trust was not retired", err)
	}
}

func TestAuditMaterialRejectsSymlinkBootstrapAndHardlinkedSigner(t *testing.T) {
	owners := testMaterialOwners()
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "audit-material")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapMaterial(link, "audit-receiver", owners, time.Now().UTC()); err == nil {
		t.Fatal("symlink bootstrap target was accepted")
	}
	directory := filepath.Join(t.TempDir(), "material")
	if err := BootstrapMaterial(directory, "audit-receiver", owners, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	signer := filepath.Join(directory, "receiver", "signer.json")
	if err := os.Link(signer, filepath.Join(directory, "receiver", "signer-copy.json")); err != nil {
		t.Fatal(err)
	}
	if _, private, err := LoadSigner(signer); err == nil {
		clear(private)
		t.Fatal("hardlinked signer was accepted")
	}
}

func TestAuditMaterialRotationRejectsWrongPermissions(t *testing.T) {
	owners := testMaterialOwners()
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Date(2026, 10, 14, 5, 6, 7, 0, time.UTC)
	if err := BootstrapMaterial(directory, "audit-receiver", owners, now); err != nil {
		t.Fatal(err)
	}
	signer := filepath.Join(directory, "receiver", "signer.json")
	if err := os.Chmod(signer, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateSigner(directory, owners, now.Add(time.Hour)); err == nil {
		t.Fatal("wrong-mode signer was rotated")
	}
}

func TestAuditMaterialBootstrapRejectsInvalidIdentityWithoutCreatingTarget(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	if err := BootstrapMaterial(directory, ".audit-receiver", testMaterialOwners(), time.Now().UTC()); err == nil {
		t.Fatal("invalid receiver identity was accepted")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid bootstrap left material target", err)
	}
}
