package sensitive

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRFC5649KnownAnswers(t *testing.T) {
	key, _ := hex.DecodeString("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	for _, tc := range []struct{ plain, wrapped string }{
		{"c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
		{"466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
	} {
		plainHex, wrappedHex := tc.plain, tc.wrapped
		t.Run(plainHex, func(t *testing.T) {
			plain, _ := hex.DecodeString(plainHex)
			want, _ := hex.DecodeString(wrappedHex)
			got, err := kwpWrap(key, plain)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("KWP known answer mismatch: %x %v", got, err)
			}
			opened, err := kwpUnwrap(key, want)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("KWP known answer unwrap failed", err)
			}
			want[len(want)-1] ^= 1
			if opened, err = kwpUnwrap(key, want); err == nil || len(opened) != 0 {
				t.Fatal("tampered KWP was accepted")
			}
		})
	}
}

func TestCF1PayloadAADPublishedVector(t *testing.T) {
	binding := Context{
		OrgID: "00000000-0000-0000-0000-000000000000", EmployeeID: "00000000-0000-0000-0000-000000000000",
		RecordID: "00000000-0000-0000-0000-000000000000", VersionID: "11111111-1111-1111-1111-111111111111",
		ObjectKind: "employee_profile", Purpose: "pii", SchemaType: "pii.profile.v2", SchemaVersion: 1,
	}
	got, err := canonicalAAD(binding, "22222222-2222-2222-2222-222222222222")
	want, _ := hex.DecodeString("5445414d4c45444745522d5041594c4f414400544c43460001000900010300000010000000000000000000000000000000000002050000000200010003010000001f544c434600010001000103000000100000000000000000000000000000000000040300000010111111111111111111111111111111110005040000000800000000000000010006050000000200010007020000000e7069692e70726f66696c652e76320008050000000200020009030000001022222222222222222222222222222222")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("CF1 published vector mismatch: %x %v", got, err)
	}
}

func TestKeydInitLockSocketWrapMACAndRestart(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(home, ".teamledger-keyd-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "keys")
	if err = InitKeyDirectory(directory); err != nil {
		t.Fatal("init", err)
	}
	if err = InitKeyDirectory(directory); err == nil {
		t.Fatal("init replaced existing key directory")
	}
	for name, mode := range map[string]os.FileMode{"root.key": 0400, "keyring.bin": 0600, ".lock": 0600} {
		info, statErr := os.Lstat(filepath.Join(directory, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
			t.Fatalf("invalid %s metadata: %v %v", name, info, statErr)
		}
	}
	socket := filepath.Join(directory, "keyd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cfg := KeydServerConfig{KeyDirectory: directory, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}, MaintenanceUIDs: []uint32{uint32(os.Geteuid())}}
	go func() { done <- ServeKeyd(ctx, cfg) }()
	client := &KeydClient{Socket: socket, Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	var ready ReadyState
	for time.Now().Before(deadline) {
		ready, err = client.Ready(context.Background())
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || ready.MaterialGeneration != 1 || len(ready.Active) != 18 {
		cancel()
		<-done
		t.Fatal("keyd not ready", ready, err)
	}
	socketInfo, statErr := os.Lstat(socket)
	if statErr != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0660 {
		t.Fatalf("keyd socket must be shared-group only: %v %v", socketInfo, statErr)
	}
	if err = ServeKeyd(context.Background(), cfg); err == nil {
		t.Fatal("second keyd acquired the persistent lock")
	}
	wrapper, err := NewKeydWrapper(client, DomainPIIPayload)
	if err != nil {
		t.Fatal(err)
	}
	binding := Context{OrgID: "aaaaaaaa-1111-4111-8111-111111111111", EmployeeID: "bbbbbbbb-2222-4222-8222-222222222222", RecordID: "cccccccc-3333-4333-8333-333333333333", VersionID: "dddddddd-4444-4444-8444-444444444444", ObjectKind: "employee_profile", Purpose: "pii", SchemaType: "pii.profile.v2", SchemaVersion: 1}
	cipher := Cipher{Wrapper: wrapper}
	plain := []byte("SYNTHETIC-KEYD-PII")
	envelope, err := cipher.Seal(context.Background(), binding, plain)
	if err != nil {
		t.Fatal("seal", err)
	}
	if len(envelope.Key.Data) != 150 || string(envelope.Key.Data[:4]) != "TLW1" || string(envelope.SealedBytes[:4]) != "TLP1" || bytes.Contains(envelope.Key.Data, plain) || bytes.Contains(envelope.SealedBytes, plain) {
		t.Fatal("noncanonical or plaintext keyd envelope")
	}
	opened, err := cipher.Open(context.Background(), binding, envelope)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("open", err)
	}
	clear(opened)
	mfaWrapper, err := NewKeydWrapper(client, DomainIdentityMFA)
	if err != nil {
		t.Fatal(err)
	}
	mfaBinding := Context{OrgID: binding.OrgID, RecordID: binding.RecordID, VersionID: binding.VersionID, ObjectKind: "local_mfa_enrollment", Purpose: "identity", SchemaType: "identity.local_mfa_enrollment.v1", SchemaVersion: 1}
	mfaCipher := Cipher{Wrapper: mfaWrapper}
	mfaPlain := []byte("SYNTHETIC-TOTP-SEED")
	mfaEnvelope, err := mfaCipher.Seal(context.Background(), mfaBinding, mfaPlain)
	if err != nil {
		t.Fatal("identity MFA seal", err)
	}
	mfaOpened, err := mfaCipher.Open(context.Background(), mfaBinding, mfaEnvelope)
	if err != nil || !bytes.Equal(mfaOpened, mfaPlain) {
		t.Fatal("identity MFA open", err)
	}
	clear(mfaOpened)
	tampered := envelope
	tampered.Key.Data = bytes.Clone(envelope.Key.Data)
	tampered.Key.Data[len(tampered.Key.Data)-1] ^= 1
	if opened, err = cipher.Open(context.Background(), binding, tampered); !errors.Is(err, ErrInvalid) || len(opened) != 0 {
		t.Fatal("tampered wrapper released plaintext", err)
	}
	value, err := client.MAC(context.Background(), DomainCommandReceipt, []byte("synthetic command"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.Verify(context.Background(), DomainCommandReceipt, KeyReference{KeyID: value.KeyID, Version: value.Version}, []byte("synthetic command"), value.Digest)
	if err != nil || !verified {
		t.Fatal("MAC verification failed", err)
	}
	verified, err = client.Verify(context.Background(), DomainCommandReceipt, KeyReference{KeyID: "wrong-key-id", Version: value.Version}, []byte("synthetic command"), value.Digest)
	if err == nil || verified {
		t.Fatal("MAC verification accepted wrong key ID", err)
	}
	verified, err = client.Verify(context.Background(), DomainCommandReceipt, KeyReference{KeyID: value.KeyID, Version: value.Version}, []byte("other"), value.Digest)
	if err != nil || verified {
		t.Fatal("wrong MAC input accepted", err)
	}
	processKey, err := client.ProcessKey(context.Background(), DomainIdentityTransaction, "oidc-transaction-v1")
	if err != nil || len(processKey) != 32 {
		t.Fatal("identity transaction derivation failed", err)
	}
	again, err := client.ProcessKey(context.Background(), DomainIdentityTransaction, "oidc-transaction-v1")
	if err != nil || !bytes.Equal(processKey, again) {
		t.Fatal("identity transaction derivation was not stable", err)
	}
	clear(processKey)
	clear(again)
	if _, err = client.ProcessKey(context.Background(), DomainCommandReceipt, "forbidden"); !errors.Is(err, ErrInvalid) {
		t.Fatal("MAC domain exposed a process key", err)
	}
	manifest := bytes.Repeat([]byte{0x5a}, 32)
	wrapperTarget := KeyReference{KeyID: "00000000-0000-4000-8000-000000000002", Version: 2}
	staged, err := client.Stage(context.Background(), DomainPIIPayload, wrapperTarget, manifest)
	if err != nil || staged.MaterialGeneration != 2 || staged.Active[DomainPIIPayload] != 1 || staged.WriteEnabled {
		t.Fatal("wrapper stage failed", staged, err)
	}
	nextKey, err := client.Rewrap(context.Background(), DomainPIIPayload, envelope.Key)
	if err != nil || nextKey.Version != 2 || nextKey.KEKID == envelope.Key.KEKID {
		t.Fatal("staged rewrap failed", nextKey, err)
	}
	rewrapped := envelope
	rewrapped.Key = nextKey
	activated, err := client.Activate(context.Background(), DomainPIIPayload, manifest)
	if err != nil || activated.MaterialGeneration != 3 || activated.Active[DomainPIIPayload] != 2 {
		t.Fatal("wrapper activation failed", activated, err)
	}
	if _, err = cipher.Seal(context.Background(), binding, plain); err == nil {
		t.Fatal("new payload write remained enabled before database acknowledgement")
	}
	for name, candidate := range map[string]Envelope{"historical": envelope, "rewrapped": rewrapped} {
		opened, err = cipher.Open(context.Background(), binding, candidate)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatal(name, " envelope unavailable after activation", err)
		}
		clear(opened)
	}
	acknowledged, err := client.Acknowledge(context.Background(), DomainPIIPayload, manifest)
	if err != nil || acknowledged.MaterialGeneration != 4 || !acknowledged.WriteEnabled {
		t.Fatal("wrapper acknowledgement failed", acknowledged, err)
	}
	retired, err := client.Retire(context.Background(), DomainPIIPayload, KeyReference{KeyID: envelope.Key.KEKID, Version: envelope.Key.Version}, bytes.Repeat([]byte{0x7c}, 32))
	if err != nil || retired.MaterialGeneration != 5 || retired.Active[DomainPIIPayload] != 2 {
		t.Fatal("wrapper retirement failed", retired, err)
	}
	if opened, err = cipher.Open(context.Background(), binding, envelope); err == nil || len(opened) != 0 {
		t.Fatal("retired wrapper remained usable", err)
	}
	if _, err = client.Retire(context.Background(), DomainPIIPayload, retired.ActiveKeys[DomainPIIPayload], bytes.Repeat([]byte{0x7c}, 32)); err == nil {
		t.Fatal("active wrapper was retired")
	}
	archiveDEK := bytes.Repeat([]byte{0x4d}, 32)
	archiveWrapped, err := client.WrapBackup(context.Background(), archiveDEK)
	if err != nil {
		t.Fatal("backup archive wrap failed", err)
	}
	backupManifest := bytes.Repeat([]byte{0x4e}, 32)
	backupTarget := KeyReference{KeyID: "00000000-0000-4000-8000-000000000004", Version: 2}
	if _, err = client.Stage(context.Background(), DomainBackupArchive, backupTarget, backupManifest); err != nil {
		t.Fatal("backup key stage failed", err)
	}
	if _, err = client.Activate(context.Background(), DomainBackupArchive, backupManifest); err != nil {
		t.Fatal("backup key activation failed", err)
	}
	if _, err = client.Acknowledge(context.Background(), DomainBackupArchive, backupManifest); err != nil {
		t.Fatal("backup key acknowledgement failed", err)
	}
	if _, err = client.Retire(context.Background(), DomainBackupArchive, KeyReference{KeyID: archiveWrapped.KEKID, Version: archiveWrapped.Version}, bytes.Repeat([]byte{0x4f}, 32)); err == nil {
		t.Fatal("backup archive key retired without an external retention inventory")
	}
	restoredArchiveDEK, err := client.UnwrapBackup(context.Background(), archiveWrapped)
	if err != nil || !bytes.Equal(restoredArchiveDEK, archiveDEK) {
		t.Fatal("retained backup archive key unavailable", err)
	}
	clear(restoredArchiveDEK)
	clear(archiveDEK)
	macManifest := bytes.Repeat([]byte{0x6b}, 32)
	macTarget := KeyReference{KeyID: "00000000-0000-4000-8000-000000000003", Version: 2}
	if _, err = client.Stage(context.Background(), DomainCommandReceipt, macTarget, macManifest); err != nil {
		t.Fatal("MAC stage failed", err)
	}
	stagingMAC, err := client.MACStaging(context.Background(), DomainCommandReceipt, macManifest, []byte("synthetic command"))
	if err != nil || stagingMAC.Version != 2 || bytes.Equal(stagingMAC.Digest, value.Digest) {
		t.Fatal("staging MAC unavailable or reused active material", err)
	}
	if _, err = client.Activate(context.Background(), DomainCommandReceipt, macManifest); err != nil {
		t.Fatal("MAC activation failed", err)
	}
	if _, err = client.MAC(context.Background(), DomainCommandReceipt, []byte("new write")); err == nil {
		t.Fatal("active MAC accepted writes before database acknowledgement")
	}
	if _, err = client.Acknowledge(context.Background(), DomainCommandReceipt, macManifest); err != nil {
		t.Fatal("MAC acknowledgement failed", err)
	}
	verified, err = client.Verify(context.Background(), DomainCommandReceipt, KeyReference{KeyID: value.KeyID, Version: value.Version}, []byte("synthetic command"), value.Digest)
	if err != nil || !verified {
		t.Fatal("historical MAC was not retained verify-only", err)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal("shutdown", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- ServeKeyd(ctx, cfg) }()
	for time.Now().Before(deadline.Add(3 * time.Second)) {
		if _, err = client.Ready(context.Background()); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("restart", err)
	}
	opened, err = cipher.Open(context.Background(), binding, rewrapped)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("restart lost active key material", err)
	}
	clear(opened)
	if opened, err = cipher.Open(context.Background(), binding, envelope); err == nil || len(opened) != 0 {
		t.Fatal("restart restored retired key material", err)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKeydAPIIdentityCannotUseMaintenanceOperations(t *testing.T) {
	server := &keydServer{
		api:         map[uint32]bool{1000: true},
		maintenance: map[uint32]bool{1002: true},
	}
	for _, operation := range []string{"probe", "rewrap", "stage", "activate", "acknowledge", "retire", "mac_staging"} {
		response := server.dispatch(1000, keydRequest{Operation: operation})
		if response.Code != "unavailable" {
			t.Fatalf("API identity unexpectedly authorized for %s: %#v", operation, response)
		}
	}
	for _, operation := range []string{"wrap", "unwrap"} {
		response := server.dispatch(1000, keydRequest{Operation: operation, Domain: DomainBackupArchive})
		if response.Code != "unavailable" {
			t.Fatalf("API identity unexpectedly authorized for backup %s: %#v", operation, response)
		}
	}
}

func TestKeyDomainUpgradeRequiresExplicitLegacyExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(home, ".teamledger-key-upgrade-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "keys")
	if err = InitKeyDirectory(directory); err != nil {
		t.Fatal(err)
	}
	lockfd, root, ring, err := loadKeyDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	for i := 16; i < len(ring.Entries); i++ {
		clear(ring.Entries[i].Material)
	}
	ring.Entries = ring.Entries[:16]
	if err = persistKeyring(directory, root, &ring); err != nil {
		t.Fatal(err)
	}
	clear(root)
	clearKeyring(&ring)
	unix.Close(lockfd)
	socket := filepath.Join(directory, "keyd.sock")
	if err = ServeKeyd(context.Background(), KeydServerConfig{KeyDirectory: directory, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}}); err == nil {
		t.Fatal("keyd accepted a legacy keyring without explicit expansion")
	}
	state, err := UpgradeKeyDomains(directory)
	if err != nil || state.MaterialGeneration != 2 || len(state.ActiveKeys) != 18 || state.Active[sensitiveDomainForTest(t, "identity_mfa")] != 1 {
		t.Fatal("legacy keyring expansion failed", state, err)
	}
	again, err := UpgradeKeyDomains(directory)
	if err != nil || again.MaterialGeneration != state.MaterialGeneration || again.Digest != state.Digest {
		t.Fatal("completed keyring expansion was not idempotent", again, err)
	}
}

func sensitiveDomainForTest(t *testing.T, name string) KeyDomain {
	t.Helper()
	for _, domain := range allKeyDomains() {
		if string(domain) == name {
			return domain
		}
	}
	t.Fatal("missing domain", name)
	return ""
}
