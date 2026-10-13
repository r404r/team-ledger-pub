package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/value"
	"golang.org/x/sys/unix"
)

type MaterialOwners struct {
	BootstrapUID int
	ReceiverUID  int
	ForwarderUID int
	GID          int
}

type signerDocument struct {
	Version int    `json:"version"`
	KeyID   string `json:"key_id"`
	Private string `json:"private_key"`
}

func validOwner(id int) bool { return id >= 0 && uint64(id) <= uint64(^uint32(0)) }

func writeMaterial(path string, data []byte, mode os.FileMode, uid, gid int, replace bool) error {
	if !validOwner(uid) || !validOwner(gid) || filepath.Base(path) == "." {
		return errors.New("invalid audit material owner")
	}
	if !replace {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("audit material already exists")
		}
	} else if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return errors.New("invalid existing audit material")
	} else if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 || stat.Uid != uint32(uid) {
		return errors.New("invalid existing audit material")
	}
	temp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"-"+value.NewID())
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return errors.New("cannot create audit material")
	}
	published := false
	defer func() {
		file.Close()
		if !published {
			_ = os.Remove(temp)
		}
	}()
	if err = file.Chmod(mode); err == nil {
		err = file.Chown(uid, gid)
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot persist audit material")
	}
	if !replace {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("audit material appeared during bootstrap")
		}
	}
	if replace {
		err = os.Rename(temp, path)
	} else {
		err = unix.Renameat2(unix.AT_FDCWD, temp, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return errors.New("cannot publish audit material")
	}
	published = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func createDir(path string, uid, gid int) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return errors.New("audit material directory exists or is unavailable")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func newCA(now time.Time) ([]byte, []byte, *x509.Certificate, ed25519.PrivateKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "TeamLedger local audit CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), certificate, private, nil
}

func newLeaf(ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time, name string, server bool) ([]byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if server {
		template.ExtKeyUsage[0] = x509.ExtKeyUsageServerAuth
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), nil
}

func BootstrapMaterial(directory, receiverName string, owners MaterialOwners, now time.Time) error {
	if !validName(receiverName) || !filepath.IsAbs(directory) || !validOwner(owners.BootstrapUID) || !validOwner(owners.ReceiverUID) || !validOwner(owners.ForwarderUID) || !validOwner(owners.GID) {
		return errors.New("invalid audit bootstrap configuration")
	}
	if err := createDir(directory, owners.BootstrapUID, owners.GID); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()
	for name, uid := range map[string]int{"bootstrap": owners.BootstrapUID, "receiver": owners.ReceiverUID, "forwarder": owners.ForwarderUID} {
		if err := createDir(filepath.Join(directory, name), uid, owners.GID); err != nil {
			return err
		}
	}
	if err := os.Chmod(directory, 0711); err != nil {
		return err
	}
	caPEM, caKeyPEM, ca, caKey, err := newCA(now.UTC().Truncate(time.Microsecond))
	if err != nil {
		return err
	}
	defer clear(caKey)
	serverCert, serverKey, err := newLeaf(ca, caKey, now, receiverName, true)
	if err != nil {
		return err
	}
	clientCert, clientKey, err := newLeaf(ca, caKey, now, "teamledger-audit-forwarder", false)
	if err != nil {
		return err
	}
	healthCert, healthKey, err := newLeaf(ca, caKey, now, "teamledger-audit-health", false)
	if err != nil {
		return err
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(receiptPrivate)
	keyID := "receipt-" + now.UTC().Format("20060102") + "-" + value.NewID()[:8]
	signerBytes, err := json.Marshal(signerDocument{1, keyID, base64.RawURLEncoding.EncodeToString(receiptPrivate)})
	if err != nil {
		return err
	}
	defer clear(signerBytes)
	trustBytes, err := ReceiptKeysBytes(ReceiptKeys{keyID: receiptPublic})
	if err != nil {
		return err
	}
	caMaterial := append(append([]byte(nil), caPEM...), caKeyPEM...)
	defer clear(caMaterial)
	files := []struct {
		path string
		data []byte
		mode os.FileMode
		uid  int
	}{
		{filepath.Join(directory, "bootstrap", "ca.pem"), caMaterial, 0400, owners.BootstrapUID},
		{filepath.Join(directory, "receiver", "ca.pem"), caPEM, 0444, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "server-cert.pem"), serverCert, 0444, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "server-key.pem"), serverKey, 0400, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "health-cert.pem"), healthCert, 0444, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "health-key.pem"), healthKey, 0400, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "signer.json"), signerBytes, 0400, owners.ReceiverUID},
		{filepath.Join(directory, "forwarder", "ca.pem"), caPEM, 0444, owners.ForwarderUID},
		{filepath.Join(directory, "forwarder", "client-cert.pem"), clientCert, 0444, owners.ForwarderUID},
		{filepath.Join(directory, "forwarder", "client-key.pem"), clientKey, 0400, owners.ForwarderUID},
		{filepath.Join(directory, "forwarder", "receipt-keys.json"), trustBytes, 0444, owners.ForwarderUID},
	}
	for _, file := range files {
		if err = writeMaterial(file.path, file.data, file.mode, file.uid, owners.GID, false); err != nil {
			return err
		}
	}
	complete = true
	return nil
}

func LoadSigner(path string) (string, ed25519.PrivateKey, error) {
	raw, err := configfile.Read(path, 16<<10, true)
	if err != nil {
		return "", nil, err
	}
	defer clear(raw)
	var document signerDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Version != 1 || !validName(document.KeyID) {
		return "", nil, errors.New("invalid receipt signer")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return "", nil, errors.New("invalid receipt signer")
	}
	clear(canonical)
	private, err := base64.RawURLEncoding.DecodeString(document.Private)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		clear(private)
		return "", nil, errors.New("invalid receipt signer")
	}
	return document.KeyID, ed25519.PrivateKey(private), nil
}

func readOwnedMaterial(path string, limit int, uid int, mode os.FileMode) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("invalid audit material")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return nil, errors.New("invalid audit material")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(uid) {
		return nil, errors.New("invalid audit material")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) == 0 || len(raw) > limit {
		clear(raw)
		return nil, errors.New("invalid audit material")
	}
	return raw, nil
}

func parseSigner(raw []byte) (signerDocument, ed25519.PrivateKey, error) {
	var document signerDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Version != 1 || !validName(document.KeyID) {
		return document, nil, errors.New("invalid receipt signer")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return document, nil, errors.New("invalid receipt signer")
	}
	clear(canonical)
	private, err := base64.RawURLEncoding.DecodeString(document.Private)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		clear(private)
		return document, nil, errors.New("invalid receipt signer")
	}
	return document, ed25519.PrivateKey(private), nil
}

func RotateSigner(directory string, owners MaterialOwners, now time.Time) (string, error) {
	signerPath := filepath.Join(directory, "receiver", "signer.json")
	trustPath := filepath.Join(directory, "forwarder", "receipt-keys.json")
	signerRaw, err := readOwnedMaterial(signerPath, 16<<10, owners.ReceiverUID, 0400)
	if err != nil {
		return "", err
	}
	defer clear(signerRaw)
	current, currentPrivate, err := parseSigner(signerRaw)
	if err != nil {
		return "", err
	}
	defer clear(currentPrivate)
	trustRaw, err := readOwnedMaterial(trustPath, 16<<10, owners.ForwarderUID, 0444)
	if err != nil {
		return "", err
	}
	defer clear(trustRaw)
	keys, err := ParseReceiptKeys(trustRaw)
	if err != nil || len(keys[current.KeyID]) != ed25519.PublicKeySize || len(keys) >= 8 {
		return "", errors.New("invalid receipt trust state")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(private)
	keyID := "receipt-" + now.UTC().Format("20060102") + "-" + value.NewID()[:8]
	keys[keyID] = public
	nextTrust, err := ReceiptKeysBytes(keys)
	if err != nil {
		return "", err
	}
	nextSigner, err := json.Marshal(signerDocument{1, keyID, base64.RawURLEncoding.EncodeToString(private)})
	if err != nil {
		return "", err
	}
	defer clear(nextSigner)
	if err = writeMaterial(trustPath, nextTrust, 0444, owners.ForwarderUID, owners.GID, true); err != nil {
		return "", err
	}
	if err = writeMaterial(signerPath, nextSigner, 0400, owners.ReceiverUID, owners.GID, true); err != nil {
		return "", err
	}
	return keyID, nil
}

func RetireSigner(directory string, owners MaterialOwners, keyID string, dependenciesCleared bool) error {
	if !validName(keyID) {
		return errors.New("invalid receipt key id")
	}
	if !dependenciesCleared {
		return errors.New("receipt signer dependencies are not cleared")
	}
	signerRaw, err := readOwnedMaterial(filepath.Join(directory, "receiver", "signer.json"), 16<<10, owners.ReceiverUID, 0400)
	if err != nil {
		return err
	}
	defer clear(signerRaw)
	current, private, err := parseSigner(signerRaw)
	if err != nil {
		return err
	}
	defer clear(private)
	if current.KeyID == keyID {
		return errors.New("cannot retire active receipt signer")
	}
	trustPath := filepath.Join(directory, "forwarder", "receipt-keys.json")
	trustRaw, err := readOwnedMaterial(trustPath, 16<<10, owners.ForwarderUID, 0444)
	if err != nil {
		return err
	}
	defer clear(trustRaw)
	keys, err := ParseReceiptKeys(trustRaw)
	if err != nil {
		return err
	}
	if _, exists := keys[keyID]; !exists {
		return errors.New("receipt signer is not trusted")
	}
	delete(keys, keyID)
	nextTrust, err := ReceiptKeysBytes(keys)
	if err != nil {
		return err
	}
	return writeMaterial(trustPath, nextTrust, 0444, owners.ForwarderUID, owners.GID, true)
}
func parseCurrentCA(raw []byte) (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	certificateBlock, rest := pem.Decode(raw)
	keyBlock, trailing := pem.Decode(rest)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, nil, nil, errors.New("invalid audit CA material")
	}
	certificate, err := x509.ParseCertificate(append([]byte(nil), certificateBlock.Bytes...))
	if err != nil || !certificate.IsCA {
		return nil, nil, nil, errors.New("invalid audit CA material")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	private, keyOK := parsedKey.(ed25519.PrivateKey)
	public, publicOK := certificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !keyOK || !publicOK || !public.Equal(private.Public()) {
		clear(private)
		return nil, nil, nil, errors.New("invalid audit CA material")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	canonical := append(append([]byte(nil), certificatePEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBlock.Bytes})...)
	if !bytes.Equal(canonical, raw) {
		clear(private)
		clear(canonical)
		return nil, nil, nil, errors.New("invalid audit CA material")
	}
	clear(canonical)
	return certificate, private, certificatePEM, nil
}

func parseCABundle(raw []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	canonical := make([]byte, 0, len(raw))
	for len(raw) != 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) == 2 {
			return nil, errors.New("invalid audit CA trust bundle")
		}
		certificate, err := x509.ParseCertificate(append([]byte(nil), block.Bytes...))
		if err != nil || !certificate.IsCA {
			return nil, errors.New("invalid audit CA trust bundle")
		}
		certificates = append(certificates, certificate)
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
		raw = rest
	}
	if len(certificates) == 0 || len(canonical) == 0 {
		return nil, errors.New("invalid audit CA trust bundle")
	}
	return certificates, nil
}

func writeLeaves(directory, receiverName string, owners MaterialOwners, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) error {
	serverCert, serverKey, err := newLeaf(ca, caKey, now, receiverName, true)
	if err != nil {
		return err
	}
	healthCert, healthKey, err := newLeaf(ca, caKey, now, "teamledger-audit-health", false)
	if err != nil {
		return err
	}
	clientCert, clientKey, err := newLeaf(ca, caKey, now, "teamledger-audit-forwarder", false)
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
		uid  int
	}{
		{filepath.Join(directory, "receiver", "server-cert.pem"), serverCert, 0444, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "server-key.pem"), serverKey, 0400, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "health-cert.pem"), healthCert, 0444, owners.ReceiverUID},
		{filepath.Join(directory, "receiver", "health-key.pem"), healthKey, 0400, owners.ReceiverUID},
		{filepath.Join(directory, "forwarder", "client-cert.pem"), clientCert, 0444, owners.ForwarderUID},
		{filepath.Join(directory, "forwarder", "client-key.pem"), clientKey, 0400, owners.ForwarderUID},
	}
	for _, file := range files {
		if err = writeMaterial(file.path, file.data, file.mode, file.uid, owners.GID, true); err != nil {
			return err
		}
	}
	return nil
}

func RotateLeaves(directory, receiverName string, owners MaterialOwners, now time.Time) error {
	if !validName(receiverName) {
		return errors.New("invalid receiver name")
	}
	raw, err := readOwnedMaterial(filepath.Join(directory, "bootstrap", "ca.pem"), 1<<20, owners.BootstrapUID, 0400)
	if err != nil {
		return err
	}
	defer clear(raw)
	ca, caKey, _, err := parseCurrentCA(raw)
	if err != nil {
		return err
	}
	defer clear(caKey)
	return writeLeaves(directory, receiverName, owners, ca, caKey, now)
}

func RotateCA(directory, receiverName string, owners MaterialOwners, now time.Time) error {
	if !validName(receiverName) {
		return errors.New("invalid receiver name")
	}
	currentPath := filepath.Join(directory, "bootstrap", "ca.pem")
	currentRaw, err := readOwnedMaterial(currentPath, 1<<20, owners.BootstrapUID, 0400)
	if err != nil {
		return err
	}
	defer clear(currentRaw)
	current, currentKey, currentPEM, err := parseCurrentCA(currentRaw)
	if err != nil {
		return err
	}
	defer clear(currentKey)
	for path, uid := range map[string]int{
		filepath.Join(directory, "receiver", "ca.pem"):  owners.ReceiverUID,
		filepath.Join(directory, "forwarder", "ca.pem"): owners.ForwarderUID,
	} {
		bundleRaw, readErr := readOwnedMaterial(path, 1<<20, uid, 0444)
		if readErr != nil {
			return readErr
		}
		bundle, parseErr := parseCABundle(bundleRaw)
		clear(bundleRaw)
		if parseErr != nil || len(bundle) > 1 && bytes.Equal(bundle[1].Raw, current.Raw) || !bytes.Equal(bundle[0].Raw, current.Raw) {
			return errors.New("audit CA rotation is already pending or trust is inconsistent")
		}
	}
	newPEM, newKeyPEM, next, nextKey, err := newCA(now.UTC().Truncate(time.Microsecond))
	if err != nil {
		return err
	}
	defer clear(nextKey)
	nextMaterial := append(append([]byte(nil), newPEM...), newKeyPEM...)
	defer clear(nextMaterial)
	dualTrust := append(append([]byte(nil), currentPEM...), newPEM...)
	for path, uid := range map[string]int{
		filepath.Join(directory, "receiver", "ca.pem"):  owners.ReceiverUID,
		filepath.Join(directory, "forwarder", "ca.pem"): owners.ForwarderUID,
	} {
		if err = writeMaterial(path, dualTrust, 0444, uid, owners.GID, true); err != nil {
			return err
		}
	}
	if err = writeLeaves(directory, receiverName, owners, next, nextKey, now); err != nil {
		return err
	}
	return writeMaterial(currentPath, nextMaterial, 0400, owners.BootstrapUID, owners.GID, true)
}

func RetireOldCA(directory string, owners MaterialOwners) error {
	currentRaw, err := readOwnedMaterial(filepath.Join(directory, "bootstrap", "ca.pem"), 1<<20, owners.BootstrapUID, 0400)
	if err != nil {
		return err
	}
	defer clear(currentRaw)
	current, private, currentPEM, err := parseCurrentCA(currentRaw)
	if err != nil {
		return err
	}
	clear(private)
	for path, uid := range map[string]int{
		filepath.Join(directory, "receiver", "ca.pem"):  owners.ReceiverUID,
		filepath.Join(directory, "forwarder", "ca.pem"): owners.ForwarderUID,
	} {
		bundleRaw, readErr := readOwnedMaterial(path, 1<<20, uid, 0444)
		if readErr != nil {
			return readErr
		}
		bundle, parseErr := parseCABundle(bundleRaw)
		clear(bundleRaw)
		if parseErr != nil {
			return parseErr
		}
		switch {
		case len(bundle) == 1 && bytes.Equal(bundle[0].Raw, current.Raw):
			continue
		case len(bundle) == 2 && bytes.Equal(bundle[1].Raw, current.Raw):
			if err = writeMaterial(path, currentPEM, 0444, uid, owners.GID, true); err != nil {
				return err
			}
		default:
			return errors.New("audit CA rotation is not ready for retirement")
		}
	}
	return nil
}
func CurrentSignerID(directory string, owners MaterialOwners) (string, error) {
	raw, err := readOwnedMaterial(filepath.Join(directory, "receiver", "signer.json"), 16<<10, owners.ReceiverUID, 0400)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	document, private, err := parseSigner(raw)
	if err != nil {
		return "", err
	}
	clear(private)
	return document.KeyID, nil
}
