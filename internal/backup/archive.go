package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const chunkSize = 1 << 20

var magic = [16]byte{'T', 'L', 'B', 'A', 'C', 'K', 'U', 'P', 0, 1, 0, 0, 0, 0, 0, 0}

type KeyDependency struct {
	Domain, KeyID string
	Version       uint32
}
type Manifest struct {
	FormatVersion           int             `json:"format_version"`
	Backend                 string          `json:"backend"`
	SchemaVersion           int             `json:"schema_version"`
	CreatedAt               time.Time       `json:"created_at"`
	DatabaseSize            int64           `json:"database_size"`
	DatabaseSHA256          string          `json:"database_sha256"`
	OrganizationIDs         []string        `json:"organization_ids"`
	KeyDependencies         []KeyDependency `json:"key_dependencies"`
	HMACState               json.RawMessage `json:"hmac_state"`
	AuditCheckpoint         json.RawMessage `json:"audit_checkpoint"`
	AuditReceiverCheckpoint json.RawMessage `json:"audit_receiver_checkpoint"`
	RevocationCheckpoint    json.RawMessage `json:"revocation_checkpoint"`
	JobFenceCheckpoint      json.RawMessage `json:"job_fence_checkpoint"`
	GraphCompCheckpoint     json.RawMessage `json:"graph_comp_checkpoint"`
}

func aeadFor(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid backup key")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func nonce(base [12]byte, sequence uint64) []byte {
	out := base
	binary.BigEndian.PutUint64(out[4:], binary.BigEndian.Uint64(out[4:])^sequence)
	return out[:]
}
func aad(kind byte, sequence uint64, size uint32) []byte {
	out := make([]byte, 29)
	copy(out, magic[:])
	out[16] = kind
	binary.BigEndian.PutUint64(out[17:], sequence)
	binary.BigEndian.PutUint32(out[25:], size)
	return out
}
func writeChunk(w io.Writer, aead cipher.AEAD, base [12]byte, kind byte, sequence uint64, plain []byte) error {
	if len(plain) > chunkSize {
		return errors.New("backup chunk too large")
	}
	header := make([]byte, 13)
	header[0] = kind
	binary.BigEndian.PutUint64(header[1:], sequence)
	binary.BigEndian.PutUint32(header[9:], uint32(len(plain)))
	sealed := aead.Seal(nil, nonce(base, sequence), plain, aad(kind, sequence, uint32(len(plain))))
	defer clear(sealed)
	if _, e := w.Write(header); e != nil {
		return e
	}
	_, e := w.Write(sealed)
	return e
}
func validManifest(manifest Manifest) bool {
	if manifest.FormatVersion != 1 || manifest.SchemaVersion < 1 || manifest.CreatedAt.IsZero() || manifest.DatabaseSize < 0 || (manifest.Backend != "sqlite" && manifest.Backend != "postgres") || len(manifest.DatabaseSHA256) != 64 {
		return false
	}
	digest, err := hex.DecodeString(manifest.DatabaseSHA256)
	if err != nil || hex.EncodeToString(digest) != manifest.DatabaseSHA256 {
		return false
	}
	for _, orgID := range manifest.OrganizationIDs {
		if orgID == "" {
			return false
		}
	}
	for _, dependency := range manifest.KeyDependencies {
		if (dependency.Domain != "pii" && dependency.Domain != "interview" && dependency.Domain != "assessment" && dependency.Domain != "financial" && dependency.Domain != "identity_mfa") || dependency.KeyID == "" || dependency.Version == 0 {
			return false
		}
	}
	return true
}

func WriteArchive(out io.Writer, database io.Reader, manifest Manifest, key []byte) error {
	aead, e := aeadFor(key)
	if e != nil {
		return e
	}
	if !validManifest(manifest) {
		return errors.New("invalid backup manifest")
	}
	var base [12]byte
	if _, e = rand.Read(base[:]); e != nil {
		return e
	}
	writer := bufio.NewWriterSize(out, chunkSize+64)
	if _, e = writer.Write(magic[:]); e != nil {
		return e
	}
	if _, e = writer.Write(base[:]); e != nil {
		return e
	}
	buffer := make([]byte, chunkSize)
	defer clear(buffer)
	hash := sha256.New()
	var total int64
	sequence := uint64(1)
	for {
		read, readErr := database.Read(buffer)
		if read > 0 {
			hash.Write(buffer[:read])
			total += int64(read)
			if e = writeChunk(writer, aead, base, 1, sequence, buffer[:read]); e != nil {
				return e
			}
			sequence++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	if total != manifest.DatabaseSize || hex.EncodeToString(hash.Sum(nil)) != manifest.DatabaseSHA256 {
		return errors.New("snapshot does not match manifest")
	}
	encoded, e := json.Marshal(manifest)
	if e != nil || len(encoded) > chunkSize {
		return errors.New("invalid backup manifest")
	}
	defer clear(encoded)
	if e = writeChunk(writer, aead, base, 2, sequence, encoded); e != nil {
		return e
	}
	sequence++
	if e = writeChunk(writer, aead, base, 0, sequence, nil); e != nil {
		return e
	}
	return writer.Flush()
}
func ReadArchive(in io.Reader, database io.Writer, key []byte) (Manifest, error) {
	aead, e := aeadFor(key)
	if e != nil {
		return Manifest{}, e
	}
	reader := bufio.NewReaderSize(in, chunkSize+64)
	header := make([]byte, 28)
	if _, e = io.ReadFull(reader, header); e != nil || !bytesEqual(header[:16], magic[:]) {
		return Manifest{}, errors.New("invalid backup header")
	}
	var base [12]byte
	copy(base[:], header[16:])
	hash := sha256.New()
	var total int64
	expected := uint64(1)
	var manifest Manifest
	seenManifest := false
	for {
		record := make([]byte, 13)
		if _, e = io.ReadFull(reader, record); e != nil {
			return Manifest{}, errors.New("truncated backup")
		}
		kind, sequence, size := record[0], binary.BigEndian.Uint64(record[1:]), binary.BigEndian.Uint32(record[9:])
		if sequence != expected || size > chunkSize {
			return Manifest{}, errors.New("invalid backup sequence")
		}
		expected++
		sealed := make([]byte, int(size)+aead.Overhead())
		if _, e = io.ReadFull(reader, sealed); e != nil {
			return Manifest{}, errors.New("truncated backup")
		}
		plain, e := aead.Open(nil, nonce(base, sequence), sealed, aad(kind, sequence, size))
		clear(sealed)
		if e != nil {
			return Manifest{}, errors.New("backup authentication failed")
		}
		if kind == 1 && !seenManifest {
			written, writeErr := database.Write(plain)
			hash.Write(plain)
			total += int64(written)
			clear(plain)
			if writeErr != nil || written != int(size) {
				return Manifest{}, io.ErrShortWrite
			}
			continue
		}
		if kind == 2 && !seenManifest {
			decoder := json.NewDecoder(bytesReader(plain))
			decoder.DisallowUnknownFields()
			e = decoder.Decode(&manifest)
			canonical, canonicalErr := json.Marshal(manifest)
			canonicalMatch := bytesEqual(canonical, plain)
			clear(canonical)
			clear(plain)
			if e != nil || canonicalErr != nil || !canonicalMatch {
				return Manifest{}, errors.New("invalid backup manifest")
			}
			seenManifest = true
			continue
		}
		clear(plain)
		if kind != 0 || size != 0 || !seenManifest {
			return Manifest{}, errors.New("invalid backup terminal")
		}
		break
	}
	if _, e = reader.ReadByte(); e != io.EOF {
		return Manifest{}, errors.New("trailing backup data")
	}
	if !validManifest(manifest) {
		return Manifest{}, errors.New("invalid backup manifest")
	}
	if total != manifest.DatabaseSize || hex.EncodeToString(hash.Sum(nil)) != manifest.DatabaseSHA256 {
		return Manifest{}, errors.New("restored snapshot digest mismatch")
	}
	return manifest, nil
}

type sliceReader struct {
	b    []byte
	done bool
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.done {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	if len(s.b) == 0 {
		s.done = true
	}
	return n, nil
}
func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
