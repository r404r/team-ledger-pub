package sensitive

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/text/unicode/norm"
)

var ErrInvalid = errors.New("invalid encrypted payload")
var ErrUnavailable = errors.New("key service unavailable")

type Context struct {
	OrgID, EmployeeID, RecordID, VersionID string
	ObjectKind, Purpose, SchemaType        string
	SchemaVersion                          uint32
}

type WrappedKey struct {
	KEKID   string
	Version uint32
	Data    []byte
}

type Wrapper interface {
	Wrap(context.Context, []byte) (WrappedKey, error)
	Unwrap(context.Context, WrappedKey) ([]byte, error)
}

// BoundWrapper binds a wrapped DEK to the immutable payload context and DEK ID.
// Production key services must implement this interface. Wrapper remains the
// narrow maintenance/test compatibility contract; Cipher never falls back to it
// when a BoundWrapper is present.
type BoundWrapper interface {
	Wrapper
	WrapBound(context.Context, Context, string, []byte) (WrappedKey, error)
	UnwrapBound(context.Context, Context, string, WrappedKey) ([]byte, error)
}

type Envelope struct {
	Context       Context
	FormatVersion uint16
	Algorithm     string
	DEKID         string
	Key           WrappedKey
	SealedBytes   []byte
}

type Cipher struct{ Wrapper Wrapper }

// RewrapKey rotates only the DEK wrapper. Payload ciphertext, AAD and business
// facts remain outside this operation and therefore cannot be silently rebound.
func RewrapKey(ctx context.Context, source, target Wrapper, current WrappedKey) (WrappedKey, error) {
	if source == nil || target == nil || !validWrappedKey(current) || ctx.Err() != nil {
		return WrappedKey{}, ErrUnavailable
	}
	dek, err := source.Unwrap(ctx, current)
	if err != nil || len(dek) != 32 {
		clear(dek)
		return WrappedKey{}, ErrUnavailable
	}
	defer clear(dek)
	next, err := target.Wrap(ctx, dek)
	if err != nil || !validWrappedKey(next) || next.KEKID == current.KEKID && next.Version == current.Version {
		clear(next.Data)
		return WrappedKey{}, ErrUnavailable
	}
	verified, err := target.Unwrap(ctx, next)
	defer clear(verified)
	if err != nil || len(verified) != 32 || subtle.ConstantTimeCompare(dek, verified) != 1 {
		clear(next.Data)
		return WrappedKey{}, ErrUnavailable
	}
	return next, nil
}

func (c Cipher) Seal(ctx context.Context, binding Context, plaintext []byte) (Envelope, error) {
	if len(plaintext) > maxPlaintext {
		return Envelope{}, ErrInvalid
	}
	if c.Wrapper == nil || ctx.Err() != nil {
		return Envelope{}, ErrUnavailable
	}
	var dek [32]byte
	defer clear(dek[:])
	if _, err := rand.Read(dek[:]); err != nil {
		return Envelope{}, ErrUnavailable
	}
	dekID, err := newDEKID()
	if err != nil {
		return Envelope{}, ErrUnavailable
	}
	bound, isBound := c.Wrapper.(BoundWrapper)
	aad, err := payloadAAD(binding, dekID, isBound)
	if err != nil {
		return Envelope{}, ErrInvalid
	}
	aead, err := newPayloadAEAD(dek[:])
	if err != nil {
		return Envelope{}, ErrUnavailable
	}
	var key WrappedKey
	if isBound {
		key, err = bound.WrapBound(ctx, binding, dekID, dek[:])
	} else {
		key, err = c.Wrapper.Wrap(ctx, dek[:])
	}
	if err != nil {
		return Envelope{}, keyError(err)
	}
	if !validWrappedKey(key) {
		return Envelope{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Envelope{}, ErrUnavailable
	}
	sealed := aead.Seal(nil, nil, plaintext, aad)
	if isBound {
		packet := make([]byte, 0, 4+2+1+12+4+len(plaintext)+16)
		packet = append(packet, "TLP1"...)
		packet = binary.BigEndian.AppendUint16(packet, 1)
		packet = append(packet, 1)
		packet = append(packet, sealed[:12]...)
		packet = binary.BigEndian.AppendUint32(packet, uint32(len(plaintext)))
		packet = append(packet, sealed[12:]...)
		clear(sealed)
		sealed = packet
	}
	return Envelope{
		Context: binding, FormatVersion: 1, Algorithm: payloadAlgorithm,
		DEKID: dekID, Key: key, SealedBytes: sealed,
	}, nil
}

func (c Cipher) Open(ctx context.Context, binding Context, envelope Envelope) ([]byte, error) {
	if envelope.Context != binding || envelope.FormatVersion != 1 ||
		envelope.Algorithm != payloadAlgorithm || !validWrappedKey(envelope.Key) {
		return nil, ErrInvalid
	}
	bound, isBound := c.Wrapper.(BoundWrapper)
	sealed := envelope.SealedBytes
	if isBound {
		var err error
		sealed, err = decodePayloadPacket(envelope.SealedBytes)
		if err != nil {
			return nil, ErrInvalid
		}
	} else if len(sealed) < 28 || len(sealed) > maxPlaintext+28 {
		return nil, ErrInvalid
	}
	var id [16]byte
	if !decodeUUID(envelope.DEKID, &id) {
		return nil, ErrInvalid
	}
	aad, err := payloadAAD(binding, envelope.DEKID, isBound)
	if err != nil {
		return nil, ErrInvalid
	}
	if c.Wrapper == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	var dek []byte
	if isBound {
		dek, err = bound.UnwrapBound(ctx, binding, envelope.DEKID, envelope.Key)
	} else {
		dek, err = c.Wrapper.Unwrap(ctx, envelope.Key)
	}
	defer clear(dek)
	if err != nil {
		return nil, keyError(err)
	}
	if len(dek) != 32 {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	aead, err := newPayloadAEAD(dek)
	if err != nil {
		return nil, ErrInvalid
	}
	plaintext, err := aead.Open(nil, nil, sealed, aad)
	if err != nil {
		clear(plaintext)
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		clear(plaintext)
		return nil, ErrUnavailable
	}
	return plaintext, nil
}

func decodePayloadPacket(packet []byte) ([]byte, error) {
	if len(packet) < 4+2+1+12+4+16 || string(packet[:4]) != "TLP1" ||
		binary.BigEndian.Uint16(packet[4:6]) != 1 || packet[6] != 1 {
		return nil, ErrInvalid
	}
	size := binary.BigEndian.Uint32(packet[19:23])
	if size > maxPlaintext || len(packet) != 23+int(size)+16 {
		return nil, ErrInvalid
	}
	sealed := make([]byte, 0, 12+int(size)+16)
	sealed = append(sealed, packet[7:19]...)
	sealed = append(sealed, packet[23:]...)
	return sealed, nil
}

const (
	maxPlaintext     = 16 * 1024
	maxWrappedKey    = 64 * 1024
	payloadAlgorithm = "A256GCM-RANDOMNONCE"
)

func keyError(err error) error {
	if errors.Is(err, ErrInvalid) {
		return ErrInvalid
	}
	return ErrUnavailable
}

func validWrappedKey(key WrappedKey) bool {
	return validKeyName(key.KEKID) && key.Version > 0 &&
		len(key.Data) > 0 && len(key.Data) <= maxWrappedKey
}

func validKeyName(key string) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for i := range len(key) {
		c := key[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func newPayloadAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func decodeUUID(value string, out *[16]byte) bool {
	if len(value) != 36 {
		return false
	}
	nibble := 0
	for i := range len(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return false
			}
			continue
		}
		c := value[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return false
		}
		if nibble%2 == 0 {
			out[nibble/2] = v << 4
		} else {
			out[nibble/2] |= v
		}
		nibble++
	}
	return true
}

func newDEKID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	var text [36]byte
	hex.Encode(text[:8], raw[:4])
	text[8] = '-'
	hex.Encode(text[9:13], raw[4:6])
	text[13] = '-'
	hex.Encode(text[14:18], raw[6:8])
	text[18] = '-'
	hex.Encode(text[19:23], raw[8:10])
	text[23] = '-'
	hex.Encode(text[24:], raw[10:])
	return string(text[:]), nil
}
func payloadAAD(binding Context, dekID string, bound bool) ([]byte, error) {
	if bound {
		return canonicalAAD(binding, dekID)
	}
	return legacyAAD(binding)
}

func legacyAAD(binding Context) ([]byte, error) {
	_, _, _, employeeOwned, err := payloadRegistry(binding)
	if err != nil {
		return nil, err
	}
	var ids [4][16]byte
	for i, value := range [4]string{binding.OrgID, binding.EmployeeID, binding.RecordID, binding.VersionID} {
		if i == 1 && !employeeOwned {
			continue
		}
		if !decodeUUID(value, &ids[i]) {
			return nil, ErrInvalid
		}
	}
	out := binary.BigEndian.AppendUint16([]byte("TEAMLEDGER-AAD"), 1)
	for i := range ids {
		if i == 1 && !employeeOwned {
			out = binary.BigEndian.AppendUint32(out, 0)
			continue
		}
		out = binary.BigEndian.AppendUint32(out, 16)
		out = append(out, ids[i][:]...)
	}
	for _, value := range []string{binding.ObjectKind, binding.Purpose, binding.SchemaType} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
		out = append(out, value...)
	}
	out = binary.BigEndian.AppendUint32(out, 4)
	return binary.BigEndian.AppendUint32(out, binding.SchemaVersion), nil
}

func cf1(fields ...cfField) ([]byte, error) {
	out := make([]byte, 0, 256)
	out = append(out, "TLCF"...)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(fields)))
	var previous uint16
	for _, field := range fields {
		if field.tag <= previous || field.tag == 0 {
			return nil, ErrInvalid
		}
		previous = field.tag
		out = binary.BigEndian.AppendUint16(out, field.tag)
		out = append(out, field.kind)
		out = binary.BigEndian.AppendUint32(out, uint32(len(field.value)))
		out = append(out, field.value...)
	}
	if len(out) > keydFrameLimit {
		return nil, ErrInvalid
	}
	return out, nil
}

type cfField struct {
	tag   uint16
	kind  byte
	value []byte
}

func cfUUID(tag uint16, value string) (cfField, error) {
	var raw [16]byte
	if !decodeUUID(value, &raw) {
		return cfField{}, ErrInvalid
	}
	return cfField{tag: tag, kind: 3, value: raw[:]}, nil
}

func cfEnum(tag, value uint16) cfField {
	return cfField{tag: tag, kind: 5, value: binary.BigEndian.AppendUint16(nil, value)}
}

func cfU64(tag uint16, value uint64) cfField {
	return cfField{tag: tag, kind: 4, value: binary.BigEndian.AppendUint64(nil, value)}
}

func payloadRegistry(binding Context) (object, purpose, schemaVersion uint16, employeeOwned bool, err error) {
	if binding.SchemaVersion != 1 || !norm.NFC.IsNormalString(binding.SchemaType) {
		return 0, 0, 0, false, ErrInvalid
	}
	var uuid [16]byte
	for _, value := range []string{binding.OrgID, binding.RecordID, binding.VersionID} {
		if !decodeUUID(value, &uuid) {
			return 0, 0, 0, false, ErrInvalid
		}
	}
	if binding.EmployeeID != "" && !decodeUUID(binding.EmployeeID, &uuid) {
		return 0, 0, 0, false, ErrInvalid
	}
	expected := ""
	switch binding.ObjectKind {
	case "employee_profile":
		object, purpose, schemaVersion, employeeOwned, expected = 1, 1, 2, true, "pii.profile.v2"
	case "employee_identifier":
		object, purpose, schemaVersion, employeeOwned, expected = 2, 1, 1, true, "pii.employee_identifier.v1"
	case "education_record":
		object, purpose, schemaVersion, employeeOwned, expected = 2, 1, 1, true, "pii.education.v1"
	case "org_unit":
		object, purpose, schemaVersion, expected = 3, 1, 1, "pii.org_unit_label.v1"
	case "team_label":
		object, purpose, schemaVersion, expected = 3, 1, 1, "org.team.label.v1"
	case "legal_entity":
		object, purpose, schemaVersion, expected = 3, 1, 1, "pii.legal_entity_label.v1"
	case "job_assignment":
		object, purpose, schemaVersion, employeeOwned, expected = 4, 1, 1, true, "pii.job_assignment_position.v1"
	case "position_assignment":
		object, purpose, schemaVersion, employeeOwned, expected = 4, 1, 1, true, "org.position.v1"
	case "structure_change":
		object, purpose, schemaVersion, expected = 5, 1, 1, "org.structure.reason.v1"
	case "interview_note_shared", "interview_note_manager_private", "interview_note_hr_confidential":
		object, schemaVersion, employeeOwned, expected = 6, 1, true, "interview.note.v1"
		purpose = map[string]uint16{"interview_note_shared": 2, "interview_note_manager_private": 3, "interview_note_hr_confidential": 4}[binding.ObjectKind]
	case "interview_action":
		object, purpose, schemaVersion, employeeOwned, expected = 7, 2, 1, true, "interview.action.v1"
	case "compensation_proposal":
		object, purpose, schemaVersion, employeeOwned, expected = 8, 5, 1, true, "compensation.proposal.v1"
	case "compensation_terms":
		object, purpose, schemaVersion, employeeOwned, expected = 8, 5, 1, true, "compensation.terms.v1"
	case "salary_range":
		object, purpose, schemaVersion, expected = 9, 5, 1, "compensation.salary_range.v1"
	case "compensation_batch_line":
		object, purpose, schemaVersion, employeeOwned, expected = 10, 5, 1, true, "compensation.batch_line.v1"
	case "compensation_batch_import":
		object, purpose, schemaVersion, expected = 10, 5, 1, "compensation.batch_import.v1"
	case "compensation_decision":
		object, purpose, schemaVersion, employeeOwned, expected = 10, 5, 1, true, "compensation.decision.v1"
	case "bonus_target":
		object, purpose, schemaVersion, employeeOwned, expected = 11, 5, 1, true, "bonus.target.v1"
	case "bonus_award":
		object, purpose, schemaVersion, employeeOwned, expected = 11, 5, 1, true, "bonus.award.v1"
	case "bonus_decision":
		object, purpose, schemaVersion, employeeOwned, expected = 11, 5, 1, true, "bonus.decision.v1"
	case "bonus_payment":
		object, purpose, schemaVersion, employeeOwned, expected = 11, 5, 1, true, "bonus.payment.v1"
	case "compensation_extension":
		object, purpose, schemaVersion, employeeOwned, expected = 11, 5, 1, true, "compensation_memo/v1"
	case "assessment_result":
		object, purpose, schemaVersion, employeeOwned, expected = 12, 6, 1, true, "assessment.result.v1"
	case "interview_reason":
		object, purpose, schemaVersion, employeeOwned, expected = 15, 2, 1, true, "interview.reason.v1"
	case "backup_archive":
		object, purpose, schemaVersion, expected = 16, 8, 1, "backup.archive.v1"
	default:
		return 0, 0, 0, false, ErrInvalid
	}
	expectedPurpose := map[uint16]string{1: "pii", 2: "interview", 3: "interview", 4: "interview", 5: "financial", 6: "interview", 8: "backup"}[purpose]
	if binding.SchemaType != expected || binding.Purpose != expectedPurpose || (!employeeOwned && binding.EmployeeID != "") {
		return 0, 0, 0, false, ErrInvalid
	}
	return object, purpose, schemaVersion, employeeOwned, nil
}

func canonicalAAD(binding Context, dekID string) ([]byte, error) {
	object, purpose, schemaVersion, employeeOwned, err := payloadRegistry(binding)
	if err != nil {
		return nil, err
	}
	org, err := cfUUID(1, binding.OrgID)
	if err != nil {
		return nil, err
	}
	ownerID := binding.RecordID
	if employeeOwned {
		ownerID = binding.EmployeeID
	}
	ownerField, err := cfUUID(1, ownerID)
	if err != nil {
		return nil, err
	}
	owner, err := cf1(ownerField)
	if err != nil {
		return nil, err
	}
	record, err := cfUUID(4, binding.VersionID)
	if err != nil {
		return nil, err
	}
	dek, err := cfUUID(9, dekID)
	if err != nil {
		return nil, err
	}
	if !norm.NFC.IsNormalString(binding.SchemaType) {
		return nil, ErrInvalid
	}
	frame, err := cf1(
		org,
		cfEnum(2, object),
		cfField{tag: 3, kind: 1, value: owner},
		record,
		cfU64(5, 1),
		cfEnum(6, purpose),
		cfField{tag: 7, kind: 2, value: []byte(binding.SchemaType)},
		cfEnum(8, schemaVersion),
		dek,
	)
	if err != nil {
		return nil, err
	}
	return append([]byte("TEAMLEDGER-PAYLOAD\x00"), frame...), nil
}
