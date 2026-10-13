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
	aad, err := canonicalAAD(binding)
	if err != nil {
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
	aead, err := newPayloadAEAD(dek[:])
	if err != nil {
		return Envelope{}, ErrUnavailable
	}
	key, err := c.Wrapper.Wrap(ctx, dek[:])
	if err != nil {
		return Envelope{}, keyError(err)
	}
	if !validWrappedKey(key) {
		return Envelope{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Envelope{}, ErrUnavailable
	}
	return Envelope{
		Context: binding, FormatVersion: 1, Algorithm: payloadAlgorithm,
		DEKID: dekID, Key: key, SealedBytes: aead.Seal(nil, nil, plaintext, aad),
	}, nil
}

func (c Cipher) Open(ctx context.Context, binding Context, envelope Envelope) ([]byte, error) {
	if envelope.Context != binding || envelope.FormatVersion != 1 ||
		envelope.Algorithm != payloadAlgorithm || !validWrappedKey(envelope.Key) ||
		len(envelope.SealedBytes) < 28 || len(envelope.SealedBytes) > maxPlaintext+28 {
		return nil, ErrInvalid
	}
	var id [16]byte
	if !decodeUUID(envelope.DEKID, &id) {
		return nil, ErrInvalid
	}
	aad, err := canonicalAAD(binding)
	if err != nil {
		return nil, ErrInvalid
	}
	if c.Wrapper == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	dek, err := c.Wrapper.Unwrap(ctx, envelope.Key)
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
	plaintext, err := aead.Open(nil, nil, envelope.SealedBytes, aad)
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

func canonicalAAD(binding Context) ([]byte, error) {
	if binding.SchemaVersion != 1 {
		return nil, ErrInvalid
	}
	employeeOwned := false
	purpose := "pii"
	switch binding.ObjectKind {
	case "employee_profile":
		if binding.SchemaType != "pii.profile.v2" {
			return nil, ErrInvalid
		}
		employeeOwned = true
	case "legal_entity":
		if binding.SchemaType != "pii.legal_entity_label.v1" {
			return nil, ErrInvalid
		}
	case "org_unit":
		if binding.SchemaType != "pii.org_unit_label.v1" {
			return nil, ErrInvalid
		}
	case "employee_identifier":
		if binding.SchemaType != "pii.employee_identifier.v1" {
			return nil, ErrInvalid
		}
		employeeOwned = true
	case "education_record":
		if binding.SchemaType != "pii.education.v1" {
			return nil, ErrInvalid
		}
		employeeOwned = true
	case "job_assignment":
		if binding.SchemaType != "pii.job_assignment_position.v1" {
			return nil, ErrInvalid
		}
		employeeOwned = true
	case "team_label":
		if binding.SchemaType != "org.team.label.v1" {
			return nil, ErrInvalid
		}
	case "position_assignment":
		if binding.SchemaType != "org.position.v1" {
			return nil, ErrInvalid
		}
		employeeOwned = true
	case "structure_change":
		if binding.SchemaType != "org.structure.reason.v1" {
			return nil, ErrInvalid
		}
	case "interview_note_shared", "interview_note_manager_private", "interview_note_hr_confidential":
		if binding.SchemaType != "interview.note.v1" {
			return nil, ErrInvalid
		}
		purpose = "interview"
		employeeOwned = true
	case "interview_action":
		if binding.SchemaType != "interview.action.v1" {
			return nil, ErrInvalid
		}
		purpose = "interview"
		employeeOwned = true
	case "interview_reason":
		if binding.SchemaType != "interview.reason.v1" {
			return nil, ErrInvalid
		}
		purpose = "interview"
		employeeOwned = true
	case "assessment_result":
		if binding.SchemaType != "assessment.result.v1" {
			return nil, ErrInvalid
		}
		purpose = "interview"
		employeeOwned = true
	case "compensation_proposal":
		if binding.SchemaType != "compensation.proposal.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "compensation_terms":
		if binding.SchemaType != "compensation.terms.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "compensation_decision":
		if binding.SchemaType != "compensation.decision.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "bonus_target":
		if binding.SchemaType != "bonus.target.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "bonus_award":
		if binding.SchemaType != "bonus.award.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "bonus_decision":
		if binding.SchemaType != "bonus.decision.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "bonus_payment":
		if binding.SchemaType != "bonus.payment.v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	case "compensation_extension":
		if binding.SchemaType != "compensation_memo/v1" {
			return nil, ErrInvalid
		}
		purpose = "financial"
		employeeOwned = true
	default:
		return nil, ErrInvalid
	}
	if binding.Purpose != purpose {
		return nil, ErrInvalid
	}
	if !employeeOwned && binding.EmployeeID != "" {
		return nil, ErrInvalid
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
	size := len("TEAMLEDGER-AAD") + 2 + 4*20 + 3*4 +
		len(binding.ObjectKind) + len(binding.Purpose) + len(binding.SchemaType) + 8
	if !employeeOwned {
		size -= 16
	}
	aad := make([]byte, 0, size)
	aad = append(aad, "TEAMLEDGER-AAD"...)
	aad = binary.BigEndian.AppendUint16(aad, 1)
	for i := range ids {
		if i == 1 && !employeeOwned {
			aad = binary.BigEndian.AppendUint32(aad, 0)
			continue
		}
		aad = binary.BigEndian.AppendUint32(aad, 16)
		aad = append(aad, ids[i][:]...)
	}
	for _, field := range [3]string{binding.ObjectKind, binding.Purpose, binding.SchemaType} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(field)))
		aad = append(aad, field...)
	}
	aad = binary.BigEndian.AppendUint32(aad, 4)
	aad = binary.BigEndian.AppendUint32(aad, binding.SchemaVersion)
	return aad, nil
}
