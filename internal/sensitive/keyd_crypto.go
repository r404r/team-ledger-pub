package sensitive

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

func domainNumber(domain KeyDomain) (uint16, bool) {
	switch domain {
	case DomainPIIPayload:
		return 1, true
	case DomainInterviewPayload:
		return 2, true
	case DomainAssessmentPayload:
		return 3, true
	case DomainFinancialPayload:
		return 4, true
	case DomainIdentityTransaction:
		return 5, true
	case DomainIdentityMapping:
		return 6, true
	case DomainBackupArchive:
		return 7, true
	case DomainStaffCodeLookup:
		return 8, true
	case DomainBonusPaymentLookup:
		return 9, true
	case DomainIdentitySubjectLookup:
		return 10, true
	case DomainCommandReceipt:
		return 11, true
	case DomainAssessmentGeneration:
		return 12, true
	case DomainCSRFToken:
		return 13, true
	case DomainCursorToken:
		return 14, true
	case DomainLocalUsernameLookup:
		return 15, true
	case DomainLocalPasswordPepper:
		return 16, true
	case DomainIdentityMFA:
		return 17, true
	case DomainLocalRecoveryCode:
		return 18, true
	default:
		return 0, false
	}
}

func domainFromNumber(number uint16) (KeyDomain, bool) {
	for _, domain := range allKeyDomains() {
		if n, _ := domainNumber(domain); n == number {
			return domain, true
		}
	}
	return "", false
}

func allKeyDomains() []KeyDomain {
	return []KeyDomain{
		DomainPIIPayload, DomainInterviewPayload, DomainAssessmentPayload, DomainFinancialPayload,
		DomainIdentityTransaction, DomainIdentityMapping, DomainBackupArchive, DomainStaffCodeLookup,
		DomainBonusPaymentLookup, DomainIdentitySubjectLookup, DomainCommandReceipt, DomainAssessmentGeneration,
		DomainCSRFToken, DomainCursorToken, DomainLocalUsernameLookup, DomainLocalPasswordPepper,
		DomainIdentityMFA, DomainLocalRecoveryCode,
	}
}

func legacyKeyDomains() []KeyDomain { return allKeyDomains()[:16] }

func wrapperDomain(domain KeyDomain) bool {
	switch domain {
	case DomainPIIPayload, DomainInterviewPayload, DomainAssessmentPayload, DomainFinancialPayload,
		DomainIdentityTransaction, DomainIdentityMapping, DomainBackupArchive, DomainIdentityMFA:
		return true
	default:
		return false
	}
}

func macDomain(domain KeyDomain) bool {
	_, ok := domainNumber(domain)
	return ok && !wrapperDomain(domain)
}

func hkdfKey(secret, salt, info []byte) [32]byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	var out [32]byte
	copy(out[:], expand.Sum(nil))
	return out
}

func uuidBytes(value string) ([16]byte, bool) {
	var out [16]byte
	return out, decodeUUID(value, &out)
}

func formatUUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
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
	return string(text[:])
}
func encodeTLW(domain KeyDomain, keyID string, version uint32, dekID string, aad, dek, material []byte) ([]byte, error) {
	digest := sha256.Sum256(aad)
	return encodeTLWDigest(domain, keyID, version, dekID, digest[:], dek, material)
}

func encodeTLWDigest(domain KeyDomain, keyID string, version uint32, dekID string, digest, dek, material []byte) ([]byte, error) {
	number, ok := domainNumber(domain)
	keyUUID, keyOK := uuidBytes(keyID)
	dekUUID, dekOK := uuidBytes(dekID)
	if !ok || number > 7 || !keyOK || !dekOK || version == 0 || len(digest) != 32 || len(dek) != 32 || len(material) != 32 {
		return nil, ErrInvalid
	}
	header := make([]byte, 0, 78)
	header = append(header, "TLW1"...)
	header = binary.BigEndian.AppendUint16(header, 1)
	header = binary.BigEndian.AppendUint16(header, number)
	header = append(header, keyUUID[:]...)
	header = binary.BigEndian.AppendUint32(header, version)
	header = append(header, dekUUID[:]...)
	header = append(header, digest...)
	info := append([]byte("TEAMLEDGER-WRAP\x00"), header...)
	derived := hkdfKey(material, dekUUID[:], info)
	clear(info)
	plaintext := make([]byte, 0, 64)
	plaintext = append(plaintext, dek...)
	plaintext = append(plaintext, digest...)
	wrapped, err := kwpWrap(derived[:], plaintext)
	clear(derived[:])
	clear(plaintext)
	if err != nil || len(wrapped) != 72 {
		clear(wrapped)
		return nil, ErrUnavailable
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(wrapped)))
	return append(header, wrapped...), nil
}

func decodeTLW(packet []byte, expectedDomain KeyDomain, expectedKeyID string, expectedVersion uint32, dekID string, aad, material []byte) ([]byte, error) {
	if len(packet) != 150 || string(packet[:4]) != "TLW1" || binary.BigEndian.Uint16(packet[4:6]) != 1 || binary.BigEndian.Uint16(packet[76:78]) != 72 || len(material) != 32 {
		return nil, ErrInvalid
	}
	domain, ok := domainFromNumber(binary.BigEndian.Uint16(packet[6:8]))
	keyUUID, keyOK := uuidBytes(expectedKeyID)
	dekUUID, dekOK := uuidBytes(dekID)
	if !ok || domain != expectedDomain || !keyOK || !dekOK || binary.BigEndian.Uint32(packet[24:28]) != expectedVersion || subtle.ConstantTimeCompare(packet[8:24], keyUUID[:]) != 1 || subtle.ConstantTimeCompare(packet[28:44], dekUUID[:]) != 1 {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(aad)
	if subtle.ConstantTimeCompare(packet[44:76], digest[:]) != 1 {
		return nil, ErrInvalid
	}
	info := append([]byte("TEAMLEDGER-WRAP\x00"), packet[:76]...)
	derived := hkdfKey(material, dekUUID[:], info)
	clear(info)
	plaintext, err := kwpUnwrap(derived[:], packet[78:])
	clear(derived[:])
	if err != nil || len(plaintext) != 64 || subtle.ConstantTimeCompare(plaintext[32:], digest[:]) != 1 {
		clear(plaintext)
		return nil, ErrInvalid
	}
	dek := make([]byte, 32)
	copy(dek, plaintext[:32])
	clear(plaintext)
	return dek, nil
}

func probeTLW(packet []byte, expectedDomain KeyDomain, expectedKeyID string, expectedVersion uint32, material []byte) ([]byte, error) {
	if len(packet) != 150 || string(packet[:4]) != "TLW1" || binary.BigEndian.Uint16(packet[4:6]) != 1 ||
		binary.BigEndian.Uint16(packet[76:78]) != 72 || len(material) != 32 {
		return nil, ErrInvalid
	}
	number, ok := domainNumber(expectedDomain)
	keyUUID, keyOK := uuidBytes(expectedKeyID)
	if !ok || !keyOK || binary.BigEndian.Uint16(packet[6:8]) != number ||
		binary.BigEndian.Uint32(packet[24:28]) != expectedVersion ||
		subtle.ConstantTimeCompare(packet[8:24], keyUUID[:]) != 1 {
		return nil, ErrInvalid
	}
	info := append([]byte("TEAMLEDGER-WRAP\x00"), packet[:76]...)
	derived := hkdfKey(material, packet[28:44], info)
	clear(info)
	plaintext, err := kwpUnwrap(derived[:], packet[78:])
	clear(derived[:])
	if err != nil || len(plaintext) != 64 || subtle.ConstantTimeCompare(plaintext[32:], packet[44:76]) != 1 {
		clear(plaintext)
		return nil, ErrInvalid
	}
	dek := make([]byte, 32)
	copy(dek, plaintext[:32])
	clear(plaintext)
	return dek, nil
}

func kwpWrap(key, plaintext []byte) ([]byte, error) {
	if (len(key) != 16 && len(key) != 24 && len(key) != 32) || len(plaintext) == 0 || len(plaintext) > 0xffffffff {
		return nil, errors.New("invalid KWP input")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := (len(plaintext) + 7) / 8
	padded := make([]byte, n*8)
	copy(padded, plaintext)
	a := [8]byte{0xa6, 0x59, 0x59, 0xa6}
	binary.BigEndian.PutUint32(a[4:], uint32(len(plaintext)))
	if n == 1 {
		out := make([]byte, 16)
		block.Encrypt(out, append(a[:], padded...))
		clear(padded)
		return out, nil
	}
	r := padded
	var input, output [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(input[:8], a[:])
			copy(input[8:], r[i*8:(i+1)*8])
			block.Encrypt(output[:], input[:])
			copy(a[:], output[:8])
			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t)
				t >>= 8
			}
			copy(r[i*8:(i+1)*8], output[8:])
		}
	}
	out := make([]byte, 8+len(r))
	copy(out, a[:])
	copy(out[8:], r)
	clear(r)
	clear(input[:])
	clear(output[:])
	return out, nil
}

func kwpUnwrap(key, wrapped []byte) ([]byte, error) {
	if (len(key) != 16 && len(key) != 24 && len(key) != 32) || len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, errors.New("invalid KWP input")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	var a [8]byte
	copy(a[:], wrapped[:8])
	r := append([]byte(nil), wrapped[8:]...)
	if n == 1 {
		var out [16]byte
		block.Decrypt(out[:], wrapped)
		copy(a[:], out[:8])
		copy(r, out[8:])
		clear(out[:])
	} else {
		var input, output [16]byte
		for j := 5; j >= 0; j-- {
			for i := n - 1; i >= 0; i-- {
				ax := a
				t := uint64(n*j + i + 1)
				for k := 0; k < 8; k++ {
					ax[7-k] ^= byte(t)
					t >>= 8
				}
				copy(input[:8], ax[:])
				copy(input[8:], r[i*8:(i+1)*8])
				block.Decrypt(output[:], input[:])
				copy(a[:], output[:8])
				copy(r[i*8:(i+1)*8], output[8:])
			}
		}
		clear(input[:])
		clear(output[:])
	}
	if a[0] != 0xa6 || a[1] != 0x59 || a[2] != 0x59 || a[3] != 0xa6 {
		clear(r)
		return nil, ErrInvalid
	}
	m := int(binary.BigEndian.Uint32(a[4:]))
	if m <= 8*(n-1) || m > 8*n {
		clear(r)
		return nil, ErrInvalid
	}
	var bad byte
	for _, b := range r[m:] {
		bad |= b
	}
	if bad != 0 {
		clear(r)
		return nil, ErrInvalid
	}
	out := make([]byte, m)
	copy(out, r[:m])
	clear(r)
	return out, nil
}
