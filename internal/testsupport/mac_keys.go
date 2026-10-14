package testsupport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/r404r/team-ledger/internal/sensitive"
)

// MACKeys is a deterministic in-process key service used only by tests.
type MACKeys struct {
	Key        []byte
	DomainKeys map[sensitive.KeyDomain][]byte
}

func (k MACKeys) MAC(_ context.Context, domain sensitive.KeyDomain, message []byte) (sensitive.MACValue, error) {
	key, keyID := k.Key, "00000000-0000-7000-8000-000000000001"
	if domainKey := k.DomainKeys[domain]; len(domainKey) != 0 {
		key, keyID = domainKey, "legacy-process-key"
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return sensitive.MACValue{KeyID: keyID, Version: 1, Digest: mac.Sum(nil)}, nil
}

func (k MACKeys) Verify(_ context.Context, domain sensitive.KeyDomain, reference sensitive.KeyReference, message, expected []byte) (bool, error) {
	if reference.Version != 1 {
		return false, nil
	}
	value, _ := k.MAC(context.Background(), domain, message)
	if reference.KeyID != value.KeyID {
		return false, nil
	}
	return hmac.Equal(value.Digest, expected), nil
}
