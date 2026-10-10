package testsupport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/r404r/team-ledger/internal/sensitive"
)

// VaultFixture controls only external Transit I/O, never application encryption
// or authorization. It is deliberately absent from the production composition.
type VaultFixture struct {
	Server           *httptest.Server
	Token            string
	Fail             atomic.Bool
	Calls            atomic.Int64
	key              []byte
	aead             cipher.AEAD
	mu               sync.Mutex
	arrived          chan struct{}
	release          <-chan struct{}
	encryptRemaining int
	encryptArrived   chan<- struct{}
	encryptRelease   <-chan struct{}
}

func NewVaultFixture() (*VaultFixture, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		clear(key)
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		clear(key)
		return nil, err
	}
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		clear(key)
		return nil, err
	}
	f := &VaultFixture{key: key, aead: aead, Token: base64.RawURLEncoding.EncodeToString(token[:])}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f, nil
}

func (f *VaultFixture) Wrapper() (sensitive.Wrapper, error) {
	return sensitive.NewVaultWrapper(f.Server.URL, "dev002-pii", f.Token, f.Server.Client())
}
func (f *VaultFixture) Close() { f.Server.Close(); clear(f.key) }
func (f *VaultFixture) BlockNextDecrypt(arrived chan struct{}, release <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arrived = arrived
	f.release = release
}
func (f *VaultFixture) BlockEncrypt(count int, arrived chan<- struct{}, release <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.encryptRemaining, f.encryptArrived, f.encryptRelease = count, arrived, release
}
func (f *VaultFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.Calls.Add(1)
	if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != f.Token {
		w.WriteHeader(403)
		return
	}
	if f.Fail.Load() {
		w.WriteHeader(503)
		return
	}
	var body struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		w.WriteHeader(400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/transit/encrypt/dev002-pii":
		dek, err := base64.StdEncoding.Strict().DecodeString(body.Plaintext)
		if err != nil || len(dek) != 32 {
			clear(dek)
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		var arrived chan<- struct{}
		var release <-chan struct{}
		if f.encryptRemaining > 0 {
			f.encryptRemaining--
			arrived, release = f.encryptArrived, f.encryptRelease
		}
		f.mu.Unlock()
		if arrived != nil {
			select {
			case arrived <- struct{}{}:
			case <-r.Context().Done():
				clear(dek)
				return
			}
			select {
			case <-release:
			case <-r.Context().Done():
				clear(dek)
				return
			}
		}
		wrapped := f.aead.Seal(nil, nil, dek, []byte("dev002-pii:v1"))
		clear(dek)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(wrapped)}})
	case "/v1/transit/decrypt/dev002-pii":
		f.mu.Lock()
		arrived, release := f.arrived, f.release
		f.arrived = nil
		f.release = nil
		f.mu.Unlock()
		if arrived != nil {
			close(arrived)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if !strings.HasPrefix(body.Ciphertext, "vault:v1:") {
			w.WriteHeader(400)
			return
		}
		wrapped, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(body.Ciphertext, "vault:v1:"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		dek, err := f.aead.Open(nil, nil, wrapped, []byte("dev002-pii:v1"))
		if err != nil || len(dek) != 32 {
			clear(dek)
			w.WriteHeader(400)
			return
		}
		defer clear(dek)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}})
	default:
		w.WriteHeader(404)
	}
}
