package sensitive_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

const syntheticVaultToken = "synthetic-test-token-not-a-credential"

func vaultClient(t *testing.T, s *httptest.Server) sensitive.Wrapper {
	t.Helper()
	w, err := sensitive.NewVaultWrapper(s.URL, "synthetic-pii-key", syntheticVaultToken, s.Client())
	if err != nil || w == nil {
		t.Fatal("valid configured TLS Vault constructor must succeed")
	}
	return w
}

func TestVaultTransitTLSWrapUnwrapAuthenticatesRealDEK(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != syntheticVaultToken || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("Transit request must POST JSON with only the Vault token authentication header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 {
			t.Error("Transit request must contain one declared field")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		aead, err := wrappingAEAD(1)
		if err != nil {
			t.Error("fixture wrapping crypto unavailable")
			return
		}
		switch r.URL.Path {
		case "/v1/transit/encrypt/synthetic-pii-key":
			dek, err := base64.StdEncoding.DecodeString(body["plaintext"])
			if err != nil || len(dek) != 32 {
				t.Error("Transit must receive exactly a base64 256-bit DEK")
				w.WriteHeader(400)
				return
			}
			wrapped := aead.Seal(nil, nil, dek, []byte("synthetic-pii-key"))
			clear(dek)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(wrapped)}})
		case "/v1/transit/decrypt/synthetic-pii-key":
			value := body["ciphertext"]
			if !strings.HasPrefix(value, "vault:v1:") {
				w.WriteHeader(400)
				return
			}
			wrapped, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "vault:v1:"))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			dek, err := aead.Open(nil, nil, wrapped, []byte("synthetic-pii-key"))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer clear(dek)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}})
		default:
			t.Error("adapter used an unexpected Transit path")
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	wrapper := vaultClient(t, s)
	dek := bytes.Repeat([]byte{0x63}, 32)
	defer clear(dek)
	key, err := wrapper.Wrap(context.Background(), dek)
	if err != nil || key.KEKID != "synthetic-pii-key" || key.Version != 1 || !bytes.HasPrefix(key.Data, []byte("vault:v1:")) {
		t.Fatal("Transit encrypt response must produce matching KEK/version metadata")
	}
	opened, err := wrapper.Unwrap(context.Background(), key)
	if err != nil || !bytes.Equal(opened, dek) {
		t.Fatal("Transit decrypt must recover the authenticated DEK")
	}
	clear(opened)
	key.Data[len(key.Data)-2] ^= 1
	opened, err = wrapper.Unwrap(context.Background(), key)
	if err == nil || len(opened) != 0 {
		t.Fatal("tampered Transit ciphertext must fail without releasing a DEK")
	}
}

func TestVaultConstructorRejectsUnsafeConfiguration(t *testing.T) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	for _, endpoint := range []string{"http://example.invalid", "https://user:secret@example.invalid", s.URL + "/other", s.URL + "?query=1", s.URL + "?", s.URL + "#fragment", s.URL + "#", "https://", "://bad"} {
		w, err := sensitive.NewVaultWrapper(endpoint, "synthetic-pii-key", syntheticVaultToken, s.Client())
		if !errors.Is(err, sensitive.ErrInvalid) || w != nil {
			t.Error("unsafe endpoint must reject with ErrInvalid and no wrapper")
		}
	}
	for _, key := range []string{"", "../other", "key/name", "key?query", "key%2fname", strings.Repeat("a", 129)} {
		w, err := sensitive.NewVaultWrapper(s.URL, key, syntheticVaultToken, s.Client())
		if !errors.Is(err, sensitive.ErrInvalid) || w != nil {
			t.Error("uncontrolled Transit key name must reject")
		}
	}
	for _, token := range []string{"", "bad\r\nheader"} {
		w, err := sensitive.NewVaultWrapper(s.URL, "synthetic-pii-key", token, s.Client())
		if !errors.Is(err, sensitive.ErrInvalid) || w != nil {
			t.Error("missing or unsafe token must reject")
		}
	}
}

func TestVaultRejectsBadMetadataBeforeExternalIO(t *testing.T) {
	requests := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(500) }))
	defer s.Close()
	wrapper := vaultClient(t, s)
	for _, key := range []sensitive.WrappedKey{
		{KEKID: "other-key", Version: 1, Data: []byte("vault:v1:synthetic")},
		{KEKID: "synthetic-pii-key", Version: 0, Data: []byte("vault:v0:synthetic")},
		{KEKID: "synthetic-pii-key", Version: 2, Data: []byte("vault:v1:synthetic")},
		{KEKID: "synthetic-pii-key", Version: 1, Data: []byte("vault:v01:synthetic")},
		{KEKID: "synthetic-pii-key", Version: 1, Data: []byte("vault:v1:")},
		{KEKID: "synthetic-pii-key", Version: 1, Data: nil},
	} {
		dek, err := wrapper.Unwrap(context.Background(), key)
		if !errors.Is(err, sensitive.ErrInvalid) || len(dek) != 0 {
			t.Error("invalid wrapped metadata must reject without key material")
		}
	}
	for _, size := range []int{0, 16, 24, 31, 33} {
		key, err := wrapper.Wrap(context.Background(), make([]byte, size))
		if !errors.Is(err, sensitive.ErrInvalid) || len(key.Data) != 0 {
			t.Error("non-256-bit wrapping input must reject")
		}
	}
	if requests != 0 {
		t.Error("invalid key material reached external Transit I/O")
	}
}

func TestVaultRejectsMalformedProtocolAndDoesNotExposeServerDetails(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"denied", `{"errors":["SYNTHETIC-SERVER-DETAIL"]}`, 403},
		{"server_error", `SYNTHETIC-SERVER-DETAIL`, 500},
		{"invalid_json", `{"data":`, 200},
		{"missing_data", `{}`, 200},
		{"wrong_data_type", `{"data":[]}`, 200},
		{"zero_version", `{"data":{"ciphertext":"vault:v0:synthetic"}}`, 200},
		{"bad_version", `{"data":{"ciphertext":"vault:vX:synthetic"}}`, 200},
		{"overflow_version", `{"data":{"ciphertext":"vault:v4294967296:synthetic"}}`, 200},
		{"noncanonical_version", `{"data":{"ciphertext":"vault:v01:synthetic"}}`, 200},
		{"duplicate_data", `{"data":{"ciphertext":"vault:v1:synthetic"},"data":{"ciphertext":"vault:v2:synthetic"}}`, 200},
		{"duplicate_ciphertext", `{"data":{"ciphertext":"vault:v1:synthetic","ciphertext":"vault:v2:synthetic"}}`, 200},
		{"empty_ciphertext", `{"data":{"ciphertext":"vault:v1:"}}`, 200},
		{"ciphertext_control", `{"data":{"ciphertext":"vault:v1:synthetic\n"}}`, 200},
		{"trailing_json", `{"data":{"ciphertext":"vault:v1:synthetic"}} {}`, 200},
		{"oversized", strings.Repeat("x", 128*1024), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer s.Close()
			key, err := vaultClient(t, s).Wrap(context.Background(), bytes.Repeat([]byte{0x63}, 32))
			if err == nil || len(key.Data) != 0 {
				t.Fatal("invalid Transit encrypt reply must fail without a wrapped result")
			}
			if strings.Contains(err.Error(), "SYNTHETIC-SERVER-DETAIL") || strings.Contains(err.Error(), syntheticVaultToken) {
				t.Error("adapter error exposes external detail or token")
			}
		})
	}
	for _, plaintext := range []string{"!not-base64!", "", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33))} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": plaintext}})
		}))
		wrapper := vaultClient(t, s)
		dek, err := wrapper.Unwrap(context.Background(), sensitive.WrappedKey{KEKID: "synthetic-pii-key", Version: 1, Data: []byte("vault:v1:synthetic")})
		s.Close()
		if err == nil || len(dek) != 0 {
			t.Error("malformed decoded Transit DEK must fail closed")
		}
	}
}

func TestVaultNeverFollowsRedirects(t *testing.T) {
	forwarded := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++; w.WriteHeader(500) }))
	defer destination.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, status) }))
		client := s.Client()
		// Both fixture servers use the fixture CA; a redirect would actually
		// reach the destination unless the adapter prohibits it.
		wrapper, err := sensitive.NewVaultWrapper(s.URL, "synthetic-pii-key", syntheticVaultToken, client)
		if err != nil {
			s.Close()
			t.Fatal("valid TLS constructor must succeed before redirect behavior")
		}
		key, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{0x63}, 32))
		s.Close()
		if err == nil || len(key.Data) != 0 {
			t.Error("Transit redirect must fail closed")
		}
	}
	if forwarded != 0 {
		t.Error("redirect exposed a Transit request to another endpoint")
	}
}

func TestVaultTransportFailureAndCancellationFailClosed(t *testing.T) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	wrapper := vaultClient(t, s)
	s.Close()
	key, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{0x63}, 32))
	if !errors.Is(err, sensitive.ErrUnavailable) || len(key.Data) != 0 {
		t.Error("TLS transport failure must return only ErrUnavailable and no key result")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dek, err := wrapper.Unwrap(ctx, sensitive.WrappedKey{KEKID: "synthetic-pii-key", Version: 1, Data: []byte("vault:v1:synthetic")})
	if !errors.Is(err, sensitive.ErrUnavailable) || len(dek) != 0 {
		t.Error("canceled key I/O must fail closed")
	}
}

func TestVaultRejectsUntrustedTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	wrapper, err := sensitive.NewVaultWrapper(s.URL, "synthetic-pii-key", syntheticVaultToken, &http.Client{})
	if err != nil {
		t.Fatal("constructor must accept a normal client before TLS trust is exercised")
	}
	key, err := wrapper.Wrap(context.Background(), bytes.Repeat([]byte{0x63}, 32))
	if !errors.Is(err, sensitive.ErrUnavailable) || len(key.Data) != 0 {
		t.Error("untrusted TLS peer must fail without returning key material")
	}
}
