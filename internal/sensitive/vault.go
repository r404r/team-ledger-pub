package sensitive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type vaultWrapper struct {
	encryptURL string
	decryptURL string
	key        string
	token      string
	client     *http.Client
}

func NewVaultWrapper(endpoint, key, token string, client *http.Client) (Wrapper, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" ||
		strings.ContainsAny(endpoint, "?#") || u.Opaque != "" || !validKeyName(key) ||
		len(token) == 0 || len(token) > 4096 {
		return nil, ErrInvalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, ErrInvalid
		}
	}
	for i := range len(token) {
		if token[i] < 33 || token[i] > 126 {
			return nil, ErrInvalid
		}
	}
	configured := http.Client{Timeout: 15 * time.Second}
	if client != nil {
		configured = *client
		if configured.Timeout <= 0 {
			configured.Timeout = 15 * time.Second
		}
	}
	configured.Jar = nil
	configured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	base := "https://" + u.Host + "/v1/transit/"
	return &vaultWrapper{
		encryptURL: base + "encrypt/" + key,
		decryptURL: base + "decrypt/" + key,
		key:        key, token: token, client: &configured,
	}, nil
}

func (v *vaultWrapper) Wrap(ctx context.Context, dek []byte) (WrappedKey, error) {
	if len(dek) != 32 {
		return WrappedKey{}, ErrInvalid
	}
	const prefix = `{"plaintext":"`
	body := make([]byte, len(prefix)+base64.StdEncoding.EncodedLen(len(dek))+2)
	copy(body, prefix)
	base64.StdEncoding.Encode(body[len(prefix):len(body)-2], dek)
	copy(body[len(body)-2:], `"}`)
	// The transport may retain the encoded request until asynchronous body
	// close. Do not clear its backing bytes while transport reads can run.
	value, err := v.transit(ctx, v.encryptURL, body, "ciphertext")
	if err != nil {
		return WrappedKey{}, err
	}
	version, ok := transitVersion(value)
	if !ok {
		return WrappedKey{}, ErrInvalid
	}
	return WrappedKey{KEKID: v.key, Version: version, Data: []byte(value)}, nil
}

func (v *vaultWrapper) Unwrap(ctx context.Context, key WrappedKey) ([]byte, error) {
	if !validWrappedKey(key) || key.KEKID != v.key {
		return nil, ErrInvalid
	}
	version, ok := transitVersion(string(key.Data))
	if !ok || version != key.Version {
		return nil, ErrInvalid
	}
	const prefix = `{"ciphertext":"`
	body := make([]byte, 0, len(prefix)+len(key.Data)+2)
	body = append(body, prefix...)
	body = append(body, key.Data...)
	body = append(body, '"', '}')
	value, err := v.transit(ctx, v.decryptURL, body, "plaintext")
	if err != nil {
		return nil, err
	}
	if len(value) != base64.StdEncoding.EncodedLen(32) {
		return nil, ErrInvalid
	}
	dek := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Strict().Decode(dek, []byte(value))
	if err != nil || n != 32 {
		clear(dek)
		return nil, ErrInvalid
	}
	return dek[:n], nil
}

func transitVersion(value string) (uint32, bool) {
	if len(value) > maxWrappedKey || !strings.HasPrefix(value, "vault:v") {
		return 0, false
	}
	end := strings.IndexByte(value[len("vault:v"):], ':')
	if end <= 0 {
		return 0, false
	}
	end += len("vault:v")
	number := value[len("vault:v"):end]
	version, err := strconv.ParseUint(number, 10, 32)
	if err != nil || version == 0 || number != strconv.FormatUint(version, 10) || end+1 == len(value) {
		return 0, false
	}
	for i := end + 1; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 || value[i] == '"' || value[i] == '\\' {
			return 0, false
		}
	}
	return uint32(version), true
}

func (v *vaultWrapper) transit(ctx context.Context, endpoint string, body []byte, field string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", v.token)
	response, err := v.client.Do(req)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return "", ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if field == "plaintext" && response.StatusCode == http.StatusBadRequest {
			return "", ErrInvalid
		}
		return "", ErrUnavailable
	}
	const maxReply = 64 * 1024
	if response.ContentLength > maxReply {
		return "", ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxReply+1))
	defer clear(raw)
	if err != nil {
		return "", ErrUnavailable
	}
	if len(raw) > maxReply {
		return "", ErrInvalid
	}
	root, err := transitObject(raw)
	if err != nil {
		return "", ErrInvalid
	}
	data, err := transitObject(root["data"])
	if err != nil {
		return "", ErrInvalid
	}
	var value string
	if err := json.Unmarshal(data[field], &value); err != nil || value == "" {
		return "", ErrInvalid
	}
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	return value, nil
}

// Vault replies may include normal lease/auth/request metadata. Ignore those
// fields, but reject duplicate object keys and trailing documents rather than
// trusting whichever security-critical field a permissive decoder keeps.
func transitObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrInvalid
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || len(fields) >= 128 {
			return nil, ErrInvalid
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrInvalid
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalid
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return fields, nil
}
