package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/configfile"
)

// Approval is explicit: absence of a policy never enables financial operations.
func compensationPolicy() (compensation.Policy, error) {
	var policy compensation.Policy
	path := os.Getenv("TEAMLEDGER_COMPENSATION_POLICY_FILE")
	if path == "" {
		return policy, nil
	}
	data, err := configfile.Read(path, 64<<10, false)
	if err != nil || !utf8.Valid(data) {
		return policy, errors.New("invalid compensation policy")
	}
	if err := uniquePolicyJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return policy, errors.New("invalid compensation policy")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return compensation.Policy{}, errors.New("invalid compensation policy")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return compensation.Policy{}, errors.New("invalid compensation policy")
	}
	// Null and omitted fields are not substitutes for approved policy values.
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return compensation.Policy{}, errors.New("invalid compensation policy")
	}
	for name, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return compensation.Policy{}, errors.New("invalid compensation policy")
		}
		if name == "currencies" {
			var scales map[string]json.RawMessage
			if json.Unmarshal(raw, &scales) != nil {
				return compensation.Policy{}, errors.New("invalid compensation policy")
			}
			for _, scale := range scales {
				if bytes.Equal(bytes.TrimSpace(scale), []byte("null")) {
					return compensation.Policy{}, errors.New("invalid compensation policy")
				}
			}
		}
	}
	if _, ok := fields["enabled"]; !ok {
		return compensation.Policy{}, errors.New("invalid compensation policy")
	}
	if policy.Enabled {
		for _, name := range []string{"currencies", "units", "payment_frequencies", "tax_bases", "rounding_modes"} {
			if _, ok := fields[name]; !ok {
				return compensation.Policy{}, errors.New("invalid compensation policy")
			}
		}
	}
	if err := policy.Validate(); err != nil {
		return compensation.Policy{}, errors.New("invalid compensation policy")
	}
	return policy, nil
}

// Token traversal catches duplicate keys before encoding/json can discard them.
func uniquePolicyJSON(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("invalid policy nesting")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate policy key")
			}
			seen[name] = true
			if err := uniquePolicyJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniquePolicyJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid policy JSON")
	}
	_, err = decoder.Token()
	return err
}
