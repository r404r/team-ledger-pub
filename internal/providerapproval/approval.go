package providerapproval

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/value"
)

type Approval struct {
	Version   int       `json:"version"`
	PolicyID  string    `json:"policy_id"`
	Audience  string    `json:"audience"`
	Endpoint  string    `json:"endpoint"`
	ExpiresAt string    `json:"expires_at"`
	Expiry    time.Time `json:"-"`
}

func Load(path string, now time.Time) (Approval, error) {
	var approval Approval
	raw, err := configfile.Read(path, 4<<10, true)
	if err != nil {
		return approval, errors.New("invalid provider approval")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&approval); err != nil {
		return approval, errors.New("invalid provider approval")
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		return approval, errors.New("invalid provider approval")
	}
	expires, err := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	endpoint, endpointErr := url.Parse(approval.Endpoint)
	if approval.Version != 1 || !value.ValidID(approval.PolicyID) || approval.Audience != "employee_followup" && approval.Audience != "manager_followup" || err != nil || !now.Before(expires) || endpointErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return Approval{}, errors.New("invalid provider approval")
	}
	approval.Endpoint = strings.TrimSuffix(approval.Endpoint, "/")
	approval.Expiry = expires
	return approval, nil
}
