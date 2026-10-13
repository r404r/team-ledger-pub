package compensation

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
)

type SalaryRangeAmounts struct {
	Minimum  string `json:"minimum"`
	Midpoint string `json:"midpoint"`
	Maximum  string `json:"maximum"`
}
type SalaryRangeView struct {
	ID            string             `json:"id"`
	LegalEntityID string             `json:"legal_entity_id"`
	Location      string             `json:"location"`
	JobFamilyID   string             `json:"job_family_id"`
	CareerLevelID string             `json:"career_level_id"`
	Currency      string             `json:"currency"`
	ValidFrom     string             `json:"valid_from"`
	ValidTo       *string            `json:"valid_to"`
	Revision      string             `json:"revision"`
	Amounts       SalaryRangeAmounts `json:"amounts"`
}

type SalaryRangeChange struct {
	Action           string              `json:"action"`
	ID               string              `json:"id,omitempty"`
	ExpectedRevision string              `json:"expected_revision"`
	LegalEntityID    string              `json:"legal_entity_id,omitempty"`
	Location         string              `json:"location,omitempty"`
	JobFamilyID      string              `json:"job_family_id,omitempty"`
	CareerLevelID    string              `json:"career_level_id,omitempty"`
	Currency         string              `json:"currency,omitempty"`
	ValidFrom        string              `json:"valid_from,omitempty"`
	ValidTo          *string             `json:"valid_to,omitempty"`
	ReplacementID    string              `json:"-"`
	EffectiveTo      string              `json:"effective_to,omitempty"`
	Amounts          *SalaryRangeAmounts `json:"amounts,omitempty"`
}

type SalaryRangeChangeCommand struct {
	Changes []SalaryRangeChange `json:"changes"`
}

type SalaryRangeQuery struct {
	LegalEntityID, Location, JobFamilyID, CareerLevelID, Currency, AsOf string
}

type SalaryRangeRecord struct {
	OrgID, ID, LegalEntityID, Location, JobFamilyID, CareerLevelID, Currency, ValidFrom, PayloadID string
	ValidTo                                                                                        *string
	Revision                                                                                       int64
}

type SalaryRangePayload struct {
	OrgID, ID, RangeID string
	Envelope           sensitive.Envelope
	CreatedAt          time.Time
}
type SalaryRangeReceipt struct {
	SubjectID, Key, RequestID string
	Digest                    []byte
	RecordedAt                time.Time
}

type SalaryRangeStore interface {
	SalaryRanges(context.Context, string, SalaryRangeQuery) ([]SalaryRangeRecord, error)
	SalaryRangePayload(context.Context, string, string) (SalaryRangePayload, error)
	SalaryRangeReceipt(context.Context, string, string, string) (SalaryRangeReceipt, bool, error)
	ApplySalaryRangeChanges(context.Context, string, []SalaryRangeRecord, []SalaryRangePayload, []SalaryRangeChange, SalaryRangeReceipt) error
}

func ValidateSalaryRangeAmounts(v SalaryRangeAmounts) error {
	minimum, err := ParseMoney(v.Minimum)
	if err != nil {
		return err
	}
	midpoint, err := ParseMoney(v.Midpoint)
	if err != nil {
		return err
	}
	maximum, err := ParseMoney(v.Maximum)
	if err != nil || midpoint == 0 || minimum > midpoint || midpoint > maximum {
		return errors.New("salary range must satisfy 0 < midpoint and minimum <= midpoint <= maximum")
	}
	return nil
}

func rangeRevision(v string, allowZero bool) (int64, bool) {
	if allowZero && v == "0" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n > 0
}
