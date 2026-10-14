package compensation

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
)

const (
	BatchNormal  = "normal"
	BatchSpecial = "special"
)

var (
	batchCodePattern = regexp.MustCompile(`^(N|S)-([0-9]{4})-([0-9]{4,})$`)
	moneyPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	percentPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?%?$`)
)

type BatchLineBasis struct {
	IdentifierID        string `json:"identifier_id"`
	IdentifierRevision  string `json:"identifier_revision"`
	EmploymentID        string `json:"employment_id"`
	EmploymentRevision  string `json:"employment_revision"`
	AssignmentID        string `json:"assignment_id"`
	AssignmentRevision  string `json:"assignment_revision"`
	SalaryRangeID       string `json:"salary_range_id"`
	SalaryRangeRevision string `json:"salary_range_revision"`
	TermID              string `json:"term_id,omitempty"`
	TermRevision        string `json:"term_revision,omitempty"`
}

type BatchWorkforceBasis struct {
	IdentifierID, EmploymentID, AssignmentID, LegalEntityID, Location, JobFamilyID, CareerLevelID string
	IdentifierRevision, EmploymentRevision, AssignmentRevision                                    int64
}

type BatchLineCommand struct {
	EmployeeID                  string         `json:"employee_id"`
	StaffCode                   string         `json:"staff_code"`
	Currency                    string         `json:"currency"`
	SalaryBefore                string         `json:"salary_before"`
	IncreaseAmount              string         `json:"increase_amount"`
	SalaryAfter                 string         `json:"salary_after"`
	PerformanceGrade            string         `json:"performance_grade,omitempty"`
	AverageMeritIncrease        string         `json:"average_merit_increase,omitempty"`
	DepartmentSuggestedIncrease string         `json:"department_suggested_increase,omitempty"`
	EffectiveDate               string         `json:"effective_date,omitempty"`
	EffectiveMonth              string         `json:"effective_month,omitempty"`
	ReasonCode                  string         `json:"reason_code,omitempty"`
	ReasonText                  string         `json:"reason_text,omitempty"`
	Basis                       BatchLineBasis `json:"basis"`
}

type AdjustmentCounts struct {
	CurrentYear   int    `json:"current_year"`
	PreviousYear  int    `json:"previous_year"`
	CountAsOfDate string `json:"count_as_of_date"`
}

type BatchLineView struct {
	BatchLineCommand
	Result                    string             `json:"result"`
	OriginalAdjustmentEventID string             `json:"original_adjustment_event_id,omitempty"`
	CorrectionMembers         []CorrectionMember `json:"correction_members,omitempty"`
	AdjustmentCounts          AdjustmentCounts   `json:"adjustment_counts"`
}

type CurrencyTotal struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

type BatchView struct {
	ID                       string          `json:"id"`
	BusinessCode             string          `json:"business_code"`
	CycleYear                int             `json:"cycle_year"`
	AdjustmentType           string          `json:"adjustment_type"`
	LegalEntityID            string          `json:"legal_entity_id"`
	DefaultEffectiveDate     string          `json:"default_effective_date,omitempty"`
	State                    string          `json:"state"`
	Revision                 string          `json:"revision"`
	ManifestDigest           string          `json:"manifest_digest,omitempty"`
	Lines                    []BatchLineView `json:"lines"`
	IncreaseTotalsByCurrency []CurrencyTotal `json:"increase_totals_by_currency"`
}

type CreateBatchCommand struct {
	CycleYear            int               `json:"cycle_year"`
	AdjustmentType       string            `json:"adjustment_type"`
	LegalEntityID        string            `json:"legal_entity_id"`
	DefaultEffectiveDate string            `json:"default_effective_date,omitempty"`
	SpecialReasons       map[string]string `json:"-"`
}

type ReplaceBatchLinesCommand struct {
	Revision    string             `json:"revision"`
	CandidateID string             `json:"candidate_id,omitempty"`
	Lines       []BatchLineCommand `json:"lines,omitempty"`
}

type BatchRecord struct {
	OrgID, ID, BusinessCode, AdjustmentType, LegalEntityID, DefaultEffectiveDate, State, ManifestDigest, CreatorSubjectID, ActivationSubjectID string
	CycleYear, Revision                                                                                                                        int64
	CreatedAt, ActivatedAt                                                                                                                     time.Time
}

type BatchPayloadRecord struct {
	OrgID, ID, BatchID, EmployeeID string
	BatchRevision                  int64
	Envelope                       sensitive.Envelope
	CreatedAt                      time.Time
}

type BatchLineRecord struct {
	OrgID, BatchID, ID, EmployeeID, PayloadID, Result string
	BatchRevision, Ordinal                            int64
}
type BatchCommandReceipt struct {
	SubjectID, Operation, Key, BatchID, RequestID string
	Digest                                        []byte
	ResultRevision                                int64
	RecordedAt                                    time.Time
}
type ImportCandidateView struct {
	ID           string             `json:"id"`
	BatchID      string             `json:"batch_id"`
	BaseRevision string             `json:"base_revision"`
	State        string             `json:"state"`
	LineCount    int                `json:"line_count"`
	Lines        []BatchLineCommand `json:"lines"`
	Errors       []string           `json:"errors"`
	ExpiresAt    string             `json:"expires_at"`
}

type ImportCandidateRecord struct {
	OrgID, ID, BatchID, SubjectID, State string
	BaseRevision, LineCount              int64
	Digest                               []byte
	Envelope                             sensitive.Envelope
	CreatedAt, ExpiresAt                 time.Time
}

type BatchCorrectionLine struct {
	EmployeeID string             `json:"employee_id"`
	Members    []CorrectionMember `json:"members"`
}

type BatchCorrectionCommand struct {
	Reason string                `json:"reason"`
	Lines  []BatchCorrectionLine `json:"lines"`
}

type BatchCorrectionView struct {
	ID              string `json:"id"`
	BusinessCode    string `json:"business_code"`
	CorrectsBatchID string `json:"corrects_batch_id"`
	State           string `json:"state"`
	ManifestDigest  string `json:"manifest_digest"`
	ActivatedAt     string `json:"activated_at"`
}

type BatchCorrectionRecord struct {
	OrgID, ID, BusinessCode, CorrectsBatchID, AdjustmentType, ManifestDigest, SubjectID string
	CycleYear                                                                           int64
	ActivatedAt                                                                         time.Time
}

type BatchCorrectionReader interface {
	AdjustmentBatchCorrection(context.Context, string, string) (BatchCorrectionRecord, error)
}

type BatchStore interface {
	CreateAdjustmentBatch(context.Context, string, string, string, string, CreateBatchCommand, BatchCommandReceipt, time.Time) (BatchRecord, error)
	AdjustmentBatchReceipt(context.Context, string, string, string, string) (BatchCommandReceipt, bool, error)
	AdjustmentBatch(context.Context, string, string) (BatchRecord, error)
	AdjustmentBatches(context.Context, string, int, string, int) ([]BatchRecord, error)
	AdjustmentBatchLines(context.Context, string, string, int64) ([]BatchLineRecord, error)
	AdjustmentBatchPayload(context.Context, string, string) (BatchPayloadRecord, error)
	AdjustmentWorkforceBasis(context.Context, string, string, string, uint32, []byte, string) (BatchWorkforceBasis, error)
	AdjustmentBatchCounts(context.Context, string, string, int) (AdjustmentCounts, error)
	AdjustmentBatchOriginalEvent(context.Context, string, string, string) (string, error)
	CreateAdjustmentImportCandidate(context.Context, ImportCandidateRecord, BatchCommandReceipt) (ImportCandidateRecord, error)
	AdjustmentImportCandidate(context.Context, string, string) (ImportCandidateRecord, error)
	ReplaceAdjustmentBatchLines(context.Context, BatchRecord, []BatchPayloadRecord, []BatchLineRecord, string, BatchCommandReceipt) (BatchRecord, error)
	MarkAdjustmentBatchActivationFailure(context.Context, BatchRecord, string, string, string, time.Time) error
	TransitionAdjustmentBatch(context.Context, BatchRecord, string, string, string, BatchCommandReceipt, time.Time) (BatchRecord, error)
}

type BatchTransitionCommand struct {
	Action         string `json:"action"`
	Revision       string `json:"revision"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func ValidateCreateBatch(c CreateBatchCommand) error {
	if c.CycleYear < 2000 || c.CycleYear > 9999 || c.LegalEntityID == "" {
		return errors.New("invalid batch header")
	}
	if c.AdjustmentType != BatchNormal && c.AdjustmentType != BatchSpecial {
		return errors.New("invalid adjustment type")
	}
	if c.AdjustmentType == BatchNormal {
		if _, err := time.Parse("2006-01-02", c.DefaultEffectiveDate); err != nil {
			return errors.New("normal default effective date is required")
		}
	} else if c.DefaultEffectiveDate != "" {
		return errors.New("special batch cannot have a default effective date")
	}
	return nil
}

func ValidateBusinessCode(code, typ string, year int) error {
	m := batchCodePattern.FindStringSubmatch(code)
	if m == nil || m[2] != strconv.Itoa(year) || (typ == BatchNormal && m[1] != "N") || (typ == BatchSpecial && m[1] != "S") {
		return errors.New("invalid batch business code")
	}
	return nil
}

func ParseMoney(v string) (int64, error) {
	if !moneyPattern.MatchString(v) {
		return 0, errors.New("money must be a canonical non-negative scale-0 integer")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, errors.New("money exceeds int64")
	}
	return n, nil
}

func ValidateBatchLines(typ string, cycleYear int, defaultDate string, lines []BatchLineCommand, activeReasons map[string]bool) ([]BatchLineView, []CurrencyTotal, error) {
	if len(lines) == 0 || len(lines) > 500 {
		return nil, nil, errors.New("batch must contain 1..500 lines")
	}
	seen := make(map[string]struct{}, len(lines))
	totals := map[string]int64{"CNY": 0, "JPY": 0}
	out := make([]BatchLineView, 0, len(lines))
	for i, line := range lines {
		if line.EmployeeID == "" || line.StaffCode == "" {
			return nil, nil, fmt.Errorf("line %d: employee and staff code are required", i+1)
		}
		if _, ok := seen[line.EmployeeID]; ok {
			return nil, nil, fmt.Errorf("line %d: duplicate employee", i+1)
		}
		seen[line.EmployeeID] = struct{}{}
		if line.Currency != "CNY" && line.Currency != "JPY" {
			return nil, nil, fmt.Errorf("line %d: unsupported currency", i+1)
		}
		before, err := ParseMoney(line.SalaryBefore)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		increase, err := ParseMoney(line.IncreaseAmount)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		after, err := ParseMoney(line.SalaryAfter)
		if err != nil || before > math.MaxInt64-increase || before+increase != after {
			return nil, nil, fmt.Errorf("line %d: salary after must equal salary before plus increase", i+1)
		}
		if totals[line.Currency] > math.MaxInt64-increase {
			return nil, nil, errors.New("BATCH_TOTAL_OVERFLOW")
		}
		totals[line.Currency] += increase
		if typ == BatchNormal {
			if !safeText(line.PerformanceGrade, 100, true) || line.EffectiveMonth != "" || line.ReasonCode != "" || line.ReasonText != "" {
				return nil, nil, fmt.Errorf("line %d: invalid normal fields", i+1)
			}
			if line.EffectiveDate == "" {
				line.EffectiveDate = defaultDate
			}
			if _, err := time.Parse("2006-01-02", line.EffectiveDate); err != nil {
				return nil, nil, fmt.Errorf("line %d: invalid effective date", i+1)
			}
			for _, reference := range []string{line.AverageMeritIncrease, line.DepartmentSuggestedIncrease} {
				if reference != "" && !percentPattern.MatchString(reference) {
					return nil, nil, fmt.Errorf("line %d: invalid reference percentage", i+1)
				}
			}
		} else if typ == BatchSpecial {
			if line.PerformanceGrade != "" || line.AverageMeritIncrease != "" || line.DepartmentSuggestedIncrease != "" || line.EffectiveDate != "" {
				return nil, nil, fmt.Errorf("line %d: invalid special fields", i+1)
			}
			if _, err := time.Parse("2006-01", line.EffectiveMonth); err != nil || !activeReasons[line.ReasonCode] || !safeText(line.ReasonText, 1000, true) {
				return nil, nil, fmt.Errorf("line %d: special month, active reason and reason text are required", i+1)
			}
		} else {
			return nil, nil, errors.New("invalid adjustment type")
		}
		result := "changed"
		if increase == 0 {
			result = "no_change"
		}
		out = append(out, BatchLineView{BatchLineCommand: line, Result: result})
	}
	summary := make([]CurrencyTotal, 0, 2)
	for _, currency := range []string{"CNY", "JPY"} {
		if totals[currency] != 0 || hasCurrency(lines, currency) {
			summary = append(summary, CurrencyTotal{Currency: currency, Amount: strconv.FormatInt(totals[currency], 10)})
		}
	}
	return out, summary, nil
}

func hasCurrency(lines []BatchLineCommand, currency string) bool {
	for _, line := range lines {
		if line.Currency == currency {
			return true
		}
	}
	return false
}
