package compensation

import (
	"errors"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
)

func TestBonusProjectionReplacementPaymentAndReversal(t *testing.T) {
	awards := []BonusAwardFact{
		{ID: "a1", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "100", ApprovedAt: "2026-01-10T00:00:00Z"},
		{ID: "a2", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "120", CorrectsAwardID: stringPointer("a1"), ApprovedAt: "2026-02-10T00:00:00Z"},
	}
	payments := []BonusPaymentFact{
		{ID: "p1", EmployeeID: "employee", Kind: "payment", Currency: "USD", Scale: 2, AmountMinor: "40", PaidDate: "2026-01-20", AwardID: stringPointer("a1")},
		{ID: "p2", EmployeeID: "employee", Kind: "payment", Currency: "USD", Scale: 2, AmountMinor: "60", PaidDate: "2026-02-20", AwardID: stringPointer("a2")},
		{ID: "r1", EmployeeID: "employee", Kind: "reversal", Currency: "USD", Scale: 2, AmountMinor: "20", PaidDate: "2026-02-21", OriginalPaymentID: stringPointer("p2")},
	}
	projection, anomalies, err := BuildBonusProjection(awards, payments)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection) != 1 || projection[0].EffectiveAwardID != "a2" || projection[0].ApprovedMinor != "120" || projection[0].PaidMinor != "80" || projection[0].BalanceMinor != "40" || projection[0].PaymentState != "partially_paid" {
		t.Fatalf("replacement projection lost history: %#v", projection)
	}
	if len(anomalies) != 0 {
		t.Fatalf("valid replacement chain produced anomalies: %#v", anomalies)
	}
}

func TestBonusProjectionPreservesAnomaliesAndExactMoney(t *testing.T) {
	awards := []BonusAwardFact{{ID: "a1", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "9007199254740993", ApprovedAt: "2026-02-10T00:00:00Z"}}
	payments := []BonusPaymentFact{
		{ID: "early", EmployeeID: "employee", Kind: "payment", Currency: "USD", Scale: 2, AmountMinor: "9007199254740994", PaidDate: "2026-02-09", AwardID: stringPointer("a1")},
		{ID: "eur", EmployeeID: "employee", Kind: "payment", Currency: "EUR", Scale: 2, AmountMinor: "40", PaidDate: "2026-02-11", AwardID: stringPointer("a1")},
		{ID: "loose", EmployeeID: "employee", Kind: "payment", Currency: "USD", Scale: 2, AmountMinor: "30", PaidDate: "2026-02-11"},
	}
	projection, anomalies, err := BuildBonusProjection(awards, payments)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection) != 1 || projection[0].PaidMinor != "9007199254740994" || projection[0].BalanceMinor != "-1" || projection[0].PaymentState != "overpaid" {
		t.Fatalf("money crossed float or overpay was hidden: %#v", projection)
	}
	want := map[string]bool{"payment_before_approval": false, "overpaid": false, "currency_mismatch": false, "unmatched": false}
	for _, anomaly := range anomalies {
		if _, ok := want[anomaly.Kind]; ok {
			want[anomaly.Kind] = true
		}
	}
	for kind, found := range want {
		if !found {
			t.Fatalf("missing %s in %#v", kind, anomalies)
		}
	}
}

func TestBonusProjectionRejectsForkAndInvalidReversal(t *testing.T) {
	base := BonusAwardFact{ID: "a1", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "100", ApprovedAt: "2026-01-10T00:00:00Z"}
	forks := []BonusAwardFact{base,
		{ID: "a2", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "110", CorrectsAwardID: stringPointer("a1"), ApprovedAt: "2026-02-10T00:00:00Z"},
		{ID: "a3", EmployeeID: "employee", State: "approved", Currency: "USD", Scale: 2, AmountMinor: "120", CorrectsAwardID: stringPointer("a1"), ApprovedAt: "2026-03-10T00:00:00Z"},
	}
	if _, _, err := BuildBonusProjection(forks, nil); !errors.Is(err, fault.Conflict) {
		t.Fatal("approved correction fork accepted", err)
	}
	payments := []BonusPaymentFact{
		{ID: "p1", EmployeeID: "employee", Kind: "payment", Currency: "USD", Scale: 2, AmountMinor: "40", PaidDate: "2026-01-20", AwardID: stringPointer("a1")},
		{ID: "r1", EmployeeID: "employee", Kind: "reversal", Currency: "USD", Scale: 2, AmountMinor: "30", PaidDate: "2026-01-21", OriginalPaymentID: stringPointer("p1")},
		{ID: "r2", EmployeeID: "employee", Kind: "reversal", Currency: "USD", Scale: 2, AmountMinor: "20", PaidDate: "2026-01-22", OriginalPaymentID: stringPointer("p1")},
	}
	if _, _, err := BuildBonusProjection([]BonusAwardFact{base}, payments); !errors.Is(err, fault.Invalid) {
		t.Fatal("over-reversal accepted", err)
	}
}

func TestBonusStateTransitionsAndMemoValidation(t *testing.T) {
	if next, err := NextBonusTargetState("draft", "confirm"); err != nil || next != "confirmed" {
		t.Fatal(next, err)
	}
	if _, err := NextBonusTargetState("withdrawn", "confirm"); !errors.Is(err, fault.Conflict) {
		t.Fatal("terminal target reopened", err)
	}
	if next, err := NextBonusAwardState("submitted", "approve", "author", "approver"); err != nil || next != "approved" {
		t.Fatal(next, err)
	}
	if _, err := NextBonusAwardState("submitted", "approve", "same", "same"); !errors.Is(err, fault.Forbidden) {
		t.Fatal("self approval accepted", err)
	}
	if err := ValidateCompensationMemo(CompensationMemo{Memo: "ok", SourceReference: stringPointer("source")}); err != nil {
		t.Fatal(err)
	}
	tooLong := ""
	for range 2001 {
		tooLong += "界"
	}
	if err := ValidateCompensationMemo(CompensationMemo{Memo: tooLong}); !errors.Is(err, fault.Invalid) {
		t.Fatal("oversize unicode memo accepted", err)
	}
}

func stringPointer(v string) *string { return &v }
