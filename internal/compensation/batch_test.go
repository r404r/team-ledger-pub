package compensation

import (
	"fmt"
	"math"
	"reflect"
	"testing"
)

func TestValidateBatchLinesNormalMixedCurrenciesAndNoChange(t *testing.T) {
	lines := []BatchLineCommand{
		{EmployeeID: "e1", StaffCode: "S1", Currency: "CNY", SalaryBefore: "10650", IncreaseAmount: "650", SalaryAfter: "11300", PerformanceGrade: "G", AverageMeritIncrease: "6.0%", DepartmentSuggestedIncrease: "6%"},
		{EmployeeID: "e2", StaffCode: "S2", Currency: "JPY", SalaryBefore: "500000", IncreaseAmount: "0", SalaryAfter: "500000", PerformanceGrade: "A"},
	}
	got, totals, err := ValidateBatchLines(BatchNormal, 2026, "2026-04-01", lines, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].EffectiveDate != "2026-04-01" || got[0].Result != "changed" || got[1].Result != "no_change" {
		t.Fatalf("unexpected normalized lines: %#v", got)
	}
	want := []CurrencyTotal{{Currency: "CNY", Amount: "650"}, {Currency: "JPY", Amount: "0"}}
	if !reflect.DeepEqual(totals, want) {
		t.Fatalf("totals=%#v want=%#v", totals, want)
	}
}

func TestValidateBatchLinesSpecialRequiresControlledReasonAndText(t *testing.T) {
	line := BatchLineCommand{EmployeeID: "e1", StaffCode: "S1", Currency: "JPY", SalaryBefore: "100", IncreaseAmount: "1", SalaryAfter: "101", EffectiveMonth: "2025-03", ReasonCode: "promotion", ReasonText: "promotion to manager"}
	got, _, err := ValidateBatchLines(BatchSpecial, 2025, "", []BatchLineCommand{line}, map[string]bool{"promotion": true})
	if err != nil || got[0].EffectiveMonth != "2025-03" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	line.ReasonText = ""
	if _, _, err = ValidateBatchLines(BatchSpecial, 2025, "", []BatchLineCommand{line}, map[string]bool{"promotion": true}); err == nil {
		t.Fatal("expected missing reason text rejection")
	}
}

func TestValidateBatchLinesRejectsDecimalNegativeMismatchDuplicateAndOverflow(t *testing.T) {
	base := BatchLineCommand{EmployeeID: "e1", StaffCode: "S1", Currency: "CNY", SalaryBefore: "100", IncreaseAmount: "1", SalaryAfter: "101", PerformanceGrade: "A"}
	for _, bad := range []string{"1.00", "-1", "01", "+1"} {
		line := base
		line.IncreaseAmount = bad
		if _, _, err := ValidateBatchLines(BatchNormal, 2025, "2025-01-01", []BatchLineCommand{line}, nil); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	mismatch := base
	mismatch.SalaryAfter = "100"
	if _, _, err := ValidateBatchLines(BatchNormal, 2025, "2025-01-01", []BatchLineCommand{mismatch}, nil); err == nil {
		t.Fatal("accepted mismatched after")
	}
	if _, _, err := ValidateBatchLines(BatchNormal, 2025, "2025-01-01", []BatchLineCommand{base, base}, nil); err == nil {
		t.Fatal("accepted duplicate employee")
	}
	overflow := []BatchLineCommand{
		{EmployeeID: "e1", StaffCode: "S1", Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "9223372036854775807", SalaryAfter: "9223372036854775807", PerformanceGrade: "A"},
		{EmployeeID: "e2", StaffCode: "S2", Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "1", SalaryAfter: "1", PerformanceGrade: "A"},
	}
	if _, _, err := ValidateBatchLines(BatchNormal, 2025, "2025-01-01", overflow, nil); err == nil || err.Error() != "BATCH_TOTAL_OVERFLOW" {
		t.Fatalf("expected overflow, got %v", err)
	}
	if n, err := ParseMoney("9223372036854775807"); err != nil || n != math.MaxInt64 {
		t.Fatalf("max int parse n=%d err=%v", n, err)
	}
}

func TestValidateBatchLinesRejectsMoreThanFiveHundredEmployees(t *testing.T) {
	lines := make([]BatchLineCommand, 501)
	for i := range lines {
		lines[i] = BatchLineCommand{EmployeeID: fmt.Sprintf("employee-%d", i), StaffCode: fmt.Sprintf("S-%d", i), Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "0", SalaryAfter: "0", PerformanceGrade: "A"}
	}
	if _, _, err := ValidateBatchLines(BatchNormal, 2026, "2026-04-01", lines, nil); err == nil {
		t.Fatal("accepted more than 500 employees")
	}
}

func TestValidateCreateBatchAndBusinessCode(t *testing.T) {
	if err := ValidateCreateBatch(CreateBatchCommand{Name: "2026 Normal", CycleYear: 2026, AdjustmentType: BatchNormal, LegalEntityID: "le", DefaultEffectiveDate: "2026-04-01", BudgetCurrency: "CNY", BudgetAmount: "1000000"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCreateBatch(CreateBatchCommand{Name: "2026 Special", CycleYear: 2026, AdjustmentType: BatchSpecial, LegalEntityID: "le", DefaultEffectiveDate: "2026-10-01", SpecialReasonCode: "promotion", SpecialReasonText: "Promotion", BudgetCurrency: "JPY", BudgetAmount: "1000000"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBusinessCode("N-2026-0001", BatchNormal, 2026); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBusinessCode("S-2026-10000", BatchSpecial, 2026); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBusinessCode("N-2026-0001", BatchSpecial, 2026); err == nil {
		t.Fatal("accepted wrong prefix")
	}
}
