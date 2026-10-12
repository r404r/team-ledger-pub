package value_test

import (
	"errors"
	"github.com/r404r/team-ledger/internal/value"
	"testing"
)

func TestMoneyPreservesExactInt64AndRejectsNoncanonicalAmounts(t *testing.T) {
	for _, text := range []string{"0", "9007199254740993", "9223372036854775807"} {
		money, err := value.ParseMoney("USD", 2, text)
		if err != nil || money.AmountMinor() != text {
			t.Fatalf("exact amount %q: %v %v", text, money, err)
		}
	}
	for _, text := range []string{"", "-1", "+1", "00", "01", "1.0", "1e3", "NaN", "9223372036854775808", " 1"} {
		if _, err := value.ParseMoney("USD", 2, text); !errors.Is(err, value.ErrFinancialValue) {
			t.Fatalf("invalid amount %q accepted: %v", text, err)
		}
	}
	for _, tc := range []struct {
		currency string
		scale    int
	}{{"usd", 2}, {"", 2}, {"US", 2}, {"USDD", 2}, {"USD", -1}, {"USD", 10}} {
		if _, err := value.ParseMoney(tc.currency, tc.scale, "1"); err == nil {
			t.Fatalf("invalid money context accepted: %+v", tc)
		}
	}
	max, _ := value.ParseMoney("USD", 2, "9223372036854775807")
	one, _ := value.ParseMoney("USD", 2, "1")
	if _, err := max.Add(one); !errors.Is(err, value.ErrFinancialValue) {
		t.Fatal("overflow must reject:", err)
	}
	for _, tc := range []struct {
		currency string
		scale    int
	}{{"JPY", 2}, {"USD", 0}} {
		other, _ := value.ParseMoney(tc.currency, tc.scale, "1")
		if _, err := one.Add(other); err == nil {
			t.Fatal("different currency or scale silently summed")
		}
	}
}

func TestExactDecimalCanonicalBoundsAndTypedRatio(t *testing.T) {
	for _, text := range []string{"0", "1", "0.000000001", "9007199254740993.123456789", "999999999999999999.999999999"} {
		d, err := value.ParseDecimal(text)
		if err != nil || d.String() != text {
			t.Fatalf("exact decimal %q: %v %v", text, d, err)
		}
	}
	for _, text := range []string{"", "00", "01", "+1", "-1", ".1", "1.", "1.0", "0.10", "1e2", "NaN", "1000000000000000000", "0.1234567891"} {
		if _, err := value.ParseDecimal(text); !errors.Is(err, value.ErrFinancialValue) {
			t.Fatalf("invalid decimal %q accepted: %v", text, err)
		}
	}
	for _, tc := range []struct {
		text  string
		ratio bool
	}{{"0", true}, {"1", true}, {"0.999999999", true}, {"1.000000001", false}, {"2", false}} {
		d, err := value.ParseDecimal(tc.text)
		if err != nil || d.Ratio() != tc.ratio {
			t.Fatalf("typed ratio %q: %v %v", tc.text, d.Ratio(), err)
		}
	}
}

func TestParseRatioPreservesCanonicalExactValueAndRejectsOutOfRange(t *testing.T) {
	for _, text := range []string{"0", "1", "0.000000001", "0.999999999"} {
		ratio, err := value.ParseRatio(text)
		if err != nil || ratio.String() != text {
			t.Fatalf("exact typed ratio %q: %v %v", text, ratio, err)
		}
	}
	for _, text := range []string{"1.000000001", "2", "999999999999999999", "-0.1", "+0.1", ".1", "0.10", "1.0", "0.1234567891", "1e-1", "NaN", ""} {
		if _, err := value.ParseRatio(text); !errors.Is(err, value.ErrFinancialValue) {
			t.Fatalf("invalid typed ratio %q accepted: %v", text, err)
		}
	}
}
