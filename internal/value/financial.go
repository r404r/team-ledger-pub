package value

import (
	"errors"
	"strconv"
	"strings"
)

var ErrFinancialValue = errors.New("invalid financial value")

// Money stores an exact final amount, never a binary floating-point approximation.
type Money struct {
	Currency string
	Scale    int
	Minor    int64
}

func ParseMoney(currency string, scale int, minor string) (Money, error) {
	if len(currency) != 3 || scale < 0 || scale > 9 {
		return Money{}, ErrFinancialValue
	}
	for i := range len(currency) {
		if currency[i] < 'A' || currency[i] > 'Z' {
			return Money{}, ErrFinancialValue
		}
	}
	n, e := strconv.ParseInt(minor, 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != minor {
		return Money{}, ErrFinancialValue
	}
	return Money{Currency: currency, Scale: scale, Minor: n}, nil
}
func (m Money) AmountMinor() string { return strconv.FormatInt(m.Minor, 10) }
func (m Money) Add(other Money) (Money, error) {
	if m.Currency != other.Currency || m.Scale != other.Scale || m.Minor < 0 || other.Minor < 0 || other.Minor > 9223372036854775807-m.Minor {
		return Money{}, ErrFinancialValue
	}
	m.Minor += other.Minor
	return m, nil
}

// Decimal is a canonical unsigned decimal bounded to 18 integer and 9 fractional
// digits. Its text and integer/fractional parts preserve every supplied exact digit.
type Decimal struct {
	text     string
	integer  uint64
	fraction uint32
}

func ParseDecimal(text string) (Decimal, error) {
	integer, fraction, hasFraction := strings.Cut(text, ".")
	if len(integer) < 1 || len(integer) > 18 || len(integer) > 1 && integer[0] == '0' {
		return Decimal{}, ErrFinancialValue
	}
	for i := range len(integer) {
		if integer[i] < '0' || integer[i] > '9' {
			return Decimal{}, ErrFinancialValue
		}
	}
	n, e := strconv.ParseUint(integer, 10, 64)
	if e != nil {
		return Decimal{}, ErrFinancialValue
	}
	d := Decimal{text: text, integer: n}
	if hasFraction {
		if len(fraction) < 1 || len(fraction) > 9 || fraction[len(fraction)-1] == '0' {
			return Decimal{}, ErrFinancialValue
		}
		for i := range len(fraction) {
			if fraction[i] < '0' || fraction[i] > '9' {
				return Decimal{}, ErrFinancialValue
			}
		}
		v, e := strconv.ParseUint(fraction, 10, 32)
		if e != nil {
			return Decimal{}, ErrFinancialValue
		}
		d.fraction = uint32(v)
	}
	return d, nil
}
func (d Decimal) String() string { return d.text }
func (d Decimal) Ratio() bool {
	return d.text != "" && (d.integer == 0 || d.integer == 1 && d.fraction == 0)
}

// Ratio is a distinct exact value constrained to [0,1]; a rate remains an
// unrestricted bounded Decimal and is never silently reinterpreted as a ratio.
type Ratio struct{ value Decimal }

func ParseRatio(text string) (Ratio, error) {
	d, e := ParseDecimal(text)
	if e != nil || !d.Ratio() {
		return Ratio{}, ErrFinancialValue
	}
	return Ratio{value: d}, nil
}
func (r Ratio) String() string { return r.value.String() }
