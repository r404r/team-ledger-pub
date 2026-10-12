package compensation

import (
	"errors"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"strings"
	"unicode/utf8"
)

var invalidPolicy = errors.New("invalid compensation policy")

func finiteName(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for i := range len(v) {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
func (p Policy) Validate() error {
	invalid := invalidPolicy
	if p.Enabled && (len(p.Currencies) == 0 || len(p.Units) == 0 || len(p.PaymentFrequencies) == 0 || len(p.TaxBases) == 0 || len(p.RoundingModes) == 0) {
		return invalid
	}
	if len(p.Currencies) > 100 {
		return invalid
	}
	for c, scale := range p.Currencies {
		if _, e := value.ParseMoney(c, scale, "0"); e != nil {
			return invalid
		}
	}
	for i, list := range [][]string{p.Units, p.PaymentFrequencies, p.TaxBases, p.RoundingModes} {
		if len(list) > 100 {
			return invalid
		}
		seen := map[string]bool{}
		for _, v := range list {
			if !finiteName(v) || seen[v] {
				return invalid
			}
			seen[v] = true
			if i == 2 && v != "gross" && v != "net" && v != "not_applicable" {
				return invalid
			}
			if i == 3 && v != "half_even" && v != "half_up" && v != "toward_zero" {
				return invalid
			}
		}
	}
	return nil
}
func (p Policy) terms(t *Terms) error {
	if t == nil {
		return fault.Invalid
	}
	scale, ok := p.Currencies[t.Currency]
	if !ok || scale != t.Scale || !contains(p.Units, t.Unit) || !contains(p.PaymentFrequencies, t.PaymentFrequency) || !contains(p.TaxBases, t.TaxBasis) || t.Components == nil || len(t.Components) > 20 {
		return fault.Invalid
	}
	if e := financialQuantity(t.Currency, t.Scale, t.AmountMinor, t.Rate); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, c := range t.Components {
		if !finiteName(c.Code) || seen[c.Code] || !contains(p.Units, c.Unit) || !contains(p.PaymentFrequencies, c.PaymentFrequency) || !contains(p.TaxBases, c.TaxBasis) {
			return fault.Invalid
		}
		seen[c.Code] = true
		if e := financialQuantity(t.Currency, t.Scale, c.AmountMinor, c.Rate); e != nil {
			return e
		}
	}
	return nil
}
func financialQuantity(currency string, scale int, amount, rate *string) error {
	if (amount == nil) == (rate == nil) {
		return fault.Invalid
	}
	if amount != nil {
		if _, e := value.ParseMoney(currency, scale, *amount); e != nil {
			return fault.Invalid
		}
	} else {
		if _, e := value.ParseDecimal(*rate); e != nil {
			return fault.Invalid
		}
	}
	return nil
}
func safeText(v string, max int, required bool) bool {
	return utf8.ValidString(v) && len(v) <= max && (!required || strings.TrimSpace(v) != "")
}
func validateCommand(p Policy, c ProposalCommand) error {
	if !value.ValidDate(c.EffectiveDate) || !safeText(c.Reason, 4096, true) || c.Members == nil {
		return fault.Invalid
	}
	if _, e := compRevision(c.CompRevision); e != nil {
		return e
	}
	if c.Kind == "initial" || c.Kind == "adjustment" {
		if len(c.Members) != 0 || (c.Kind == "initial" && c.BeforeTermID != nil) || (c.Kind == "adjustment" && (c.BeforeTermID == nil || !value.ValidID(*c.BeforeTermID))) {
			return fault.Invalid
		}
		return p.terms(c.After)
	}
	if c.Kind != "correction" || c.BeforeTermID != nil || c.After != nil || len(c.Members) < 1 || len(c.Members) > 100 {
		return fault.Invalid
	}
	keys := map[string]CorrectionMember{}
	originals := map[string]bool{}
	for _, m := range c.Members {
		if !finiteName(m.MemberKey) || len(m.MemberKey) > 32 || !value.ValidID(m.OriginalEventID) || originals[m.OriginalEventID] || !value.ValidDate(m.EffectiveDate) {
			return fault.Invalid
		}
		if _, ok := keys[m.MemberKey]; ok {
			return fault.Invalid
		}
		keys[m.MemberKey] = m
		originals[m.OriginalEventID] = true
		switch m.Action {
		case "reverse":
			if m.After != nil || m.BeforeRef != nil {
				return fault.Invalid
			}
		case "replace":
			if e := p.terms(m.After); e != nil {
				return e
			}
			if m.BeforeRef != nil {
				if (m.BeforeRef.TermID == nil) == (m.BeforeRef.MemberKey == nil) {
					return fault.Invalid
				}
				if m.BeforeRef.TermID != nil && !value.ValidID(*m.BeforeRef.TermID) {
					return fault.Invalid
				}
			}
		default:
			return fault.Invalid
		}
	}
	for _, m := range c.Members {
		if m.BeforeRef != nil && m.BeforeRef.MemberKey != nil {
			target, ok := keys[*m.BeforeRef.MemberKey]
			if !ok || target.Action != "replace" || target.MemberKey == m.MemberKey {
				return fault.Invalid
			}
		}
	}
	// Explicit topological walk rejects cycles without repairing any reference.
	for _, m := range c.Members {
		seen := map[string]bool{}
		for m.BeforeRef != nil && m.BeforeRef.MemberKey != nil {
			if seen[m.MemberKey] {
				return fault.Invalid
			}
			seen[m.MemberKey] = true
			m = keys[*m.BeforeRef.MemberKey]
		}
	}
	return nil
}
