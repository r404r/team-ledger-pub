package compensation

import (
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

type BonusAwardFact struct {
	ID, EmployeeID, State, Currency, AmountMinor, ApprovedAt string
	Scale                                                    int
	CorrectsAwardID                                          *string
}

type BonusPaymentFact struct {
	ID, EmployeeID, Kind, Currency, AmountMinor, PaidDate string
	Scale                                                 int
	AwardID, OriginalPaymentID                            *string
}

type BonusBalance struct {
	EffectiveAwardID string `json:"effective_award_id"`
	Currency         string `json:"currency"`
	Scale            int    `json:"scale"`
	ApprovedMinor    string `json:"approved_minor"`
	PaidMinor        string `json:"paid_minor"`
	BalanceMinor     string `json:"balance_minor"`
	PaymentState     string `json:"payment_state"`
}

type BonusAnomaly struct {
	Kind      string  `json:"kind"`
	PaymentID string  `json:"payment_id"`
	AwardID   *string `json:"award_id"`
}

type CompensationMemo struct {
	Memo            string  `json:"memo"`
	SourceReference *string `json:"source_reference,omitempty"`
}

func NextBonusTargetState(state, action string) (string, error) {
	switch {
	case state == "draft" && action == "confirm":
		return "confirmed", nil
	case (state == "draft" || state == "confirmed") && action == "withdraw":
		return "withdrawn", nil
	default:
		return "", fault.Conflict
	}
}

func NextBonusAwardState(state, action, author, actor string) (string, error) {
	if action == "approve" && author == actor {
		return "", fault.Forbidden
	}
	switch {
	case state == "draft" && action == "submit":
		return "submitted", nil
	case (state == "draft" || state == "submitted") && action == "withdraw":
		return "withdrawn", nil
	case state == "submitted" && action == "approve":
		return "approved", nil
	case state == "submitted" && action == "reject":
		return "rejected", nil
	default:
		return "", fault.Conflict
	}
}

func ValidateCompensationMemo(m CompensationMemo) error {
	if !utf8.ValidString(m.Memo) || m.Memo == "" || utf8.RuneCountInString(m.Memo) > 2000 {
		return fault.Invalid
	}
	if m.SourceReference != nil && (!utf8.ValidString(*m.SourceReference) || utf8.RuneCountInString(*m.SourceReference) > 200) {
		return fault.Invalid
	}
	// JSON syntax overhead is bounded separately at the HTTP boundary. This
	// domain bound prevents a valid value from exceeding the 16 KiB envelope.
	if len(m.Memo)+(func() int {
		if m.SourceReference == nil {
			return 0
		}
		return len(*m.SourceReference)
	})() > 16<<10 {
		return fault.Invalid
	}
	return nil
}

type awardNode struct {
	fact      BonusAwardFact
	amount    int64
	child     string
	effective string
}

type paymentNode struct {
	fact   BonusPaymentFact
	amount int64
}

func BuildBonusProjection(awards []BonusAwardFact, payments []BonusPaymentFact) ([]BonusBalance, []BonusAnomaly, error) {
	nodes := make(map[string]*awardNode, len(awards))
	for _, award := range awards {
		if award.ID == "" || award.EmployeeID == "" || nodes[award.ID] != nil {
			return nil, nil, fault.Invalid
		}
		money, err := value.ParseMoney(award.Currency, award.Scale, award.AmountMinor)
		if err != nil || money.Minor <= 0 {
			return nil, nil, fault.Invalid
		}
		nodes[award.ID] = &awardNode{fact: award, amount: money.Minor}
	}
	for _, node := range nodes {
		if node.fact.State != "approved" || node.fact.CorrectsAwardID == nil {
			continue
		}
		parent := nodes[*node.fact.CorrectsAwardID]
		if parent == nil || parent.fact.State != "approved" || parent.fact.EmployeeID != node.fact.EmployeeID || parent.child != "" {
			return nil, nil, fault.Conflict
		}
		parent.child = node.fact.ID
	}
	for id, node := range nodes {
		if node.fact.State != "approved" {
			continue
		}
		seen := map[string]bool{}
		cursor := id
		for {
			if seen[cursor] {
				return nil, nil, fault.Conflict
			}
			seen[cursor] = true
			current := nodes[cursor]
			if current == nil || current.fact.State != "approved" {
				return nil, nil, fault.Conflict
			}
			if current.child == "" {
				node.effective = cursor
				break
			}
			cursor = current.child
		}
	}

	paymentNodes := make(map[string]paymentNode, len(payments))
	reversed := make(map[string]int64)
	for _, payment := range payments {
		if payment.ID == "" || payment.EmployeeID == "" || paymentNodes[payment.ID].fact.ID != "" || payment.Kind != "payment" && payment.Kind != "reversal" {
			return nil, nil, fault.Invalid
		}
		money, err := value.ParseMoney(payment.Currency, payment.Scale, payment.AmountMinor)
		if err != nil || money.Minor <= 0 {
			return nil, nil, fault.Invalid
		}
		if _, err = time.Parse("2006-01-02", payment.PaidDate); err != nil {
			return nil, nil, fault.Invalid
		}
		paymentNodes[payment.ID] = paymentNode{fact: payment, amount: money.Minor}
	}
	for _, payment := range payments {
		if payment.Kind != "reversal" {
			continue
		}
		if payment.OriginalPaymentID == nil {
			return nil, nil, fault.Invalid
		}
		original, ok := paymentNodes[*payment.OriginalPaymentID]
		if !ok || original.fact.Kind != "payment" || original.fact.EmployeeID != payment.EmployeeID || original.fact.Currency != payment.Currency || original.fact.Scale != payment.Scale || reversed[original.fact.ID] > original.amount-paymentNodes[payment.ID].amount {
			return nil, nil, fault.Invalid
		}
		reversed[original.fact.ID] += paymentNodes[payment.ID].amount
	}

	paid := make(map[string]int64)
	anomalies := make([]BonusAnomaly, 0)
	for _, payment := range payments {
		if payment.Kind == "reversal" {
			continue
		}
		p := paymentNodes[payment.ID]
		if payment.AwardID == nil {
			anomalies = append(anomalies, BonusAnomaly{Kind: "unmatched", PaymentID: payment.ID})
			continue
		}
		award := nodes[*payment.AwardID]
		if award == nil || award.fact.EmployeeID != payment.EmployeeID {
			return nil, nil, fault.Invalid
		}
		if award.fact.State != "approved" {
			anomalies = append(anomalies, BonusAnomaly{Kind: "unapproved_award", PaymentID: payment.ID, AwardID: payment.AwardID})
			continue
		}
		effective := nodes[award.effective]
		if effective.fact.Currency != payment.Currency {
			anomalies = append(anomalies, BonusAnomaly{Kind: "currency_mismatch", PaymentID: payment.ID, AwardID: payment.AwardID})
			continue
		}
		if effective.fact.Scale != payment.Scale {
			anomalies = append(anomalies, BonusAnomaly{Kind: "scale_mismatch", PaymentID: payment.ID, AwardID: payment.AwardID})
			continue
		}
		approvedDate := award.fact.ApprovedAt
		if len(approvedDate) < 10 || payment.PaidDate < approvedDate[:10] {
			anomalies = append(anomalies, BonusAnomaly{Kind: "payment_before_approval", PaymentID: payment.ID, AwardID: payment.AwardID})
		}
		net := p.amount - reversed[payment.ID]
		if net < 0 || paid[award.effective] > int64(^uint64(0)>>1)-net {
			return nil, nil, fault.Invalid
		}
		paid[award.effective] += net
	}

	projection := make([]BonusBalance, 0)
	for _, award := range awards {
		node := nodes[award.ID]
		if award.State != "approved" || node.child != "" {
			continue
		}
		p := paid[award.ID]
		balance := node.amount - p
		state := "unpaid"
		if p == node.amount {
			state = "paid"
		} else if p > node.amount {
			state = "overpaid"
			anomalies = append(anomalies, BonusAnomaly{Kind: "overpaid", AwardID: &node.fact.ID})
		} else if p > 0 {
			state = "partially_paid"
		}
		projection = append(projection, BonusBalance{EffectiveAwardID: award.ID, Currency: award.Currency, Scale: award.Scale, ApprovedMinor: strconv.FormatInt(node.amount, 10), PaidMinor: strconv.FormatInt(p, 10), BalanceMinor: strconv.FormatInt(balance, 10), PaymentState: state})
	}
	return projection, anomalies, nil
}
