package store_test

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestFinancialObjectResolverUsesCanonicalOwnerAndExactRevision(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			employee, err := f.Service.Create(ctx, f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_FINANCIAL_OBJECT_OWNER"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
			if err != nil {
				t.Fatal(err)
			}
			request := func(actor testsupport.Credential) compensation.Request {
				return compensation.Request{TokenHash: actor.Hash, Purpose: "compensation_management", Key: value.NewID(), RequestID: value.NewID()}
			}
			amount := "100"
			proposal, err := f.Compensation.CreateProposal(ctx, request(f.CompW), employee.ID, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: &compensation.Terms{Currency: "USD", Scale: 2, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}, Reason: "SYNTHETIC_CANONICAL_OBJECT", Members: []compensation.CorrectionMember{}})
			if err != nil {
				t.Fatal(err)
			}
			submitted, err := f.Compensation.TransitionProposal(ctx, request(f.CompW), proposal.ID, compensation.TransitionCommand{Action: "submit", Revision: proposal.Revision, CompRevision: proposal.CompRevision})
			if err != nil {
				t.Fatal(err)
			}
			approved, err := f.Compensation.TransitionProposal(ctx, request(f.CompApprover), proposal.ID, compensation.TransitionCommand{Action: "approve", Revision: submitted.Revision, CompRevision: submitted.CompRevision, DecisionReason: "SYNTHETIC_INDEPENDENT_APPROVAL"})
			if err != nil {
				t.Fatal(err)
			}
			schedule, err := f.Repo.CompensationSchedule(ctx, f.OrgID, employee.ID, compensation.CurrentQuery{AsOf: "2026-01-01", FutureLimit: 100})
			if err != nil || len(schedule) != 1 {
				t.Fatal("approved financial schedule:", schedule, err)
			}
			event, err := f.Repo.CompensationEvent(ctx, f.OrgID, schedule[0].EventID)
			if err != nil {
				t.Fatal(err)
			}
			term, err := f.Repo.CompensationTerm(ctx, f.OrgID, schedule[0].TermID)
			if err != nil {
				t.Fatal(err)
			}
			f.FinancialKMS.Fail.Store(true)
			calls := f.FinancialKMS.Calls.Load()
			for _, target := range []struct {
				ref      authz.ObjectReference
				revision string
			}{
				{authz.ObjectReference{Kind: "compensation_proposal", ID: proposal.ID}, approved.Revision},
				{authz.ObjectReference{Kind: "compensation_event", ID: event.ID}, strconv.FormatInt(event.Sequence, 10)},
				{authz.ObjectReference{Kind: "compensation_term", ID: term.ID}, strconv.FormatInt(term.Version, 10)},
			} {
				info, err := f.Repo.Object(ctx, f.OrgID, target.ref)
				if err != nil || info.Reference != target.ref || info.EmployeeID != employee.ID || info.Category != "financial" || info.Revision != target.revision || info.Published || !reflect.DeepEqual(info.Lineage, []authz.ObjectReference{target.ref}) {
					t.Fatal("financial canonical metadata must bind exact owner/revision with no aggregate lineage:", target, info, err)
				}
				if _, err := f.Repo.Object(ctx, f.OtherOrgID, target.ref); !errors.Is(err, fault.NotFound) {
					t.Fatal("financial canonical resolver crossed organization:", err)
				}
			}
			for _, ref := range []authz.ObjectReference{{Kind: "compensation_aggregate", ID: employee.ID}, {Kind: "compensation_terms", ID: term.ID}, {Kind: "compensation_term", ID: event.ID}, {Kind: "compensation_event", ID: term.ID}} {
				if _, err := f.Repo.Object(ctx, f.OrgID, ref); !errors.Is(err, fault.NotFound) {
					t.Fatal("resolver admitted arbitrary family or crossed immutable type:", ref, err)
				}
			}
			if f.FinancialKMS.Calls.Load() != calls {
				t.Fatal("canonical financial object metadata reached KMS")
			}
		})
	}
}
