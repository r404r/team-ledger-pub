package compensation

import (
	"errors"
	"github.com/r404r/team-ledger/internal/fault"
	"testing"
)

func TestApprovedFutureChainUsesIdentityAndFullCorrectionClosure(t *testing.T) {
	original := []EventRecord{
		{ID: "e0", Kind: "initial", EffectiveDate: "2026-01-01", AfterTermID: new("t0"), Sequence: 1},
		{ID: "e1", Kind: "adjustment", EffectiveDate: "2027-01-01", BeforeTermID: new("t0"), AfterTermID: new("t1"), Sequence: 2},
		{ID: "e2", Kind: "adjustment", EffectiveDate: "2027-02-01", BeforeTermID: new("t1"), AfterTermID: new("t2"), Sequence: 3},
	}
	schedule, err := simulate(original)
	if err != nil || len(schedule) != 3 {
		t.Fatalf("approved historical/future chain must have three segments: %v, %d", err, len(schedule))
	}
	if schedule[0].TermID != "t0" || schedule[1].TermID != "t1" || schedule[2].TermID != "t2" {
		t.Fatal("projection selected incorrect term identities")
	}
	incomplete := append(append([]EventRecord{}, original...), EventRecord{ID: "r1", Kind: "correction_replacement", EffectiveDate: "2027-01-01", BeforeTermID: new("t0"), AfterTermID: new("n1"), CorrectsEventID: new("e1"), Sequence: 4})
	if _, err = simulate(incomplete); !errors.Is(err, fault.Conflict) {
		t.Fatalf("unchanged dependent e2 must reject entire correction, got %v", err)
	}
	complete := append(incomplete, EventRecord{ID: "r2", Kind: "correction_replacement", EffectiveDate: "2027-02-01", BeforeTermID: new("n1"), AfterTermID: new("n2"), CorrectsEventID: new("e2"), Sequence: 5})
	schedule, err = simulate(complete)
	if err != nil || len(schedule) != 3 || schedule[1].TermID != "n1" || schedule[2].TermID != "n2" {
		t.Fatalf("full explicit replacement must preserve every segment: %v", err)
	}
}

func TestReverseWholeChainAllowsNewInitialWithoutDeletingHistory(t *testing.T) {
	events := []EventRecord{
		{ID: "i", Kind: "initial", EffectiveDate: "2026-01-01", AfterTermID: new("t"), Sequence: 1},
		{ID: "a", Kind: "adjustment", EffectiveDate: "2027-01-01", BeforeTermID: new("t"), AfterTermID: new("u"), Sequence: 2},
		{ID: "ri", Kind: "correction_reversal", EffectiveDate: "2026-01-01", CorrectsEventID: new("i"), Sequence: 3},
	}
	if _, err := simulate(events); !errors.Is(err, DependencyIncomplete) {
		t.Fatal("reverse root alone left orphan successor:", err)
	}
	events = append(events, EventRecord{ID: "ra", Kind: "correction_reversal", EffectiveDate: "2027-01-01", CorrectsEventID: new("a"), Sequence: 4})
	if schedule, err := simulate(events); err != nil || len(schedule) != 0 {
		t.Fatal("complete reversal should leave no active terms:", schedule, err)
	}
	events = append(events, EventRecord{ID: "new", Kind: "initial", EffectiveDate: "2026-02-01", AfterTermID: new("newterm"), Sequence: 5})
	if schedule, err := simulate(events); err != nil || len(schedule) != 1 || schedule[0].TermID != "newterm" {
		t.Fatal("immutable reversal history prevented legal reinitial:", schedule, err)
	}
}

func TestFutureInitialAndAmbiguousDatesCannotAcquireSecondRoot(t *testing.T) {
	original := EventRecord{ID: "i", Kind: "initial", EffectiveDate: "2027-01-01", AfterTermID: new("t"), Sequence: 1}
	for _, next := range []EventRecord{
		{ID: "duplicate", Kind: "initial", EffectiveDate: "2026-01-01", AfterTermID: new("u"), Sequence: 2},
		{ID: "same_day", Kind: "adjustment", EffectiveDate: "2027-01-01", BeforeTermID: new("t"), AfterTermID: new("u"), Sequence: 2},
		{ID: "wrong_before", Kind: "adjustment", EffectiveDate: "2027-02-01", BeforeTermID: new("other"), AfterTermID: new("u"), Sequence: 2},
	} {
		if _, err := simulate([]EventRecord{original, next}); !errors.Is(err, fault.Conflict) {
			t.Fatalf("ambiguous/rootless chain accepted %s: %v", next.ID, err)
		}
	}
}
