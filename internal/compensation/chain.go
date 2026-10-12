package compensation

import (
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
	"sort"
)

// DependencyIncomplete is a conflict, not an input repair request. Callers must
// explicitly replace/reverse every affected immutable successor reference.
type chainConflict struct{ detail *fault.Fault }

func (e *chainConflict) Error() string        { return e.detail.Error() }
func (e *chainConflict) Unwrap() error        { return e.detail }
func (e *chainConflict) Is(target error) bool { return target == fault.Conflict }

var DependencyIncomplete = &chainConflict{detail: &fault.Fault{Status: 409, Code: "CONFLICT", Reason: "DEPENDENCY_INCOMPLETE"}}

func activeEvents(events []EventRecord) ([]EventRecord, error) {
	ordered := append([]EventRecord(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	active := make(map[string]EventRecord, len(events))
	seen := make(map[string]bool, len(events))
	var previous int64
	for _, e := range ordered {
		if e.ID == "" || seen[e.ID] || e.Sequence < 1 || e.Sequence <= previous || !value.ValidDate(e.EffectiveDate) {
			return nil, fault.Conflict
		}
		if e.OrgID != ordered[0].OrgID || e.EmployeeID != ordered[0].EmployeeID {
			return nil, fault.Conflict
		}
		previous = e.Sequence
		seen[e.ID] = true
		switch e.Kind {
		case "initial", "adjustment":
			if e.CorrectsEventID != nil || e.AfterTermID == nil || (e.Kind == "initial" && e.BeforeTermID != nil) || (e.Kind == "adjustment" && e.BeforeTermID == nil) {
				return nil, fault.Conflict
			}
		case "correction_replacement", "correction_reversal":
			if e.CorrectsEventID == nil {
				return nil, fault.Conflict
			}
			old, ok := active[*e.CorrectsEventID]
			if !ok || old.OrgID != e.OrgID || old.EmployeeID != e.EmployeeID {
				return nil, fault.Conflict
			}
			delete(active, old.ID)
			if e.Kind == "correction_reversal" {
				if e.BeforeTermID != nil {
					return nil, fault.Conflict
				}
				continue
			}
			if e.AfterTermID == nil {
				return nil, fault.Conflict
			}
		default:
			return nil, fault.Conflict
		}
		active[e.ID] = e
	}
	out := make([]EventRecord, 0, len(active))
	for _, e := range active {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EffectiveDate == out[j].EffectiveDate {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].EffectiveDate < out[j].EffectiveDate
	})
	return out, nil
}

// simulate validates the complete active past/future chain. Event timestamps
// cannot settle ambiguity: every date has one predecessor identity and root.
func simulate(events []EventRecord) ([]ScheduleRecord, error) {
	active, err := activeEvents(events)
	if err != nil {
		return nil, err
	}
	out := make([]ScheduleRecord, 0, len(active))
	terms := make(map[string]bool, len(active))
	var previous string
	for i, e := range active {
		if i == 0 {
			if e.BeforeTermID != nil || e.Kind == "adjustment" {
				return nil, DependencyIncomplete
			}
		} else {
			if e.EffectiveDate == active[i-1].EffectiveDate || e.BeforeTermID == nil || *e.BeforeTermID != previous {
				return nil, DependencyIncomplete
			}
		}
		if e.AfterTermID == nil || *e.AfterTermID == "" {
			return nil, DependencyIncomplete
		}
		if terms[*e.AfterTermID] {
			return nil, DependencyIncomplete
		}
		terms[*e.AfterTermID] = true
		out = append(out, ScheduleRecord{OrgID: e.OrgID, EmployeeID: e.EmployeeID, EffectiveDate: e.EffectiveDate, TermID: *e.AfterTermID, EventID: e.ID})
		if i > 0 {
			out[i-1].ValidTo = new(e.EffectiveDate)
		}
		previous = *e.AfterTermID
	}
	return out, nil
}
