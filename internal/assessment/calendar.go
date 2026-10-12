package assessment

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errInvalidPolicy = errors.New("invalid assessment policy")

func parseDate(s string) (time.Time, error) {
	if len(s) != 10 {
		return time.Time{}, errInvalidPolicy
	}
	v, err := time.Parse("2006-01-02", s)
	if err != nil || v.Format("2006-01-02") != s {
		return time.Time{}, errInvalidPolicy
	}
	return v, nil
}

func parseLocalClock(s string) (int, int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, errInvalidPolicy
	}
	hour, err1 := strconv.Atoi(s[:2])
	minute, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, errInvalidPolicy
	}
	return hour, minute, nil
}

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func addMonthsClamped(anchor time.Time, months int) time.Time {
	year, month := anchor.Year(), int(anchor.Month())-1+months
	year += month / 12
	month %= 12
	if month < 0 {
		month += 12
		year--
	}
	m := time.Month(month + 1)
	day := anchor.Day()
	if max := daysInMonth(year, m); day > max {
		day = max
	}
	return time.Date(year, m, day, 0, 0, 0, 0, time.UTC)
}

func cadenceBoundary(anchor time.Time, cadence Cadence, index int) time.Time {
	switch cadence.Unit {
	case "day":
		return anchor.AddDate(0, 0, cadence.Count*index)
	case "week":
		return anchor.AddDate(0, 0, 7*cadence.Count*index)
	default:
		return addMonthsClamped(anchor, cadence.Count*index)
	}
}

func wallTuple(t time.Time) int64 {
	return int64(t.Year())*100000000 + int64(t.Month())*1000000 + int64(t.Day())*10000 + int64(t.Hour())*100 + int64(t.Minute())
}

// resolveLocal chooses the later instant for a repeated wall time. For a gap it
// chooses the first valid local minute after the requested wall clock.
func resolveLocal(date time.Time, hour, minute int, loc *time.Location) (time.Time, error) {
	naive := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, time.UTC)
	wanted := int64(date.Year())*100000000 + int64(date.Month())*1000000 + int64(date.Day())*10000 + int64(hour)*100 + int64(minute)
	var exact, after time.Time
	hasExact, hasAfter := false, false
	limit := naive.Add(48 * time.Hour)
	for probe := naive.Add(-48 * time.Hour); !probe.After(limit); {
		localProbe := probe.In(loc)
		_, offset := localProbe.Zone()
		candidate := naive.Add(-time.Duration(offset) * time.Second)
		localCandidate := candidate.In(loc)
		if wallTuple(localCandidate) == wanted && (!hasExact || candidate.After(exact)) {
			exact, hasExact = candidate, true
		}
		_, transition := localProbe.ZoneBounds()
		if transition.IsZero() || transition.After(limit) {
			break
		}
		localTransition := transition.In(loc)
		if wall := wallTuple(localTransition); wall > wanted && (!hasAfter || transition.Before(after)) {
			after, hasAfter = transition, true
		}
		if !transition.After(probe) {
			return time.Time{}, errInvalidPolicy
		}
		probe = transition
	}
	if hasExact {
		return exact.UTC(), nil
	}
	if hasAfter {
		return after.UTC(), nil
	}
	return time.Time{}, errInvalidPolicy
}

func validatePolicy(command PolicyCommand) (time.Time, time.Time, *time.Location, int, int, error) {
	if command.Cadence.Count < 1 || command.Cadence.Count > 365 || command.Cadence.Unit != "day" && command.Cadence.Unit != "week" && command.Cadence.Unit != "month" || command.DueOffsetDays < 0 || command.DueOffsetDays > 365 || command.Purpose != "interview_followup" || command.AIMode != "disabled" && command.AIMode != "manual_approved" && command.AIMode != "periodic_structured_v1" {
		return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
	}
	anchor, err := parseDate(command.AnchorDate)
	if err != nil {
		return time.Time{}, time.Time{}, nil, 0, 0, err
	}
	through, err := parseDate(command.WindowThrough)
	if err != nil || !through.After(anchor) {
		return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
	}
	loc, err := time.LoadLocation(command.Timezone)
	if err != nil || command.Timezone == "" || command.Timezone == "Local" {
		return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
	}
	hour, minute, err := parseLocalClock(command.LocalDueTime)
	if err != nil {
		return time.Time{}, time.Time{}, nil, 0, 0, err
	}
	allowed := map[string]bool{"actual_started_at": true, "actual_ended_at": true, "shared_published_note": true}
	if len(command.RequiredFields) == 0 || len(command.RequiredFields) > len(allowed) {
		return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
	}
	seen := map[string]bool{}
	for _, field := range command.RequiredFields {
		if !allowed[field] || seen[field] {
			return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
		}
		seen[field] = true
	}
	previous := ""
	for _, pause := range command.PauseIntervals {
		from, fromErr := parseDate(pause.From)
		to, toErr := parseDate(pause.To)
		if fromErr != nil || toErr != nil || !to.After(from) || previous != "" && pause.From < previous {
			return time.Time{}, time.Time{}, nil, 0, 0, errInvalidPolicy
		}
		previous = pause.To
	}
	return anchor, through, loc, hour, minute, nil
}

func GenerateWindows(command PolicyCommand, revision int64) ([]Window, error) {
	anchor, through, loc, hour, minute, err := validatePolicy(command)
	if err != nil || revision < 1 {
		return nil, errInvalidPolicy
	}
	windows := make([]Window, 0)
	for index := 0; index < 1000; index++ {
		start := cadenceBoundary(anchor, command.Cadence, index)
		if !start.Before(through) {
			break
		}
		end := cadenceBoundary(anchor, command.Cadence, index+1)
		if end.After(through) {
			end = through
		}
		startAt, resolveErr := resolveLocal(start, 0, 0, loc)
		if resolveErr != nil {
			return nil, resolveErr
		}
		endAt, resolveErr := resolveLocal(end, 0, 0, loc)
		if resolveErr != nil || !endAt.After(startAt) {
			return nil, errInvalidPolicy
		}
		dueDate := end.AddDate(0, 0, command.DueOffsetDays)
		dueAt, resolveErr := resolveLocal(dueDate, hour, minute, loc)
		if resolveErr != nil {
			return nil, resolveErr
		}
		localStart, localEnd, localDueDate := start.Format("2006-01-02"), end.Format("2006-01-02"), dueDate.Format("2006-01-02")
		paused := false
		for _, pause := range command.PauseIntervals {
			windowOverlapsPause := localStart < pause.To && pause.From < localEnd
			dueFallsInPause := localDueDate >= pause.From && localDueDate < pause.To
			if windowOverlapsPause || dueFallsInPause {
				paused = true
				break
			}
		}
		windows = append(windows, Window{PolicyRevision: revision, LocalStart: localStart, LocalEnd: localEnd, StartAt: startAt, EndAt: endAt, DueAt: dueAt, Paused: paused})
	}
	if len(windows) == 0 || len(windows) >= 1000 || windows[len(windows)-1].LocalEnd != command.WindowThrough {
		return nil, fmt.Errorf("%w: unsupported window horizon", errInvalidPolicy)
	}
	return windows, nil
}

func canonicalPolicy(command PolicyCommand) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%d|%s|%s|%d|%s|%s|%s|%s", command.Cadence.Unit, command.Cadence.Count, command.AnchorDate, command.Timezone, command.DueOffsetDays, command.LocalDueTime, command.WindowThrough, command.Purpose, command.AIMode)
	fields := append([]string(nil), command.RequiredFields...)
	sort.Strings(fields)
	for _, field := range fields {
		b.WriteByte('|')
		b.WriteString(field)
	}
	for _, pause := range command.PauseIntervals {
		b.WriteByte('|')
		b.WriteString(pause.From)
		b.WriteByte('/')
		b.WriteString(pause.To)
	}
	return b.String()
}
