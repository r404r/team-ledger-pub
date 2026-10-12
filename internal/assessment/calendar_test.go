package assessment

import (
	"testing"
	"time"
)

func TestGenerateWindowsKeepsOriginalMonthAnchorAcrossClamping(t *testing.T) {
	policy := PolicyCommand{
		ExpectedRevision: "0",
		Cadence:          Cadence{Unit: "month", Count: 1},
		AnchorDate:       "2026-01-31",
		Timezone:         "UTC",
		DueOffsetDays:    0,
		LocalDueTime:     "17:00",
		WindowThrough:    "2026-04-01",
		Purpose:          "interview_followup",
		AIMode:           "disabled",
		RequiredFields:   []string{"actual_started_at", "actual_ended_at"},
	}
	windows, err := GenerateWindows(policy, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 3 {
		t.Fatalf("got %d windows", len(windows))
	}
	want := [][2]string{{"2026-01-31", "2026-02-28"}, {"2026-02-28", "2026-03-31"}, {"2026-03-31", "2026-04-01"}}
	for i, pair := range want {
		if got := windows[i].LocalStart; got != pair[0] || windows[i].LocalEnd != pair[1] {
			t.Fatalf("window %d got [%s,%s), want [%s,%s)", i, got, windows[i].LocalEnd, pair[0], pair[1])
		}
	}
}

func TestGenerateWindowsResolvesDSTGapForwardAndFoldLater(t *testing.T) {
	for _, tc := range []struct {
		name, anchor, through, timezone, dueTime, wantDue string
	}{
		{"gap", "2026-03-07", "2026-03-08", "America/New_York", "02:30", "2026-03-08T07:00:00Z"},
		{"fold", "2026-10-31", "2026-11-01", "America/New_York", "01:30", "2026-11-01T06:30:00Z"},
		{"skipped local day", "2011-12-29", "2011-12-30", "Pacific/Apia", "00:00", "2011-12-30T10:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			windows, err := GenerateWindows(PolicyCommand{ExpectedRevision: "0", Cadence: Cadence{Unit: "day", Count: 1}, AnchorDate: tc.anchor, Timezone: tc.timezone, DueOffsetDays: 0, LocalDueTime: tc.dueTime, WindowThrough: tc.through, Purpose: "interview_followup", AIMode: "disabled", RequiredFields: []string{"actual_started_at"}}, 1)
			if err != nil || len(windows) != 1 {
				t.Fatal(windows, err)
			}
			if got := windows[0].DueAt.UTC().Format(time.RFC3339); got != tc.wantDue {
				t.Fatalf("due got %s want %s", got, tc.wantDue)
			}
		})
	}
}

func TestFilterWindowsDefaultsToCurrentWindowForLongPolicies(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windows := make([]Window, 150)
	for index := range windows {
		windows[index] = Window{StartAt: base.Add(time.Duration(index) * time.Hour), EndAt: base.Add(time.Duration(index+1) * time.Hour)}
	}
	selected, err := filterWindows(windows, StatusQuery{}, base.Add(75*time.Minute))
	if err != nil || len(selected) != 1 || !selected[0].StartAt.Equal(base.Add(time.Hour)) {
		t.Fatal("unbounded default did not select exactly the current window:", selected, err)
	}
	selected, err = filterWindows(windows, StatusQuery{}, base.Add(-time.Hour))
	if err != nil || len(selected) != 0 {
		t.Fatal("time outside the policy must return an empty bounded view:", selected, err)
	}
}

func TestGenerateWindowsPausesAnyOverlappingWindowOrPausedDueDate(t *testing.T) {
	base := PolicyCommand{ExpectedRevision: "0", Cadence: Cadence{Unit: "month", Count: 1}, AnchorDate: "2026-10-01", Timezone: "UTC", DueOffsetDays: 2, LocalDueTime: "17:00", WindowThrough: "2026-11-01", Purpose: "interview_followup", AIMode: "disabled", RequiredFields: []string{"actual_started_at"}}
	for _, tc := range []struct {
		name  string
		pause PauseInterval
		want  bool
	}{
		{"ends at window start", PauseInterval{From: "2026-09-20", To: "2026-10-01"}, false},
		{"starts during window", PauseInterval{From: "2026-10-20", To: "2026-11-10"}, true},
		{"ends during window", PauseInterval{From: "2026-09-20", To: "2026-10-20"}, true},
		{"covers due after window", PauseInterval{From: "2026-11-01", To: "2026-11-04"}, true},
		{"starts after due", PauseInterval{From: "2026-11-04", To: "2026-11-10"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := base
			command.PauseIntervals = []PauseInterval{tc.pause}
			windows, err := GenerateWindows(command, 1)
			if err != nil || len(windows) != 1 {
				t.Fatal(windows, err)
			}
			if windows[0].Paused != tc.want {
				t.Fatalf("paused=%v want %v", windows[0].Paused, tc.want)
			}
		})
	}
}

func TestGenerateWindowsRequiresEveryPolicyChoice(t *testing.T) {
	base := PolicyCommand{ExpectedRevision: "0", Cadence: Cadence{Unit: "week", Count: 2}, AnchorDate: "2026-01-01", Timezone: "UTC", DueOffsetDays: 2, LocalDueTime: "12:00", WindowThrough: "2026-02-01", Purpose: "interview_followup", AIMode: "manual_approved", RequiredFields: []string{"actual_started_at"}}
	invalid := []PolicyCommand{base, base, base, base}
	invalid[0].Cadence.Count = 0
	invalid[1].Timezone = ""
	invalid[2].AIMode = ""
	invalid[3].RequiredFields = nil
	for i, command := range invalid {
		if _, err := GenerateWindows(command, 1); err == nil {
			t.Fatalf("invalid policy %d accepted", i)
		}
	}
}
