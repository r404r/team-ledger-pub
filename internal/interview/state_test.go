package interview

import (
	"errors"
	"testing"

	"github.com/r404r/team-ledger/internal/fault"
)

func TestInterviewAndActionTerminalTransitions(t *testing.T) {
	for _, tc := range []struct {
		name, status, action, want string
		transition                 func(string, string) (string, error)
		wantErr                    error
	}{
		{"interview_start", "scheduled", "start", "in_progress", nextInterviewStatus, nil},
		{"interview_complete", "in_progress", "complete", "completed", nextInterviewStatus, nil},
		{"interview_cancel_scheduled", "scheduled", "cancel", "cancelled", nextInterviewStatus, nil},
		{"interview_cancel_started", "in_progress", "cancel", "cancelled", nextInterviewStatus, nil},
		{"completed_does_not_reopen", "completed", "start", "", nextInterviewStatus, fault.Conflict},
		{"cancelled_does_not_reopen", "cancelled", "start", "", nextInterviewStatus, fault.Conflict},
		{"not_completed_without_start", "scheduled", "complete", "", nextInterviewStatus, fault.Conflict},
		{"unknown_interview_action", "scheduled", "finish", "", nextInterviewStatus, fault.Invalid},
		{"explicit_backfill_completion", "scheduled", "complete_backfilled", "completed", nextInterviewStatus, nil},
		{"backfill_not_a_reopen", "completed", "complete_backfilled", "", nextInterviewStatus, fault.Conflict},
		{"action_start", "todo", "start", "in_progress", nextActionStatus, nil},
		{"action_done_from_todo", "todo", "complete", "done", nextActionStatus, nil},
		{"action_done_after_start", "in_progress", "complete", "done", nextActionStatus, nil},
		{"action_cancel", "in_progress", "cancel", "cancelled", nextActionStatus, nil},
		{"action_cancel_todo", "todo", "cancel", "cancelled", nextActionStatus, nil},
		{"done_does_not_reopen", "done", "start", "", nextActionStatus, fault.Conflict},
		{"cancelled_action_does_not_reopen", "cancelled", "start", "", nextActionStatus, fault.Conflict},
		{"started_action_is_not_restarted", "in_progress", "start", "", nextActionStatus, fault.Conflict},
		{"unknown_action_transition", "todo", "reopen", "", nextActionStatus, fault.Invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.transition(tc.status, tc.action)
			if got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("transition (%s, %s) = (%q, %v); want (%q, %v)", tc.status, tc.action, got, err, tc.want, tc.wantErr)
			}
		})
	}
}
