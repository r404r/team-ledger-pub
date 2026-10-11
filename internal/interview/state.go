package interview

import "github.com/r404r/team-ledger/internal/fault"

// This internal mode distinguishes explicit backfill intent, never a wire action.
const backfilledCompletion = "complete_backfilled"

func nextInterviewStatus(status, action string) (string, error) {
	if status != "scheduled" && status != "in_progress" && status != "completed" && status != "cancelled" {
		return "", fault.Invalid
	}
	if action != "start" && action != "complete" && action != backfilledCompletion && action != "cancel" {
		return "", fault.Invalid
	}
	if status == "completed" || status == "cancelled" {
		return "", fault.Conflict
	}
	if action == "cancel" {
		return "cancelled", nil
	}
	if status == "scheduled" && action == "start" {
		return "in_progress", nil
	}
	if status == "scheduled" && action == backfilledCompletion {
		return "completed", nil
	}
	if status == "in_progress" && action == "complete" {
		return "completed", nil
	}
	return "", fault.Conflict
}

func nextActionStatus(status, action string) (string, error) {
	if status != "todo" && status != "in_progress" && status != "done" && status != "cancelled" {
		return "", fault.Invalid
	}
	if action != "start" && action != "complete" && action != "cancel" {
		return "", fault.Invalid
	}
	if status == "done" || status == "cancelled" {
		return "", fault.Conflict
	}
	if action == "cancel" {
		return "cancelled", nil
	}
	if action == "complete" {
		return "done", nil
	}
	if status == "todo" && action == "start" {
		return "in_progress", nil
	}
	return "", fault.Conflict
}
