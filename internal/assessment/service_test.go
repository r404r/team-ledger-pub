package assessment_test

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func assessmentBackends(t *testing.T, run func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, testsupport.NewHarness(t, backend)) })
	}
}

func assessmentRequest(credential testsupport.Credential) assessment.Request {
	return assessment.Request{TokenHash: credential.Hash, Purpose: "interview_followup", Key: value.NewID(), RequestID: value.NewID()}
}

func assessmentEmployee(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	created, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{LocalName: "SYNTHETIC_ASSESSMENT_EMPLOYEE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("real employee setup:", err)
	}
	return created.ID
}

func issueInterviewRead(t *testing.T, f *testsupport.Fixture, employee string) {
	t.Helper()
	var epoch int64
	query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	_, err := f.Authz.Issue(context.Background(), authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{
		SubjectID: f.Reader.SubjectID, Capability: "interview.read", Category: "metadata",
		Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "interview_followup",
		ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano),
		AuthorityID: f.AuthorityIDs["interview.read/metadata"], ExpectedRevision: strconv.FormatInt(epoch, 10),
	})
	if err != nil {
		t.Fatal("approved interview read grant:", err)
	}
}

func TestAssessmentPolicyWindowsFactsAndPartialCoverage(t *testing.T) {
	assessmentBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := assessmentEmployee(t, f)

		unconfigured, err := f.Assessment.Status(ctx, assessmentRequest(f.FollowupManager), employee, assessment.StatusQuery{})
		if err != nil || unconfigured.State != "unconfigured" || unconfigured.Policy != nil || len(unconfigured.Items) != 0 {
			t.Fatal("explicit unconfigured state:", unconfigured, err)
		}

		command := assessment.PolicyCommand{
			ExpectedRevision: "0", Cadence: assessment.Cadence{Unit: "week", Count: 1},
			AnchorDate: "2026-10-01", Timezone: "UTC", DueOffsetDays: 1, LocalDueTime: "17:00", WindowThrough: "2026-11-01",
			Purpose: "interview_followup", AIMode: "periodic_structured_v1", RequiredFields: []string{"actual_ended_at", "actual_started_at"},
		}
		if _, err = f.Assessment.PutPolicy(ctx, assessmentRequest(f.Reader), employee, command); !errors.Is(err, fault.NotFound) {
			t.Fatal("interview read must not imply policy management:", err)
		}
		request := assessmentRequest(f.FollowupManager)
		policy, err := f.Assessment.PutPolicy(ctx, request, employee, command)
		if err != nil || policy.Revision != "1" || policy.Timezone != "UTC" || !reflect.DeepEqual(policy.RequiredFields, []string{"actual_ended_at", "actual_started_at"}) {
			t.Fatal("policy commit:", policy, err)
		}
		replayed, err := f.Assessment.PutPolicy(ctx, request, employee, command)
		if err != nil || !reflect.DeepEqual(replayed, policy) {
			t.Fatal("idempotent policy replay:", replayed, err)
		}
		changed := command
		changed.AIMode = "disabled"
		if _, err = f.Assessment.PutPolicy(ctx, request, employee, changed); !errors.Is(err, fault.Mismatch) {
			t.Fatal("changed command under one key must mismatch:", err)
		}
		if _, err = f.Assessment.PutPolicy(ctx, assessmentRequest(f.FollowupManager), employee, command); !errors.Is(err, fault.Conflict) {
			t.Fatal("stale policy revision must conflict:", err)
		}

		scheduled, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, interview.CreateCommand{ScheduledAt: f.Now.Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano), Participants: []interview.Party{{Kind: "subject", ID: f.Owner.SubjectID}, {Kind: "employee", ID: employee}}})
		if err != nil {
			t.Fatal("real scheduled interview:", err)
		}
		due := f.Now.AddDate(0, 0, -1).Format("2006-01-02")
		action, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), scheduled.ID, interview.ActionCommand{ExpectedRevision: scheduled.Revision, MinimalSharedText: "SYNTHETIC_ASSESSMENT_ACTION", Owner: interview.Party{Kind: "employee", ID: employee}, DueDate: &due})
		if err != nil || action.Status != "todo" || action.InterviewRevision == nil {
			t.Fatal("real open action:", action, err)
		}
		started := f.Now.Add(-90 * time.Minute).Format(time.RFC3339Nano)
		running, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), scheduled.ID, interview.TransitionCommand{Action: "start", ExpectedRevision: *action.InterviewRevision, ActualStartedAt: &started})
		if err != nil {
			t.Fatal("real interview start:", err)
		}
		ended := f.Now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
		if _, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), scheduled.ID, interview.TransitionCommand{Action: "complete", ExpectedRevision: running.Revision, ActualEndedAt: &ended}); err != nil {
			t.Fatal("real interview completion:", err)
		}

		status, err := f.Assessment.Status(ctx, assessmentRequest(f.FollowupManager), employee, assessment.StatusQuery{From: "2026-10-01", To: "2026-11-01"})
		if err != nil || status.State != "configured" || status.AIState != "blocked" || status.AIBlockReason != "automation_not_enabled" || status.Coverage.Interviews != "complete" || status.Coverage.Actions != "complete" {
			t.Fatal("configured deterministic status:", status, err)
		}
		var matched, scheduledOnly bool
		for _, item := range status.Items {
			if item.Facts.OccurredCount == 1 {
				matched = item.Facts.ScheduledCount == 0 && item.State == "completed" && item.Facts.CompleteCount == 1 && item.Facts.OpenActionCount == 1 && item.Facts.OverdueActionCount == 1
			} else if item.Facts.ScheduledCount == 1 {
				scheduledOnly = item.Facts.OpenActionCount == 0 && item.Facts.DueActionCount == 0 && item.Facts.OverdueActionCount == 0
			} else if item.Facts.OpenActionCount != 0 || item.Facts.DueActionCount != 0 || item.Facts.OverdueActionCount != 0 {
				t.Fatal("action facts leaked into a different follow-up window:", item)
			}
		}
		if !matched || !scheduledOnly {
			t.Fatal("scheduled and actual/action facts were not attributed to their separate windows:", status.Items)
		}

		issueInterviewRead(t, f, employee)
		partial, err := f.Assessment.Status(ctx, assessmentRequest(f.Reader), employee, assessment.StatusQuery{})
		if err != nil || partial.Coverage.Actions != "partial_access" || partial.Coverage.Notes != "not_required" {
			t.Fatal("partial coverage must stay explicit without inventing action facts:", partial, err)
		}
		for _, item := range partial.Items {
			if item.Facts.OpenActionCount != 0 || item.State != "partial_access" {
				t.Fatal("partial reader received hidden action facts or a complete state:", item)
			}
		}
	})
}

func TestAssessmentPolicyReplayReturnsOriginalAfterNewerPolicy(t *testing.T) {
	assessmentBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := assessmentEmployee(t, f)
		firstCommand := assessment.PolicyCommand{
			ExpectedRevision: "0", Cadence: assessment.Cadence{Unit: "week", Count: 1},
			AnchorDate: "2026-10-01", Timezone: "UTC", DueOffsetDays: 1, LocalDueTime: "17:00", WindowThrough: "2026-11-01",
			Purpose: "interview_followup", AIMode: "periodic_structured_v1", RequiredFields: []string{"actual_started_at"},
		}
		firstRequest := assessmentRequest(f.FollowupManager)
		first, err := f.Assessment.PutPolicy(ctx, firstRequest, employee, firstCommand)
		if err != nil {
			t.Fatal("first policy:", err)
		}
		secondCommand := firstCommand
		secondCommand.ExpectedRevision = "1"
		secondCommand.AIMode = "disabled"
		second, err := f.Assessment.PutPolicy(ctx, assessmentRequest(f.FollowupManager), employee, secondCommand)
		if err != nil || second.Revision != "2" {
			t.Fatal("newer policy:", second, err)
		}
		replayed, err := f.Assessment.PutPolicy(ctx, firstRequest, employee, firstCommand)
		if err != nil || !reflect.DeepEqual(replayed, first) {
			t.Fatal("original replay after newer policy:", replayed, err)
		}
		changed := firstCommand
		changed.AIMode = "manual_approved"
		if _, err = f.Assessment.PutPolicy(ctx, firstRequest, employee, changed); !errors.Is(err, fault.Mismatch) {
			t.Fatal("changed command under original key must still mismatch:", err)
		}
		status, err := f.Assessment.Status(ctx, assessmentRequest(f.FollowupManager), employee, assessment.StatusQuery{})
		if err != nil || status.Policy == nil || status.Policy.Revision != "2" || status.Policy.AIMode != "disabled" {
			t.Fatal("replay changed current policy:", status, err)
		}
	})
}
