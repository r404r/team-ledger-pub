package assessment_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestAssessmentIndependentApprovalLeaseFencingEncryptedDraftAndPublish(t *testing.T) {
	assessmentBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		deletePublish := "DELETE FROM capability_assignment WHERE org_id=? AND subject_id=? AND capability='assessment.publish'"
		if f.Backend == "postgres" {
			deletePublish = "DELETE FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 AND capability='assessment.publish'"
		}
		if _, err := f.Repo.DB.Exec(deletePublish, f.OrgID, f.FollowupManager.SubjectID); err != nil {
			t.Fatal("remove requester review capability:", err)
		}
		employee := assessmentEmployee(t, f)
		anchor := f.Now.UTC().Format("2006-01-02")
		through := f.Now.UTC().AddDate(0, 0, 15).Format("2006-01-02")
		_, err := f.Assessment.PutPolicy(ctx, assessmentRequest(f.FollowupManager), employee, assessment.PolicyCommand{
			ExpectedRevision: "0", Cadence: assessment.Cadence{Unit: "week", Count: 1}, AnchorDate: anchor,
			Timezone: "UTC", DueOffsetDays: 0, LocalDueTime: "23:00", WindowThrough: through,
			Purpose: "interview_followup", AIMode: "manual_approved", RequiredFields: []string{"actual_started_at", "actual_ended_at"},
		})
		if err != nil {
			t.Fatal("policy:", err)
		}
		scheduled, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, interview.CreateCommand{
			ScheduledAt:  f.Now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			Participants: []interview.Party{{Kind: "subject", ID: f.Owner.SubjectID}, {Kind: "employee", ID: employee}},
		})
		if err != nil {
			t.Fatal("source interview:", err)
		}
		status, err := f.Assessment.Status(ctx, assessmentRequest(f.FollowupManager), employee, assessment.StatusQuery{})
		if err != nil || len(status.Items) != 1 {
			t.Fatal("current window:", status, err)
		}
		input, err := f.Assessment.RequestAssessment(ctx, assessmentRequest(f.FollowupManager), employee, assessment.AssessmentCommand{WindowID: status.Items[0].Window.ID})
		if err != nil || input.Status != "proposed" || input.Input.Template != "periodic_structured_v1" {
			t.Fatal("proposed minimal input:", input, err)
		}
		_, err = f.Assessment.ApproveAssessment(ctx, assessmentRequest(f.FollowupManager), employee, assessment.ApproveCommand{InputID: input.ID, ProviderPolicyID: f.AssessmentProviderID, Audience: "manager_followup"})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("requester must not self-approve:", err)
		}
		job, err := f.Assessment.ApproveAssessment(ctx, assessmentRequest(f.Manager), employee, assessment.ApproveCommand{InputID: input.ID, ProviderPolicyID: f.AssessmentProviderID, Audience: "manager_followup"})
		if err != nil || job.State != "queued" {
			t.Fatal("independent approval:", job, err)
		}
		worker := assessment.WorkerRequest{WorkerID: f.AssessmentWorkerID, CertDigest: f.AssessmentWorkerDigest, Key: value.NewID(), RequestID: value.NewID()}
		lease, err := f.Assessment.Claim(ctx, worker)
		if err != nil || lease.JobID != job.ID || lease.Attempt != 1 || lease.Fence != 1 {
			t.Fatal("leased job:", lease, err)
		}
		replayedLease, err := f.Assessment.Claim(ctx, worker)
		if err != nil || replayedLease.JobID != lease.JobID || replayedLease.Token != lease.Token || replayedLease.Fence != lease.Fence {
			t.Fatal("claim receipt replay:", replayedLease, err)
		}
		bad := lease
		replacement := "0"
		if bad.Token[len(bad.Token)-1] == '0' {
			replacement = "1"
		}
		bad.Token = bad.Token[:len(bad.Token)-1] + replacement
		if _, err = f.Assessment.Heartbeat(ctx, worker, bad.JobID, bad.Token, bad.Fence); !errors.Is(err, fault.Conflict) {
			t.Fatal("stale token must fail:", err)
		}
		prohibited := assessment.ResultDocument{Summary: "Employee performance rating", Claims: []string{"Rank the employee."}, Sources: []assessment.Citation{{Kind: "followup_window", ID: lease.Input.Window.ID, Version: lease.Input.Window.PolicyRevision}}}
		if _, err = f.Assessment.Submit(ctx, worker, lease, prohibited); !errors.Is(err, fault.Invalid) {
			t.Fatal("scoring/ranking output must be rejected:", err)
		}
		prohibited.Summary, prohibited.Claims = "Employee health diagnosis", []string{"Follow up."}
		if _, err = f.Assessment.Submit(ctx, worker, lease, prohibited); !errors.Is(err, fault.Invalid) {
			t.Fatal("health-diagnosis output must be rejected:", err)
		}
		document := assessment.ResultDocument{Summary: "Synthetic follow-up assessment", Claims: []string{"No completed interview was recorded in this window."}, Sources: []assessment.Citation{{Kind: "followup_window", ID: lease.Input.Window.ID, Version: lease.Input.Window.PolicyRevision}}}
		draft, err := f.Assessment.Submit(ctx, worker, lease, document)
		if err != nil || draft.Status != "draft" || draft.Revision != "1" {
			t.Fatal("worker result:", draft, err)
		}
		replayed, err := f.Assessment.Submit(ctx, worker, lease, document)
		if err != nil || replayed.ID != draft.ID || replayed.Revision != draft.Revision {
			t.Fatal("accepted worker result receipt replay:", replayed, err)
		}
		var exported []map[string]any
		_, err = f.Assessment.ExportResults(ctx, assessmentRequest(f.FollowupManager), assessment.ExportCommand{Format: "ndjson", Objects: []assessment.ExportObject{{Kind: "assessment_result", ID: draft.ID, ExpectedRevision: draft.Revision}}}, func(event assessment.ExportEvent) error {
			var decoded map[string]any
			if decodeErr := json.Unmarshal(event.EncodedJSON, &decoded); decodeErr != nil {
				return decodeErr
			}
			exported = append(exported, decoded)
			return nil
		})
		if err != nil || len(exported) != 3 || exported[1]["kind"] != "assessment_result" {
			t.Fatal("bounded AI result export:", exported, err)
		}
		var plaintextCount int
		query := "SELECT count(*) FROM assessment_payload WHERE instr(CAST(sealed_bytes AS TEXT),?)>0"
		if f.Backend == "postgres" {
			query = "SELECT count(*) FROM assessment_payload WHERE position($1::bytea in sealed_bytes)>0"
		}
		if err = f.Repo.DB.QueryRow(query, []byte(document.Summary)).Scan(&plaintextCount); err != nil || plaintextCount != 0 {
			t.Fatal("plaintext crossed encrypted boundary:", plaintextCount, err)
		}
		samples, sampleErr := f.Repo.BackupKeySamples(ctx)
		assessmentSample := false
		for _, sample := range samples {
			if sample.Domain == "assessment" {
				dek, unwrapErr := f.Assessment.Cipher.Wrapper.Unwrap(ctx, sample.Key)
				assessmentSample = unwrapErr == nil && len(dek) == 32
				clear(dek)
				break
			}
		}
		if sampleErr != nil || !assessmentSample {
			t.Fatal("restore inventory must probe assessment payload with the assessment wrapper:", samples, sampleErr)
		}

		read, err := f.Assessment.GetResult(ctx, assessmentRequest(f.Manager), employee, draft.ID)
		if err != nil || read.Document.Summary != document.Summary {
			t.Fatal("human read:", read, err)
		}
		if _, err = f.Assessment.TransitionResult(ctx, assessmentRequest(f.FollowupManager), employee, assessment.ResultCommand{ResultID: draft.ID, ExpectedRevision: "1", Action: "edit", Document: document}); !errors.Is(err, fault.NotFound) {
			t.Fatal("assessment reader/requester must not edit draft:", err)
		}
		approvedSourceID := document.Sources[0].ID
		document.Sources[0].ID = value.NewID()
		if _, err = f.Assessment.TransitionResult(ctx, assessmentRequest(f.Manager), employee, assessment.ResultCommand{ResultID: draft.ID, ExpectedRevision: "1", Action: "edit", Document: document}); !errors.Is(err, fault.Invalid) {
			t.Fatal("human edit must retain approved citations:", err)
		}
		document.Sources[0].ID = approvedSourceID
		document.Summary = "Human-reviewed follow-up assessment"
		edited, err := f.Assessment.TransitionResult(ctx, assessmentRequest(f.Manager), employee, assessment.ResultCommand{ResultID: draft.ID, ExpectedRevision: "1", Action: "edit", Document: document})
		if err != nil || edited.Revision != "2" {
			t.Fatal("human edit:", edited, err)
		}
		published, err := f.Assessment.TransitionResult(ctx, assessmentRequest(f.Manager), employee, assessment.ResultCommand{ResultID: draft.ID, ExpectedRevision: "2", Action: "publish"})
		if err != nil || published.Status != "published" || published.Revision != strconv.Itoa(2) {
			t.Fatal("human publish:", published, err)
		}
		if _, err = f.Assessment.TransitionResult(ctx, assessmentRequest(f.Manager), employee, assessment.ResultCommand{ResultID: draft.ID, ExpectedRevision: "2", Action: "publish"}); !errors.Is(err, fault.Conflict) {
			t.Fatal("published result is terminal:", err)
		}
		jobs, err := f.Assessment.Jobs(ctx, assessmentRequest(f.Manager), employee)
		if err != nil || len(jobs) != 1 || jobs[0].State != "completed" || jobs[0].CompletedAt.Equal(time.Time{}) {
			t.Fatal("persistent job view:", jobs, err)
		}
		started := f.Now.Add(-time.Hour).Format(time.RFC3339Nano)
		running, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), scheduled.ID, interview.TransitionCommand{Action: "start", ExpectedRevision: scheduled.Revision, ActualStartedAt: &started})
		if err != nil {
			t.Fatal("source mutation:", err)
		}
		if _, err = f.Assessment.GetResult(ctx, assessmentRequest(f.Manager), employee, draft.ID); !errors.Is(err, fault.NotFound) {
			t.Fatal("source mutation must make invalidated plaintext unreadable:", err)
		}
		replacementInput, err := f.Assessment.RequestAssessment(ctx, assessmentRequest(f.FollowupManager), employee, assessment.AssessmentCommand{WindowID: input.WindowID})
		if err != nil || replacementInput.Status != "proposed" {
			t.Fatal("invalidated generation must allow a replacement proposal:", replacementInput, err)
		}
		ended := f.Now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
		if _, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), scheduled.ID, interview.TransitionCommand{Action: "complete", ExpectedRevision: running.Revision, ActualEndedAt: &ended}); err != nil {
			t.Fatal("second source mutation:", err)
		}
		if _, err = f.Assessment.ApproveAssessment(ctx, assessmentRequest(f.Manager), employee, assessment.ApproveCommand{InputID: replacementInput.ID, ProviderPolicyID: f.AssessmentProviderID, Audience: "manager_followup"}); !errors.Is(err, fault.Conflict) {
			t.Fatal("source mutation must invalidate an unapproved proposal:", err)
		}
	})
}
func TestAssessmentPeriodicSchedulerStableGenerationAndRestartDedupe(t *testing.T) {
	assessmentBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := assessmentEmployee(t, f)
		anchor := f.Now.UTC().AddDate(0, 0, -14).Format("2006-01-02")
		through := f.Now.UTC().AddDate(0, 0, 1).Format("2006-01-02")
		_, err := f.Assessment.PutPolicy(ctx, assessmentRequest(f.Owner), employee, assessment.PolicyCommand{
			ExpectedRevision: "0", Cadence: assessment.Cadence{Unit: "week", Count: 1}, AnchorDate: anchor,
			Timezone: "UTC", DueOffsetDays: 0, LocalDueTime: "00:00", WindowThrough: through,
			Purpose: "interview_followup", AIMode: "periodic_structured_v1", RequiredFields: []string{"actual_started_at"},
			Standing: &assessment.StandingPolicyCommand{ServiceSubjectID: f.FollowupManager.SubjectID, Audience: "manager_followup", ExpiresAt: f.Now.Add(24 * time.Hour).Format(time.RFC3339Nano), ProviderPolicyID: f.AssessmentProviderID, TemplateVersion: "periodic_structured_v1"},
		})
		if err != nil {
			t.Fatal("standing policy:", err)
		}
		first, err := f.Assessment.ScanDue(ctx)
		if err != nil || first.Enqueued == 0 || first.Blocked != 0 {
			t.Fatal("first persistent scan:", first, err)
		}
		second, err := f.Assessment.ScanDue(ctx)
		if err != nil || second.Enqueued != 0 {
			t.Fatal("restart/multi-instance dedupe:", second, err)
		}
		jobs, err := f.Assessment.Jobs(ctx, assessmentRequest(f.Owner), employee)
		if err != nil || len(jobs) != first.Enqueued {
			t.Fatal("one stable job per due generation:", len(jobs), first, err)
		}
		if err = f.Exec(ctx, "UPDATE assessment_job SET deadline_at=? WHERE org_id=? AND state='queued'", "UPDATE assessment_job SET deadline_at=$1 WHERE org_id=$2 AND state='queued'", f.Repo.BindTime(f.Now), f.OrgID); err != nil {
			t.Fatal("expire queued jobs:", err)
		}
		_, err = f.Assessment.Claim(ctx, assessment.WorkerRequest{WorkerID: f.AssessmentWorkerID, CertDigest: f.AssessmentWorkerDigest, Key: value.NewID(), RequestID: value.NewID()})
		if !errors.Is(err, fault.NotFound) {
			t.Fatal("expired queued job must not be leased:", err)
		}
		var expiredInputs int
		expiredQuery := "SELECT count(*) FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=? AND j.state='failed' AND j.error_code='deadline_exceeded' AND i.status='invalidated'"
		if f.Backend == "postgres" {
			expiredQuery = "SELECT count(*) FROM assessment_job j JOIN approved_assessment_input i ON i.org_id=j.org_id AND i.id=j.input_id WHERE j.org_id=$1 AND j.state='failed' AND j.error_code='deadline_exceeded' AND i.status='invalidated'"
		}
		if err = f.Repo.DB.QueryRowContext(ctx, expiredQuery, f.OrgID).Scan(&expiredInputs); err != nil || expiredInputs != first.Enqueued {
			t.Fatal("expired queued job and approved input must close atomically:", expiredInputs, err)
		}
		replacement, err := f.Assessment.ScanDue(ctx)
		if err != nil || replacement.Enqueued == 0 {
			t.Fatal("expired queued input must release its generation for replacement:", replacement, err)
		}
		provider := f.Assessment.ProviderPolicies[f.AssessmentProviderID]
		provider.Enabled = false
		f.Assessment.ProviderPolicies[f.AssessmentProviderID] = provider
		blocked, err := f.Assessment.ScanDue(ctx)
		if err != nil || blocked.Blocked == 0 {
			t.Fatal("disabled provider must persist blocked scan:", blocked, err)
		}
		provider.Enabled, provider.ExpiresAt = true, f.Now
		f.Assessment.ProviderPolicies[f.AssessmentProviderID] = provider
		expired, err := f.Assessment.ScanDue(ctx)
		if err != nil || expired.Blocked == 0 {
			t.Fatal("expired provider approval must dynamically block scan:", expired, err)
		}
		var blockedRows int
		query := "SELECT count(*) FROM followup_window WHERE org_id=? AND employee_id=? AND automation_state='blocked' AND block_reason='provider_not_approved' AND last_scanned_at IS NOT NULL"
		if f.Backend == "postgres" {
			query = "SELECT count(*) FROM followup_window WHERE org_id=$1 AND employee_id=$2 AND automation_state='blocked' AND block_reason='provider_not_approved' AND last_scanned_at IS NOT NULL"
		}
		if err = f.Repo.DB.QueryRow(query, f.OrgID, employee).Scan(&blockedRows); err != nil || blockedRows == 0 {
			t.Fatal("blocked scan heartbeat:", blockedRows, err)
		}
	})
}
