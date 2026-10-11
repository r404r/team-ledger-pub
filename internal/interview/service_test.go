package interview_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func interviewBackends(t *testing.T, run func(*testing.T, *testsupport.Fixture)) {
	t.Helper()
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, testsupport.NewHarness(t, backend)) })
	}
}
func interviewEmployee(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	r, err := f.Service.Create(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateCommand{Profile: organization.Profile{DisplayName: "SYNTHETIC_INTERVIEW_EMPLOYEE"}, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("real employee setup:", err)
	}
	return r.ID
}
func scheduledInterview(t *testing.T, f *testsupport.Fixture, employee string) interview.Result {
	t.Helper()
	r, err := f.Interviews.Create(context.Background(), f.InterviewRequest(f.Owner), employee, interview.CreateCommand{ScheduledAt: f.Now.Add(-2 * time.Hour).Format(time.RFC3339Nano), Participants: []interview.Party{{Kind: "subject", ID: f.Owner.SubjectID}, {Kind: "employee", ID: employee}}})
	if err != nil || r.Status != "scheduled" || r.Revision != "1" {
		t.Fatal("scheduled interview setup:", r, err)
	}
	return r
}
func interviewDetail(t *testing.T, f *testsupport.Fixture, id string) interview.DetailView {
	t.Helper()
	v, err := f.Interviews.Detail(context.Background(), f.InterviewRequest(f.Owner), id, interview.DetailQuery{IncludeSections: []string{"shared", "manager_private", "hr_confidential"}, IncludeActions: true})
	if err != nil {
		t.Fatal("real interview reload:", err)
	}
	return v
}
func saveInterviewNote(t *testing.T, f *testsupport.Fixture, id string, cmd interview.NoteCommand) interview.Result {
	t.Helper()
	r, err := f.Interviews.SaveNote(context.Background(), f.InterviewRequest(f.Owner), id, cmd)
	if err != nil || r.HeadID == nil || r.HeadRevision == nil || r.VersionNo == nil {
		t.Fatal("real immutable note setup:", r, err)
	}
	return r
}
func readInterviewNote(t *testing.T, f *testsupport.Fixture, id string) interview.NoteView {
	t.Helper()
	v, err := f.Interviews.NoteVersion(context.Background(), f.InterviewRequest(f.Owner), id)
	if err != nil {
		t.Fatal("real immutable note read:", err)
	}
	return v
}
func interviewFacts(t *testing.T, f *testsupport.Fixture) map[string]int {
	t.Helper()
	result := make(map[string]int)
	for _, table := range []string{"interview", "interview_event", "interview_participant", "note_head", "note_version", "action_item", "action_item_event", "interview_payload", "source_reference", "interview_receipt"} {
		result[table] = f.Count(t, table)
	}
	return result
}
func requireInterviewFacts(t *testing.T, f *testsupport.Fixture, want map[string]int) {
	t.Helper()
	if got := interviewFacts(t, f); !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected operation changed aggregate/history/payload/source/receipt facts: got %v want %v", got, want)
	}
}
func grantInterview(t *testing.T, f *testsupport.Fixture, who testsupport.Credential, employee, capability, category string, target *authz.ObjectReference, sources ...authz.ObjectReference) authz.Result {
	t.Helper()
	var epoch int64
	query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	request := authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}
	command := authz.IssueCommand{SubjectID: who.SubjectID, Capability: capability, Category: category, Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "interview_followup", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: capability == "note.publish" || capability == "sensitive.export", ObjectRef: target, ApprovedSourceRefs: sources, AuthorityID: f.AuthorityIDs[capability+"/"+category], ExpectedRevision: strconv.FormatInt(epoch, 10)}
	r, err := f.Authz.Issue(context.Background(), request, command)
	if err != nil {
		t.Fatalf("approved real %s/%s grant: %v", capability, category, err)
	}
	return r
}
func revokeInterviewGrant(t *testing.T, f *testsupport.Fixture, grant authz.Result) {
	t.Helper()
	var epoch int64
	query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	_, err := f.Authz.Revoke(context.Background(), authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, grant.ID, authz.RevokeCommand{ExpectedRevision: grant.Revision, ExpectedAuthEpoch: strconv.FormatInt(epoch, 10), Reason: "policy_change"})
	if err != nil {
		t.Fatal("real grant revocation:", err)
	}
}

func TestInterviewBackfillRetainsActualRecordedAndParticipants(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		start, end := f.Now.Add(-72*time.Hour).Format(time.RFC3339Nano), f.Now.Add(-71*time.Hour).Format(time.RFC3339Nano)
		cmd := interview.CreateCommand{ScheduledAt: f.Now.Add(-240 * time.Hour).Format(time.RFC3339Nano), Backfilled: true, ActualStartedAt: &start, ActualEndedAt: &end, Participants: []interview.Party{{Kind: "employee", ID: employee}, {Kind: "subject", ID: f.Reader.SubjectID}}}
		r, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, cmd)
		if err != nil || r.Status != "completed" || r.Revision != "1" {
			t.Fatal("backfill must create completed fact:", r, err)
		}
		v := interviewDetail(t, f, r.ID).Interview
		if !v.Backfilled || v.ActualStartedAt == nil || v.ActualEndedAt == nil || !v.ActualStartedAt.Equal(f.Now.Add(-72*time.Hour)) || !v.ActualEndedAt.Equal(f.Now.Add(-71*time.Hour)) || !v.RecordedAt.Equal(f.Now) || v.AuthorSubjectID != f.Owner.SubjectID || !reflect.DeepEqual(v.Participants, cmd.Participants) {
			t.Fatalf("actual/recorded/author/participants lost: %+v", v)
		}
		before := interviewFacts(t, f)
		for _, action := range []string{"start", "complete", "cancel"} {
			_, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: action, ExpectedRevision: "1", ActualStartedAt: &start, ActualEndedAt: &end, Reason: "SYNTHETIC_TERMINAL_REASON"})
			if !errors.Is(err, fault.Conflict) {
				t.Fatalf("completed backfill %s must conflict: %v", action, err)
			}
		}
		requireInterviewFacts(t, f, before)
		if after := interviewDetail(t, f, r.ID).Interview; !reflect.DeepEqual(v, after) {
			t.Fatal("terminal attempt altered historical actual/recorded facts")
		}
		page, err := f.Interviews.List(ctx, f.InterviewRequest(f.Owner), employee, interview.ListQuery{From: f.Now.Add(-72 * time.Hour).Format("2006-01-02"), To: f.Now.Add(-48 * time.Hour).Format("2006-01-02"), Status: "completed", Limit: 1})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != r.ID || page.Consistency != "current" {
			t.Fatal("calendar must use actual occurrence, not backfill scheduled/recorded date:", page, err)
		}
		if _, err = f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{}); !errors.Is(err, fault.NotFound) {
			t.Fatal("participant identity must not create interview authority:", err)
		}
	})
}

func TestInterviewThreeCategoriesDraftPublishAndCompletedCorrection(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		r := scheduledInterview(t, f, interviewEmployee(t, f))
		type history struct {
			draft, published interview.Result
			envelope         []byte
		}
		histories := make(map[string]history)
		for _, category := range []string{"shared", "manager_private", "hr_confidential"} {
			draft := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: category, ExpectedHeadRevision: "0", Text: "SYNTHETIC_DRAFT_" + category, Action: "save_draft"})
			if draft.Status != "draft" || *draft.VersionNo != "1" || *draft.HeadRevision != "1" {
				t.Fatal("first draft revision must be explicit:", draft)
			}
			record, err := f.Repo.InterviewVersion(ctx, f.OrgID, draft.ID)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := f.Repo.InterviewPayload(ctx, f.OrgID, record.PayloadID)
			if err != nil {
				t.Fatal(err)
			}
			published := saveInterviewNote(t, f, r.ID, interview.NoteCommand{HeadID: draft.HeadID, Category: category, ExpectedHeadRevision: *draft.HeadRevision, Text: "SYNTHETIC_PUBLISHED_" + category, EditReason: "SYNTHETIC_REVIEW", Action: "publish", SupersedesVersionID: &draft.ID})
			if published.Status != "published" || *published.VersionNo != "2" || *published.HeadRevision != "2" || *published.HeadID != *draft.HeadID {
				t.Fatal("publish must append same-head version:", published)
			}
			histories[category] = history{draft, published, bytes.Clone(payload.Envelope.SealedBytes)}
		}
		started := f.Now.Add(-time.Hour).Format(time.RFC3339Nano)
		current := interviewDetail(t, f, r.ID).Interview
		run, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "start", ExpectedRevision: current.Revision, ActualStartedAt: &started})
		if err != nil || run.Status != "in_progress" {
			t.Fatal("normal start:", run, err)
		}
		ended := f.Now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
		completed, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "complete", ExpectedRevision: run.Revision, ActualEndedAt: &ended})
		if err != nil || completed.Status != "completed" {
			t.Fatal("normal complete:", completed, err)
		}
		completedView := interviewDetail(t, f, r.ID).Interview
		for category, h := range histories {
			cmd := interview.NoteCommand{HeadID: h.published.HeadID, Category: category, ExpectedHeadRevision: *h.published.HeadRevision, Text: "SYNTHETIC_CORRECTION_" + category, EditReason: "SYNTHETIC_EXPLICIT_CORRECTION", Action: "publish", SupersedesVersionID: &h.published.ID}
			correction := saveInterviewNote(t, f, r.ID, cmd)
			if *correction.HeadRevision != "3" || *correction.VersionNo != "3" || *correction.HeadID != *h.draft.HeadID {
				t.Fatal("completed correction must append immutable same-category version")
			}
			old := readInterviewNote(t, f, h.draft.ID)
			published := readInterviewNote(t, f, h.published.ID)
			fixed := readInterviewNote(t, f, correction.ID)
			if old.Text != "SYNTHETIC_DRAFT_"+category || old.Status != "draft" || published.Text != "SYNTHETIC_PUBLISHED_"+category || published.Status != "published" || fixed.Text != cmd.Text || fixed.EditReason != cmd.EditReason || fixed.SupersedesVersionID == nil || *fixed.SupersedesVersionID != published.ID {
				t.Fatal("immutable draft/publication/correction content or lineage lost")
			}
			record, err := f.Repo.InterviewVersion(ctx, f.OrgID, h.draft.ID)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := f.Repo.InterviewPayload(ctx, f.OrgID, record.PayloadID)
			if err != nil || !bytes.Equal(payload.Envelope.SealedBytes, h.envelope) {
				t.Fatal("draft ciphertext was overwritten by publish/correction")
			}
		}
		after := interviewDetail(t, f, r.ID)
		if len(after.Sections) != 3 || f.Count(t, "note_version") != 9 || after.Interview.Status != "completed" || !after.Interview.RecordedAt.Equal(completedView.RecordedAt) || !after.Interview.ActualStartedAt.Equal(*completedView.ActualStartedAt) || !after.Interview.ActualEndedAt.Equal(*completedView.ActualEndedAt) {
			t.Fatal("corrections must preserve completed actual/recorded facts and all three histories")
		}
		for _, section := range after.Sections {
			if len(section.Versions) != 3 || section.PublishedVersionID == nil || section.HeadRevision == nil || *section.HeadRevision != "3" {
				t.Fatal("category history/head projection incomplete:", section)
			}
		}
	})
}

func TestInterviewActionOverdueSurvivesCompletionAndTerminalHistory(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		source := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_ACTION_SOURCE", Action: "publish"})
		due := f.Now.Add(-24 * time.Hour).Format("2006-01-02")
		refs := []interview.SourceRef{{Kind: "note_version", ID: source.ID, ExpectedVersion: *source.VersionNo}}
		current := interviewDetail(t, f, r.ID).Interview
		made, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: current.Revision, MinimalSharedText: "SYNTHETIC_MINIMAL_FOLLOWUP", Owner: interview.Party{Kind: "employee", ID: employee}, DueDate: &due, SourceRefs: refs})
		if err != nil || made.Status != "todo" || made.Revision != "1" || made.InterviewRevision == nil {
			t.Fatal("action creation:", made, err)
		}
		initial := interviewDetail(t, f, r.ID).ActionItems
		if len(initial) != 1 || !initial[0].Overdue || initial[0].DueDate == nil || *initial[0].DueDate != due || len(initial[0].Events) != 1 || !reflect.DeepEqual(initial[0].SourceRefs, refs) {
			t.Fatal("action must reload overdue due/source/original event:", initial)
		}
		started := f.Now.Add(-time.Hour).Format(time.RFC3339Nano)
		run, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "start", ExpectedRevision: *made.InterviewRevision, ActualStartedAt: &started})
		if err != nil {
			t.Fatal(err)
		}
		ended := f.Now.Add(-time.Minute).Format(time.RFC3339Nano)
		_, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "complete", ExpectedRevision: run.Revision, ActualEndedAt: &ended})
		if err != nil {
			t.Fatal(err)
		}
		outstanding := interviewDetail(t, f, r.ID).ActionItems[0]
		if outstanding.Status != "todo" || outstanding.Revision != "1" || !outstanding.Overdue {
			t.Fatal("interview completion must not auto-close overdue action")
		}
		noAliasFacts, noAliasCalls := interviewFacts(t, f), f.InterviewKMS.Calls.Load()
		if _, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "done", ExpectedRevision: "1"}); !errors.Is(err, fault.Invalid) {
			t.Fatal("done is a terminal status, not an accepted wire action alias:", err)
		}
		requireInterviewFacts(t, f, noAliasFacts)
		if f.InterviewKMS.Calls.Load() != noAliasCalls {
			t.Fatal("removed action alias reached KMS")
		}
		inProgress, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "start", ExpectedRevision: "1", SafeBlockerText: "SYNTHETIC_SAFE_BLOCKER"})
		if err != nil || inProgress.Status != "in_progress" || inProgress.Revision != "2" {
			t.Fatal("action start:", inProgress, err)
		}
		done, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "2"})
		if err != nil || done.Status != "done" || done.Revision != "3" {
			t.Fatal("action completion after interview completion:", done, err)
		}
		terminal := interviewDetail(t, f, r.ID).ActionItems[0]
		if terminal.Overdue || terminal.DueDate == nil || *terminal.DueDate != due || terminal.MinimalSharedText != outstanding.MinimalSharedText || terminal.Owner != outstanding.Owner || !reflect.DeepEqual(terminal.SourceRefs, refs) || !terminal.RecordedAt.Equal(outstanding.RecordedAt) || len(terminal.Events) != 3 {
			t.Fatal("terminal action must preserve due/source/owner/recorded/history while clearing overdue:", terminal)
		}
		statuses := make(map[string]string)
		for _, event := range terminal.Events {
			statuses[event.Revision] = event.Status
			if event.Revision == "2" && event.SafeBlockerText != "SYNTHETIC_SAFE_BLOCKER" {
				t.Fatal("historic blocker changed")
			}
		}
		if !reflect.DeepEqual(statuses, map[string]string{"1": "todo", "2": "in_progress", "3": "done"}) {
			t.Fatal("immutable action event sequence lost:", statuses)
		}
		before := interviewFacts(t, f)
		for _, action := range []string{"start", "complete", "cancel"} {
			_, err = f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: action, ExpectedRevision: "3"})
			if !errors.Is(err, fault.Conflict) {
				t.Fatalf("terminal action %s: %v", action, err)
			}
		}
		requireInterviewFacts(t, f, before)
	})
}

func TestInterviewRejectedCommandsLeaveNoPartialFacts(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		scheduled := f.Now.Add(-time.Hour).Format(time.RFC3339Nano)
		actual := f.Now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
		future := f.Now.Add(time.Minute).Format(time.RFC3339Nano)
		for name, cmd := range map[string]interview.CreateCommand{
			"unplanned actual":               {ScheduledAt: scheduled, ActualStartedAt: &actual},
			"missing backfill end":           {ScheduledAt: scheduled, Backfilled: true, ActualStartedAt: &actual},
			"future backfill":                {ScheduledAt: scheduled, Backfilled: true, ActualStartedAt: &actual, ActualEndedAt: &future},
			"reversed backfill":              {ScheduledAt: scheduled, Backfilled: true, ActualStartedAt: &actual, ActualEndedAt: &scheduled},
			"invalid timestamp":              {ScheduledAt: "2026-02-30T12:00:00Z"},
			"duplicate participant":          {ScheduledAt: scheduled, Participants: []interview.Party{{Kind: "subject", ID: f.Owner.SubjectID}, {Kind: "subject", ID: f.Owner.SubjectID}}},
			"cross organization participant": {ScheduledAt: scheduled, Participants: []interview.Party{{Kind: "subject", ID: f.OtherOwner.SubjectID}}},
			"untyped participant":            {ScheduledAt: scheduled, Participants: []interview.Party{{Kind: "arbitrary", ID: f.Owner.SubjectID}}},
		} {
			t.Run(name, func(t *testing.T) {
				before := interviewFacts(t, f)
				_, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, cmd)
				if !errors.Is(err, fault.Invalid) {
					t.Fatal("invalid creation must reject:", err)
				}
				requireInterviewFacts(t, f, before)
			})
		}
		r := scheduledInterview(t, f, employee)
		other := scheduledInterview(t, f, employee)
		note := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_VALID_NOTE", Action: "publish"})
		unrelated := saveInterviewNote(t, f, other.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_OTHER_HEAD", Action: "publish"})
		for name, cmd := range map[string]interview.NoteCommand{
			"wrong category":          {HeadID: note.HeadID, Category: "manager_private", ExpectedHeadRevision: "1", Text: "synthetic", EditReason: "synthetic", Action: "publish", SupersedesVersionID: &note.ID},
			"foreign interview head":  {HeadID: unrelated.HeadID, Category: "shared", ExpectedHeadRevision: "1", Text: "synthetic", EditReason: "synthetic", Action: "publish"},
			"foreign head supersedes": {HeadID: note.HeadID, Category: "shared", ExpectedHeadRevision: "1", Text: "synthetic", EditReason: "synthetic", Action: "publish", SupersedesVersionID: &unrelated.ID},
			"empty text":              {Category: "manager_private", ExpectedHeadRevision: "0", Text: " \n ", Action: "save_draft"},
			"unknown category":        {Category: "private", ExpectedHeadRevision: "0", Text: "synthetic", Action: "save_draft"},
			"unsupported source":      {Category: "manager_private", ExpectedHeadRevision: "0", Text: "synthetic", Action: "publish", SourceRefs: []interview.SourceRef{{Kind: "ai_summary", ID: note.ID, ExpectedVersion: "1"}}},
			"wrong source revision":   {HeadID: note.HeadID, Category: "shared", ExpectedHeadRevision: "1", Text: "synthetic", EditReason: "synthetic", Action: "publish", SourceRefs: []interview.SourceRef{{Kind: "note_version", ID: note.ID, ExpectedVersion: "2"}}},
		} {
			t.Run(name, func(t *testing.T) {
				before := interviewFacts(t, f)
				_, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), r.ID, cmd)
				if err == nil {
					t.Fatal("invalid note accepted")
				}
				if !errors.Is(err, fault.Invalid) && !errors.Is(err, fault.Conflict) && !errors.Is(err, fault.NotFound) {
					t.Fatal("invalid lineage/body must reject with domain error:", err)
				}
				requireInterviewFacts(t, f, before)
			})
		}
		for name, cmd := range map[string]interview.ActionCommand{
			"cross organization owner": {Owner: interview.Party{Kind: "subject", ID: f.OtherOwner.SubjectID}, MinimalSharedText: "synthetic"},
			"missing owner":            {MinimalSharedText: "synthetic"},
			"unknown owner":            {Owner: interview.Party{Kind: "employee", ID: value.NewID()}, MinimalSharedText: "synthetic"},
			"invalid due":              {Owner: interview.Party{Kind: "employee", ID: employee}, DueDate: new("2026-02-30"), MinimalSharedText: "synthetic"},
			"blank action text":        {Owner: interview.Party{Kind: "employee", ID: employee}, MinimalSharedText: " "},
		} {
			t.Run(name, func(t *testing.T) {
				cmd.ExpectedRevision = interviewDetail(t, f, r.ID).Interview.Revision
				before := interviewFacts(t, f)
				_, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, cmd)
				if !errors.Is(err, fault.Invalid) {
					t.Fatal("invalid action must reject:", err)
				}
				requireInterviewFacts(t, f, before)
			})
		}
		before := interviewFacts(t, f)
		if _, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "complete", ExpectedRevision: interviewDetail(t, f, r.ID).Interview.Revision, ActualEndedAt: &actual}); !errors.Is(err, fault.Conflict) {
			t.Fatal("scheduled cannot complete before start:", err)
		}
		if _, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "cancel", ExpectedRevision: interviewDetail(t, f, r.ID).Interview.Revision}); !errors.Is(err, fault.Invalid) {
			t.Fatal("cancellation requires explicit nonblank reason:", err)
		}
		requireInterviewFacts(t, f, before)
	})
}

func TestInterviewCurrentObjectReadProjectionAndSQLBeforeLimit(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		hidden := scheduledInterview(t, f, employee)
		visible := scheduledInterview(t, f, employee)
		// Repository order is canonical ID; arrange a definitely earlier hidden row.
		if hidden.ID > visible.ID {
			hidden, visible = visible, hidden
		}
		first := saveInterviewNote(t, f, visible.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXACT_OLD_VERSION", Action: "publish"})
		second := saveInterviewNote(t, f, visible.ID, interview.NoteCommand{HeadID: first.HeadID, Category: "shared", ExpectedHeadRevision: "1", Text: "SYNTHETIC_EXACT_OLD_VERSION", EditReason: "synthetic", Action: "publish", SupersedesVersionID: &first.ID})
		old, hiddenVersion := first, second
		if old.ID < hiddenVersion.ID {
			old, hiddenVersion = hiddenVersion, old
		}
		latest := saveInterviewNote(t, f, visible.ID, interview.NoteCommand{HeadID: second.HeadID, Category: "shared", ExpectedHeadRevision: "2", Text: "SYNTHETIC_HIDDEN_CURRENT_VERSION", EditReason: "synthetic", Action: "publish", SupersedesVersionID: &second.ID})
		private := saveInterviewNote(t, f, visible.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Text: "SYNTHETIC_HIDDEN_PRIVATE", Action: "publish"})
		grantInterview(t, f, f.Reader, employee, "note.read", "shared", &authz.ObjectReference{Kind: "note_version", ID: old.ID})
		exact, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), old.ID)
		if err != nil || exact.Text != "SYNTHETIC_EXACT_OLD_VERSION" || exact.VersionNo != *old.VersionNo || exact.SupersedesVersionID != nil {
			t.Fatal("exact immutable handover must not require broad interview metadata or disclose hidden predecessor:", exact, err)
		}
		grantInterview(t, f, f.Reader, employee, "interview.read", "metadata", &authz.ObjectReference{Kind: "interview", ID: visible.ID})
		f.InterviewKMS.Fail.Store(true)
		calls := f.InterviewKMS.Calls.Load()
		for _, id := range []string{latest.ID, hiddenVersion.ID, private.ID, value.NewID()} {
			denied, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), id)
			if !errors.Is(err, fault.NotFound) || denied.Text != "" {
				t.Fatal("exact old-version grant must not cover current/private/missing version:", denied, err)
			}
		}
		if _, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), hidden.ID, interview.DetailQuery{}); !errors.Is(err, fault.NotFound) {
			t.Fatal("interview object grant cannot fall back to whole employee:", err)
		}
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("unauthorized canonical objects reached KMS")
		}
		page, err := f.Interviews.List(ctx, f.InterviewRequest(f.Reader), employee, interview.ListQuery{Limit: 1})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != visible.ID || page.NextCursor != nil {
			t.Fatal("SQL object scope must filter hidden interview before page limit:", page, err)
		}
		f.InterviewKMS.Fail.Store(false)
		detail, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), visible.ID, interview.DetailQuery{IncludeSections: []string{"shared", "manager_private", "hr_confidential"}, IncludeActions: true, Category: "shared", Limit: 1})
		if err != nil || len(detail.Sections) != 1 || detail.NextCursor != nil || len(detail.ActionItems) != 0 {
			t.Fatal("hidden categories/versions must not consume visible page or produce hidden cursor:", detail, err)
		}
		section := detail.Sections[0]
		if section.Category != "shared" || section.HeadRevision != nil || section.PublishedVersionID != nil || section.DraftVersionID != nil || len(section.Versions) != 1 || section.Versions[0].ID != old.ID {
			t.Fatal("exact historical read leaked current head revision/pointers or versions:", section)
		}
		raw, err := json.Marshal(detail)
		if err != nil || bytes.Contains(raw, []byte(latest.ID)) || bytes.Contains(raw, []byte(hiddenVersion.ID)) || bytes.Contains(raw, []byte(private.ID)) || bytes.Contains(raw, []byte("SYNTHETIC_HIDDEN")) {
			t.Fatal("hidden object identifiers/content escaped projection")
		}
	})
}

func TestInterviewApprovedMinimizedSourcesRemainIndependentCurrentReads(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		private := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Text: "SYNTHETIC_PRIVATE_SOURCE_MUST_NOT_COPY", Action: "publish"})
		target := &authz.ObjectReference{Kind: "interview", ID: r.ID}
		source := authz.ObjectReference{Kind: "note_version", ID: private.ID}
		grantInterview(t, f, f.Owner, employee, "note.publish", "shared", target, source)
		cmd := interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_MANUAL_MINIMAL_SHARED", Action: "publish", SourceRefs: []interview.SourceRef{{Kind: "note_version", ID: private.ID, ExpectedVersion: *private.VersionNo}}}
		before := interviewFacts(t, f)
		calls := f.InterviewKMS.Calls.Load()
		if _, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), r.ID, cmd); !errors.Is(err, fault.Forbidden) {
			t.Fatal("cross-category source requires explicit minimization confirmation:", err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("unconfirmed source reached KMS")
		}
		cmd.ConfirmMinimized = true
		shared := saveInterviewNote(t, f, r.ID, cmd)
		grantInterview(t, f, f.Reader, employee, "note.read", "shared", &authz.ObjectReference{Kind: "note_version", ID: shared.ID})
		projected, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), shared.ID)
		if err != nil || projected.Text != cmd.Text || len(projected.SourceRefs) != 0 {
			t.Fatal("target read must not imply private source read or disclose source references:", projected, err)
		}
		raw, err := json.Marshal(projected)
		if err != nil || bytes.Contains(raw, []byte(private.ID)) || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_SOURCE")) || bytes.Contains(raw, []byte("manager_private")) {
			t.Fatal("source minimization leaked private tuple/content")
		}
		readGrant := grantInterview(t, f, f.Reader, employee, "note.read", "manager_private", &source)
		projected, err = f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), shared.ID)
		if err != nil || !reflect.DeepEqual(projected.SourceRefs, cmd.SourceRefs) || projected.Text != cmd.Text {
			t.Fatal("independent current source read must reveal only approved immutable reference:", projected, err)
		}
		revokeInterviewGrant(t, f, readGrant)
		projected, err = f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), shared.ID)
		if err != nil || len(projected.SourceRefs) != 0 || projected.Text != cmd.Text {
			t.Fatal("source read revocation must immediately remove only source metadata:", projected, err)
		}
		wrongEmployee := interviewEmployee(t, f)
		wrongInterview := scheduledInterview(t, f, wrongEmployee)
		before = interviewFacts(t, f)
		wrongCmd := cmd
		if _, err = f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), wrongInterview.ID, wrongCmd); !errors.Is(err, fault.Invalid) && !errors.Is(err, fault.NotFound) {
			t.Fatal("published source cannot cross target employee:", err)
		}
		requireInterviewFacts(t, f, before)
		if err = f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE subject_id=? AND capability='note.read' AND category='manager_private'", "UPDATE access_grant SET revoked=true WHERE subject_id=$1 AND capability='note.read' AND category='manager_private'", f.Owner.SubjectID); err != nil {
			t.Fatal(err)
		}
		cmd.HeadID, cmd.ExpectedHeadRevision, cmd.SupersedesVersionID, cmd.EditReason = shared.HeadID, *shared.HeadRevision, &shared.ID, "SYNTHETIC_SOURCE_RECHECK"
		before, calls = interviewFacts(t, f), f.InterviewKMS.Calls.Load()
		if _, err = f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), r.ID, cmd); !errors.Is(err, fault.NotFound) {
			t.Fatal("source approval cannot replace current independent source note.read:", err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("revoked source read reached KMS or copied source into target")
		}
	})
}

func TestInterviewReceiptsMismatchAndCurrentRevoke(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		request := f.InterviewRequest(f.Owner)
		cmd := interview.CreateCommand{ScheduledAt: f.Now.Add(-time.Hour).Format(time.RFC3339Nano)}
		first, err := f.Interviews.Create(ctx, request, employee, cmd)
		if err != nil {
			t.Fatal(err)
		}
		before := interviewFacts(t, f)
		calls, audits := f.InterviewKMS.Calls.Load(), f.Count(t, "audit_event")
		replay, err := f.Interviews.Create(ctx, request, employee, cmd)
		if err != nil || !reflect.DeepEqual(first, replay) {
			t.Fatal("same key must confirm original interview:", replay, err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls || f.Count(t, "audit_event") != audits {
			t.Fatal("creation confirmation created audit or touched KMS")
		}
		changed := cmd
		changed.ScheduledAt = f.Now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
		if _, err = f.Interviews.Create(ctx, request, employee, changed); !errors.Is(err, fault.Mismatch) {
			t.Fatal("same key changed command must mismatch:", err)
		}
		target := &authz.ObjectReference{Kind: "interview", ID: first.ID}
		grantInterview(t, f, f.Reader, employee, "note.read", "shared", target)
		writeGrant := grantInterview(t, f, f.Reader, employee, "note.write", "shared", target)
		noteRequest := f.InterviewRequest(f.Reader)
		noteCmd := interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_RECEIPT_BOUND_NOTE", Action: "save_draft"}
		saved, err := f.Interviews.SaveNote(ctx, noteRequest, first.ID, noteCmd)
		if err != nil {
			t.Fatal("real delegated note save:", err)
		}
		before = interviewFacts(t, f)
		calls, audits = f.InterviewKMS.Calls.Load(), f.Count(t, "audit_event")
		confirmed, err := f.Interviews.SaveNote(ctx, noteRequest, first.ID, noteCmd)
		if err != nil || !reflect.DeepEqual(saved, confirmed) {
			t.Fatal("note receipt must precede stale initial-head validation:", confirmed, err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls || f.Count(t, "audit_event") != audits {
			t.Fatal("note confirmation appended history/audit or reached KMS")
		}
		changedNote := noteCmd
		changedNote.Text = "SYNTHETIC_CHANGED_RECEIPT_NOTE"
		if _, err = f.Interviews.SaveNote(ctx, noteRequest, first.ID, changedNote); !errors.Is(err, fault.Mismatch) {
			t.Fatal("note key reuse must bind original canonical body:", err)
		}
		revokeInterviewGrant(t, f, writeGrant)
		calls = f.InterviewKMS.Calls.Load()
		if _, err = f.Interviews.SaveNote(ctx, noteRequest, first.ID, noteCmd); !errors.Is(err, fault.NotFound) {
			t.Fatal("receipt cannot revive currently revoked write right:", err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("revoked receipt confirmation reached KMS")
		}
		rows, err := f.Repo.DB.Query("SELECT result_json FROM interview_receipt")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var metadata map[string]any
			if json.Unmarshal([]byte(raw), &metadata) != nil || metadata["id"] == nil || bytes.Contains([]byte(raw), []byte(noteCmd.Text)) || bytes.Contains([]byte(raw), []byte("text")) {
				t.Fatal("receipt must be metadata-only JSON object:", raw)
			}
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInterviewWritesNeedIndependentReadAndPublishAlwaysNeedsMFA(t *testing.T) {
	for _, loss := range []string{"read", "mfa"} {
		t.Run(loss, func(t *testing.T) {
			interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx := context.Background()
				employee := interviewEmployee(t, f)
				r := scheduledInterview(t, f, employee)
				target := &authz.ObjectReference{Kind: "interview", ID: r.ID}
				grantInterview(t, f, f.Reader, employee, "note.write", "shared", target)
				grantInterview(t, f, f.Reader, employee, "note.publish", "shared", target)
				if loss == "mfa" {
					grantInterview(t, f, f.Reader, employee, "note.read", "shared", target)
					// Even a mistakenly permissive grant policy cannot bypass mandatory operation MFA.
					if err := f.Exec(ctx, "UPDATE access_grant SET mfa_required=0 WHERE subject_id=? AND capability='note.publish'", "UPDATE access_grant SET mfa_required=false WHERE subject_id=$1 AND capability='note.publish'", f.Reader.SubjectID); err != nil {
						t.Fatal(err)
					}
					if err := f.Exec(ctx, "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now.Add(-time.Microsecond)), f.Reader.Hash); err != nil {
						t.Fatal(err)
					}
				}
				before := interviewFacts(t, f)
				calls := f.InterviewKMS.Calls.Load()
				cmd := interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_DENIED_PUBLICATION", Action: "publish"}
				if _, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Reader), r.ID, cmd); !errors.Is(err, fault.NotFound) {
					t.Fatal("write/read/MFA are independent requirements:", err)
				}
				requireInterviewFacts(t, f, before)
				if f.InterviewKMS.Calls.Load() != calls {
					t.Fatal("missing independent read or current MFA reached KMS")
				}
			})
		})
	}
}

func TestInterviewExportRejectsEntireUnauthorizedSetBeforeKMS(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		shared := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXPORT_ALLOWED", Action: "publish"})
		private := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXPORT_DENIED", Action: "publish"})
		exact := &authz.ObjectReference{Kind: "note_version", ID: shared.ID}
		grantInterview(t, f, f.Reader, employee, "note.read", "shared", exact)
		exportGrant := grantInterview(t, f, f.Reader, employee, "sensitive.export", "shared", exact)
		before := interviewFacts(t, f)
		calls := f.InterviewKMS.Calls.Load()
		f.InterviewKMS.Fail.Store(true)
		events := []interview.ExportEvent{}
		cmd := interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "note_version", ID: shared.ID, ExpectedRevision: "1"}, {Kind: "note_version", ID: private.ID, ExpectedRevision: "1"}}}
		id, err := f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), cmd, func(event interview.ExportEvent) error { events = append(events, event); return nil })
		if !errors.Is(err, fault.NotFound) || id != "" || len(events) != 0 {
			t.Fatal("mixed unauthorized export must not prepare/header/release partial authorized content:", id, events, err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("unauthorized export set reached unavailable KMS")
		}
		f.InterviewKMS.Fail.Store(false)
		cmd.Objects = cmd.Objects[:1]
		request := f.InterviewRequest(f.Reader)
		events = nil
		id, err = f.Interviews.Export(ctx, request, cmd, func(event interview.ExportEvent) error { events = append(events, event); return nil })
		if err != nil || id == "" || len(events) != 3 || events[0].Kind != "header" || events[0].Status != "prepared" || events[1].Kind != "object" || events[1].NoteVersion == nil || events[1].NoteVersion.Text != "SYNTHETIC_EXPORT_ALLOWED" || events[2].Kind != "complete" {
			t.Fatal("authorized export stream must carry exact object between durable header and completion:", id, events, err)
		}
		facts := interviewFacts(t, f)
		replayEvents := []interview.ExportEvent{}
		replayID, err := f.Interviews.Export(ctx, request, cmd, func(event interview.ExportEvent) error { replayEvents = append(replayEvents, event); return nil })
		if err != nil || replayID != id || len(replayEvents) != 3 || replayEvents[1].NoteVersion == nil || replayEvents[1].NoteVersion.Text != events[1].NoteVersion.Text {
			t.Fatal("same canonical export key must reauthorize and restream same export ID:", replayID, replayEvents, err)
		}
		requireInterviewFacts(t, f, facts)
		changed := cmd
		changed.Objects = []interview.ExportObject{{Kind: "note_version", ID: shared.ID, ExpectedRevision: "2"}}
		calls = f.InterviewKMS.Calls.Load()
		if _, err = f.Interviews.Export(ctx, request, changed, func(interview.ExportEvent) error { t.Fatal("mismatched replay emitted data"); return nil }); !errors.Is(err, fault.Mismatch) {
			t.Fatal("export receipt must bind original expected immutable revision:", err)
		}
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("mismatched export receipt reached KMS")
		}
		revokeInterviewGrant(t, f, exportGrant)
		if _, err = f.Interviews.Export(ctx, request, cmd, func(interview.ExportEvent) error { t.Fatal("revoked export receipt emitted stream"); return nil }); !errors.Is(err, fault.NotFound) {
			t.Fatal("prepared export receipt cannot revive current export authority:", err)
		}
		requireInterviewFacts(t, f, facts)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("currently revoked export receipt reached KMS")
		}
	})
}

func TestInterviewConcurrentExportOriginalKeyKeepsEveryEncodedEventOnWinningReceipt(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		r := scheduledInterview(t, f, interviewEmployee(t, f))
		note := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXPORT_CONCURRENT_RECEIPT", Action: "publish"})
		request := f.InterviewRequest(f.Owner)
		command := interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "note_version", ID: note.ID, ExpectedRevision: "1"}}}
		before := f.Count(t, "interview_receipt")
		type outcome struct {
			id     string
			err    error
			events []interview.ExportEvent
		}
		consume := func() outcome {
			var out outcome
			out.id, out.err = f.Interviews.Export(ctx, request, command, func(event interview.ExportEvent) error {
				var decoded interview.ExportEvent
				if err := json.Unmarshal(event.EncodedJSON, &decoded); err != nil {
					return err
				}
				out.events = append(out.events, decoded)
				return nil
			})
			return out
		}
		arrived, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		f.InterviewKMS.BlockNextDecrypt(arrived, release)
		first := make(chan outcome, 1)
		go func() { first <- consume() }()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("first native export never reached external decrypt")
		}
		winner := consume()
		unblock()
		var delayed outcome
		select {
		case delayed = <-first:
		case <-time.After(5 * time.Second):
			t.Fatal("delayed native export never resumed")
		}
		if winner.err != nil || delayed.err != nil || winner.id == "" || delayed.id != winner.id {
			t.Fatal("same concurrent original command must confirm the single winning receipt:", winner.id, winner.err, delayed.id, delayed.err)
		}
		for _, out := range []outcome{winner, delayed} {
			if len(out.events) != 3 || out.events[0].Kind != "header" || out.events[1].Kind != "object" || out.events[2].Kind != "complete" || out.events[1].NoteVersion == nil || out.events[1].NoteVersion.ID != note.ID || out.events[1].NoteVersion.Text != "SYNTHETIC_EXPORT_CONCURRENT_RECEIPT" {
				t.Fatal("concurrent encoded consumer lost original object or completion:", out.events)
			}
			for _, event := range out.events {
				if event.ExportID != winner.id {
					t.Fatalf("encoded %s belongs to a discarded preparation: got %s want winning receipt %s", event.Kind, event.ExportID, winner.id)
				}
			}
		}
		if f.Count(t, "interview_receipt") != before+1 {
			t.Fatal("concurrent original command created more than one durable preparation")
		}
	})
}

func TestInterviewExportPartialOnCurrentPermissionLossAndWriterFailure(t *testing.T) {
	for _, interruption := range []string{"revoked", "writer"} {
		t.Run(interruption, func(t *testing.T) {
			interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx := context.Background()
				employee := interviewEmployee(t, f)
				r := scheduledInterview(t, f, employee)
				note := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXPORT_RELEASE_CHECK", Action: "publish"})
				exact := &authz.ObjectReference{Kind: "note_version", ID: note.ID}
				grantInterview(t, f, f.Reader, employee, "note.read", "shared", exact)
				exportGrant := grantInterview(t, f, f.Reader, employee, "sensitive.export", "shared", exact)
				before := f.Count(t, "interview_receipt")
				events := []interview.ExportEvent{}
				writerErr := errors.New("synthetic transport disconnected")
				id, err := f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "note_version", ID: note.ID, ExpectedRevision: "1"}}}, func(event interview.ExportEvent) error {
					events = append(events, event)
					if event.Kind == "header" {
						if f.Count(t, "interview_receipt") != before+1 {
							t.Fatal("export header preceded durable preparation receipt")
						}
						if interruption == "revoked" {
							revokeInterviewGrant(t, f, exportGrant)
						} else {
							return writerErr
						}
					}
					return nil
				})
				if err == nil || id == "" || len(events) != 2 || events[0].Kind != "header" || events[1].Kind != "partial" || events[1].Status != "partial" || events[1].Reason == "" {
					t.Fatal("permission/write failure must terminate partial, never complete:", id, events, err)
				}
				for _, event := range events {
					if event.NoteVersion != nil || event.ActionItem != nil || event.Interview != nil {
						t.Fatal("partial before first object released plaintext")
					}
				}
				var partial int
				if err := f.Repo.DB.QueryRow("SELECT count(*) FROM audit_event WHERE outcome='partial'").Scan(&partial); err != nil || partial != 1 {
					t.Fatal("partial stream lost mandatory partial audit:", partial, err)
				}
				if f.Count(t, "interview_receipt") != before+1 {
					t.Fatal("partial stream must retain only durable metadata preparation")
				}
			})
		})
	}
}

type interviewRaceResult struct {
	result interview.Result
	err    error
}

func raceInterviewCommands(t *testing.T, f *testsupport.Fixture, commands [2]func(context.Context, *interview.Service, interview.Request) (interview.Result, error)) [2]interviewRaceResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	second, err := store.Open(ctx, f.Backend, f.DSN)
	if err != nil {
		t.Fatal("second real independent connection pool:", err)
	}
	defer second.Close()
	sibling := &interview.Service{Store: second, Cipher: f.Interviews.Cipher, DigestKey: f.Interviews.DigestKey, CursorKey: f.Interviews.CursorKey, Now: f.Interviews.Now}
	services := [2]*interview.Service{f.Interviews, sibling}
	requests := [2]interview.Request{f.InterviewRequest(f.Owner), f.InterviewRequest(f.Owner)}
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() { cancel(); unblock() }()
	f.InterviewKMS.BlockEncrypt(2, arrived, release)
	ready := make(chan struct{})
	results := make(chan struct {
		index int
		value interviewRaceResult
	}, 2)
	for index := range 2 {
		go func() {
			<-ready
			r, err := commands[index](ctx, services[index], requests[index])
			results <- struct {
				index int
				value interviewRaceResult
			}{index, interviewRaceResult{r, err}}
		}()
	}
	close(ready)
	for range 2 {
		select {
		case <-arrived:
		case early := <-results:
			t.Fatalf("both commands must prepare real encryption outside transaction before CAS race; contender %d returned early: %v", early.index, early.value.err)
		case <-ctx.Done():
			t.Fatal("two independent connections failed to reach concurrent external encryption")
		}
	}
	unblock()
	var outcomes [2]interviewRaceResult
	for range 2 {
		select {
		case done := <-results:
			outcomes[done.index] = done.value
		case <-ctx.Done():
			t.Fatal("native CAS race did not finish")
		}
	}
	accepted, conflicts := 0, 0
	for _, outcome := range outcomes {
		if outcome.err == nil {
			accepted++
		} else if errors.Is(outcome.err, fault.Conflict) {
			conflicts++
		} else {
			t.Fatal("CAS loser must be domain conflict, not deadlock/storage failure:", outcome.err)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatalf("two independent concurrent connections require exactly one accepted mutation and one conflict: %+v", outcomes)
	}
	return outcomes
}

func TestInterviewCASRealConnectionsKnownZeroAndExistingHead(t *testing.T) {
	for _, initial := range []bool{true, false} {
		name := "existing_revision_one"
		if initial {
			name = "known_zero"
		}
		t.Run(name, func(t *testing.T) {
			interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				r := scheduledInterview(t, f, interviewEmployee(t, f))
				var base interview.Result
				expected := "0"
				if !initial {
					base = saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_CAS_ORIGINAL", Action: "publish"})
					expected = *base.HeadRevision
				}
				before := interviewFacts(t, f)
				commands := [2]func(context.Context, *interview.Service, interview.Request) (interview.Result, error){}
				for index := range 2 {
					cmd := interview.NoteCommand{Category: "shared", HeadID: base.HeadID, ExpectedHeadRevision: expected, Text: fmt.Sprintf("SYNTHETIC_CAS_CONTENDER_%d", index), EditReason: "SYNTHETIC_CAS_EDIT", Action: "publish"}
					if !initial {
						cmd.SupersedesVersionID = &base.ID
					}
					commands[index] = func(ctx context.Context, svc *interview.Service, req interview.Request) (interview.Result, error) {
						return svc.SaveNote(ctx, req, r.ID, cmd)
					}
				}
				outcomes := raceInterviewCommands(t, f, commands)
				var winner interview.Result
				for _, outcome := range outcomes {
					if outcome.err == nil {
						winner = outcome.result
					}
				}
				want := 1
				if !initial {
					want = 2
				}
				detail := interviewDetail(t, f, r.ID)
				if len(detail.Sections) != 1 || len(detail.Sections[0].Versions) != want || detail.Sections[0].HeadRevision == nil || *detail.Sections[0].HeadRevision != strconv.Itoa(want) || detail.Sections[0].PublishedVersionID == nil || *detail.Sections[0].PublishedVersionID != winner.ID {
					t.Fatal("CAS winner must be sole current head/history append:", detail)
				}
				if f.Count(t, "note_head") != 1 || f.Count(t, "note_version") != before["note_version"]+1 || f.Count(t, "interview_payload") != before["interview_payload"]+1 || f.Count(t, "interview_receipt") != before["interview_receipt"]+1 {
					t.Fatal("CAS loser persisted head/version/payload/receipt")
				}
				if !initial && readInterviewNote(t, f, base.ID).Text != "SYNTHETIC_CAS_ORIGINAL" {
					t.Fatal("CAS correction overwrote retained original")
				}
			})
		})
	}
}

func TestInterviewAndActionCASRealConnectionsOneEvent(t *testing.T) {
	for _, aggregate := range []string{"interview", "action_item"} {
		t.Run(aggregate, func(t *testing.T) {
			interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
				employee := interviewEmployee(t, f)
				r := scheduledInterview(t, f, employee)
				var action interview.Result
				if aggregate == "action_item" {
					var err error
					action, err = f.Interviews.CreateAction(context.Background(), f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: "1", MinimalSharedText: "SYNTHETIC_ACTION_CAS", Owner: interview.Party{Kind: "employee", ID: employee}})
					if err != nil {
						t.Fatal(err)
					}
				}
				before := interviewFacts(t, f)
				commands := [2]func(context.Context, *interview.Service, interview.Request) (interview.Result, error){}
				for index := range 2 {
					if aggregate == "interview" {
						cmd := interview.TransitionCommand{Action: "start", ExpectedRevision: "1", ActualStartedAt: new(f.Now.Add(-time.Hour).Format(time.RFC3339Nano)), Reason: fmt.Sprintf("SYNTHETIC_TRANSITION_CAS_%d", index)}
						commands[index] = func(ctx context.Context, svc *interview.Service, req interview.Request) (interview.Result, error) {
							return svc.Transition(ctx, req, r.ID, cmd)
						}
					} else {
						cmd := interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "1", SafeBlockerText: fmt.Sprintf("SYNTHETIC_ACTION_CAS_%d", index)}
						commands[index] = func(ctx context.Context, svc *interview.Service, req interview.Request) (interview.Result, error) {
							return svc.TransitionAction(ctx, req, action.ID, cmd)
						}
					}
				}
				raceInterviewCommands(t, f, commands)
				detail := interviewDetail(t, f, r.ID)
				if aggregate == "interview" {
					if detail.Interview.Revision != "2" || detail.Interview.Status != "in_progress" || f.Count(t, "interview_event") != before["interview_event"]+1 {
						t.Fatal("interview CAS must accept exactly one immutable transition")
					}
				} else {
					if len(detail.ActionItems) != 1 || detail.ActionItems[0].Revision != "2" || detail.ActionItems[0].Status != "done" || len(detail.ActionItems[0].Events) != 2 || f.Count(t, "action_item_event") != before["action_item_event"]+1 {
						t.Fatal("action CAS must accept exactly one immutable event")
					}
				}
				if f.Count(t, "interview_payload") != before["interview_payload"]+1 || f.Count(t, "interview_receipt") != before["interview_receipt"]+1 {
					t.Fatal("CAS loser left encrypted payload or command receipt")
				}
			})
		})
	}
}

func TestInterviewUnavailableKMSAndAuditRollbackAllFacts(t *testing.T) {
	for _, failure := range []string{"kms", "audit"} {
		for _, mutation := range []string{"note", "note_read", "interview_transition", "action_create", "action_transition", "export"} {
			t.Run(failure+"/"+mutation, func(t *testing.T) {
				interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
					ctx := context.Background()
					employee := interviewEmployee(t, f)
					r := scheduledInterview(t, f, employee)
					original := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_ROLLBACK_ORIGINAL", Action: "publish"})
					current, err := f.Repo.Interview(ctx, f.OrgID, r.ID)
					if err != nil {
						t.Fatal(err)
					}
					var action interview.Result
					if mutation == "action_transition" {
						action, err = f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: current.Revision, MinimalSharedText: "SYNTHETIC_ROLLBACK_ACTION", Owner: interview.Party{Kind: "employee", ID: employee}})
						if err != nil {
							t.Fatal(err)
						}
						current, err = f.Repo.Interview(ctx, f.OrgID, r.ID)
						if err != nil {
							t.Fatal(err)
						}
					}
					before := interviewFacts(t, f)
					if failure == "kms" {
						f.InterviewKMS.Fail.Store(true)
					} else if err = f.Exec(ctx, "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
						t.Fatal(err)
					}
					switch mutation {
					case "note":
						_, err = f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), r.ID, interview.NoteCommand{HeadID: original.HeadID, Category: "shared", ExpectedHeadRevision: "1", Text: "SYNTHETIC_ROLLBACK_NEW_NOTE", EditReason: "SYNTHETIC_ROLLBACK_EDIT", Action: "publish", SupersedesVersionID: &original.ID})
					case "note_read":
						var released interview.NoteView
						released, err = f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Owner), original.ID)
						if released.Text != "" || len(released.SourceRefs) != 0 {
							t.Fatal("failed KMS/read audit released partial note:", released)
						}
					case "interview_transition":
						_, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "cancel", ExpectedRevision: current.Revision, Reason: "SYNTHETIC_ROLLBACK_CANCEL_REASON"})
					case "action_create":
						_, err = f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: current.Revision, MinimalSharedText: "SYNTHETIC_ROLLBACK_NEW_ACTION", Owner: interview.Party{Kind: "employee", ID: employee}})
					case "action_transition":
						_, err = f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), action.ID, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "1", SafeBlockerText: "SYNTHETIC_ROLLBACK_BLOCKER"})
					case "export":
						_, err = f.Interviews.Export(ctx, f.InterviewRequest(f.Owner), interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "note_version", ID: original.ID, ExpectedRevision: "1"}}}, func(event interview.ExportEvent) error {
							if failure == "audit" || event.NoteVersion != nil || event.ActionItem != nil || event.Interview != nil || event.Kind == "complete" {
								t.Fatal("failed export prepare/KMS released content or successful completion:", event)
							}
							return nil
						})
					}
					wantErr := fault.Unavailable
					if failure == "audit" {
						wantErr = fault.AuditUnavailable
					}
					if !errors.Is(err, wantErr) {
						t.Fatal("external/audit failure must fail closed with explicit fault:", err)
					}
					requireInterviewFacts(t, f, before)
					after, err := f.Repo.Interview(ctx, f.OrgID, r.ID)
					if err != nil || after.Number != current.Number || after.Status != current.Status {
						t.Fatal("failed mutation moved interview head/status:", after, err)
					}
					head, ok, err := f.Repo.InterviewHead(ctx, f.OrgID, r.ID, "shared")
					if err != nil || !ok || head.Revision != 1 || head.PublishedID != original.ID {
						t.Fatal("failed mutation moved note head:", head, err)
					}
					if mutation == "action_transition" {
						retained, err := f.Repo.InterviewAction(ctx, f.OrgID, action.ID)
						if err != nil || retained.Number != 1 || retained.Status != "todo" || len(retained.EventRecords) != 1 {
							t.Fatal("failed action transition left partial current/event:", retained, err)
						}
					}
				})
			})
		}
	}
}

func TestInterviewReadRechecksCurrentGrantAfterRealDecrypt(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		note := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_REVOKED_DURING_KMS", Action: "publish"})
		readGrant := grantInterview(t, f, f.Reader, employee, "note.read", "shared", &authz.ObjectReference{Kind: "note_version", ID: note.ID})
		before := interviewFacts(t, f)
		arrived, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		f.InterviewKMS.BlockNextDecrypt(arrived, release)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		type readResult struct {
			view interview.NoteView
			err  error
		}
		results := make(chan readResult, 1)
		request := f.InterviewRequest(f.Reader)
		go func() { v, err := f.Interviews.NoteVersion(ctx, request, note.ID); results <- readResult{v, err} }()
		select {
		case <-arrived:
		case early := <-results:
			t.Fatal("authorized read must reach real Transit decrypt before revocation:", early.err)
		case <-ctx.Done():
			t.Fatal("real decrypt gate did not arrive")
		}
		revokeInterviewGrant(t, f, readGrant)
		unblock()
		select {
		case result := <-results:
			if !errors.Is(result.err, fault.Forbidden) || result.view.Text != "" || len(result.view.SourceRefs) != 0 {
				t.Fatal("current authorization epoch changed before release; decrypted plaintext must be discarded:", result.view, result.err)
			}
		case <-ctx.Done():
			t.Fatal("current release recheck did not complete")
		}
		requireInterviewFacts(t, f, before)
	})
}

func TestInterviewMinimizedActionSourceRequiresOwnApprovalAndStaysProjected(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		source := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "hr_confidential", ExpectedHeadRevision: "0", Text: "SYNTHETIC_HR_SOURCE_NEVER_COPY", Action: "publish"})
		target := &authz.ObjectReference{Kind: "interview", ID: r.ID}
		sourceObject := authz.ObjectReference{Kind: "note_version", ID: source.ID}
		// Note publication approval is not action-write source approval.
		grantInterview(t, f, f.Owner, employee, "note.publish", "shared", target, sourceObject)
		cmd := interview.ActionCommand{ExpectedRevision: interviewDetail(t, f, r.ID).Interview.Revision, MinimalSharedText: "SYNTHETIC_MANUAL_MINIMAL_ACTION", Owner: interview.Party{Kind: "subject", ID: f.Reader.SubjectID}, SourceRefs: []interview.SourceRef{{Kind: "note_version", ID: source.ID, ExpectedVersion: "1"}}, ConfirmMinimized: true}
		before := interviewFacts(t, f)
		calls := f.InterviewKMS.Calls.Load()
		if _, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, cmd); !errors.Is(err, fault.Forbidden) {
			t.Fatal("note.publish approval cannot authorize action.write source:", err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("missing action approval reached KMS")
		}
		grantInterview(t, f, f.Owner, employee, "action.write", "shared", target, sourceObject)
		made, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, cmd)
		if err != nil {
			t.Fatal("approved manual minimal action:", err)
		}
		grantInterview(t, f, f.Reader, employee, "interview.read", "metadata", target)
		grantInterview(t, f, f.Reader, employee, "action.read", "shared", &authz.ObjectReference{Kind: "action_item", ID: made.ID})
		view, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{IncludeActions: true})
		if err != nil || len(view.ActionItems) != 1 || view.ActionItems[0].MinimalSharedText != cmd.MinimalSharedText || view.ActionItems[0].Owner != cmd.Owner || len(view.ActionItems[0].SourceRefs) != 0 {
			t.Fatal("action reader/owner must not inherit HR source access:", view, err)
		}
		raw, err := json.Marshal(view)
		if err != nil || bytes.Contains(raw, []byte(source.ID)) || bytes.Contains(raw, []byte("SYNTHETIC_HR_SOURCE")) {
			t.Fatal("action source projection leaked HR source")
		}
		done, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "1"})
		if err != nil || done.Status != "done" {
			t.Fatal(err)
		}
		retained := interviewDetail(t, f, r.ID).ActionItems[0]
		if !reflect.DeepEqual(retained.SourceRefs, cmd.SourceRefs) || retained.MinimalSharedText != cmd.MinimalSharedText || len(retained.Events) != 2 {
			t.Fatal("action transition dropped original source tuple/minimal content/history:", retained)
		}
		grantInterview(t, f, f.Reader, employee, "sensitive.export", "shared", &authz.ObjectReference{Kind: "action_item", ID: made.ID})
		events := []interview.ExportEvent{}
		exportID, err := f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "action_item", ID: made.ID, ExpectedRevision: done.Revision}}}, func(event interview.ExportEvent) error { events = append(events, event); return nil })
		if err != nil || exportID == "" || len(events) != 3 || events[1].ActionItem == nil || events[1].ActionItem.MinimalSharedText != cmd.MinimalSharedText || events[1].ActionItem.Status != "done" || len(events[1].ActionItem.Events) != 2 || len(events[1].ActionItem.SourceRefs) != 0 {
			t.Fatal("authorized action export must retain terminal shared history but independently project private source:", events, err)
		}
		raw, err = json.Marshal(events)
		if err != nil || bytes.Contains(raw, []byte(source.ID)) || bytes.Contains(raw, []byte("SYNTHETIC_HR_SOURCE")) {
			t.Fatal("action export leaked private provenance")
		}
	})
}

func TestInterviewCancellationEncryptsReasonAndNeverReopensOrAutoCancelsAction(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		action, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: "1", MinimalSharedText: "SYNTHETIC_OPEN_ACTION_AFTER_CANCEL", Owner: interview.Party{Kind: "employee", ID: employee}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "cancel", ExpectedRevision: *action.InterviewRevision, Reason: "SYNTHETIC_ENCRYPTED_CANCELLATION_REASON"})
		if err != nil || result.Status != "cancelled" {
			t.Fatal("explicit cancellation:", result, err)
		}
		detail := interviewDetail(t, f, r.ID)
		if len(detail.ActionItems) != 1 || detail.ActionItems[0].Status != "todo" {
			t.Fatal("interview cancellation must not implicitly mutate action lifecycle")
		}
		raw, err := json.Marshal(detail.Interview)
		if err != nil || bytes.Contains(raw, []byte("SYNTHETIC_ENCRYPTED_CANCELLATION_REASON")) {
			t.Fatal("metadata leaked raw cancellation reason")
		}
		before := interviewFacts(t, f)
		_, err = f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_NOTE_AFTER_CANCEL", EditReason: "synthetic", Action: "publish"})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("cancelled interview cannot accept note correction:", err)
		}
		_, err = f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: result.Revision, MinimalSharedText: "SYNTHETIC_ACTION_AFTER_CANCEL", Owner: interview.Party{Kind: "employee", ID: employee}})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("cancelled interview cannot create new action:", err)
		}
		_, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "start", ExpectedRevision: result.Revision, ActualStartedAt: new(f.Now.Add(-time.Hour).Format(time.RFC3339Nano))})
		if !errors.Is(err, fault.Conflict) {
			t.Fatal("cancelled interview cannot reopen:", err)
		}
		requireInterviewFacts(t, f, before)
		cancelled, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), action.ID, interview.ActionTransitionCommand{Action: "cancel", ExpectedRevision: "1", SafeBlockerText: "SYNTHETIC_SAFE_CANCEL_BLOCKER"})
		if err != nil || cancelled.Status != "cancelled" || cancelled.Revision != "2" {
			t.Fatal("explicit independent action cancellation:", cancelled, err)
		}
		before = interviewFacts(t, f)
		if _, err = f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), action.ID, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "2"}); !errors.Is(err, fault.Conflict) {
			t.Fatal("cancelled action cannot complete:", err)
		}
		requireInterviewFacts(t, f, before)
	})
}

func TestInterviewListIANACalendarCursorPagingAndCurrentGraph(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		if err := f.Exec(ctx, "UPDATE organization SET timezone='Asia/Tokyo' WHERE id=?", "UPDATE organization SET timezone='Asia/Tokyo' WHERE id=$1", f.OrgID); err != nil {
			t.Fatal(err)
		}
		zone, err := time.LoadLocation("Asia/Tokyo")
		if err != nil {
			t.Fatal("real IANA timezone:", err)
		}
		from := f.Now.In(zone).AddDate(0, 0, -3).Format("2006-01-02")
		midnight, err := time.ParseInLocation("2006-01-02", from, zone)
		if err != nil {
			t.Fatal(err)
		}
		end := midnight.AddDate(0, 0, 1)
		expected := make(map[string]bool)
		for index, at := range []time.Time{midnight.Add(-time.Microsecond), midnight, end.Add(-time.Microsecond), end} {
			r, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, interview.CreateCommand{ScheduledAt: at.UTC().Format(time.RFC3339Nano)})
			if err != nil {
				t.Fatal(err)
			}
			if index == 1 || index == 2 {
				expected[r.ID] = true
			}
		}
		backfill, err := f.Interviews.Create(ctx, f.InterviewRequest(f.Owner), employee, interview.CreateCommand{ScheduledAt: midnight.AddDate(0, 0, -10).UTC().Format(time.RFC3339Nano), Backfilled: true, ActualStartedAt: new(midnight.Add(time.Hour).UTC().Format(time.RFC3339Nano)), ActualEndedAt: new(midnight.Add(2 * time.Hour).UTC().Format(time.RFC3339Nano))})
		if err != nil {
			t.Fatal(err)
		}
		expected[backfill.ID] = true
		query := interview.ListQuery{From: from, To: end.Format("2006-01-02"), Limit: 1}
		first, err := f.Interviews.List(ctx, f.InterviewRequest(f.Owner), employee, query)
		if err != nil || len(first.Items) != 1 || first.NextCursor == nil || first.AsOf != f.Now.In(zone).Format("2006-01-02") || first.Consistency != "current" {
			t.Fatal("local calendar current page:", first, err)
		}
		seen := make(map[string]bool)
		page := first
		for index := 0; ; index++ {
			if index > 3 || len(page.Items) != 1 || !expected[page.Items[0].ID] || seen[page.Items[0].ID] {
				t.Fatal("cursor duplicated, leaked boundary, or lost calendar row:", page)
			}
			seen[page.Items[0].ID] = true
			if page.NextCursor == nil {
				break
			}
			query.Cursor = *page.NextCursor
			page, err = f.Interviews.List(ctx, f.InterviewRequest(f.Owner), employee, query)
			if err != nil {
				t.Fatal("current cursor follow:", err)
			}
		}
		if !reflect.DeepEqual(seen, expected) {
			t.Fatal("calendar [from,to) must use local occurrence and enumerate each visible object:", seen, expected)
		}
		originalQuery := interview.ListQuery{From: from, To: end.Format("2006-01-02"), Limit: 1, Cursor: *first.NextCursor}
		changedQuery := originalQuery
		changedQuery.Status = "completed"
		if _, err = f.Interviews.List(ctx, f.InterviewRequest(f.Owner), employee, changedQuery); !errors.Is(err, fault.Conflict) {
			t.Fatal("cursor must bind original filter:", err)
		}
		if err = f.Exec(ctx, "UPDATE organization SET graph_revision=graph_revision+1 WHERE id=?", "UPDATE organization SET graph_revision=graph_revision+1 WHERE id=$1", f.OrgID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.Interviews.List(ctx, f.InterviewRequest(f.Owner), employee, originalQuery); !errors.Is(err, fault.Conflict) {
			t.Fatal("current graph epoch must invalidate old cursor:", err)
		}
	})
}

func TestInterviewMetadataExportNeverBundlesNotesAndExportRequiresCurrentMFA(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		private := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "hr_confidential", ExpectedHeadRevision: "0", Text: "SYNTHETIC_EXPORT_HIDDEN_HR", Action: "publish"})
		exact := &authz.ObjectReference{Kind: "interview", ID: r.ID}
		grantInterview(t, f, f.Reader, employee, "interview.read", "metadata", exact)
		grantInterview(t, f, f.Reader, employee, "sensitive.export", "metadata", exact)
		f.InterviewKMS.Fail.Store(true)
		calls := f.InterviewKMS.Calls.Load()
		events := []interview.ExportEvent{}
		metadata, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{})
		if err != nil {
			t.Fatal("independent metadata read:", err)
		}
		cmd := interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "interview", ID: r.ID, ExpectedRevision: metadata.Interview.Revision}}}
		id, err := f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), cmd, func(event interview.ExportEvent) error { events = append(events, event); return nil })
		if err != nil || id == "" || len(events) != 3 || events[1].Interview == nil || events[1].Interview.ID != r.ID || events[1].NoteVersion != nil || events[1].ActionItem != nil || f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("independent metadata export must not bundle/decrypt unreadable notes:", id, events, err)
		}
		raw, err := json.Marshal(events)
		if err != nil || bytes.Contains(raw, []byte(private.ID)) || bytes.Contains(raw, []byte("SYNTHETIC_EXPORT_HIDDEN_HR")) {
			t.Fatal("metadata export leaked hidden note")
		}
		if err = f.Exec(ctx, "UPDATE access_grant SET mfa_required=0 WHERE subject_id=? AND capability='sensitive.export'", "UPDATE access_grant SET mfa_required=false WHERE subject_id=$1 AND capability='sensitive.export'", f.Reader.SubjectID); err != nil {
			t.Fatal(err)
		}
		if err = f.Exec(ctx, "UPDATE session SET mfa_until=? WHERE token_hash=?", "UPDATE session SET mfa_until=$1 WHERE token_hash=$2", f.Repo.BindTime(f.Now.Add(-time.Microsecond)), f.Reader.Hash); err != nil {
			t.Fatal(err)
		}
		before := interviewFacts(t, f)
		_, err = f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), cmd, func(interview.ExportEvent) error { t.Fatal("export without current MFA emitted stream"); return nil })
		if !errors.Is(err, fault.NotFound) {
			t.Fatal("export operation independently requires current MFA even permissive grant:", err)
		}
		requireInterviewFacts(t, f, before)
		if f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("MFA denial or metadata export reached KMS")
		}
	})
}

func TestInterviewActionCreationCASUsesAggregateRevisionAcrossConnections(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		before := interviewFacts(t, f)
		commands := [2]func(context.Context, *interview.Service, interview.Request) (interview.Result, error){}
		for index := range 2 {
			cmd := interview.ActionCommand{ExpectedRevision: "1", MinimalSharedText: fmt.Sprintf("SYNTHETIC_CREATE_ACTION_CAS_%d", index), Owner: interview.Party{Kind: "employee", ID: employee}}
			commands[index] = func(ctx context.Context, svc *interview.Service, request interview.Request) (interview.Result, error) {
				return svc.CreateAction(ctx, request, r.ID, cmd)
			}
		}
		outcomes := raceInterviewCommands(t, f, commands)
		var winner interview.Result
		for _, result := range outcomes {
			if result.err == nil {
				winner = result.result
			}
		}
		detail := interviewDetail(t, f, r.ID)
		if detail.Interview.Revision != "2" || len(detail.ActionItems) != 1 || detail.ActionItems[0].ID != winner.ID || detail.ActionItems[0].Revision != "1" || len(detail.ActionItems[0].Events) != 1 || winner.InterviewRevision == nil || *winner.InterviewRevision != "2" {
			t.Fatal("action creation aggregate CAS must persist sole action/event and one revision bump:", winner, detail)
		}
		if f.Count(t, "action_item") != before["action_item"]+1 || f.Count(t, "action_item_event") != before["action_item_event"]+1 || f.Count(t, "interview_payload") != before["interview_payload"]+1 || f.Count(t, "interview_receipt") != before["interview_receipt"]+1 {
			t.Fatal("action creation CAS loser left partial action/event/payload/receipt")
		}
	})
}

func TestInterviewActionMaximumTextAndBlockerRemainIndependentImmutablePayloads(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		text, blocker := strings.Repeat("x", 12288), strings.Repeat("b", 4096)
		made, err := f.Interviews.CreateAction(ctx, f.InterviewRequest(f.Owner), r.ID, interview.ActionCommand{ExpectedRevision: "1", MinimalSharedText: text, Owner: interview.Party{Kind: "employee", ID: employee}})
		if err != nil {
			t.Fatal("maximum valid minimal shared text must persist:", err)
		}
		original, err := f.Repo.InterviewAction(ctx, f.OrgID, made.ID)
		if err != nil || len(original.EventRecords) != 1 {
			t.Fatal("initial immutable action event:", err)
		}
		firstPayloadID := original.EventRecords[0].PayloadID
		firstPayload, err := f.Repo.InterviewPayload(ctx, f.OrgID, firstPayloadID)
		if err != nil {
			t.Fatal(err)
		}
		firstCiphertext := bytes.Clone(firstPayload.Envelope.SealedBytes)
		start, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "start", ExpectedRevision: "1", SafeBlockerText: blocker})
		if err != nil || start.Status != "in_progress" || start.Revision != "2" {
			t.Fatal("individually valid max blocker must not duplicate base text into oversized transition payload:", start, err)
		}
		current := interviewDetail(t, f, r.ID).ActionItems
		if len(current) != 1 || current[0].MinimalSharedText != text || current[0].SafeBlockerText != blocker || len(current[0].Events) != 2 {
			t.Fatal("separate immutable base/current blocker payloads must reconstruct both complete fields")
		}
		done, err := f.Interviews.TransitionAction(ctx, f.InterviewRequest(f.Owner), made.ID, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "2"})
		if err != nil || done.Status != "done" || done.Revision != "3" {
			t.Fatal("terminal append after maximum fields:", done, err)
		}
		terminal := interviewDetail(t, f, r.ID).ActionItems[0]
		if terminal.MinimalSharedText != text || terminal.SafeBlockerText != "" || terminal.Status != "done" || terminal.Revision != "3" || len(terminal.Events) != 3 {
			t.Fatal("terminal read must retain full initial text, clear current omitted blocker, and retain all events")
		}
		foundHistoricBlocker := false
		for _, event := range terminal.Events {
			if event.Revision == "2" {
				foundHistoricBlocker = true
				if event.Status != "in_progress" || event.SafeBlockerText != blocker {
					t.Fatal("maximum historic blocker changed after terminal append")
				}
			}
		}
		if !foundHistoricBlocker {
			t.Fatal("terminal action omitted maximum blocker history")
		}
		retained, err := f.Repo.InterviewPayload(ctx, f.OrgID, firstPayloadID)
		if err != nil || !bytes.Equal(retained.Envelope.SealedBytes, firstCiphertext) {
			t.Fatal("start/done rewrote first immutable action ciphertext:", err)
		}
		action, err := f.Repo.InterviewAction(ctx, f.OrgID, made.ID)
		if err != nil || len(action.EventRecords) != 3 || action.EventRecords[0].PayloadID != firstPayloadID || action.PayloadID == firstPayloadID {
			t.Fatal("terminal action must reference new blocker event while preserving original base payload lineage:", err)
		}
	})
}

func TestInterviewScheduledExplicitBackfillTransitionRetainsBoundedStateHistory(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		r := scheduledInterview(t, f, interviewEmployee(t, f))
		initial := interviewDetail(t, f, r.ID)
		recorded := f.Now
		start, end := f.Now.Add(-90*time.Minute).Format(time.RFC3339Nano), f.Now.Add(-30*time.Minute).Format(time.RFC3339Nano)
		valid := interview.TransitionCommand{Action: "complete", ExpectedRevision: "1", Backfilled: true, ActualStartedAt: &start, ActualEndedAt: &end}
		before := interviewFacts(t, f)
		ordinary := valid
		ordinary.Backfilled = false
		if _, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, ordinary); !errors.Is(err, fault.Conflict) {
			t.Fatal("ordinary scheduled completion cannot skip start:", err)
		}
		for name, cmd := range map[string]interview.TransitionCommand{
			"missing start":           {Action: "complete", ExpectedRevision: "1", Backfilled: true, ActualEndedAt: &end},
			"missing end":             {Action: "complete", ExpectedRevision: "1", Backfilled: true, ActualStartedAt: &start},
			"reversed actuals":        {Action: "complete", ExpectedRevision: "1", Backfilled: true, ActualStartedAt: &end, ActualEndedAt: &start},
			"future end":              {Action: "complete", ExpectedRevision: "1", Backfilled: true, ActualStartedAt: &start, ActualEndedAt: new(f.Now.Add(time.Minute).Format(time.RFC3339Nano))},
			"backfilled start action": {Action: "start", ExpectedRevision: "1", Backfilled: true, ActualStartedAt: &start},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, cmd); !errors.Is(err, fault.Invalid) {
					t.Fatal("explicit backfill must validate actual tuple/action before any persistence:", err)
				}
				requireInterviewFacts(t, f, before)
			})
		}
		requireInterviewFacts(t, f, before)
		f.Now = f.Now.Add(time.Minute)
		request := f.InterviewRequest(f.Owner)
		completed, err := f.Interviews.Transition(ctx, request, r.ID, valid)
		if err != nil || completed.Status != "completed" || completed.Revision != "2" {
			t.Fatal("explicit scheduled backfill must atomically complete:", completed, err)
		}
		detail := interviewDetail(t, f, r.ID)
		if !detail.Interview.Backfilled || detail.Interview.Status != "completed" || !detail.Interview.ScheduledAt.Equal(initial.Interview.ScheduledAt) || !detail.Interview.RecordedAt.Equal(recorded) || detail.Interview.ActualStartedAt == nil || detail.Interview.ActualEndedAt == nil || detail.Interview.ActualStartedAt.Format(time.RFC3339Nano) != start || detail.Interview.ActualEndedAt.Format(time.RFC3339Nano) != end || len(detail.InterviewEvents) != 2 {
			t.Fatal("backfill replaced original recorded/scheduled facts or lost actual/history")
		}
		history := make(map[string]interview.InterviewEventView)
		for _, event := range detail.InterviewEvents {
			history[event.Revision] = event
		}
		planned, finished := history["1"], history["2"]
		if planned.Status != "scheduled" || planned.Backfilled || planned.ActualStartedAt != nil || planned.ActualEndedAt != nil || !planned.RecordedAt.Equal(recorded) || finished.Status != "completed" || !finished.Backfilled || finished.ActualStartedAt == nil || finished.ActualEndedAt == nil || finished.ActualStartedAt.Format(time.RFC3339Nano) != start || finished.ActualEndedAt.Format(time.RFC3339Nano) != end || !finished.RecordedAt.Equal(f.Now) || finished.AuthorSubjectID != f.Owner.SubjectID {
			t.Fatal("immutable state history must distinguish original recording from explicit actual backfill:", history)
		}
		after := interviewFacts(t, f)
		confirmed, err := f.Interviews.Transition(ctx, request, r.ID, valid)
		if err != nil || !reflect.DeepEqual(confirmed, completed) {
			t.Fatal("backfill receipt replay must confirm terminal original commit:", confirmed, err)
		}
		requireInterviewFacts(t, f, after)
		if _, err = f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, valid); !errors.Is(err, fault.Conflict) {
			t.Fatal("new stale/terminal backfill command cannot append second completion:", err)
		}
		requireInterviewFacts(t, f, after)
	})
}

func TestInterviewCancellationReasonRequiresIndependentCurrentSharedInterviewRead(t *testing.T) {
	interviewBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := interviewEmployee(t, f)
		r := scheduledInterview(t, f, employee)
		note := saveInterviewNote(t, f, r.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Text: "SYNTHETIC_REASON_EXACT_VERSION_READ", Action: "publish"})
		reason := "SYNTHETIC_CANCEL_REASON_PRIVATE_FROM_METADATA"
		cancelled, err := f.Interviews.Transition(ctx, f.InterviewRequest(f.Owner), r.ID, interview.TransitionCommand{Action: "cancel", ExpectedRevision: interviewDetail(t, f, r.ID).Interview.Revision, Reason: reason})
		if err != nil || cancelled.Status != "cancelled" {
			t.Fatal(err)
		}
		target := &authz.ObjectReference{Kind: "interview", ID: r.ID}
		grantInterview(t, f, f.Reader, employee, "interview.read", "metadata", target)
		grantInterview(t, f, f.Reader, employee, "note.read", "shared", &authz.ObjectReference{Kind: "note_version", ID: note.ID})
		f.InterviewKMS.Fail.Store(true)
		calls := f.InterviewKMS.Calls.Load()
		metadata, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{})
		if err != nil || metadata.Interview.Status != "cancelled" || len(metadata.InterviewEvents) != 2 || f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("metadata/exact note-version reader must see state history without reason or KMS:", metadata, err)
		}
		for _, event := range metadata.InterviewEvents {
			if event.Reason != nil {
				t.Fatal("exact version authority must not widen into interview cancellation reason")
			}
		}
		raw, err := json.Marshal(metadata)
		if err != nil || bytes.Contains(raw, []byte(reason)) {
			t.Fatal("raw reason leaked into metadata history")
		}
		reasonGrant := grantInterview(t, f, f.Reader, employee, "note.read", "shared", target)
		f.InterviewKMS.Fail.Store(false)
		authorized, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{})
		if err != nil || len(authorized.InterviewEvents) != 2 || f.InterviewKMS.Calls.Load() <= calls {
			t.Fatal("independent shared interview read must decrypt authorized reason:", err)
		}
		reasons := 0
		for _, event := range authorized.InterviewEvents {
			if event.Status == "cancelled" {
				if event.Reason == nil || *event.Reason != reason || event.AuthorSubjectID != f.Owner.SubjectID {
					t.Fatal("authorized cancellation reason/author lost:", event)
				}
				reasons++
			} else if event.Reason != nil {
				t.Fatal("reason wrongly attached to earlier immutable state")
			}
		}
		if reasons != 1 {
			t.Fatal("cancellation reason must belong exactly to cancelled event")
		}
		revokeInterviewGrant(t, f, reasonGrant)
		f.InterviewKMS.Fail.Store(true)
		calls = f.InterviewKMS.Calls.Load()
		hidden, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), r.ID, interview.DetailQuery{})
		if err != nil || len(hidden.InterviewEvents) != 2 || f.InterviewKMS.Calls.Load() != calls {
			t.Fatal("current reason authority revocation must preserve metadata-only history without KMS:", err)
		}
		for _, event := range hidden.InterviewEvents {
			if event.Reason != nil {
				t.Fatal("revoked reason authority survived immutable history read")
			}
		}
		f.InterviewKMS.Fail.Store(false)
		if err := f.Exec(ctx, "DROP TABLE audit_event", "DROP TABLE audit_event"); err != nil {
			t.Fatal(err)
		}
		denied, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Owner), r.ID, interview.DetailQuery{})
		if !errors.Is(err, fault.AuditUnavailable) || len(denied.InterviewEvents) != 0 {
			t.Fatal("mandatory history read audit failure must discard decrypted reason and partial history:", denied, err)
		}
	})
}
