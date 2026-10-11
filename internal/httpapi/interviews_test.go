package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func interviewHTTPRequest(t *testing.T, f *testsupport.Fixture, credential testsupport.Credential, method, path, body, key string) *http.Request {
	t.Helper()
	r := apiRequest(t, f, credential, method, path, body, key)
	r.Header.Set("X-Access-Purpose", "interview_followup")
	return r
}

func interviewHTTPSetup(t *testing.T, f *testsupport.Fixture) (organization.Result, interview.Result) {
	t.Helper()
	var employee organization.Result
	apiSend(t, f, apiRequest(t, f, f.Owner, "POST", "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), 201, &employee)
	snapshot, err := f.Repo.Security(context.Background(), f.Owner.Hash, "", employee.ID)
	if err != nil || !snapshot.Allows("interview.read", "metadata", employee.ID, "interview_followup", f.Now) || !snapshot.Allows("interview.write", "metadata", employee.ID, "interview_followup", f.Now) {
		t.Fatal("consumer prerequisite: actual current approved read/write fixture is required", err)
	}
	command := interview.CreateCommand{ScheduledAt: f.Now.Add(-2 * time.Hour).Format(time.RFC3339Nano), Participants: []interview.Party{{Kind: "employee", ID: employee.ID}, {Kind: "subject", ID: f.Reader.SubjectID}}}
	var made interview.Result
	body, key := structureJSON(t, command), value.NewID()
	path := "/api/v1/employees/" + employee.ID + "/interviews"
	apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", path, body, key), 201, &made)
	var replay interview.Result
	apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", path, body, key), 201, &replay)
	if made.ID != replay.ID || made.Status != "scheduled" || made.Revision != "1" || f.Count(t, "interview") != 1 {
		t.Fatal("actual scheduling/replay must retain exactly one persisted scheduled aggregate")
	}
	return employee, made
}

func interviewHTTPGrant(t *testing.T, f *testsupport.Fixture, subject, employee, capability, category string, object *authz.ObjectReference) authz.Result {
	t.Helper()
	var session struct {
		Epoch string `json:"auth_epoch"`
	}
	apiSend(t, f, apiRequest(t, f, f.Manager, "GET", "/api/v1/session", "", ""), 200, &session)
	command := authz.IssueCommand{SubjectID: subject, Capability: capability, Category: category, Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "interview_followup", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: object, AuthorityID: f.AuthorityIDs[capability+"/"+category], ExpectedRevision: session.Epoch}
	r := apiRequest(t, f, f.Manager, "POST", "/api/v1/access-grants", structureJSON(t, command), value.NewID())
	r.Header.Set("X-Access-Purpose", authz.ManagementPurpose)
	var grant authz.Result
	apiSend(t, f, r, 201, &grant)
	return grant
}

func TestR3HTTPPersistedVersionsTerminalActionAndExactHandover(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			employee, made := interviewHTTPSetup(t, f)
			base := "/api/v1/interviews/" + made.ID
			var drafts, published [3]interview.Result
			categories := [...]string{"shared", "manager_private", "hr_confidential"}
			for i, category := range categories {
				command := interview.NoteCommand{Category: category, ExpectedHeadRevision: "0", Text: "SYNTHETIC_R3_" + category + "_DRAFT", Action: "save_draft", SourceRefs: []interview.SourceRef{}}
				apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/note-versions", structureJSON(t, command), value.NewID()), 201, &drafts[i])
				command.HeadID, command.ExpectedHeadRevision, command.SupersedesVersionID = drafts[i].HeadID, "1", &drafts[i].ID
				command.Text, command.EditReason, command.Action = "SYNTHETIC_R3_"+category+"_PUBLISHED", "SYNTHETIC_PUBLISH_REASON", "publish"
				apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/note-versions", structureJSON(t, command), value.NewID()), 201, &published[i])
				if published[i].Status != "published" || published[i].VersionNo == nil || *published[i].VersionNo != "2" || published[i].HeadRevision == nil || *published[i].HeadRevision != "2" {
					t.Fatal("publishing must append v2 rather than mutate the saved draft")
				}
			}
			pastDue := f.Now.Add(-24 * time.Hour).Format("2006-01-02")
			command := interview.ActionCommand{ExpectedRevision: "1", MinimalSharedText: "SYNTHETIC_SHARED_ACTION", Owner: interview.Party{Kind: "subject", ID: f.Owner.SubjectID}, DueDate: &pastDue, SourceRefs: []interview.SourceRef{}}
			var action interview.Result
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/action-items", structureJSON(t, command), value.NewID()), 201, &action)
			actualStart, actualEnd := f.Now.Add(-time.Hour).Format(time.RFC3339Nano), f.Now.Add(-30*time.Minute).Format(time.RFC3339Nano)
			var started, completed interview.Result
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/transitions", structureJSON(t, interview.TransitionCommand{Action: "start", ExpectedRevision: "2", ActualStartedAt: &actualStart}), value.NewID()), 200, &started)
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/transitions", structureJSON(t, interview.TransitionCommand{Action: "complete", ExpectedRevision: started.Revision, ActualEndedAt: &actualEnd}), value.NewID()), 200, &completed)
			var detail interview.DetailView
			get := base + "?include_sections=shared,manager_private,hr_confidential&include_actions=true&limit=100"
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "GET", get, "", ""), 200, &detail)
			if detail.Interview.Status != "completed" || len(detail.InterviewEvents) != 3 || len(detail.ActionItems) != 1 || detail.ActionItems[0].Status != "todo" || !detail.ActionItems[0].Overdue || detail.ActionItems[0].DueDate == nil || *detail.ActionItems[0].DueDate != pastDue {
				t.Fatal("completed interview must retain independently overdue todo and actual immutable transition history")
			}
			correction := interview.NoteCommand{HeadID: published[0].HeadID, Category: "shared", ExpectedHeadRevision: "2", Text: "SYNTHETIC_SHARED_CORRECTION", EditReason: "SYNTHETIC_CORRECTION_REASON", Action: "publish", SupersedesVersionID: &published[0].ID, SourceRefs: []interview.SourceRef{}}
			var revised interview.Result
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/note-versions", structureJSON(t, correction), value.NewID()), 201, &revised)
			for i, draft := range drafts {
				var original interview.NoteView
				apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "GET", "/api/v1/note-versions/"+draft.ID, "", ""), 200, &original)
				if original.Text != "SYNTHETIC_R3_"+categories[i]+"_DRAFT" || original.Status != "draft" || original.VersionNo != "1" || original.AuthorSubjectID != f.Owner.SubjectID || !original.RecordedAt.Equal(f.Now) {
					t.Fatal("published/corrected notes must not replace historical draft text/state/author/recorded facts")
				}
			}
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", base+"/transitions", structureJSON(t, interview.TransitionCommand{Action: "start", ExpectedRevision: completed.Revision, ActualStartedAt: &actualStart}), value.NewID()), 409, nil)
			var finished interview.Result
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", "/api/v1/action-items/"+action.ID+"/transitions", structureJSON(t, interview.ActionTransitionCommand{Action: "complete", ExpectedRevision: "1"}), value.NewID()), 200, &finished)
			apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "GET", get, "", ""), 200, &detail)
			if finished.Status != "done" || detail.ActionItems[0].Overdue || detail.ActionItems[0].DueDate == nil || *detail.ActionItems[0].DueDate != pastDue || detail.ActionItems[0].MinimalSharedText != "SYNTHETIC_SHARED_ACTION" || len(detail.ActionItems[0].Events) != 2 {
				t.Fatal("action completion must clear only derived overdue, preserving due/text/immutable history")
			}
			interviewHTTPGrant(t, f, f.Reader.SubjectID, employee.ID, "interview.read", "metadata", &authz.ObjectReference{Kind: "interview", ID: made.ID})
			apiSend(t, f, interviewHTTPRequest(t, f, f.Reader, "GET", get, "", ""), 200, &detail)
			if len(detail.Sections) != 0 || len(detail.ActionItems) != 0 {
				t.Fatal("participant and metadata grants must not authorize any notes or actions")
			}
			// A minimal interview handover is not employee-directory authority.
			apiSend(t, f, interviewHTTPRequest(t, f, f.Reader, "GET", "/api/v1/session?employee_id="+employee.ID, "", ""), 404, nil)
			interviewHTTPGrant(t, f, f.Reader.SubjectID, employee.ID, "interview.write", "metadata", &authz.ObjectReference{Kind: "interview", ID: made.ID})
			var handedOver interview.ListView
			apiSend(t, f, interviewHTTPRequest(t, f, f.Reader, "GET", "/api/v1/employees/"+employee.ID+"/interviews", "", ""), 200, &handedOver)
			if len(handedOver.Items) != 1 || handedOver.Items[0].ID != made.ID {
				t.Fatal("independent interview authority must list only the explicitly handed-over interview")
			}
			readList := false
			for _, permission := range handedOver.Permissions {
				if permission.Capability == "interview.write" {
					t.Fatal("exact existing-interview write must not offer employee-wide new interview creation")
				}
				readList = readList || permission == (interview.Permission{Capability: "interview.read", Category: "metadata"})
			}
			if !readList {
				t.Fatal("independent interview list must offer its actual read operation without directory rights")
			}
			interviewHTTPGrant(t, f, f.Reader.SubjectID, employee.ID, "note.read", "shared", &authz.ObjectReference{Kind: "note_version", ID: published[0].ID})
			interviewHTTPGrant(t, f, f.Reader.SubjectID, employee.ID, "sensitive.export", "shared", &authz.ObjectReference{Kind: "note_version", ID: published[0].ID})
			apiSend(t, f, interviewHTTPRequest(t, f, f.Reader, "GET", get, "", ""), 200, &detail)
			if len(detail.Sections) != 1 || detail.Sections[0].Category != "shared" || len(detail.Sections[0].Versions) != 1 || detail.Sections[0].Versions[0].ID != published[0].ID || detail.Sections[0].HeadRevision != nil || detail.Sections[0].PublishedVersionID != nil && *detail.Sections[0].PublishedVersionID != published[0].ID || detail.Sections[0].Versions[0].SupersedesVersionID != nil {
				t.Fatal("explicit old-version handover cannot reveal current head revision, newer/private versions or unreadable superseded ID")
			}
			exportShared := false
			for _, permission := range detail.Permissions {
				if permission.Capability != "sensitive.export" {
					continue
				}
				if permission.Category != "shared" {
					t.Fatal("old shared-version handover must not offer metadata or private export")
				}
				exportShared = true
			}
			if !exportShared {
				t.Fatal("approved readable old shared version must offer the consumer's explicit export selection")
			}
			for _, id := range []string{drafts[0].ID, revised.ID, published[1].ID, published[2].ID} {
				apiSend(t, f, interviewHTTPRequest(t, f, f.Reader, "GET", "/api/v1/note-versions/"+id, "", ""), 404, nil)
			}
			export := interview.ExportCommand{Objects: []interview.ExportObject{{Kind: "note_version", ID: published[0].ID, ExpectedRevision: "2"}}, Format: "ndjson"}
			response, err := f.Server.Client().Do(interviewHTTPRequest(t, f, f.Reader, "POST", "/api/v1/sensitive-exports", structureJSON(t, export), value.NewID()))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/x-ndjson" {
				t.Fatal("real authorized export must stream NDJSON")
			}
			bytes, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(string(bytes)))
			var events []interview.ExportEvent
			for {
				var event interview.ExportEvent
				if err = decoder.Decode(&event); err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			if len(events) != 3 || events[0].Kind != "header" || events[1].NoteVersion == nil || events[1].NoteVersion.ID != published[0].ID || events[1].NoteVersion.Text != "SYNTHETIC_R3_shared_PUBLISHED" || events[2].Kind != "complete" {
				t.Fatal("stream must contain exactly approved original version and explicit completed outcome")
			}
			if !value.ValidID(events[0].ExportID) || events[1].ExportID != events[0].ExportID || events[2].ExportID != events[0].ExportID {
				t.Fatal("every encoded stream event must identify the same durable export; otherwise the consumer cannot accept completion")
			}
			for _, forbidden := range []string{"SYNTHETIC_R3_manager_private", "SYNTHETIC_R3_hr_confidential", "SYNTHETIC_SHARED_CORRECTION", published[1].ID, published[2].ID, revised.ID, drafts[0].ID} {
				if strings.Contains(string(bytes), forbidden) {
					t.Fatal("exact-version export leaked unrelated historical/private source")
				}
			}
		})
	}
}

func TestR3HTTPStrictBodiesRejectExpansionWithoutCipherOrFacts(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			_, made := interviewHTTPSetup(t, f)
			path := "/api/v1/interviews/" + made.ID + "/note-versions"
			body := structureJSON(t, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Text: "SYNTHETIC_STRICT_PRIVATE", Action: "save_draft", SourceRefs: []interview.SourceRef{}})
			before, calls := f.Count(t, "interview_payload"), f.InterviewKMS.Calls.Load()
			for _, invalid := range []string{
				strings.Replace(body, `"category":"manager_private"`, `"category":"manager_private","audience":["all"]`, 1),
				strings.Replace(body, `"category":"manager_private"`, `"category":"manager_private","grant":{"capability":"note.read"}`, 1),
				strings.Replace(body, `"confirm_minimized":false`, `"confirm_minimized":null`, 1),
				strings.Replace(body, `"category":"manager_private"`, `"category":"manager_private","category":"shared"`, 1),
				strings.Replace(body, `"expected_head_revision":"0"`, `"expected_head_revision":0`, 1),
				strings.Replace(body, `"source_refs":[]`, `"source_refs":[{"kind":"note_version","id":"`+value.NewID()+`","expected_version":"1","text":"SYNTHETIC_HIDDEN_SOURCE"}]`, 1),
			} {
				apiSend(t, f, interviewHTTPRequest(t, f, f.Owner, "POST", path, invalid, value.NewID()), 422, nil)
			}
			if f.Count(t, "interview_payload") != before || f.Count(t, "note_version") != 0 || f.InterviewKMS.Calls.Load() != calls {
				t.Fatal("ordinary editing expansion/framing must be refused before any cipher or partial notes")
			}
		})
	}
}
