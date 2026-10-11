package authz_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/interview"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func authorityInterview(t *testing.T, f *testsupport.Fixture, employee string) interview.Result {
	t.Helper()
	r, err := f.Interviews.Create(context.Background(), f.InterviewRequest(f.Owner), employee, interview.CreateCommand{ScheduledAt: f.Now.Add(-time.Hour).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal("real interview setup:", err)
	}
	return r
}

func authorityNote(t *testing.T, f *testsupport.Fixture, id string, command interview.NoteCommand) interview.Result {
	t.Helper()
	r, err := f.Interviews.SaveNote(context.Background(), f.InterviewRequest(f.Owner), id, command)
	if err != nil || r.HeadID == nil || r.HeadRevision == nil || r.VersionNo == nil {
		t.Fatal("real encrypted version setup:", r, err)
	}
	return r
}

func objectGrantCommand(t *testing.T, f *testsupport.Fixture, subject, employee, capability, category string, ref *authz.ObjectReference) authz.IssueCommand {
	t.Helper()
	var epoch int64
	query := "SELECT auth_epoch FROM authorization_guard WHERE org_id=?"
	if f.Backend == "postgres" {
		query = "SELECT auth_epoch FROM authorization_guard WHERE org_id=$1"
	}
	if err := f.Repo.DB.QueryRow(query, f.OrgID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	return authz.IssueCommand{SubjectID: subject, Capability: capability, Category: category, Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "interview_followup", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Hour).Format(time.RFC3339Nano), MFARequired: capability == "note.publish" || capability == "sensitive.export", ObjectRef: ref, AuthorityID: f.AuthorityIDs[capability+"/"+category], ExpectedRevision: strconv.FormatInt(epoch, 10)}
}

func objectIssue(t *testing.T, f *testsupport.Fixture, command authz.IssueCommand) authz.Result {
	t.Helper()
	r, err := f.Authz.Issue(context.Background(), managementRequest(f), command)
	if err != nil {
		t.Fatal("real bounded object approval:", err)
	}
	return r
}

func TestTypedVersionHandoverReadsOnlyApprovedVersion(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := makeEmployee(t, f)
		meeting := authorityInterview(t, f, employee)
		old := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_EXACT_HANDOVER"})
		latest := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "shared", HeadID: old.HeadID, ExpectedHeadRevision: *old.HeadRevision, SupersedesVersionID: &old.ID, Action: "publish", Text: "SYNTHETIC_OTHER_VERSION", EditReason: "SYNTHETIC_CORRECTION"})
		private := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_NOT_HANDED_OVER"})
		if _, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), old.ID); !errors.Is(err, fault.NotFound) {
			t.Fatal("new manager must have no implicit historical rights:", err)
		}
		metadata := authz.ObjectReference{Kind: "interview", ID: meeting.ID}
		objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, "interview.read", "metadata", &metadata))
		exact := authz.ObjectReference{Kind: "note_version", ID: old.ID}
		made := objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "shared", &exact))
		view, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), old.ID)
		if err != nil || view.Text != "SYNTHETIC_EXACT_HANDOVER" || view.VersionNo != "1" {
			t.Fatal("approved one historical version not returned:", view, err)
		}
		for _, id := range []string{latest.ID, private.ID} {
			if _, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), id); !errors.Is(err, fault.NotFound) {
				t.Fatal("exact version handover leaked another version/category:", err)
			}
		}
		snapshot, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
		if err != nil || snapshot.Allows("note.read", "shared", employee, "interview_followup", f.Now) {
			t.Fatal("persisted object restriction became broad scope:", err)
		}
		detail, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), meeting.ID, interview.DetailQuery{IncludeSections: []string{"shared", "manager_private", "hr_confidential"}, IncludeActions: true})
		if err != nil || len(detail.Sections) != 1 || detail.Sections[0].Category != "shared" || len(detail.Sections[0].Versions) != 1 || detail.Sections[0].Versions[0].ID != old.ID || detail.Sections[0].HeadRevision != nil || detail.Sections[0].DraftVersionID != nil || detail.Sections[0].PublishedVersionID != nil {
			t.Fatal("bounded historical projection exposed unrelated head/current pointer/category:", detail, err)
		}
		for name, projection := range map[string]any{"direct immutable version": view, "detail historical section": detail} {
			raw, err := json.Marshal(projection)
			if err != nil || strings.Contains(string(raw), *old.HeadID) {
				t.Fatal(name+" disclosed unapproved canonical head in actual JSON:", string(raw), err)
			}
		}
		exportGrant := objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, "sensitive.export", "shared", &exact))
		var exported []interview.ExportEvent
		_, err = f.Interviews.Export(ctx, f.InterviewRequest(f.Reader), interview.ExportCommand{Format: "ndjson", Objects: []interview.ExportObject{{Kind: "note_version", ID: old.ID, ExpectedRevision: "1"}}}, func(event interview.ExportEvent) error {
			if strings.Contains(string(event.EncodedJSON), *old.HeadID) {
				t.Fatal("authorized version export disclosed unapproved canonical head:", string(event.EncodedJSON))
			}
			var decoded interview.ExportEvent
			if err := json.Unmarshal(event.EncodedJSON, &decoded); err != nil {
				return err
			}
			exported = append(exported, decoded)
			return nil
		})
		if err != nil || len(exported) != 3 || exported[1].NoteVersion == nil || exported[1].NoteVersion.ID != old.ID || exported[1].NoteVersion.Text != view.Text || exported[2].Kind != "complete" {
			t.Fatal("exact historical version export lost immutable content or completion:", exported, err)
		}
		page, err := f.Authz.List(ctx, managementRequest(f), authz.Filter{SubjectID: f.Reader.SubjectID, Capability: "note.read", ObjectKind: "note_version", ObjectID: old.ID, Limit: 1})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != made.ID || page.Items[0].ObjectRef == nil || *page.Items[0].ObjectRef != exact || len(page.Items[0].ApprovedSourceRefs) != 0 || page.NextCursor != nil {
			t.Fatal("typed filtered security projection lost actual object fact:", page, err)
		}
		encoded, err := json.Marshal(page)
		if err != nil || strings.Contains(string(encoded), "SYNTHETIC_EXACT_HANDOVER") || strings.Contains(string(encoded), "SYNTHETIC_OTHER_VERSION") || strings.Contains(string(encoded), "SYNTHETIC_NOT_HANDED_OVER") {
			t.Fatal("grant projection disclosed note text")
		}
		revoked, err := f.Authz.Revoke(ctx, managementRequest(f), made.ID, authz.RevokeCommand{ExpectedRevision: made.Revision, ExpectedAuthEpoch: exportGrant.AuthEpoch, Reason: "access_no_longer_required"})
		if err != nil || revoked.Status != "revoked" {
			t.Fatal("real exact-version revoke:", err)
		}
		if _, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), old.ID); !errors.Is(err, fault.NotFound) {
			t.Fatal("known old version survived current revocation:", err)
		}
		currentExact := authz.ObjectReference{Kind: "note_version", ID: latest.ID}
		objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "shared", &currentExact))
		current, err := f.Interviews.Detail(ctx, f.InterviewRequest(f.Reader), meeting.ID, interview.DetailQuery{IncludeSections: []string{"shared"}})
		if err != nil || len(current.Sections) != 1 || len(current.Sections[0].Versions) != 1 || current.Sections[0].Versions[0].ID != latest.ID || current.Sections[0].HeadID != "" || current.Sections[0].Versions[0].HeadID != "" || current.Sections[0].HeadRevision != nil || current.Sections[0].DraftVersionID != nil || current.Sections[0].PublishedVersionID != nil {
			t.Fatal("exact current version must not reveal that it is a head pointer:", current, err)
		}
		owner, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Owner), old.ID)
		if err != nil || owner.HeadID != *old.HeadID {
			t.Fatal("independent current head-read authority lost its canonical head projection:", owner, err)
		}
	})
}

func TestTypedObjectIssueChecksFamilyCategoryOwnerAndScopeBeforeDigest(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee, other := makeEmployee(t, f), makeEmployee(t, f)
		meeting := authorityInterview(t, f, employee)
		note := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_TYPED_OWNER"})
		ref := authz.ObjectReference{Kind: "note_version", ID: note.ID}
		baselineGrants, baselineReceipts := f.Count(t, "access_grant"), f.Count(t, "grant_command_receipt")
		for _, test := range []struct {
			name  string
			alter func(*authz.IssueCommand)
			want  error
		}{
			{"wrong category", func(c *authz.IssueCommand) { c.Category = "shared"; c.AuthorityID = f.AuthorityIDs["note.read/shared"] }, fault.Forbidden},
			{"wrong owner", func(c *authz.IssueCommand) { c.Scope.ID = other }, fault.Forbidden},
			{"wrong family", func(c *authz.IssueCommand) {
				c.Capability = "action.read"
				c.Category = "shared"
				c.AuthorityID = f.AuthorityIDs["action.read/shared"]
			}, fault.Invalid},
			{"wrong kind tuple", func(c *authz.IssueCommand) { c.ObjectRef = &authz.ObjectReference{Kind: "note_head", ID: note.ID} }, fault.Forbidden},
			{"missing object", func(c *authz.IssueCommand) {
				c.ObjectRef = &authz.ObjectReference{Kind: "note_version", ID: value.NewID()}
			}, fault.Forbidden},
		} {
			t.Run(test.name, func(t *testing.T) {
				command := objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "manager_private", &ref)
				test.alter(&command)
				service := *f.Authz
				service.DigestKey = nil
				if _, err := service.Issue(ctx, managementRequest(f), command); !errors.Is(err, test.want) {
					t.Fatal("authorization/typed validation must run before digest readiness:", err)
				}
			})
		}
		if f.Count(t, "access_grant") != baselineGrants || f.Count(t, "grant_command_receipt") != baselineReceipts {
			t.Fatal("invalid typed issue left facts or receipt")
		}
		command := objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "manager_private", &ref)
		command.Scope = authz.Scope{Kind: "org", ID: f.OrgID}
		made := objectIssue(t, f, command)
		if made.ID == "" {
			t.Fatal("approved org scope plus typed object must remain supported")
		}
		if _, err := f.Repo.Object(ctx, f.OtherOrgID, ref); !errors.Is(err, fault.NotFound) {
			t.Fatal("typed metadata lookup leaked across organizations:", err)
		}
		info, err := f.Repo.Object(ctx, f.OrgID, ref)
		if err != nil || info.EmployeeID != employee || info.Category != "manager_private" || !info.Published || info.Revision != "1" || len(info.Lineage) != 3 || info.Lineage[0].ID != meeting.ID || info.Lineage[1].ID != *note.HeadID || info.Lineage[2] != ref {
			t.Fatal("canonical immutable metadata tuple incorrect:", info, err)
		}
	})
}

func TestSourceApprovalRequiresPublishedSameOwnerCurrentReadAndFiniteTarget(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee, other := makeEmployee(t, f), makeEmployee(t, f)
		meeting, otherMeeting := authorityInterview(t, f, employee), authorityInterview(t, f, other)
		published := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_PRIVATE_SOURCE"})
		draft := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "hr_confidential", ExpectedHeadRevision: "0", Action: "save_draft", Text: "SYNTHETIC_UNPUBLISHED_SOURCE"})
		foreign := authorityNote(t, f, otherMeeting.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_OTHER_EMPLOYEE_SOURCE"})
		target := authz.ObjectReference{Kind: "interview", ID: meeting.ID}
		base := objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.publish", "shared", &target)
		base.ApprovedSourceRefs = []authz.ObjectReference{{Kind: "note_version", ID: published.ID}}
		beforeGrants, beforeReceipts, beforeApprovals := f.Count(t, "access_grant"), f.Count(t, "grant_command_receipt"), f.Count(t, "access_grant_source_approval")
		for _, test := range []struct {
			name  string
			alter func(*authz.IssueCommand)
			want  error
		}{
			{"unpublished", func(c *authz.IssueCommand) {
				c.ApprovedSourceRefs = []authz.ObjectReference{{Kind: "note_version", ID: draft.ID}}
			}, fault.Forbidden},
			{"wrong employee", func(c *authz.IssueCommand) {
				c.ApprovedSourceRefs = []authz.ObjectReference{{Kind: "note_version", ID: foreign.ID}}
			}, fault.Forbidden},
			{"wrong source family", func(c *authz.IssueCommand) {
				c.ApprovedSourceRefs = []authz.ObjectReference{{Kind: "note_head", ID: *published.HeadID}}
			}, fault.Invalid},
			{"duplicate source", func(c *authz.IssueCommand) {
				c.ApprovedSourceRefs = append(c.ApprovedSourceRefs, c.ApprovedSourceRefs[0])
			}, fault.Invalid},
			{"source grants on read", func(c *authz.IssueCommand) {
				c.Capability = "note.read"
				c.AuthorityID = f.AuthorityIDs["note.read/shared"]
			}, fault.Invalid},
			{"source scope not minimized", func(c *authz.IssueCommand) { c.Scope = authz.Scope{Kind: "org", ID: f.OrgID} }, fault.Invalid},
			{"delegated category escalation", func(c *authz.IssueCommand) { c.AuthorityID = f.AuthorityIDs["note.publish/manager_private"] }, fault.Forbidden},
			{"delegated capability escalation", func(c *authz.IssueCommand) { c.AuthorityID = f.AuthorityIDs["action.write/shared"] }, fault.Forbidden},
		} {
			t.Run(test.name, func(t *testing.T) {
				command := base
				test.alter(&command)
				if _, err := f.Authz.Issue(ctx, managementRequest(f), command); !errors.Is(err, test.want) {
					t.Fatal("invalid source approval accepted:", err)
				}
			})
		}
		if f.Count(t, "access_grant") != beforeGrants || f.Count(t, "grant_command_receipt") != beforeReceipts || f.Count(t, "access_grant_source_approval") != beforeApprovals {
			t.Fatal("rejected source approvals wrote partial facts/receipt")
		}
		request := managementRequest(f)
		made, err := f.Authz.Issue(ctx, request, base)
		if err != nil || f.Count(t, "access_grant_source_approval") != beforeApprovals+1 {
			t.Fatal("published sameowner source approval not persisted:", err)
		}
		stored, err := f.Repo.Grant(ctx, f.OrgID, made.ID)
		if err != nil || !reflect.DeepEqual(stored.ApprovedSourceRefs, base.ApprovedSourceRefs) {
			t.Fatal("immutable approved source projection lost:", stored, err)
		}
		if err := f.Exec(ctx, "DELETE FROM capability_assignment WHERE org_id=? AND subject_id=? AND capability='note.read'", "DELETE FROM capability_assignment WHERE org_id=$1 AND subject_id=$2 AND capability='note.read'", f.OrgID, f.Manager.SubjectID); err != nil {
			t.Fatal(err)
		}
		service := *f.Authz
		service.DigestKey = nil
		if _, err := service.Issue(ctx, request, base); !errors.Is(err, fault.Forbidden) {
			t.Fatal("committed source receipt/approved target cannot bypass current manager source read before digest:", err)
		}
		if f.Count(t, "access_grant_source_approval") != beforeApprovals+1 || f.Count(t, "grant_command_receipt") != beforeReceipts+1 {
			t.Fatal("denied approval replay changed immutable facts")
		}
	})
}

func TestIndependentSourceApprovalDoesNotGrantSourceReadOrPublishOnItsOwn(t *testing.T) {
	grantBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := makeEmployee(t, f)
		meeting := authorityInterview(t, f, employee)
		private := authorityNote(t, f, meeting.ID, interview.NoteCommand{Category: "manager_private", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_APPROVAL_NEVER_COPIES_PRIVATE"})
		target := authz.ObjectReference{Kind: "interview", ID: meeting.ID}
		for _, pair := range [][2]string{{"interview.read", "metadata"}, {"note.read", "shared"}, {"note.write", "shared"}, {"note.publish", "shared"}} {
			objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, pair[0], pair[1], &target))
		}
		ref := authz.ObjectReference{Kind: "note_version", ID: private.ID}
		sourceRead := objectIssue(t, f, objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "manager_private", &ref))
		command := interview.NoteCommand{Category: "shared", ExpectedHeadRevision: "0", Action: "publish", Text: "SYNTHETIC_HUMAN_MINIMAL_SLICE", SourceRefs: []interview.SourceRef{{Kind: "note_version", ID: private.ID, ExpectedVersion: *private.VersionNo}}, ConfirmMinimized: true}
		beforeGrants, beforeVersions, beforeReceipts := f.Count(t, "access_grant"), f.Count(t, "note_version"), f.Count(t, "interview_receipt")
		if _, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Reader), meeting.ID, command); !errors.Is(err, fault.NotFound) && !errors.Is(err, fault.Forbidden) {
			t.Fatal("independently read/write/publish grants must not silently approve crosscategory sources:", err)
		}
		if f.Count(t, "access_grant") != beforeGrants || f.Count(t, "note_version") != beforeVersions || f.Count(t, "interview_receipt") != beforeReceipts {
			t.Fatal("unapproved publication wrote grant/content/receipt")
		}
		approval := objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.publish", "shared", &target)
		approval.ApprovedSourceRefs = []authz.ObjectReference{ref}
		objectIssue(t, f, approval)
		grants := f.Count(t, "access_grant")
		made, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Reader), meeting.ID, command)
		if err != nil {
			t.Fatal("separate source approval must permit manual target publication:", err)
		}
		if f.Count(t, "access_grant") != grants {
			t.Fatal("note publication wrote an implicit grant")
		}
		shared, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), made.ID)
		if err != nil || shared.Text != command.Text || strings.Contains(shared.Text, "SYNTHETIC_APPROVAL_NEVER_COPIES_PRIVATE") || len(shared.SourceRefs) != 1 {
			t.Fatal("approved minimal text/source projection incorrect:", shared, err)
		}
		original, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Owner), private.ID)
		if err != nil || original.Category != "manager_private" || original.Text != "SYNTHETIC_APPROVAL_NEVER_COPIES_PRIVATE" {
			t.Fatal("sharing mutated original private version:", original, err)
		}
		epoch := objectGrantCommand(t, f, f.Reader.SubjectID, employee, "note.read", "shared", &target).ExpectedRevision
		if _, err := f.Authz.Revoke(ctx, managementRequest(f), sourceRead.ID, authz.RevokeCommand{ExpectedRevision: sourceRead.Revision, ExpectedAuthEpoch: epoch, Reason: "policy_change"}); err != nil {
			t.Fatal(err)
		}
		snapshot, err := f.Repo.Security(ctx, f.Reader.Hash, f.OrgID, employee)
		if err != nil || snapshot.AllowsObject("note.read", "manager_private", employee, "interview_followup", f.Now, authz.ObjectReference{Kind: "interview", ID: meeting.ID}, authz.ObjectReference{Kind: "note_head", ID: *private.HeadID}, ref) {
			t.Fatal("source approval bypassed revoked independent source read:", err)
		}
		if _, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), private.ID); !errors.Is(err, fault.NotFound) {
			t.Fatal("known private source remained readable after loss:", err)
		}
		reloaded, err := f.Interviews.NoteVersion(ctx, f.InterviewRequest(f.Reader), made.ID)
		if err != nil || reloaded.Text != command.Text || len(reloaded.SourceRefs) != 0 {
			t.Fatal("target read must remain independent while hiding revoked source metadata:", reloaded, err)
		}
		ownerApproval := objectGrantCommand(t, f, f.Owner.SubjectID, employee, "note.publish", "shared", &target)
		ownerApproval.ApprovedSourceRefs = []authz.ObjectReference{ref}
		objectIssue(t, f, ownerApproval)
		if err := f.Exec(ctx, "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND capability='note.read' AND category='manager_private'", "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND capability='note.read' AND category='manager_private'", f.OrgID, f.Owner.SubjectID); err != nil {
			t.Fatal(err)
		}
		correction := command
		correction.HeadID, correction.ExpectedHeadRevision, correction.SupersedesVersionID, correction.EditReason = made.HeadID, *made.HeadRevision, &made.ID, "SYNTHETIC_AUTHOR_LOST_SOURCE_RIGHTS"
		approvedFacts, versions, receipts := f.Count(t, "access_grant_source_approval"), f.Count(t, "note_version"), f.Count(t, "interview_receipt")
		if _, err := f.Interviews.SaveNote(ctx, f.InterviewRequest(f.Owner), meeting.ID, correction); !errors.Is(err, fault.NotFound) && !errors.Is(err, fault.Forbidden) {
			t.Fatal("source author with target approval bypassed current source rights:", err)
		}
		if f.Count(t, "access_grant_source_approval") != approvedFacts || f.Count(t, "note_version") != versions || f.Count(t, "interview_receipt") != receipts {
			t.Fatal("failed publication rolled back prior independent approval or left partial content")
		}
	})
}
