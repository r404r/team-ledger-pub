package compensation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestCompensationEventExportRechecksEachTermReadAndExportAtRelease(t *testing.T) {
	for _, capability := range []string{"compensation.read", "sensitive.export"} {
		for _, change := range []string{"revoke", "expire"} {
			t.Run(capability+"/"+change, func(t *testing.T) {
				financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
					ctx := context.Background()
					employee := financeEmployee(t, f, false)
					financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms("314159"), Reason: "SYNTHETIC_RELEASE_BODY"})
					term := financeCurrent(t, f, employee, "2026-01-01").CurrentTerm
					event, err := f.Repo.CompensationEvent(ctx, f.OrgID, term.EventID)
					if err != nil {
						t.Fatal(err)
					}
					financeRevokeBroad(t, f, f.FinExporter, "compensation.read")
					financeRevokeBroad(t, f, f.FinExporter, "sensitive.export")
					eventRef := &authz.ObjectReference{Kind: "compensation_event", ID: event.ID}
					termRef := &authz.ObjectReference{Kind: "compensation_term", ID: term.ID}
					var selected authz.Result
					for _, cap := range []string{"compensation.read", "sensitive.export"} {
						financeGrant(t, f, f.FinExporter, employee, cap, eventRef)
						if cap == capability && change == "expire" {
							selected, err = f.Authz.Issue(ctx, authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{SubjectID: f.FinExporter.SubjectID, Capability: cap, Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Minute).Format(time.RFC3339Nano), MFARequired: true, ObjectRef: termRef, AuthorityID: f.AuthorityIDs[cap+"/financial"], ExpectedRevision: financeEpoch(t, f)})
							if err != nil {
								t.Fatal(err)
							}
						} else {
							grant := financeGrant(t, f, f.FinExporter, employee, cap, termRef)
							if cap == capability {
								selected = grant
							}
						}
					}
					var stream bytes.Buffer
					var kinds []string
					command := compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: eventRef.Kind, ID: eventRef.ID, ExpectedRevision: strconv.FormatInt(event.Sequence, 10)}}}
					_, err = f.Compensation.Export(ctx, financeRequest(f.FinExporter), command, func(e compensation.ExportEvent) error {
						var envelope struct {
							Kind string `json:"kind"`
						}
						if err := json.Unmarshal(e.EncodedJSON, &envelope); err != nil {
							t.Fatal(err)
						}
						kinds = append(kinds, envelope.Kind)
						stream.Write(e.EncodedJSON)
						if envelope.Kind == "header" {
							if change == "revoke" {
								financeRevoke(t, f, selected)
							} else {
								f.Now = f.Now.Add(2 * time.Minute)
							}
						}
						return nil
					})
					if err == nil || len(kinds) != 2 || kinds[0] != "header" || kinds[1] != "partial" || bytes.Contains(stream.Bytes(), []byte("314159")) || bytes.Contains(stream.Bytes(), []byte("SYNTHETIC_RELEASE_BODY")) {
						t.Fatal("revoked or expired independent term permission released decrypted financial body", kinds, err)
					}
				})
			})
		}
	}
}

func TestCompensationEventExportRechecksBroadGroupReadAtRelease(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms("100"), Reason: "SYNTHETIC_ORIGINAL_REASON"})
		current := financeCurrent(t, f, employee, "2026-01-01")
		original := current.CurrentTerm
		financeApprove(t, f, employee, compensation.ProposalCommand{Kind: "correction", CompRevision: current.CompRevision, Reason: "SYNTHETIC_BROAD_GROUP_REASON", Members: []compensation.CorrectionMember{{MemberKey: "group_member", Action: "replace", OriginalEventID: original.EventID, EffectiveDate: "2026-01-01", After: financeTerms("314159")}}})
		corrected := financeCurrent(t, f, employee, "2026-01-01").CurrentTerm
		event, err := f.Repo.CompensationEvent(ctx, f.OrgID, corrected.EventID)
		if err != nil {
			t.Fatal(err)
		}
		financeRevokeBroad(t, f, f.FinExporter, "compensation.read")
		financeRevokeBroad(t, f, f.FinExporter, "sensitive.export")
		eventRef := &authz.ObjectReference{Kind: "compensation_event", ID: event.ID}
		for _, target := range []*authz.ObjectReference{eventRef, {Kind: "compensation_term", ID: original.ID}, {Kind: "compensation_term", ID: corrected.ID}} {
			for _, cap := range []string{"compensation.read", "sensitive.export"} {
				financeGrant(t, f, f.FinExporter, employee, cap, target)
			}
		}
		_, err = f.Authz.Issue(ctx, authz.Request{TokenHash: f.Manager.Hash, Purpose: authz.ManagementPurpose, Key: value.NewID(), RequestID: value.NewID()}, authz.IssueCommand{SubjectID: f.FinExporter.SubjectID, Capability: "compensation.read", Category: "financial", Scope: authz.Scope{Kind: "employee", ID: employee}, Purpose: "compensation_management", ValidFrom: f.Now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.Now.Add(time.Minute).Format(time.RFC3339Nano), MFARequired: true, AuthorityID: f.AuthorityIDs["compensation.read/financial"], ExpectedRevision: financeEpoch(t, f)})
		if err != nil {
			t.Fatal(err)
		}
		command := compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: eventRef.Kind, ID: eventRef.ID, ExpectedRevision: strconv.FormatInt(event.Sequence, 10)}}}
		var before bytes.Buffer
		if _, err = f.Compensation.Export(ctx, financeRequest(f.FinExporter), command, func(e compensation.ExportEvent) error { before.Write(e.EncodedJSON); return nil }); err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"group_member", "SYNTHETIC_BROAD_GROUP_REASON", "SYNTHETIC_DECISION_approve", "314159"} {
			if !bytes.Contains(before.Bytes(), []byte(marker)) {
				t.Fatal("approved broad reader did not receive its actual group/term projection", marker)
			}
		}
		epoch := financeEpoch(t, f)
		var stream bytes.Buffer
		var kinds []string
		_, err = f.Compensation.Export(ctx, financeRequest(f.FinExporter), command, func(e compensation.ExportEvent) error {
			var envelope struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(e.EncodedJSON, &envelope); err != nil {
				t.Fatal(err)
			}
			kinds = append(kinds, envelope.Kind)
			stream.Write(e.EncodedJSON)
			if envelope.Kind == "header" {
				f.Now = f.Now.Add(2 * time.Minute)
			}
			return nil
		})
		if err == nil || len(kinds) != 2 || kinds[0] != "header" || kinds[1] != "partial" {
			t.Fatal("broad read expiry released a prepared correction-group object", kinds, err)
		}
		for _, marker := range []string{"group_member", "SYNTHETIC_BROAD_GROUP_REASON", "SYNTHETIC_DECISION_approve", "314159"} {
			if bytes.Contains(stream.Bytes(), []byte(marker)) {
				t.Fatal("expired group authorization released prepared body", marker)
			}
		}
		if got := financeEpoch(t, f); got != epoch {
			t.Fatal("expiry regression changed auth epoch", epoch, got)
		}
		snapshot, err := f.Repo.Security(ctx, f.FinExporter.Hash, f.OrgID, employee)
		if err != nil || !snapshot.AllowsObject("compensation.read", "financial", employee, "compensation_management", f.Now, *eventRef) || !snapshot.AllowsObject("sensitive.export", "financial", employee, "compensation_management", f.Now, *eventRef) || snapshot.Allows("compensation.read", "financial", employee, "compensation_management", f.Now) {
			t.Fatal("exact event grants must remain valid after only broad read expires", err)
		}
		var narrow bytes.Buffer
		if _, err = f.Compensation.Export(ctx, financeRequest(f.FinExporter), command, func(e compensation.ExportEvent) error { narrow.Write(e.EncodedJSON); return nil }); err != nil {
			t.Fatal("fresh exact-event export was unnecessarily denied", err)
		}
		for _, marker := range []string{"group_member", "SYNTHETIC_BROAD_GROUP_REASON", "SYNTHETIC_DECISION_approve"} {
			if bytes.Contains(narrow.Bytes(), []byte(marker)) {
				t.Fatal("fresh exact-event export exposed broader group fields", marker)
			}
		}
		if !bytes.Contains(narrow.Bytes(), []byte("314159")) || !bytes.Contains(narrow.Bytes(), []byte(`"kind":"complete"`)) {
			t.Fatal("fresh exact-event/term authorization lost its authorized projection")
		}
	})
}
