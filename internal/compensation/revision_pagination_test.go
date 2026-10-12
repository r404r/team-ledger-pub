package compensation_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func financeVersionedDraft(t *testing.T, f *testsupport.Fixture, employee string, count int) (compensation.Result, []compensation.ProposalCommand, []string) {
	t.Helper()
	commands := make([]compensation.ProposalCommand, 0, count)
	times := make([]string, 0, count)
	var p compensation.Result
	for n := 1; n <= count; n++ {
		command := compensation.ProposalCommand{Kind: "initial", EffectiveDate: "2026-01-01", CompRevision: "0", After: financeTerms(strconv.FormatInt(9007199254740993+int64(n), 10)), Reason: "SYNTHETIC_ORIGINAL_REVISION_" + strconv.Itoa(n), Members: []compensation.CorrectionMember{}}
		if n == 1 {
			p = financeDraft(t, f, employee, command)
		} else {
			var err error
			p, err = f.Compensation.EditProposal(context.Background(), financeRequest(f.CompW), p.ID, compensation.DraftCommand{Kind: command.Kind, EffectiveDate: command.EffectiveDate, CompRevision: command.CompRevision, Revision: p.Revision, After: command.After, Reason: command.Reason, Members: command.Members})
			if err != nil {
				t.Fatal("append original draft revision", err)
			}
		}
		commands = append(commands, command)
		times = append(times, f.Now.UTC().Format(time.RFC3339Nano))
	}
	return p, commands, times
}

func financeZeroChanges(t *testing.T, view compensation.ChangesView, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(view, compensation.ChangesView{}) {
		t.Fatal("failed read returned a head, history, cursor, or permission DTO", view, err)
	}
}

func TestCompensationRevisionPagesPreserveAll105OriginalSnapshotsAndFinalPage(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		p, commands, times := financeVersionedDraft(t, f, employee, 105)
		rows, err := f.Repo.CompensationRevisions(ctx, f.OrgID, p.ID, 0, 101)
		if err != nil || len(rows) != 101 || rows[0].Revision != 105 || rows[100].Revision != 5 {
			t.Fatal("native initial metadata window is not descending and finite", len(rows), err)
		}
		rows, err = f.Repo.CompensationRevisions(ctx, f.OrgID, p.ID, 6, 101)
		if err != nil || len(rows) != 5 || rows[0].Revision != 5 || rows[4].Revision != 1 {
			t.Fatal("native older window omitted the final original revision", rows, err)
		}
		for _, query := range []compensation.ChangesQuery{{RecordKind: "proposals", ProposalID: p.ID, Limit: 1}, {RecordKind: "approvals", Limit: 1}} {
			calls := f.FinancialKMS.Calls.Load()
			view, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
			if err != nil || view.Revisions == nil || len(view.Revisions) != 0 {
				t.Fatal("ordinary modes returned nested or implicit history", view, err)
			}
			if query.RecordKind == "proposals" && (len(view.Proposals) != 1 || view.Proposals[0].Revision != "105" || view.Proposals[0].Reason != commands[104].Reason || f.FinancialKMS.Calls.Load()-calls != 1) {
				t.Fatal("ordinary proposal page decrypted more than its exact head", view, err)
			}
		}
		calls := f.FinancialKMS.Calls.Load()
		var stream bytes.Buffer
		_, err = f.Compensation.Export(ctx, financeRequest(f.FinExporter), compensation.ExportCommand{Format: "ndjson", Objects: []compensation.ExportObject{{Kind: "compensation_proposal", ID: p.ID, ExpectedRevision: "105"}}}, func(e compensation.ExportEvent) error { _, err := stream.Write(e.EncodedJSON); return err })
		if err != nil || f.FinancialKMS.Calls.Load()-calls != 1 {
			t.Fatal("selected proposal export decrypted implicit history", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(stream.String()), "\n") {
			var envelope struct {
				Kind     string                     `json:"kind"`
				Proposal map[string]json.RawMessage `json:"compensation_proposal"`
			}
			if err := json.Unmarshal([]byte(line), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Kind == "object" {
				if _, obsolete := envelope.Proposal["revisions"]; obsolete {
					t.Fatal("proposal export still exposes the obsolete embedded history contract")
				}
				var head compensation.ProposalView
				if err := json.Unmarshal([]byte(line), &struct {
					Proposal *compensation.ProposalView `json:"compensation_proposal"`
				}{&head}); err != nil || head.Revision != "105" || head.Reason != commands[104].Reason || head.After == nil || *head.After.AmountMinor != *commands[104].After.AmountMinor {
					t.Fatal("export did not represent the expected current snapshot", head, err)
				}
			}
		}
		query := compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID}
		remaining, pages := 105, 0
		for {
			calls := f.FinancialKMS.Calls.Load()
			page, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
			want := remaining
			if want > 20 {
				want = 20
			}
			if err != nil || page.RecordKind != query.RecordKind || len(page.Proposals) != 1 || page.Proposals[0].Revision != "105" || page.Proposals[0].Reason != commands[104].Reason || page.Approvals == nil || len(page.Approvals) != 0 || len(page.Revisions) != want {
				t.Fatal("independent default-20 history page lost its current head or rows", page, err)
			}
			opens := int64(want + 1)
			if pages == 0 {
				opens-- // The already decrypted current head is reused in the first page.
			}
			if f.FinancialKMS.Calls.Load()-calls != opens {
				t.Fatal("history decrypt exceeded the actual page plus current snapshot (including a probe row)")
			}
			for _, row := range page.Revisions {
				if row.Revision != strconv.Itoa(remaining) || row.Status != "draft" || row.RecordedAt != times[remaining-1] || row.DecisionReason != "" || !reflect.DeepEqual(row.Command, commands[remaining-1]) {
					t.Fatal("history duplicated, reordered, or changed an original amount/reason/command", row, remaining)
				}
				remaining--
			}
			pages++
			if page.NextCursor == "" {
				if remaining != 0 || pages != 6 {
					t.Fatal("history silently truncated before its final page", remaining, pages)
				}
				break
			}
			if remaining == 0 {
				t.Fatal("final page falsely advertises older history")
			}
			query.Cursor = page.NextCursor
		}
		if f.Count(t, "compensation_proposal_revision") != 105 {
			t.Fatal("bounded reads or exports deleted immutable financial history")
		}
	})
}

func TestCompensationRevisionReadsRejectHiddenWrongOwnerAndRevokedBeforeDecrypt(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		other := financeEmployee(t, f, false)
		selected, _, _ := financeVersionedDraft(t, f, employee, 3)
		hidden, _, _ := financeVersionedDraft(t, f, employee, 3)
		wrongOwner, _, _ := financeVersionedDraft(t, f, other, 3)
		financeRevokeBroad(t, f, f.FinR, "compensation.read")
		grant := financeGrant(t, f, f.FinR, employee, "compensation.read", &authz.ObjectReference{Kind: "compensation_proposal", ID: selected.ID})
		query := compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: selected.ID, Limit: 1}
		page, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
		if err != nil || len(page.Revisions) != 1 || page.Revisions[0].Revision != "3" || page.NextCursor == "" {
			t.Fatal("exact proposal grant lost original history access", page, err)
		}
		query.Cursor = page.NextCursor
		for _, id := range []string{hidden.ID, wrongOwner.ID, value.NewID()} {
			denied := query
			denied.ProposalID, denied.Cursor = id, ""
			calls := f.FinancialKMS.Calls.Load()
			view, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, denied)
			financeZeroChanges(t, view, err)
			if !errors.Is(err, fault.NotFound) || f.FinancialKMS.Calls.Load() != calls {
				t.Fatal("hidden/wrong-owner proposal reached a decrypt or disclosed a different boundary", err)
			}
		}
		calls := f.FinancialKMS.Calls.Load()
		view, err := f.Compensation.Changes(ctx, financeRequest(f.FinExporter), other, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: selected.ID, Limit: 1})
		financeZeroChanges(t, view, err)
		if !errors.Is(err, fault.NotFound) || f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("broad reader used a proposal under the wrong canonical employee", err)
		}
		financeRevoke(t, f, grant)
		calls = f.FinancialKMS.Calls.Load()
		view, err = f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
		financeZeroChanges(t, view, err)
		if f.FinancialKMS.Calls.Load() != calls {
			t.Fatal("revoked cursor reached historical decrypt")
		}
	})
}

func financeCursorField(t *testing.T, key []byte, token, field string, data any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatal("missing signed cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	body[field], err = json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("TEAMLEDGER-COMPENSATION-CURSOR-v1\x00"))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func TestCompensationRevisionCursorBindsModeProposalHeadReaderAndCanonicalPosition(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		employee := financeEmployee(t, f, false)
		p, _, _ := financeVersionedDraft(t, f, employee, 3)
		other, _, _ := financeVersionedDraft(t, f, employee, 3)
		query := compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 1}
		page, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, query)
		if err != nil || page.NextCursor == "" {
			t.Fatal("missing older revision cursor", err)
		}
		query.Cursor = page.NextCursor
		normalQuery := compensation.ChangesQuery{RecordKind: "proposals", Limit: 1}
		normal, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, normalQuery)
		if err != nil || normal.NextCursor == "" {
			t.Fatal("missing ordinary proposal cursor", err)
		}
		assertInvalid := func(request compensation.Request, q compensation.ChangesQuery) {
			t.Helper()
			calls := f.FinancialKMS.Calls.Load()
			view, err := f.Compensation.Changes(ctx, request, employee, q)
			financeZeroChanges(t, view, err)
			if !errors.Is(err, fault.Invalid) || f.FinancialKMS.Calls.Load() != calls {
				t.Fatal("changed or malformed cursor binding was accepted or decrypted", err)
			}
		}
		crossProposal := query
		crossProposal.ProposalID = other.ID
		assertInvalid(financeRequest(f.FinR), crossProposal)
		assertInvalid(financeRequest(f.FinExporter), query)
		otherSessionHash := sha256.Sum256([]byte(value.NewID()))
		if err := f.Exec(ctx, "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) SELECT ?,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version FROM session WHERE token_hash=?", "INSERT INTO session(token_hash,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version) SELECT $1,org_id,subject_id,subject_epoch,expires_at,idle_expires_at,mfa_until,revoked,csrf_hash,csrf_version FROM session WHERE token_hash=$2", otherSessionHash[:], f.FinR.Hash); err != nil {
			t.Fatal("create independent native session for the same reader", err)
		}
		otherSession := financeRequest(f.FinR)
		otherSession.TokenHash = otherSessionHash[:]
		assertInvalid(otherSession, query)
		changedLimit := query
		changedLimit.Limit = 2
		assertInvalid(financeRequest(f.FinR), changedLimit)
		crossMode := normalQuery
		crossMode.Cursor = query.Cursor
		assertInvalid(financeRequest(f.FinR), crossMode)
		crossMode = query
		crossMode.Cursor = normal.NextCursor
		assertInvalid(financeRequest(f.FinR), crossMode)
		for _, position := range []string{"0", "01", "+1", "-1", "9223372036854775808", "2026-01-01T00:00:00Z|" + p.ID} {
			malformed := query
			malformed.Cursor = financeCursorField(t, f.CursorKey, query.Cursor, "after", position)
			assertInvalid(financeRequest(f.FinR), malformed)
		}
		for _, position := range []string{"1", "2026-01-01T00:00:00+00:00|" + p.ID, "2026-01-01T00:00:00Z|invalid"} {
			malformed := normalQuery
			malformed.Cursor = financeCursorField(t, f.CursorKey, normal.NextCursor, "after", position)
			assertInvalid(financeRequest(f.FinR), malformed)
		}
		expired := query
		expired.Cursor = financeCursorField(t, f.CursorKey, query.Cursor, "expires", f.Now.Add(-time.Microsecond))
		assertInvalid(financeRequest(f.FinR), expired)
		tampered := query
		tampered.Cursor = query.Cursor + ".invalid"
		assertInvalid(financeRequest(f.FinR), tampered)
		financeTransition(t, f, p, "submit", "0")
		assertInvalid(financeRequest(f.FinR), query)
		fresh, err := f.Compensation.Changes(ctx, financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 1})
		if err != nil || len(fresh.Revisions) != 1 || fresh.Revisions[0].Revision != "4" || fresh.Revisions[0].Status != "submitted" {
			t.Fatal("explicit reload did not pick the changed proposal head", fresh, err)
		}
		// A changed authorization epoch invalidates the page even when the reader
		// retains its broad read permission and the proposal head is unchanged.
		financeGrant(t, f, f.FinR, employee, "compensation.read", &authz.ObjectReference{Kind: "compensation_proposal", ID: p.ID})
		query.Cursor = fresh.NextCursor
		assertInvalid(financeRequest(f.FinR), query)
	})
}

func TestCompensationRevisionPagesPreserveTransitionDecisionAndCommand(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		p, commands, _ := financeVersionedDraft(t, f, employee, 2)
		p = financeTransition(t, f, p, "submit", "0")
		p = financeTransition(t, f, p, "reject", "0")
		page, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, compensation.ChangesQuery{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 100})
		if err != nil || len(page.Revisions) != 4 || page.NextCursor != "" || page.Revisions[0].Status != "rejected" || page.Revisions[0].DecisionReason != "SYNTHETIC_DECISION_reject" || page.Revisions[1].Status != "submitted" || page.Revisions[1].DecisionReason != "" || !reflect.DeepEqual(page.Revisions[0].Command, commands[1]) || !reflect.DeepEqual(page.Revisions[1].Command, commands[1]) || !reflect.DeepEqual(page.Revisions[3].Command, commands[0]) {
			t.Fatal("transition history lost the original reason, decision, or amount", page, err)
		}
	})
}

func TestCompensationRevisionModeRejectsConflictingFiltersAndUnboundedLimits(t *testing.T) {
	financeBackends(t, func(t *testing.T, f *testsupport.Fixture) {
		employee := financeEmployee(t, f, false)
		p, _, _ := financeVersionedDraft(t, f, employee, 2)
		for _, query := range []compensation.ChangesQuery{
			{RecordKind: "proposal_revisions"},
			{RecordKind: "proposal_revisions", ProposalID: "invalid"},
			{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: -1},
			{RecordKind: "proposal_revisions", ProposalID: p.ID, Limit: 101},
			{RecordKind: "proposal_revisions", ProposalID: p.ID, From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z"},
			{RecordKind: "proposal_revisions", ProposalID: p.ID, Status: "draft"},
		} {
			calls := f.FinancialKMS.Calls.Load()
			view, err := f.Compensation.Changes(context.Background(), financeRequest(f.FinR), employee, query)
			financeZeroChanges(t, view, err)
			if !errors.Is(err, fault.Invalid) || f.FinancialKMS.Calls.Load() != calls {
				t.Fatal("invalid revision query decrypted or acquired different history semantics", query, err)
			}
		}
		for _, limit := range []int{0, 102} {
			if _, err := f.Repo.CompensationRevisions(context.Background(), f.OrgID, p.ID, 0, limit); !errors.Is(err, fault.Invalid) {
				t.Fatal("native revision reader accepted an unbounded metadata window", limit, err)
			}
			if _, err := f.Repo.CompensationApprovalEvents(context.Background(), f.OrgID, value.NewID(), compensation.Scope{Broad: true}, limit); !errors.Is(err, fault.Invalid) {
				t.Fatal("native approval reader accepted an unbounded event window", limit, err)
			}
		}
	})
}
