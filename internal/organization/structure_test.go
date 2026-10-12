package organization_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func makeTeam(t *testing.T, f *testsupport.Fixture, code string) organization.StructureResult {
	t.Helper()
	r, err := f.Service.CreateTeam(context.Background(), f.Request(f.Owner), f.OrgID, organization.CreateTeamCommand{Code: code, Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}})
	if err != nil {
		t.Fatal("real team creation:", err)
	}
	return r
}
func graphRevision(t *testing.T, f *testsupport.Fixture) string {
	t.Helper()
	g, err := f.Repo.GraphState(context.Background(), f.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(g.Revision, 10)
}
func change(t *testing.T, f *testsupport.Fixture, items ...organization.StructureItem) organization.StructureResult {
	t.Helper()
	r, err := f.Service.ChangeStructure(context.Background(), f.Request(f.Owner), f.OrgID, organization.StructureCommand{ExpectedGraphRevision: graphRevision(t, f), Changes: items})
	if err != nil {
		t.Fatal("real structure command:", err)
	}
	return r
}
func membership(employee, team, from string) organization.StructureItem {
	return organization.StructureItem{Action: "add", Kind: "membership", EmployeeID: new(employee), TeamID: new(team), IsPrimary: new(true), Lifecycle: &organization.Lifecycle{ValidFrom: from}}
}
func position(employee, team, from, title string) organization.StructureItem {
	return organization.StructureItem{Action: "add", Kind: "position", EmployeeID: new(employee), TeamID: new(team), IsPrimary: new(true), Lifecycle: &organization.Lifecycle{ValidFrom: from}, Position: &organization.PositionPayload{Title: title}}
}
func end(kind, ref, day string) organization.StructureItem {
	return organization.StructureItem{Action: "end", Kind: kind, Ref: new(ref), EndDate: new(day)}
}

func TestStructureFutureTransferImmutableFactsOriginalReceiptAndHistory(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		a, b := makeTeam(t, f, "A"), makeTeam(t, f, "B")
		e := create(t, f, "SYNTHETIC_STRUCTURE_EMPLOYEE").ID
		first := change(t, f, membership(e, b.ID, "2026-01-01"), position(e, b.ID, "2026-01-01", "SYNTHETIC_POSITION_X"))
		req := f.Request(f.Owner)
		cmd := organization.StructureCommand{ExpectedGraphRevision: first.GraphRevision, Reason: new("SYNTHETIC_GLOBAL_TRANSFER_REASON"), Changes: []organization.StructureItem{end("membership", first.Items[0].ID, "2027-01-01"), end("position", first.Items[1].ID, "2027-01-01"), membership(e, a.ID, "2027-01-01"), position(e, a.ID, "2027-01-01", "SYNTHETIC_POSITION_Y")}}
		committed, err := f.Service.ChangeStructure(ctx, req, f.OrgID, cmd)
		if err != nil {
			t.Fatal(err)
		}
		before, err := f.Service.Read(ctx, f.Request(f.Owner), e, "2026-12-31", true)
		if err != nil || len(before.Memberships) != 1 || before.Memberships[0].TeamID != b.ID || len(before.Positions) != 1 || before.Positions[0].Position == nil || before.Positions[0].Position.Title != "SYNTHETIC_POSITION_X" {
			t.Fatal("before transfer must retain original tenure/payload", err)
		}
		at, err := f.Service.Read(ctx, f.Request(f.Owner), e, "2027-01-01", true)
		if err != nil || len(at.Memberships) != 1 || at.Memberships[0].TeamID != a.ID || at.Positions[0].Position.Title != "SYNTHETIC_POSITION_Y" || at.Revision != "1" {
			t.Fatal("exact boundary must show replacement tenure and independent profile revision", err)
		}
		graph, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range graph.Relations {
			if r.ID == first.Items[0].ID {
				found = true
				if r.Lifecycle.ValidTo != nil || r.EffectiveTo == nil || *r.EffectiveTo != "2027-01-01" || r.ChangeID != first.ID || r.EndChangeID != committed.ID || r.Superseded {
					t.Fatal("end overwrote immutable original fact or revoked future tenure early")
				}
			}
		}
		if !found {
			t.Fatal("original stable relation missing")
		}
		calls, audits, changes := f.KMS.Calls.Load(), f.Count(t, "audit_event"), f.Count(t, "structure_change")
		replayed, err := f.Service.ChangeStructure(ctx, req, f.OrgID, cmd)
		if err != nil || !reflect.DeepEqual(replayed, committed) || f.KMS.Calls.Load() != calls || f.Count(t, "audit_event") != audits || f.Count(t, "structure_change") != changes {
			t.Fatal("original safe receipt must precede stale graph/object validation and KMS", err)
		}
		different := cmd
		different.Reason = new("different protected reason")
		if _, err = f.Service.ChangeStructure(ctx, req, f.OrgID, different); !errors.Is(err, fault.Mismatch) {
			t.Fatal("different command same key must reject", err)
		}
		history, err := f.Service.History(ctx, f.Request(f.Owner), e, organization.HistoryQuery{})
		if err != nil || len(history.Items) != 2 {
			t.Fatal("actual employee structure history", err)
		}
		refs := map[string]bool{}
		reason := false
		for _, h := range history.Items {
			if h.ActorSubjectID != f.Owner.SubjectID || h.RecordedAt.Location() != time.UTC {
				t.Fatal("history lost original actor/time")
			}
			if h.Reason != nil && *h.Reason == *cmd.Reason {
				reason = true
			}
			for _, r := range h.Items {
				refs[r.ID] = true
				if r.EmployeeID != e {
					t.Fatal("mixed command history leaked another employee")
				}
			}
		}
		if !reason || !refs[first.Items[0].ID] || !refs[committed.Items[2].ID] {
			t.Fatal("history lost stable old/new refs or independently org-authorized reason")
		}
		observer, err := f.Service.Read(ctx, f.Request(f.Observer), e, "2027-01-01", true)
		if err != nil || observer.Profile != nil || observer.Revision != "" || observer.Positions[0].Position != nil {
			t.Fatal("metadata-only projection leaked payload or profile revision", err)
		}
		safeHistory, err := f.Service.History(ctx, f.Request(f.Observer), e, organization.HistoryQuery{})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range safeHistory.Items {
			if h.Reason != nil {
				t.Fatal("employee metadata exposed org reason")
			}
			for _, r := range h.Items {
				if r.Position != nil {
					t.Fatal("history exposed encrypted position")
				}
			}
		}
	})
}

func TestStructureReplaceSupersedesAndLifecycleGraphFailureRollsBack(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		team := makeTeam(t, f, "T")
		e := create(t, f, "synthetic replacement").ID
		old := change(t, f, membership(e, team.ID, "2026-01-01"))
		replacement := membership(e, team.ID, "2026-02-01")
		replacement.Action = "replace"
		replacement.Ref = new(old.Items[0].ID)
		made := change(t, f, replacement)
		g, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		oldRetained, newRetained := false, false
		for _, r := range g.Relations {
			if r.ID == old.Items[0].ID {
				oldRetained = r.Superseded && r.Lifecycle.ValidFrom == "2026-01-01" && r.Lifecycle.ValidTo == nil
			}
			if r.ID == made.Items[0].ID {
				newRetained = r.SupersedesID == old.Items[0].ID
			}
		}
		if !oldRetained || !newRetained {
			t.Fatal("explicit replacement lost original facts/correction chain")
		}
		before := g
		counts := []int{f.Count(t, "structure_change"), f.Count(t, "structure_change_item"), f.Count(t, "structure_command_receipt"), f.Count(t, "team_lifecycle_history"), f.Count(t, "audit_event")}
		bad := organization.StructureCommand{ExpectedGraphRevision: made.GraphRevision, Changes: []organization.StructureItem{{Action: "lifecycle", Kind: "team_lifecycle", TeamID: new(team.ID), Lifecycle: &organization.Lifecycle{ValidFrom: "2026-01-01", ValidTo: new("2026-12-31")}}}}
		if _, err = f.Service.ChangeStructure(ctx, f.Request(f.Owner), f.OrgID, bad); !errors.Is(err, fault.Invalid) {
			t.Fatal("lifecycle ending before open tenure must reject", err)
		}
		after, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("graph failure changed projection/revision/epoch", err)
		}
		for i, table := range []string{"structure_change", "structure_change_item", "structure_command_receipt", "team_lifecycle_history", "audit_event"} {
			if f.Count(t, table) != counts[i] {
				t.Fatal("graph failure left partial immutable facts", table)
			}
		}
	})
}

func TestStructureAuditFailureRollsBackEveryFactProjectionEpochAndReceipt(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		team := makeTeam(t, f, "AUDIT")
		e := create(t, f, "synthetic audit employee").ID
		old := change(t, f, membership(e, team.ID, "2026-01-01"), position(e, team.ID, "2026-01-01", "old title"))
		before, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, table := range []string{"structure_change", "structure_change_item", "structure_command_receipt", "organizational_payload", "team_lifecycle_history", "employee_lifecycle_history"} {
			counts[table] = f.Count(t, table)
		}
		if err = f.DisableAudit(ctx); err != nil {
			t.Fatal(err)
		}
		replacement := position(e, team.ID, "2026-01-01", "new audit rollback title")
		replacement.Action = "replace"
		replacement.Ref = new(old.Items[1].ID)
		cmd := organization.StructureCommand{ExpectedGraphRevision: old.GraphRevision, Reason: new("new audit rollback reason"), Changes: []organization.StructureItem{end("membership", old.Items[0].ID, "2027-01-01"), replacement, {Action: "lifecycle", Kind: "employee_lifecycle", EmployeeID: new(e), Lifecycle: &organization.Lifecycle{ValidFrom: "2026-01-01"}}}}
		if _, err = f.Service.ChangeStructure(ctx, f.Request(f.Owner), f.OrgID, cmd); !errors.Is(err, fault.AuditUnavailable) {
			t.Fatal("mandatory audit failure must abort complete structural transaction", err)
		}
		after, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("audit rollback failed original end/supersede/lifecycle/CAS/epoch", err)
		}
		for table, count := range counts {
			if f.Count(t, table) != count {
				t.Fatal("audit rollback left fact/payload/receipt", table)
			}
		}
	})
}

func teamGrant(t *testing.T, f *testsupport.Fixture, subject, team, cap string) {
	t.Helper()
	ctx := context.Background()
	if err := f.Exec(ctx, "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,team_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES(?,?,?,?,'metadata','team',?,?,'organization_management',?,?,0,0,0)", "INSERT INTO access_grant(id,org_id,subject_id,capability,category,scope_kind,scope_id,team_id,purpose,valid_from,expires_at,revoked,relation_bound,mfa_required) VALUES($1,$2,$3,$4,'metadata','team',$5,$6,'organization_management',$7,$8,false,false,false)", value.NewID(), f.OrgID, subject, cap, team, team, f.Repo.BindTime(f.Now.Add(-time.Hour)), f.Repo.BindTime(f.Now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
}
func TestStructureExactScopedWriterAndOriginalTransferReceipt(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		a, b := makeTeam(t, f, "SCOPE_A"), makeTeam(t, f, "SCOPE_B")
		e := create(t, f, "synthetic scope employee").ID
		old := change(t, f, membership(e, a.ID, "2026-01-01"))
		for _, cap := range []string{"organization.read", "organization.write"} {
			teamGrant(t, f, f.Reader.SubjectID, a.ID, cap)
		}
		teamGrant(t, f, f.Reader.SubjectID, b.ID, "organization.read")
		req := f.Request(f.Reader)
		cmd := organization.StructureCommand{ExpectedGraphRevision: old.GraphRevision, Changes: []organization.StructureItem{end("membership", old.Items[0].ID, "2026-10-11"), membership(e, b.ID, "2026-10-11")}}
		result, err := f.Service.ChangeStructure(ctx, req, f.OrgID, cmd)
		if err != nil {
			t.Fatal("exact team scope must cover currently-member employee mutation with independently visible endpoint", err)
		}
		replay, err := f.Service.ChangeStructure(ctx, req, f.OrgID, cmd)
		if err != nil || !reflect.DeepEqual(result, replay) {
			t.Fatal("safe original receipt incorrectly demanded now-ended original membership", err)
		}
		if _, err = f.Service.ChangeStructure(ctx, f.Request(f.Reader), f.OrgID, organization.StructureCommand{ExpectedGraphRevision: result.GraphRevision, Changes: []organization.StructureItem{end("membership", result.Items[1].ID, "2026-11-01")}}); !errors.Is(err, fault.Forbidden) {
			t.Fatal("old team's write coverage must not authorize new current team", err)
		}
		teamGrant(t, f, f.Stranger.SubjectID, a.ID, "organization.read")
		change(t, f, organization.StructureItem{Action: "add", Kind: "team_parent", TeamID: new(b.ID), ParentTeamID: new(a.ID), Lifecycle: &organization.Lifecycle{ValidFrom: "2026-01-01"}})
		tree, err := f.Service.Tree(ctx, f.Request(f.Stranger), f.OrgID, organization.TreeQuery{AsOf: "2026-10-11", RootTeamID: a.ID})
		if err != nil || len(tree.Nodes) != 1 || tree.Nodes[0].ID != a.ID || len(tree.Edges) != 0 || len(tree.Employees) != 0 {
			t.Fatal("parent grants must not silently authorize descendants/historical employee members", err)
		}
		if _, err = f.Service.Read(ctx, f.Request(f.Stranger), e, "2026-01-01", false); !errors.Is(err, fault.NotFound) {
			t.Fatal("historical membership cannot recover current team authorization", err)
		}
	})
}

func TestDirectoryBoundedEncryptedSearchCursorAndMixedHistory(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		a, b := create(t, f, "SYNTHETIC_SEARCH_ALPHA").ID, create(t, f, "SYNTHETIC_SEARCH_BETA").ID
		query := organization.DirectoryQuery{AsOf: "2026-10-11", Q: "SYNTHETIC_SEARCH", IncludeProfile: true, Limit: 1}
		page, err := f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, query)
		if err != nil || len(page.Items) != 1 || page.NextCursor == nil {
			t.Fatal("real decrypt/search pagination", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(*page.NextCursor)
		if err != nil || bytes.Contains(raw, []byte(query.Q)) {
			t.Fatal("cursor persisted low-entropy raw search")
		}
		query.Cursor = *page.NextCursor
		next, err := f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, query)
		if err != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID || next.NextCursor != nil {
			t.Fatal("keyset must cover authorized remaining match without duplicates", err)
		}
		changed := query
		changed.Q = "SYNTHETIC_SEARCH_ALPHA"
		if _, err = f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, changed); !errors.Is(err, fault.Conflict) {
			t.Fatal("changed query must invalidate cursor", err)
		}
		if _, err = f.Service.Directory(ctx, f.Request(f.Observer), f.OrgID, query); !errors.Is(err, fault.Forbidden) {
			t.Fatal("metadata reader cannot search names", err)
		}
		team := makeTeam(t, f, "MIXED")
		change(t, f, position(a, team.ID, "2026-01-01", "private alpha position"), position(b, team.ID, "2026-01-01", "private beta position"))
		h, err := f.Service.History(ctx, f.Request(f.Owner), a, organization.HistoryQuery{Limit: 1})
		if err != nil || len(h.Items) != 1 || len(h.Items[0].Items) != 1 || h.Items[0].Items[0].EmployeeID != a {
			t.Fatal("matching one employee must not disclose mixed-command rows", err)
		}
		encoded, _ := json.Marshal(h)
		if bytes.Contains(encoded, []byte(b)) || bytes.Contains(encoded, []byte("private beta position")) {
			t.Fatal("mixed history disclosed another employee payload/ref")
		}
		if _, err = f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, query); !errors.Is(err, fault.Conflict) {
			t.Fatal("graph/epoch change must invalidate old directory cursor", err)
		}
	})
}

func TestOrganizationEncryptedMarkersNeverReachSQLiteOrWAL(t *testing.T) {
	f := testsupport.NewHarness(t, "sqlite")
	ctx := context.Background()
	label := "SYNTHETIC_TEAM_LABEL_STORAGE_PRIVATE"
	team, err := f.Service.CreateTeam(ctx, f.Request(f.Owner), f.OrgID, organization.CreateTeamCommand{Code: "SAFE_CODE", Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}, Label: &label})
	if err != nil {
		t.Fatal(err)
	}
	employee := create(t, f, "SYNTHETIC_ORG_EMPLOYEE_STORAGE_PRIVATE").ID
	reason := "SYNTHETIC_STRUCTURE_REASON_STORAGE_PRIVATE"
	title := "SYNTHETIC_POSITION_TITLE_STORAGE_PRIVATE"
	if _, err = f.Service.ChangeStructure(ctx, f.Request(f.Owner), f.OrgID, organization.StructureCommand{ExpectedGraphRevision: team.GraphRevision, Reason: &reason, Changes: []organization.StructureItem{position(employee, team.ID, "2026-01-01", title)}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{f.DSN, f.DSN + "-wal"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{label, reason, title, "SYNTHETIC_ORG_EMPLOYEE_STORAGE_PRIVATE"} {
			if bytes.Contains(data, []byte(marker)) {
				t.Fatal("protected marker reached real storage", path)
			}
		}
	}
}

func TestDirectoryStopsAtFiveHundredAuthorizedDecryptCandidates(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		for i := range 501 {
			create(t, f, "synthetic bounded scan employee "+strconv.Itoa(i))
		}
		before := f.KMS.Calls.Load()
		query := organization.DirectoryQuery{AsOf: "2026-10-11", Q: "SYNTHETIC_ABSENT_SEARCH_TOKEN", IncludeProfile: true, Limit: 50}
		first, err := f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, query)
		if err != nil || len(first.Items) != 0 || first.NextCursor == nil || !first.SearchIncomplete || f.KMS.Calls.Load()-before != 500 {
			t.Fatal("empty-match page must stop after 500 authorized decrypts and expose only a bounded scan cursor", err)
		}
		query.Cursor = *first.NextCursor
		before = f.KMS.Calls.Load()
		last, err := f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, query)
		if err != nil || len(last.Items) != 0 || last.NextCursor != nil || last.SearchIncomplete || f.KMS.Calls.Load()-before != 1 {
			t.Fatal("continuation must scan the remaining authorized candidate exactly once", err)
		}
	})
}

func TestConcurrentGraphCommandsPreparedAtSameRevisionCommitOneLegalWinner(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		a, b := makeTeam(t, f, "CONCURRENT_A"), makeTeam(t, f, "CONCURRENT_B")
		revision := b.GraphRevision
		before, err := f.Repo.GraphState(ctx, f.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		arrived, release := make(chan struct{}, 2), make(chan struct{})
		f.KMS.BlockEncrypt(2, arrived, release)
		type outcome struct {
			result organization.StructureResult
			err    error
		}
		done := make(chan outcome, 2)
		for _, endpoints := range [][2]string{{a.ID, b.ID}, {b.ID, a.ID}} {
			go func() {
				cmd := organization.StructureCommand{ExpectedGraphRevision: revision, Reason: new("synthetic concurrent graph reason"), Changes: []organization.StructureItem{{Action: "add", Kind: "team_parent", TeamID: new(endpoints[0]), ParentTeamID: new(endpoints[1]), Lifecycle: &organization.Lifecycle{ValidFrom: "2026-01-01"}}}}
				result, err := f.Service.ChangeStructure(ctx, f.Request(f.Owner), f.OrgID, cmd)
				done <- outcome{result, err}
			}()
		}
		for range 2 {
			select {
			case <-arrived:
			case <-ctx.Done():
				close(release)
				t.Fatal("both real encrypted graph commands must reach KMS outside guards")
			}
		}
		close(release)
		success, conflict := 0, 0
		for range 2 {
			select {
			case out := <-done:
				if out.err == nil {
					success++
				} else if errors.Is(out.err, fault.Conflict) {
					conflict++
				} else {
					t.Fatal("concurrent graph command returned unexpected result", out.err)
				}
			case <-ctx.Done():
				t.Fatal("graph writers did not complete")
			}
		}
		after, err := f.Repo.Graph(ctx, f.OrgID)
		if err != nil || success != 1 || conflict != 1 || len(after.Relations) != 1 || after.Revision != before.Revision+1 || after.AuthEpoch != before.AuthEpoch+1 || f.Count(t, "structure_change") != 3 || f.Count(t, "structure_command_receipt") != 3 || f.Count(t, "organizational_payload") != 1 {
			t.Fatal("same revision competition must commit one legal graph and no losing facts/epoch/payload/receipt", err)
		}
	})
}

func TestTreeLimitBoundsEmployeesAsWellAsNodes(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		team := makeTeam(t, f, "BOUNDED_TREE")
		a, b := create(t, f, "synthetic bounded tree a").ID, create(t, f, "synthetic bounded tree b").ID
		change(t, f, membership(a, team.ID, "2026-01-01"), membership(b, team.ID, "2026-01-01"))
		if tree, err := f.Service.Tree(context.Background(), f.Request(f.Owner), f.OrgID, organization.TreeQuery{AsOf: "2026-10-11", RootTeamID: team.ID, Limit: 2}); !errors.Is(err, fault.Invalid) || len(tree.Nodes) != 0 || len(tree.Employees) != 0 {
			t.Fatal("bounded tree must explicitly reject oversized authorized snapshot, not silently omit employees", err)
		}
	})
}

func TestTreeSnapshotLimitCountsParentEdgesWithNodesAndEmployees(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		root, child := makeTeam(t, f, "BUDGET_ROOT"), makeTeam(t, f, "BUDGET_CHILD")
		a, b := create(t, f, "synthetic total budget a").ID, create(t, f, "synthetic total budget b").ID
		change(t, f,
			organization.StructureItem{Action: "add", Kind: "team_parent", TeamID: new(child.ID), ParentTeamID: new(root.ID), Lifecycle: &organization.Lifecycle{ValidFrom: "2026-01-01"}},
			membership(a, root.ID, "2026-01-01"), membership(b, child.ID, "2026-01-01"))
		query := organization.TreeQuery{AsOf: "2026-10-11", RootTeamID: root.ID, Limit: 5}
		exact, err := f.Service.Tree(context.Background(), f.Request(f.Owner), f.OrgID, query)
		if err != nil || len(exact.Nodes) != 2 || len(exact.Edges) != 1 || len(exact.Employees) != 2 || exact.Edges[0].ChildTeamID != child.ID || exact.Edges[0].ParentTeamID != root.ID {
			t.Fatal("exact total budget must retain both teams, parent edge and employees", err)
		}
		query.Limit = 4
		oversized, err := f.Service.Tree(context.Background(), f.Request(f.Owner), f.OrgID, query)
		if !errors.Is(err, fault.Invalid) || len(oversized.Nodes)+len(oversized.Edges)+len(oversized.Employees) != 0 {
			t.Fatal("one parent edge over the combined snapshot budget must reject without partial projection", err)
		}
	})
}

func TestTreeRequiresRealMetadataGrantEvenForEmptyHistoricalProjection(t *testing.T) {
	backends(t, func(t *testing.T, f *testsupport.Fixture) {
		ctx := context.Background()
		team := makeTeam(t, f, "EMPTY_HISTORY")
		view, err := f.Service.Tree(ctx, f.Request(f.Stranger), f.OrgID, organization.TreeQuery{AsOf: "2025-01-01"})
		if !errors.Is(err, fault.NotFound) || view.GraphRevision != "" || view.AuthEpoch != "" {
			t.Fatal("grantless authenticated subject must not learn graph/epoch through empty tree", err)
		}
		teamGrant(t, f, f.Stranger.SubjectID, team.ID, "organization.read")
		view, err = f.Service.Tree(ctx, f.Request(f.Stranger), f.OrgID, organization.TreeQuery{AsOf: "2025-01-01", RootTeamID: team.ID})
		if err != nil || len(view.Nodes) != 0 || len(view.Edges) != 0 || len(view.Employees) != 0 || view.GraphRevision == "" {
			t.Fatal("independently approved exact team reader should receive authorized empty historical projection", err)
		}
	})
}

func TestRevokePreventsEveryNewInFlightOrganizationSensitiveRelease(t *testing.T) {
	for _, operation := range []string{"tree", "directory", "history"} {
		t.Run(operation, func(t *testing.T) {
			backends(t, func(t *testing.T, f *testsupport.Fixture) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				team, err := f.Service.CreateTeam(ctx, f.Request(f.Owner), f.OrgID, organization.CreateTeamCommand{Code: "SENSITIVE_RELEASE", Lifecycle: organization.Lifecycle{ValidFrom: "2026-01-01"}, Label: new("synthetic private team label")})
				if err != nil {
					t.Fatal(err)
				}
				employee := create(t, f, "synthetic private release employee").ID
				change(t, f, position(employee, team.ID, "2026-01-01", "synthetic private position"))
				arrived, release := make(chan struct{}), make(chan struct{})
				f.KMS.BlockNextDecrypt(arrived, release)
				done := make(chan error, 1)
				go func() {
					switch operation {
					case "tree":
						view, err := f.Service.Tree(ctx, f.Request(f.Owner), f.OrgID, organization.TreeQuery{AsOf: "2026-10-11", IncludeLabels: true})
						if err != nil && len(view.Nodes) != 0 {
							done <- errors.New("denied tree retained plaintext output")
							return
						}
						done <- err
					case "directory":
						page, err := f.Service.Directory(ctx, f.Request(f.Owner), f.OrgID, organization.DirectoryQuery{AsOf: "2026-10-11", IncludeProfile: true})
						if err != nil && len(page.Items) != 0 {
							done <- errors.New("denied directory retained plaintext output")
							return
						}
						done <- err
					case "history":
						page, err := f.Service.History(ctx, f.Request(f.Owner), employee, organization.HistoryQuery{})
						if err != nil && len(page.Items) != 0 {
							done <- errors.New("denied history retained plaintext output")
							return
						}
						done <- err
					}
				}()
				select {
				case <-arrived:
				case <-ctx.Done():
					close(release)
					t.Fatal("sensitive read did not reach real KMS outside transaction guards")
				}
				tx, err := f.Repo.DB.BeginTx(ctx, nil)
				if err != nil {
					close(release)
					t.Fatal(err)
				}
				defer tx.Rollback()
				guard, revoke := "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=?", "UPDATE access_grant SET revoked=1 WHERE org_id=? AND subject_id=? AND category='pii'"
				if f.Backend == "postgres" {
					guard, revoke = "UPDATE authorization_guard SET auth_epoch=auth_epoch+1 WHERE org_id=$1", "UPDATE access_grant SET revoked=true WHERE org_id=$1 AND subject_id=$2 AND category='pii'"
				}
				if _, err = tx.ExecContext(ctx, guard, f.OrgID); err == nil {
					_, err = tx.ExecContext(ctx, revoke, f.OrgID, f.Owner.SubjectID)
				}
				if err == nil {
					err = tx.Commit()
				}
				close(release)
				if err != nil {
					t.Fatal("real revocation must commit while decrypt is outside guards", err)
				}
				select {
				case err := <-done:
					if !errors.Is(err, fault.Forbidden) {
						t.Fatal("revoke must synchronously close sensitive release without plaintext", err)
					}
				case <-ctx.Done():
					t.Fatal("denied sensitive read did not finish")
				}
			})
		})
	}
}
