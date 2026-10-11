package organization

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (s *Service) structureAuthority(ctx context.Context, r Reader, req Request, org, op string, write bool) (authz.Snapshot, error) {
	if len(req.TokenHash) != 32 || r == nil {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	snap, err := r.Security(ctx, req.TokenHash, "", "")
	if err != nil {
		return snap, err
	}
	now := s.clock()
	if !snap.Valid(now) {
		return snap, fault.Unauthenticated
	}
	if snap.OrgID != org {
		return snap, fault.NotFound
	}
	if write {
		if !snap.Allows("organization.read", "metadata", "", req.Purpose, now) {
			return snap, fault.NotFound
		}
		if !snap.Allows("organization.write", "metadata", "", req.Purpose, now) {
			return snap, fault.Forbidden
		}
	}
	return snap, nil
}
func (s *Service) sealOrganization(ctx context.Context, org, employee, record, kind, schema string, payload any) (OrganizationPayload, error) {
	data, err := json.Marshal(payload)
	if err != nil || len(data) > 16<<10 {
		clear(data)
		return OrganizationPayload{}, fault.Invalid
	}
	defer clear(data)
	p := OrganizationPayload{ID: value.NewID(), RecordedAt: s.clock()}
	binding := sensitive.Context{OrgID: org, EmployeeID: employee, RecordID: record, VersionID: p.ID, ObjectKind: kind, Purpose: "pii", SchemaType: schema, SchemaVersion: 1}
	p.Envelope, err = s.Cipher.Seal(ctx, binding, data)
	if err != nil {
		return OrganizationPayload{}, fault.Unavailable
	}
	return p, nil
}
func confirmStructure(r StructureReceipt, digest []byte) (StructureResult, error) {
	if subtle.ConstantTimeCompare(r.Digest, digest) != 1 {
		return StructureResult{}, fault.Mismatch
	}
	return r.Result, nil
}
func (s *Service) structureReplay(ctx context.Context, req Request, snap authz.Snapshot, op string, digest []byte) (StructureResult, bool, error) {
	_, found, err := s.Store.StructureReceipt(ctx, snap.OrgID, snap.SubjectID, op, req.Key)
	if !found || err != nil {
		return StructureResult{}, false, err
	}
	var result StructureResult
	err = s.Store.WithTx(ctx, snap.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, snap.OrgID, []string{snap.SubjectID}); err != nil {
			return err
		}
		current, err := s.structureAuthority(ctx, tx, req, snap.OrgID, op, op == "OP-ORG-02")
		if err != nil {
			return err
		}
		r, exists, err := tx.StructureReceipt(ctx, current.OrgID, current.SubjectID, op, req.Key)
		if err != nil {
			return err
		}
		if !exists {
			return fault.Unavailable
		}
		if err = s.receiptAuthority(ctx, tx, req, current, r.Targets); err != nil {
			return err
		}
		result, err = confirmStructure(r, digest)
		return err
	})
	if err != nil {
		return StructureResult{}, true, err
	}
	return result, true, nil
}
func codeValid(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for i := range code {
		c := code[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
func textValid(text *string, max int, nonempty bool) bool {
	return text == nil || utf8.ValidString(*text) && len(*text) <= max && (!nonempty || strings.TrimSpace(*text) != "")
}
func (s *Service) CreateTeam(ctx context.Context, req Request, org string, cmd CreateTeamCommand) (StructureResult, error) {
	const op = "OP-ORG-02"
	snap, err := s.structureAuthority(ctx, s.Store, req, org, op, true)
	if err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	if !value.ValidID(org) || !value.ValidID(req.Key) || !codeValid(cmd.Code) || !validLifecycle(cmd.Lifecycle) || !textValid(cmd.Label, 256, false) {
		return StructureResult{}, fault.Invalid
	}
	if err = s.receiptAuthority(ctx, s.Store, req, snap, teamReceiptTargets(org, cmd.Label != nil)); err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	digest, err := s.digest(req, snap, op, org, cmd)
	if err != nil {
		return StructureResult{}, err
	}
	if result, found, err := s.structureReplay(ctx, req, snap, op, digest); found || err != nil {
		return result, s.denied(ctx, req, snap, op, err)
	}
	team := Team{ID: value.NewID(), OrgID: org, Code: cmd.Code, Lifecycle: cmd.Lifecycle}
	change := StructureChange{ID: value.NewID(), OrgID: org, SubjectID: snap.SubjectID, RecordedAt: s.clock()}
	fact := LifecycleFact{ID: value.NewID(), OrgID: org, Kind: "team_lifecycle", ObjectID: team.ID, ChangeID: change.ID, Lifecycle: cmd.Lifecycle}
	write := StructureWrite{Team: &team, Change: change, Lifecycles: []LifecycleFact{fact}}
	write.Change.Items = []HistoryRelation{{Action: "lifecycle", Kind: "team_lifecycle", ID: fact.ID, TeamID: team.ID, ValidFrom: cmd.Lifecycle.ValidFrom, ValidTo: cmd.Lifecycle.ValidTo}}
	if cmd.Label != nil {
		p, err := s.sealOrganization(ctx, org, "", team.ID, "team_label", "org.team.label.v1", struct {
			Label string `json:"label"`
		}{*cmd.Label})
		if err != nil {
			return StructureResult{}, err
		}
		team.LabelPayloadID = p.ID
		write.Payloads = append(write.Payloads, p)
	}
	var result StructureResult
	targets := teamReceiptTargets(org, cmd.Label != nil)
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
		if err := tx.LockGraph(ctx, org); err != nil {
			return err
		}
		if err := tx.LockSubjects(ctx, org, []string{snap.SubjectID}); err != nil {
			return err
		}
		current, err := s.structureAuthority(ctx, tx, req, org, op, true)
		if err != nil {
			return err
		}
		if r, found, err := tx.StructureReceipt(ctx, org, current.SubjectID, op, req.Key); err != nil {
			return err
		} else if found {
			if err = s.receiptAuthority(ctx, tx, req, current, r.Targets); err != nil {
				return err
			}
			result, err = confirmStructure(r, digest)
			return err
		}
		if current.AuthEpoch != snap.AuthEpoch {
			return fault.Forbidden
		}
		if err = s.receiptAuthority(ctx, tx, req, current, targets); err != nil {
			return err
		}
		g, err := tx.Graph(ctx, org)
		if err != nil {
			return err
		}
		for _, t := range g.Teams {
			if t.Code == team.Code {
				return fault.Conflict
			}
		}
		current, err = s.structureAuthority(ctx, tx, req, org, op, true)
		if err != nil {
			return err
		}
		if err = s.receiptAuthority(ctx, tx, req, current, targets); err != nil {
			return err
		}
		revision, epoch, err := tx.CommitStructure(ctx, org, g.Revision, write)
		if err != nil {
			return err
		}
		result = StructureResult{ID: team.ID, GraphRevision: strconv.FormatInt(revision, 10), AuthEpoch: strconv.FormatInt(epoch, 10)}
		if err = tx.SaveStructureReceipt(ctx, org, current.SubjectID, op, req.Key, StructureReceipt{Digest: digest, Result: result, Targets: targets}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(req, current, "", op, "allowed"))
	})
	if err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	return result, nil
}

func validateItem(item StructureItem) bool {
	if item.Action != "add" && item.Action != "end" && item.Action != "replace" && item.Action != "lifecycle" {
		return false
	}
	ids := []*string{item.Ref, item.EmployeeID, item.TeamID, item.ParentTeamID, item.ManagerEmployeeID}
	for _, id := range ids {
		if id != nil && !value.ValidID(*id) {
			return false
		}
	}
	if item.Action == "end" {
		return (item.Kind == "team_parent" || item.Kind == "membership" || item.Kind == "position" || item.Kind == "reporting_line") && item.Ref != nil && item.EndDate != nil && value.ValidDate(*item.EndDate) && item.EmployeeID == nil && item.TeamID == nil && item.ParentTeamID == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil && item.IsPrimary == nil && item.Lifecycle == nil && item.Position == nil
	}
	if item.EndDate != nil || item.Lifecycle == nil || !validLifecycle(*item.Lifecycle) {
		return false
	}
	if item.Action == "lifecycle" {
		return item.Ref == nil && item.ParentTeamID == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil && item.IsPrimary == nil && item.Position == nil && ((item.Kind == "team_lifecycle" && item.TeamID != nil && item.EmployeeID == nil) || (item.Kind == "employee_lifecycle" && item.EmployeeID != nil && item.TeamID == nil))
	}
	if (item.Action == "replace") != (item.Ref != nil) {
		return false
	}
	switch item.Kind {
	case "team_parent":
		return item.TeamID != nil && item.ParentTeamID != nil && item.EmployeeID == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil && item.IsPrimary == nil && item.Position == nil
	case "membership":
		return item.EmployeeID != nil && item.TeamID != nil && item.IsPrimary != nil && *item.IsPrimary && item.ParentTeamID == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil && item.Position == nil
	case "position":
		return item.EmployeeID != nil && item.IsPrimary != nil && *item.IsPrimary && item.Position != nil && item.ParentTeamID == nil && item.ManagerEmployeeID == nil && item.ReportingKind == nil && positionValid(*item.Position)
	case "reporting_line":
		return item.EmployeeID != nil && item.ManagerEmployeeID != nil && item.ReportingKind != nil && (*item.ReportingKind == "administrative" || *item.ReportingKind == "dotted") && item.TeamID == nil && item.ParentTeamID == nil && item.IsPrimary == nil && item.Position == nil
	}
	return false
}
func ptrValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func historyRelation(action string, r Relation) HistoryRelation {
	h := HistoryRelation{Action: action, Kind: r.Kind, ID: r.ID, EmployeeID: r.EmployeeID, TeamID: r.TeamID, ParentTeamID: r.ParentTeamID, ManagerEmployeeID: r.ManagerEmployeeID, ReportingKind: r.ReportingKind, ValidFrom: r.Lifecycle.ValidFrom, ValidTo: r.Lifecycle.ValidTo, EffectiveTo: r.EffectiveTo, SupersedesID: r.SupersedesID, Superseded: r.Superseded}
	if r.Kind == "membership" || r.Kind == "position" {
		primary := r.IsPrimary
		h.IsPrimary = &primary
	}
	if action == "end" {
		h.EndDate = r.EffectiveTo
	}
	return h
}
func applyStructure(g Graph, items []StructureItem, ids []string, write *StructureWrite) (Graph, error) {
	g.Teams = append([]Team(nil), g.Teams...)
	g.Employees = append([]Employee(nil), g.Employees...)
	g.Relations = append([]Relation(nil), g.Relations...)
	for i, item := range items {
		if item.Action == "lifecycle" {
			found := false
			obj := ptrValue(item.EmployeeID)
			if item.Kind == "team_lifecycle" {
				obj = ptrValue(item.TeamID)
				for j := range g.Teams {
					if g.Teams[j].ID == obj {
						g.Teams[j].Lifecycle = *item.Lifecycle
						found = true
						break
					}
				}
			} else {
				for j := range g.Employees {
					if g.Employees[j].ID == obj {
						g.Employees[j].Lifecycle = *item.Lifecycle
						found = true
						break
					}
				}
			}
			if !found {
				return Graph{}, fault.Invalid
			}
			fact := LifecycleFact{ID: ids[i], OrgID: g.OrgID, Kind: item.Kind, ObjectID: obj, ChangeID: write.Change.ID, Lifecycle: *item.Lifecycle}
			write.Lifecycles = append(write.Lifecycles, fact)
			write.Change.Items = append(write.Change.Items, HistoryRelation{Action: item.Action, Kind: item.Kind, ID: fact.ID, EmployeeID: ptrValue(item.EmployeeID), TeamID: ptrValue(item.TeamID), ValidFrom: fact.Lifecycle.ValidFrom, ValidTo: fact.Lifecycle.ValidTo})
			continue
		}
		old := -1
		if item.Ref != nil {
			for j, r := range g.Relations {
				if r.ID == *item.Ref && r.Kind == item.Kind {
					old = j
					break
				}
			}
			if old < 0 || g.Relations[old].Superseded {
				return Graph{}, fault.Invalid
			}
		}
		if item.Action == "end" {
			r := g.Relations[old]
			if r.EffectiveTo != nil || *item.EndDate <= r.Lifecycle.ValidFrom {
				return Graph{}, fault.Invalid
			}
			r.EffectiveTo = item.EndDate
			r.EndChangeID = write.Change.ID
			g.Relations[old] = r
			write.Ended = append(write.Ended, r)
			write.Change.Items = append(write.Change.Items, historyRelation("end", r))
			continue
		}
		r := Relation{ID: ids[i], OrgID: g.OrgID, Kind: item.Kind, EmployeeID: ptrValue(item.EmployeeID), TeamID: ptrValue(item.TeamID), ParentTeamID: ptrValue(item.ParentTeamID), ManagerEmployeeID: ptrValue(item.ManagerEmployeeID), ReportingKind: ptrValue(item.ReportingKind), Lifecycle: *item.Lifecycle, ChangeID: write.Change.ID}
		if item.IsPrimary != nil {
			r.IsPrimary = *item.IsPrimary
		}
		if item.Kind == "position" {
			for _, p := range write.Payloads {
				if p.Envelope.Context.RecordID == r.ID {
					r.PayloadID = p.ID
					break
				}
			}
		}
		if old >= 0 {
			previous := g.Relations[old]
			if previous.EmployeeID != r.EmployeeID || r.Kind == "team_parent" && previous.TeamID != r.TeamID {
				return Graph{}, fault.Invalid
			}
			previous.Superseded = true
			g.Relations[old] = previous
			write.Superseded = append(write.Superseded, previous)
			r.SupersedesID = previous.ID
		}
		g.Relations = append(g.Relations, r)
		write.Added = append(write.Added, r)
		write.Change.Items = append(write.Change.Items, historyRelation(item.Action, r))
	}
	if err := ValidateGraph(g); err != nil {
		return Graph{}, err
	}
	return g, nil
}
func (s *Service) ChangeStructure(ctx context.Context, req Request, org string, cmd StructureCommand) (StructureResult, error) {
	const op = "OP-ORG-03"
	snap, err := s.structureAuthority(ctx, s.Store, req, org, op, false)
	if err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	expected, valid := value.Revision(cmd.ExpectedGraphRevision)
	if !value.ValidID(org) || !value.ValidID(req.Key) || !valid || len(cmd.Changes) < 1 || len(cmd.Changes) > 100 || !textValid(cmd.Reason, 4096, false) {
		return StructureResult{}, fault.Invalid
	}
	for _, item := range cmd.Changes {
		if !validateItem(item) {
			return StructureResult{}, fault.Invalid
		}
	}
	digest, err := s.digest(req, snap, op, org, cmd)
	if err != nil {
		return StructureResult{}, err
	}
	if result, found, err := s.structureReplay(ctx, req, snap, op, digest); found || err != nil {
		return result, s.denied(ctx, req, snap, op, err)
	}
	initialGraph, err := s.Store.Graph(ctx, org)
	if err != nil {
		return StructureResult{}, err
	}
	if _, err = s.itemAuthority(ctx, s.Store, req, snap, initialGraph, cmd.Changes, cmd.Reason != nil); err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	write := StructureWrite{Change: StructureChange{ID: value.NewID(), OrgID: org, SubjectID: snap.SubjectID, RecordedAt: s.clock()}}
	ids := make([]string, len(cmd.Changes))
	for i, item := range cmd.Changes {
		ids[i] = value.NewID()
		if item.Action == "end" {
			ids[i] = *item.Ref
		}
		if item.Position != nil {
			p, err := s.sealOrganization(ctx, org, *item.EmployeeID, ids[i], "position_assignment", "org.position.v1", item.Position)
			if err != nil {
				return StructureResult{}, err
			}
			write.Payloads = append(write.Payloads, p)
		}
	}
	if cmd.Reason != nil {
		p, err := s.sealOrganization(ctx, org, "", write.Change.ID, "structure_change", "org.structure.reason.v1", struct {
			Reason string `json:"reason"`
		}{*cmd.Reason})
		if err != nil {
			return StructureResult{}, err
		}
		write.Change.ReasonPayloadID = p.ID
		write.Payloads = append(write.Payloads, p)
	}
	var result StructureResult
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
		if err := tx.LockGraph(ctx, org); err != nil {
			return err
		}
		if err := tx.LockSubjects(ctx, org, []string{snap.SubjectID}); err != nil {
			return err
		}
		current, err := s.structureAuthority(ctx, tx, req, org, op, false)
		if err != nil {
			return err
		}
		if previous, found, err := tx.StructureReceipt(ctx, org, current.SubjectID, op, req.Key); err != nil {
			return err
		} else if found {
			if err = s.receiptAuthority(ctx, tx, req, current, previous.Targets); err != nil {
				return err
			}
			result, err = confirmStructure(previous, digest)
			return err
		}
		g, err := tx.Graph(ctx, org)
		if err != nil {
			return err
		}
		if g.Revision != expected {
			return fault.Conflict
		}
		if current.AuthEpoch != snap.AuthEpoch {
			return fault.Forbidden
		}
		targets, err := s.itemAuthority(ctx, tx, req, current, g, cmd.Changes, cmd.Reason != nil)
		if err != nil {
			return err
		}
		if _, err = applyStructure(g, cmd.Changes, ids, &write); err != nil {
			return err
		}
		current, err = s.structureAuthority(ctx, tx, req, org, op, false)
		if err != nil {
			return err
		}
		if err = s.receiptAuthority(ctx, tx, req, current, targets); err != nil {
			return err
		}
		revision, epoch, err := tx.CommitStructure(ctx, org, expected, write)
		if err != nil {
			return err
		}
		result = StructureResult{ID: write.Change.ID, GraphRevision: strconv.FormatInt(revision, 10), AuthEpoch: strconv.FormatInt(epoch, 10), Items: make([]StructureItemResult, len(cmd.Changes))}
		for i, item := range cmd.Changes {
			result.Items[i] = StructureItemResult{Kind: item.Kind, ID: ids[i]}
		}
		if err = tx.SaveStructureReceipt(ctx, org, current.SubjectID, op, req.Key, StructureReceipt{Digest: digest, Result: result, Targets: targets}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(req, current, "", op, "allowed"))
	})
	if err != nil {
		return StructureResult{}, s.denied(ctx, req, snap, op, err)
	}
	return result, nil
}
