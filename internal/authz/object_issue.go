package authz

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"github.com/r404r/team-ledger/internal/fault"
)

func normalizeObjectCommand(command *IssueCommand) bool {
	if command.Category == "financial" && (command.RelationBound || command.RelationRef != nil) {
		return false
	}
	if command.ObjectRef != nil && (!ValidObjectReference(*command.ObjectRef) || !ObjectPair(command.Capability, command.Category, command.ObjectRef.Kind)) {
		return false
	}
	if len(command.ApprovedSourceRefs) > 10 {
		return false
	}
	if len(command.ApprovedSourceRefs) == 0 {
		command.ApprovedSourceRefs = []ObjectReference{}
		return true
	}
	if command.Scope.Kind != "employee" || command.Capability != "note.publish" && command.Capability != "action.write" {
		return false
	}
	command.ApprovedSourceRefs = slices.Clone(command.ApprovedSourceRefs)
	slices.SortFunc(command.ApprovedSourceRefs, func(a, b ObjectReference) int { return cmp.Compare(a.ID, b.ID) })
	for i, ref := range command.ApprovedSourceRefs {
		if ref.Kind != "note_version" || !ValidObjectReference(ref) || i > 0 && ref == command.ApprovedSourceRefs[i-1] {
			return false
		}
	}
	return true
}

// These are the manager's current approval checks, not the NEW recipient's
// qualification. They therefore also precede committed-receipt recovery.
func (s *Service) approveObjects(ctx context.Context, r Reader, current Snapshot, grant *GrantDTO) error {
	if grant.ObjectRef != nil {
		object, err := r.Object(ctx, current.OrgID, *grant.ObjectRef)
		if errors.Is(err, fault.NotFound) {
			return fault.Forbidden
		}
		if err != nil {
			return err
		}
		if object.Reference != *grant.ObjectRef || !CanonicalLineage(object.Lineage...) || object.Reference.Kind != "interview" && object.Category != grant.Category {
			return fault.Forbidden
		}
		covered, err := r.ScopeCovered(ctx, current.OrgID, grant.Scope, Scope{Kind: "employee", ID: object.EmployeeID}, s.clock())
		if err != nil {
			return err
		}
		grant.ObjectEmployeeID = object.EmployeeID
		if !covered {
			return fault.Forbidden
		}
	}
	for _, ref := range grant.ApprovedSourceRefs {
		source, err := r.Object(ctx, current.OrgID, ref)
		if errors.Is(err, fault.NotFound) {
			return fault.Forbidden
		}
		if err != nil {
			return err
		}
		if source.Reference != ref || source.EmployeeID != grant.Scope.ID || !source.Published || !current.AllowsObject("note.read", source.Category, source.EmployeeID, "interview_followup", s.clock(), source.Lineage...) {
			return fault.Forbidden
		}
	}
	return nil
}
