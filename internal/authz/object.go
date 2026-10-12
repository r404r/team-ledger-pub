package authz

import (
	"time"

	"github.com/r404r/team-ledger/internal/value"
)

func noteCategory(category string) bool {
	return category == "shared" || category == "manager_private" || category == "hr_confidential"
}

func requiresMFA(capability string) bool {
	return capability == "access_grant.manage" || capability == "audit.read" || capability == "note.publish" || capability == "sensitive.export" || capability == "interview_policy.manage" || capability == "assessment.input.approve" || capability == "assessment.publish" || SupportedPair(capability, "financial", "compensation_management")
}

func financialObjectKind(kind string) bool {
	return kind == "compensation_proposal" || kind == "compensation_event" || kind == "compensation_term"
}

func ValidObjectReference(ref ObjectReference) bool {
	return value.ValidID(ref.ID) && (ref.Kind == "interview" || ref.Kind == "note_head" || ref.Kind == "note_version" || ref.Kind == "action_item" || financialObjectKind(ref.Kind))
}

// ObjectPair confines a grant to a typed family. Immutable versions cannot be
// write/publish targets, and interview grants remain category-specific.
func ObjectPair(capability, category, kind string) bool {
	switch capability {
	case "interview.read", "interview.write":
		return category == "metadata" && kind == "interview"
	case "note.read":
		return noteCategory(category) && (kind == "interview" || kind == "note_head" || kind == "note_version")
	case "note.write", "note.publish":
		return noteCategory(category) && (kind == "interview" || kind == "note_head")
	case "action.read", "action.write":
		return category == "shared" && (kind == "interview" || kind == "action_item")
	case "compensation.read":
		return category == "financial" && financialObjectKind(kind)
	case "compensation.propose", "compensation.approve":
		return category == "financial" && kind == "compensation_proposal"
	case "sensitive.export":
		return category == "metadata" && kind == "interview" || noteCategory(category) && (kind == "interview" || kind == "note_head" || kind == "note_version" || category == "shared" && kind == "action_item") || category == "financial" && financialObjectKind(kind)
	}
	return false
}

// CanonicalLineage accepts parent-to-child interview tuples or a singleton
// exact financial object. Financial events/terms never imply a proposal or
// aggregate. Ownership is supplied by the typed object reader, not callers.
func CanonicalLineage(lineage ...ObjectReference) bool {
	if len(lineage) == 1 && financialObjectKind(lineage[0].Kind) {
		return ValidObjectReference(lineage[0])
	}
	if len(lineage) < 1 || len(lineage) > 3 || lineage[0].Kind != "interview" {
		return false
	}
	for i, ref := range lineage {
		if !ValidObjectReference(ref) {
			return false
		}
		for _, previous := range lineage[:i] {
			if previous.ID == ref.ID {
				return false
			}
		}
	}
	return len(lineage) == 1 || len(lineage) == 2 && (lineage[1].Kind == "note_head" || lineage[1].Kind == "action_item") || len(lineage) == 3 && lineage[1].Kind == "note_head" && lineage[2].Kind == "note_version"
}

func objectMatches(ref *ObjectReference, capability, category string, lineage []ObjectReference) bool {
	if ref == nil {
		return true
	}
	if !ObjectPair(capability, category, ref.Kind) || !ValidObjectReference(*ref) {
		return false
	}
	for _, candidate := range lineage {
		if *ref == candidate {
			return true
		}
	}
	return false
}

func sourceMatches(grant Grant, employee string, source *ObjectReference) bool {
	if source == nil {
		return true
	}
	for _, ref := range grant.ApprovedSourceRefs {
		if ref == *source && grant.ApprovedSourceEmployees[ref.ID] == employee {
			return true
		}
	}
	return false
}

func (s Snapshot) AllowsObject(capability, category, employee, purpose string, now time.Time, lineage ...ObjectReference) bool {
	if employee == "" || !CanonicalLineage(lineage...) || !ObjectPair(capability, category, lineage[len(lineage)-1].Kind) {
		return false
	}
	return s.allows(capability, category, employee, "", purpose, now, lineage, nil)
}

func (s Snapshot) AllowsApprovedSource(capability, category, employee, purpose string, now time.Time, source ObjectReference, lineage ...ObjectReference) bool {
	if capability != "note.publish" && capability != "action.write" || source.Kind != "note_version" || !ValidObjectReference(source) || employee == "" || !CanonicalLineage(lineage...) || !ObjectPair(capability, category, lineage[len(lineage)-1].Kind) {
		return false
	}
	return s.allows(capability, category, employee, "", purpose, now, lineage, &source)
}
