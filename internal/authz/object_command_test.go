package authz

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestAbsentSourceApprovalPreservesOriginalNullObjectReceiptBody(t *testing.T) {
	command := IssueCommand{SubjectID: "11111111-1111-4111-8111-111111111111", Capability: "organization.read", Category: "metadata", Scope: Scope{Kind: "org", ID: "22222222-2222-4222-8222-222222222222"}, Purpose: "organization_management", ValidFrom: "2026-10-11T00:00:00Z", ExpiresAt: "2026-10-11T01:00:00Z", AuthorityID: "33333333-3333-4333-8333-333333333333", ExpectedRevision: "1"}
	original := `{"subject_id":"11111111-1111-4111-8111-111111111111","capability":"organization.read","category":"metadata","scope":{"kind":"org","id":"22222222-2222-4222-8222-222222222222"},"purpose":"organization_management","valid_from":"2026-10-11T00:00:00Z","expires_at":"2026-10-11T01:00:00Z","mfa_required":false,"relation_bound":false,"relation_ref":null,"object_ref":null,"authority_id":"33333333-3333-4333-8333-333333333333","expected_revision":"1"}`
	for _, refs := range [][]ObjectReference{nil, {}} {
		command.ApprovedSourceRefs = refs
		if !normalizeObjectCommand(&command) {
			t.Fatal("optional empty approvals rejected")
		}
		body, err := json.Marshal(command)
		if err != nil || string(body) != original {
			t.Fatalf("new optional field changed immutable v5 receipt digest body: %s %v", body, err)
		}
	}
}

func TestSourceApprovalCommandDigestIsCanonicalAndExact(t *testing.T) {
	first := ObjectReference{Kind: "note_version", ID: "44444444-4444-4444-8444-444444444444"}
	second := ObjectReference{Kind: "note_version", ID: "55555555-5555-4555-8555-555555555555"}
	command := IssueCommand{Capability: "note.publish", Category: "shared", Scope: Scope{Kind: "employee", ID: "33333333-3333-4333-8333-333333333333"}, ApprovedSourceRefs: []ObjectReference{second, first}}
	callerRefs := command.ApprovedSourceRefs
	if !normalizeObjectCommand(&command) || !reflect.DeepEqual(command.ApprovedSourceRefs, []ObjectReference{first, second}) || !reflect.DeepEqual(callerRefs, []ObjectReference{second, first}) {
		t.Fatal("approval canonicalization changed caller memory or lost exact refs")
	}
	service := Service{DigestKey: bytes.Repeat([]byte{1}, 32)}
	request := Request{Purpose: ManagementPurpose}
	current := Snapshot{OrgID: "22222222-2222-4222-8222-222222222222", SubjectID: "11111111-1111-4111-8111-111111111111"}
	one, err := service.digest(request, current, "OP-SEC-02", "", command)
	if err != nil {
		t.Fatal(err)
	}
	command.ApprovedSourceRefs = []ObjectReference{first, second}
	if !normalizeObjectCommand(&command) {
		t.Fatal("sorted approval rejected")
	}
	two, err := service.digest(request, current, "OP-SEC-02", "", command)
	if err != nil || !bytes.Equal(one, two) {
		t.Fatal("same approved source set produced different receipt digest:", err)
	}
	command.ApprovedSourceRefs = []ObjectReference{first}
	if !normalizeObjectCommand(&command) {
		t.Fatal("one source rejected")
	}
	changed, err := service.digest(request, current, "OP-SEC-02", "", command)
	if err != nil || bytes.Equal(one, changed) {
		t.Fatal("changed approved source set reused original receipt digest:", err)
	}
	command.ApprovedSourceRefs = []ObjectReference{first, first}
	if normalizeObjectCommand(&command) {
		t.Fatal("duplicate source set accepted")
	}
	command.ApprovedSourceRefs = make([]ObjectReference, 11)
	if normalizeObjectCommand(&command) {
		t.Fatal("unbounded source approval accepted")
	}
}

func TestFinancialGrantCommandsAndFiltersAreFinite(t *testing.T) {
	ref := ObjectReference{Kind: "compensation_proposal", ID: "44444444-4444-4444-8444-444444444444"}
	base := IssueCommand{Capability: "compensation.approve", Category: "financial", Purpose: "compensation_management", Scope: Scope{Kind: "employee", ID: "33333333-3333-4333-8333-333333333333"}, ObjectRef: &ref}
	if !normalizeObjectCommand(&base) {
		t.Fatal("finite exact proposal approval rejected")
	}
	for _, mutate := range []func(*IssueCommand){
		func(c *IssueCommand) { c.RelationBound = true },
		func(c *IssueCommand) { c.RelationRef = &RelationReference{Kind: "reporting_line", ID: ref.ID} },
		func(c *IssueCommand) { c.ObjectRef = &ObjectReference{Kind: "compensation_event", ID: ref.ID} },
		func(c *IssueCommand) { c.ObjectRef = &ObjectReference{Kind: "compensation_term", ID: ref.ID} },
		func(c *IssueCommand) { c.ObjectRef = &ObjectReference{Kind: "bonus_award", ID: ref.ID} },
		func(c *IssueCommand) { c.ApprovedSourceRefs = []ObjectReference{{Kind: "note_version", ID: ref.ID}} },
	} {
		command := base
		mutate(&command)
		if normalizeObjectCommand(&command) {
			t.Fatal("financial command admitted relation, immutable write, arbitrary family or interview source")
		}
	}
	for _, kind := range []string{"compensation_proposal", "compensation_event", "compensation_term"} {
		for _, capability := range []string{"compensation.read", "compensation.propose", "compensation.approve", "sensitive.export"} {
			if !validFilter(Filter{Category: "financial", Purpose: "compensation_management", Capability: capability, ObjectKind: kind, ObjectID: ref.ID, Limit: 1}) {
				t.Fatal("finite financial grant metadata filter rejected")
			}
		}
	}
	for _, filter := range []Filter{
		{Category: "salary", Limit: 1},
		{Purpose: "bonus_management", Limit: 1},
		{Capability: "compensation.write", Limit: 1},
		{ObjectKind: "compensation_aggregate", Limit: 1},
	} {
		if validFilter(filter) {
			t.Fatal("unsupported financial metadata filter admitted")
		}
	}
}
