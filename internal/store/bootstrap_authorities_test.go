package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/r404r/team-ledger/internal/store"
)

var expectedBootstrapAuthorities = map[string]struct{}{
	"organization.read|metadata|organization_management":              {},
	"organization.write|metadata|organization_management":             {},
	"pii.read|pii|organization_management":                            {},
	"pii.write|pii|organization_management":                           {},
	"audit.read|audit|security_administration":                        {},
	"identity.manage|audit|security_administration":                   {},
	"interview.read|metadata|interview_followup":                      {},
	"interview.write|metadata|interview_followup":                     {},
	"interview_policy.manage|metadata|interview_followup":             {},
	"assessment.request|metadata|interview_followup":                  {},
	"assessment.read|metadata|interview_followup":                     {},
	"assessment.input.approve|metadata|interview_followup":            {},
	"assessment.publish|metadata|interview_followup":                  {},
	"note.read|shared|interview_followup":                             {},
	"note.read|manager_private|interview_followup":                    {},
	"note.read|hr_confidential|interview_followup":                    {},
	"note.write|shared|interview_followup":                            {},
	"note.write|manager_private|interview_followup":                   {},
	"note.write|hr_confidential|interview_followup":                   {},
	"note.publish|shared|interview_followup":                          {},
	"note.publish|manager_private|interview_followup":                 {},
	"note.publish|hr_confidential|interview_followup":                 {},
	"action.read|shared|interview_followup":                           {},
	"action.write|shared|interview_followup":                          {},
	"compensation.read|financial|compensation_management":             {},
	"compensation.propose|financial|compensation_management":          {},
	"compensation.approve|financial|compensation_management":          {},
	"bonus.target.manage|financial|compensation_management":           {},
	"bonus.propose|financial|compensation_management":                 {},
	"bonus.approve|financial|compensation_management":                 {},
	"bonus.payment.record|financial|compensation_management":          {},
	"compensation.extension.manage|financial|compensation_management": {},
	"sensitive.export|pii|organization_management":                    {},
	"sensitive.export|metadata|interview_followup":                    {},
	"sensitive.export|shared|interview_followup":                      {},
	"sensitive.export|manager_private|interview_followup":             {},
	"sensitive.export|hr_confidential|interview_followup":             {},
	"sensitive.export|financial|compensation_management":              {},
}

func assertBootstrapAuthorities(t *testing.T, ctx context.Context, repo *store.Repository, orgID, subjectID string) {
	t.Helper()
	query := "SELECT capability,category,purpose,scope_kind,scope_id,mfa_required,approved_by,policy_version FROM delegation_authority WHERE org_id=? AND manager_subject_id=?"
	if repo.Backend == "postgres" {
		query = "SELECT capability,category,purpose,scope_kind,scope_id,mfa_required,approved_by,policy_version FROM delegation_authority WHERE org_id=$1 AND manager_subject_id=$2"
	}
	rows, err := repo.DB.QueryContext(ctx, query, orgID, subjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	actual := make(map[string]struct{}, len(expectedBootstrapAuthorities))
	for rows.Next() {
		var capability, category, purpose, scopeKind, scopeID, approvedBy, policy string
		var mfaRequired bool
		if err = rows.Scan(&capability, &category, &purpose, &scopeKind, &scopeID, &mfaRequired, &approvedBy, &policy); err != nil {
			t.Fatal(err)
		}
		if scopeKind != "org" || scopeID != orgID || !mfaRequired || approvedBy != subjectID || policy != "bootstrap_admin.v1" {
			t.Fatalf("invalid bootstrap authority metadata for %s: scope=%s/%s mfa=%t approved_by=%s policy=%s", capability, scopeKind, scopeID, mfaRequired, approvedBy, policy)
		}
		key := fmt.Sprintf("%s|%s|%s", capability, category, purpose)
		if _, duplicate := actual[key]; duplicate {
			t.Fatalf("duplicate bootstrap authority %s", key)
		}
		actual[key] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expectedBootstrapAuthorities) {
		t.Fatalf("bootstrap authority count=%d, want %d: %v", len(actual), len(expectedBootstrapAuthorities), actual)
	}
	for key := range expectedBootstrapAuthorities {
		if _, ok := actual[key]; !ok {
			t.Errorf("missing bootstrap authority %s", key)
		}
	}
	if _, forbidden := actual["access_grant.manage|audit|security_administration"]; forbidden {
		t.Fatal("access_grant.manage became recursively delegable")
	}
}
