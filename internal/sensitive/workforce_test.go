package sensitive_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func TestWorkforceCipherAcceptsOnlyBoundedKindSchemaPairs(t *testing.T) {
	base := profileContext()
	cases := []struct {
		kind, schema  string
		employeeOwned bool
	}{
		{kind: "legal_entity", schema: "pii.legal_entity_label.v1"},
		{kind: "org_unit", schema: "pii.org_unit_label.v1"},
		{kind: "employee_identifier", schema: "pii.employee_identifier.v1", employeeOwned: true},
		{kind: "education_record", schema: "pii.education.v1", employeeOwned: true},
		{kind: "job_assignment", schema: "pii.job_assignment_position.v1", employeeOwned: true},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			binding := base
			binding.ObjectKind, binding.SchemaType = tc.kind, tc.schema
			if !tc.employeeOwned {
				binding.EmployeeID = ""
			}
			wrapper := &controlledWrapper{}
			cipher := sensitive.Cipher{Wrapper: wrapper}
			plain := []byte("SYNTHETIC-WORKFORCE-PII")
			envelope, err := cipher.Seal(context.Background(), binding, plain)
			if err != nil {
				t.Fatal("valid workforce binding rejected", err)
			}
			opened, err := cipher.Open(context.Background(), binding, envelope)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("workforce payload did not round-trip", err)
			}
			wrong := binding
			wrong.SchemaType = "pii.profile.v1"
			if _, err = cipher.Seal(context.Background(), wrong, plain); err != sensitive.ErrInvalid {
				t.Fatal("wrong workforce schema reached encryption")
			}
			wrong = binding
			if tc.employeeOwned {
				wrong.EmployeeID = ""
			} else {
				wrong.EmployeeID = base.EmployeeID
			}
			if _, err = cipher.Seal(context.Background(), wrong, plain); err != sensitive.ErrInvalid {
				t.Fatal("wrong workforce ownership shape reached encryption")
			}
		})
	}
}
