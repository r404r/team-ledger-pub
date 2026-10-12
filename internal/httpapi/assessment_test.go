package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/r404r/team-ledger/internal/assessment"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestAssessmentHTTPPolicyAndStatusContract(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			path := "/api/v1/employees/" + employee.ID
			command := assessment.PolicyCommand{ExpectedRevision: "0", Cadence: assessment.Cadence{Unit: "month", Count: 1}, AnchorDate: "2026-01-31", Timezone: "America/New_York", DueOffsetDays: 2, LocalDueTime: "09:30", WindowThrough: "2026-05-01", PauseIntervals: []assessment.PauseInterval{}, Purpose: "interview_followup", AIMode: "manual_approved", RequiredFields: []string{"actual_started_at", "actual_ended_at"}}
			var policy assessment.PolicyView
			apiSend(t, f, interviewHTTPRequest(t, f, f.FollowupManager, http.MethodPut, path+"/interview-policy", structureJSON(t, command), value.NewID()), http.StatusOK, &policy)
			if policy.Revision != "1" || policy.Timezone != command.Timezone || policy.AnchorDate != command.AnchorDate || policy.PauseIntervals == nil || policy.RequiredFields == nil {
				t.Fatal("policy API did not preserve explicit schedule semantics and array shapes:", policy)
			}
			var status assessment.StatusView
			apiSend(t, f, interviewHTTPRequest(t, f, f.FollowupManager, http.MethodGet, path+"/interview-status?from=2026-01-01&to=2026-05-01", "", ""), http.StatusOK, &status)
			if status.State != "configured" || status.Policy == nil || len(status.Items) != 4 || status.AIState != "awaiting_manual_input" {
				t.Fatal("status API did not expose configured deterministic windows:", status)
			}
			bad := `{"expected_revision":"1","expected_revision":"1"}`
			apiSend(t, f, interviewHTTPRequest(t, f, f.FollowupManager, http.MethodPut, path+"/interview-policy", bad, value.NewID()), http.StatusUnprocessableEntity, nil)
		})
	}
}
