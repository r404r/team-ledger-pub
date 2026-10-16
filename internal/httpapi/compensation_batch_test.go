package httpapi_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestAdjustmentBatchNormalActivatesExactScaleZeroSalaryAtomically(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			legalEntity := prepareBatchEmployee(t, f, employee.ID, "S-001", "Shanghai", "CNY")

			create := compensation.CreateBatchCommand{Name: "2026 Normal", CycleYear: 2026, AdjustmentType: compensation.BatchNormal, LegalEntityID: legalEntity, DefaultEffectiveDate: "2026-04-01", BudgetCurrency: "CNY", BudgetAmount: "1000000"}
			createKey := value.NewID()
			var batch compensation.BatchView
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches", structureJSON(t, create), createKey), http.StatusCreated, &batch)
			if batch.BusinessCode != "N-2026-0001" || batch.Revision != "1" || batch.State != "draft" {
				t.Fatalf("unexpected batch: %#v", batch)
			}
			originalBatchID := batch.ID
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches", structureJSON(t, create), createKey), http.StatusCreated, &batch)
			if batch.ID != originalBatchID || f.Count(t, "compensation_adjustment_batch") != 1 || f.Count(t, "compensation_batch_command_receipt") != 1 {
				t.Fatal("create replay did not recover the single committed batch")
			}

			bad := compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, Lines: []compensation.BatchLineCommand{{EmployeeID: employee.ID, StaffCode: "S-001", Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "-1", SalaryAfter: "0", PerformanceGrade: "G"}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, bad), value.NewID()), http.StatusUnprocessableEntity, nil)
			wrongStaff := compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, Lines: []compensation.BatchLineCommand{{EmployeeID: employee.ID, StaffCode: "S-WRONG", Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "1", SalaryAfter: "1", PerformanceGrade: "G"}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, wrongStaff), value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "compensation_batch_line") != 0 {
				t.Fatal("mismatched Staff Code changed the draft")
			}

			headers := []string{"Staff Code", "Currency", "Salary Before Adjustment", "Increase amount", "Salary After Adjustment", "Performance Grade", "Average Merit Increase", "Department Suggested Increase"}
			row := []string{"S-001", "CNY", "0", "650", "650", "G", "6.0%", "6%"}
			workbook := batchWorkbook(t, headers, row)
			invalidRow := append([]string(nil), row...)
			invalidRow[5] = ""
			invalidWorkbook := batchWorkbook(t, headers, invalidRow)
			importPath := "/api/v1/compensation-adjustment-batches/" + batch.ID + "/imports?revision=" + batch.Revision
			var invalidCandidate compensation.ImportCandidateView
			apiSend(t, f, financeHTTPRequestBytes(t, f, f.CompW, http.MethodPost, importPath, invalidWorkbook, value.NewID(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"), http.StatusCreated, &invalidCandidate)
			if invalidCandidate.State != "invalid" || invalidCandidate.LineCount != 0 || len(invalidCandidate.Errors) != 1 || f.Count(t, "compensation_batch_line") != 0 {
				t.Fatalf("semantic workbook error was not staged: %#v", invalidCandidate)
			}
			importKey := value.NewID()
			var candidate compensation.ImportCandidateView
			importPath = "/api/v1/compensation-adjustment-batches/" + batch.ID + "/imports?revision=" + batch.Revision
			apiSend(t, f, financeHTTPRequestBytes(t, f, f.CompW, http.MethodPost, importPath, workbook, importKey, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"), http.StatusCreated, &candidate)
			if candidate.State != "valid" || candidate.LineCount != 1 || len(candidate.Lines) != 1 || candidate.Lines[0].StaffCode != "S-001" || candidate.Lines[0].IncreaseAmount != "650" || candidate.Lines[0].EffectiveDate != "2026-04-01" || f.Count(t, "compensation_batch_line") != 0 {
				t.Fatalf("import mutated draft or returned invalid candidate: %#v", candidate)
			}
			apiSend(t, f, financeHTTPRequestBytes(t, f, f.CompW, http.MethodPost, importPath, workbook, importKey, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"), http.StatusCreated, &candidate)
			if f.Count(t, "compensation_batch_import_candidate") != 2 {
				t.Fatal("candidate replay duplicated staging row")
			}
			valid := compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, CandidateID: candidate.ID}
			draftKey := value.NewID()
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, valid), draftKey), http.StatusOK, &batch)
			if batch.Revision != "2" || len(batch.Lines) != 1 || batch.ManifestDigest == "" || len(batch.IncreaseTotalsByCurrency) != 1 || batch.IncreaseTotalsByCurrency[0].Amount != "650" {
				t.Fatalf("unexpected prepared batch: %#v", batch)
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, valid), draftKey), http.StatusOK, &batch)
			if batch.Revision != "2" || f.Count(t, "compensation_batch_payload") != 1 || f.Count(t, "compensation_batch_command_receipt") != 4 {
				t.Fatal("draft replay duplicated encrypted rows or receipt")
			}

			transition := compensation.BatchTransitionCommand{Action: "submit", Revision: batch.Revision, ManifestDigest: batch.ManifestDigest}
			activationKey := value.NewID()
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/transitions", structureJSON(t, transition), activationKey), http.StatusOK, &batch)
			if batch.State != "activated" || batch.Revision != "3" || len(batch.Lines) != 1 {
				t.Fatalf("unexpected activated batch: %#v", batch)
			}
			if batch.Lines[0].OriginalAdjustmentEventID == "" {
				t.Fatal("activated batch must expose its original adjustment event for correction")
			}
			if len(batch.Lines[0].CorrectionMembers) == 0 || batch.Lines[0].CorrectionMembers[0].OriginalEventID != batch.Lines[0].OriginalAdjustmentEventID || batch.Lines[0].CorrectionMembers[0].After == nil || batch.Lines[0].CorrectionMembers[0].After.AmountMinor == nil || *batch.Lines[0].CorrectionMembers[0].After.AmountMinor != "650" {
				t.Fatal("activated batch did not expose a complete correction template")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/transitions", structureJSON(t, transition), activationKey), http.StatusOK, &batch)
			if batch.Revision != "3" || f.Count(t, "compensation_batch_activation") != 1 || f.Count(t, "compensation_batch_command_receipt") != 5 || f.Count(t, "compensation_batch_state_history") != 4 {
				t.Fatal("activation replay duplicated financial facts")
			}

			var current compensation.CurrentView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/employees/"+employee.ID+"/compensation?as_of=2026-04-01", "", ""), http.StatusOK, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.Scale != 0 || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != "650" || current.CurrentTerm.Terms.Currency != "CNY" {
				t.Fatalf("batch activation did not publish exact salary: %#v", current)
			}
			amount := "700"
			correction := compensation.BatchCorrectionCommand{Reason: "SYNTHETIC_BATCH_CORRECTION", Lines: []compensation.BatchCorrectionLine{{EmployeeID: employee.ID, Members: []compensation.CorrectionMember{{MemberKey: "corrected_initial", Action: "replace", OriginalEventID: current.CurrentTerm.EventID, EffectiveDate: "2026-04-01", After: &compensation.Terms{Currency: "CNY", Scale: 0, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}}}}}}
			correctionKey := value.NewID()
			var corrected compensation.BatchCorrectionView
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/corrections", structureJSON(t, correction), correctionKey), http.StatusCreated, &corrected)
			if corrected.BusinessCode != "NC-2026-0001" || corrected.CorrectsBatchID != batch.ID || corrected.State != "activated" {
				t.Fatalf("unexpected batch correction: %#v", corrected)
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/corrections", structureJSON(t, correction), correctionKey), http.StatusCreated, &corrected)
			if f.Count(t, "compensation_batch_correction") != 1 {
				t.Fatal("batch correction replay duplicated facts")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/employees/"+employee.ID+"/compensation?as_of=2026-04-01", "", ""), http.StatusOK, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != "700" {
				t.Fatalf("batch correction did not rebuild the successor schedule: %#v", current)
			}
			amount = "750"
			unrooted := compensation.BatchCorrectionCommand{Reason: "SYNTHETIC_UNROOTED_BATCH_CORRECTION", Lines: []compensation.BatchCorrectionLine{{EmployeeID: employee.ID, Members: []compensation.CorrectionMember{{MemberKey: "unrooted", Action: "replace", OriginalEventID: current.CurrentTerm.EventID, EffectiveDate: "2026-04-01", After: &compensation.Terms{Currency: "CNY", Scale: 0, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}}}}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/corrections", structureJSON(t, unrooted), value.NewID()), http.StatusConflict, nil)
			counts, err := f.Repo.AdjustmentBatchCounts(context.Background(), f.OrgID, employee.ID, 2026)
			if err != nil || counts.CurrentYear != 1 {
				t.Fatalf("correction must not inflate adjustment counts: counts=%#v err=%v", counts, err)
			}
		})
	}
}

func TestAdjustmentBatchActivationRechecksAuthorizationAfterDecrypt(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			legalEntity := prepareBatchEmployee(t, f, employee.ID, "R-001", "Shanghai", "CNY")
			var batch compensation.BatchView
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches", structureJSON(t, compensation.CreateBatchCommand{Name: "2026 Normal", CycleYear: 2026, AdjustmentType: compensation.BatchNormal, LegalEntityID: legalEntity, DefaultEffectiveDate: "2026-04-01", BudgetCurrency: "CNY", BudgetAmount: "1000000"}), value.NewID()), http.StatusCreated, &batch)
			draft := compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, Lines: []compensation.BatchLineCommand{{EmployeeID: employee.ID, StaffCode: "R-001", Currency: "CNY", SalaryBefore: "0", IncreaseAmount: "100", SalaryAfter: "100", PerformanceGrade: "A", EffectiveDate: "2026-04-01"}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, draft), value.NewID()), http.StatusOK, &batch)
			transition := compensation.BatchTransitionCommand{Action: "submit", Revision: batch.Revision, ManifestDigest: batch.ManifestDigest}
			request := financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/transitions", structureJSON(t, transition), value.NewID())
			arrived, release := make(chan struct{}), make(chan struct{})
			f.FinancialKMS.BlockNextDecrypt(arrived, release)
			finished := make(chan *http.Response, 1)
			go func() {
				response, _ := f.Server.Client().Do(request)
				finished <- response
			}()
			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				close(release)
				t.Fatal("batch decrypt did not reach authorization barrier")
			}
			if err := f.Exec(t.Context(), "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2", f.OrgID, f.CompW.SubjectID); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			response := <-finished
			if response == nil {
				t.Fatal("activation returned no response")
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusUnauthorized || f.Count(t, "compensation_batch_activation") != 0 || f.Count(t, "compensation_event") != 0 {
				t.Fatalf("revoked activation released financial facts: status=%d body=%q err=%v", response.StatusCode, body, err)
			}
		})
	}
}

func TestAdjustmentBatchSpecialUsesControlledReasonAndReportsYearCounts(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			legalEntity := prepareBatchEmployee(t, f, employee.ID, "T-001", "Tokyo", "JPY")
			var batch compensation.BatchView
			create := compensation.CreateBatchCommand{Name: "2026 Special", CycleYear: 2026, AdjustmentType: compensation.BatchSpecial, LegalEntityID: legalEntity, DefaultEffectiveDate: "2025-03-01", SpecialReasonCode: "market_adjustment", SpecialReasonText: "market alignment", BudgetCurrency: "JPY", BudgetAmount: "1000000"}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches", structureJSON(t, create), value.NewID()), http.StatusCreated, &batch)
			if err := f.Exec(t.Context(), "INSERT INTO compensation_special_reason(org_id,code,label,active) VALUES(?,?,?,1)", "INSERT INTO compensation_special_reason(org_id,code,label,active) VALUES($1,$2,$3,TRUE)", f.OrgID, "obsolete_reason", "Obsolete"); err != nil {
				t.Fatal(err)
			}
			invalid := compensation.ReplaceBatchLinesCommand{Revision: "1", Lines: []compensation.BatchLineCommand{{EmployeeID: employee.ID, StaffCode: "T-001", Currency: "JPY", SalaryBefore: "0", IncreaseAmount: "1000", SalaryAfter: "1000", EffectiveMonth: "2025-03", ReasonCode: "obsolete_reason", ReasonText: "market alignment"}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, invalid), value.NewID()), http.StatusUnprocessableEntity, nil)
			valid := invalid
			valid.Lines[0].ReasonCode = "market_adjustment"
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/draft", structureJSON(t, valid), value.NewID()), http.StatusOK, &batch)
			if batch.BusinessCode != "S-2026-0001" || batch.Lines[0].AdjustmentCounts.CurrentYear != 0 || batch.Lines[0].AdjustmentCounts.PreviousYear != 0 {
				t.Fatalf("unexpected special draft: %#v", batch)
			}
			transition := compensation.BatchTransitionCommand{Action: "submit", Revision: batch.Revision, ManifestDigest: batch.ManifestDigest}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/transitions", structureJSON(t, transition), value.NewID()), http.StatusOK, &batch)
			if batch.Lines[0].AdjustmentCounts.CurrentYear != 0 || batch.Lines[0].AdjustmentCounts.PreviousYear != 1 || batch.Lines[0].AdjustmentCounts.CountAsOfDate != f.Now.Format("2006-01-02") {
				t.Fatalf("activated effective-year count not visible: %#v", batch.Lines[0].AdjustmentCounts)
			}
			var current compensation.CurrentView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/employees/"+employee.ID+"/compensation?as_of=2025-03-01", "", ""), http.StatusOK, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != "1000" || current.CurrentTerm.Terms.Currency != "JPY" {
				t.Fatalf("special activation did not publish JPY salary: %#v", current)
			}
		})
	}
}

func TestAdjustmentBatchPreviewRequiresExplicitSalaryCorrectionAndPreservesHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			var employee organization.Result
			apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/employees", createJSON, value.NewID()), http.StatusCreated, &employee)
			legalEntity := prepareBatchEmployee(t, f, employee.ID, "M-001", "Shanghai", "CNY")
			establishMonthlySalary(t, f, employee.ID, "2026-01-01", "10000")

			var batch compensation.BatchView
			create := compensation.CreateBatchCommand{Name: "2026-10 Special", CycleYear: 2026, AdjustmentType: compensation.BatchSpecial, LegalEntityID: legalEntity, DefaultEffectiveDate: "2026-10-01", SpecialReasonCode: "market_adjustment", SpecialReasonText: "market alignment", BudgetCurrency: "CNY", BudgetAmount: "1000000"}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches", structureJSON(t, create), value.NewID()), http.StatusCreated, &batch)
			previewCommand := compensation.PreviewBatchLinesCommand{Revision: batch.Revision, Lines: []compensation.BatchLineCommand{
				{},
				{StaffCode: "M-001", Currency: "CNY", SalaryBefore: "11000", IncreaseAmount: "500", SalaryAfter: "11500"},
				{},
			}}
			var candidate compensation.ImportCandidateView
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/previews", structureJSON(t, previewCommand), value.NewID()), http.StatusCreated, &candidate)
			if candidate.State != "valid" || candidate.LineCount != 1 || len(candidate.Lines) != 1 || candidate.Lines[0].EmployeeID != employee.ID || candidate.Lines[0].EffectiveMonth != "2026-10" || candidate.Lines[0].ReasonCode != "market_adjustment" || len(candidate.Warnings) != 1 || candidate.Warnings[0].Code != "SALARY_BEFORE_MISMATCH" || candidate.Warnings[0].CurrentSalaryBefore != "10000" {
				t.Fatalf("unexpected manual preview: %#v", candidate)
			}
			applyPath := "/api/v1/compensation-adjustment-batches/" + batch.ID + "/draft"
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, applyPath, structureJSON(t, compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, CandidateID: candidate.ID}), value.NewID()), http.StatusConflict, nil)
			if f.Count(t, "compensation_batch_line") != 0 {
				t.Fatal("unconfirmed salary mismatch changed the draft")
			}
			apply := compensation.ReplaceBatchLinesCommand{Revision: batch.Revision, CandidateID: candidate.ID, ConfirmSalaryCorrections: []string{employee.ID}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPatch, applyPath, structureJSON(t, apply), value.NewID()), http.StatusOK, &batch)
			if len(batch.Lines) != 1 || !batch.Lines[0].CorrectSalaryBefore || batch.Lines[0].Basis.CurrentSalaryBefore != "10000" {
				t.Fatalf("confirmed correction was not frozen: %#v", batch)
			}
			transition := compensation.BatchTransitionCommand{Action: "submit", Revision: batch.Revision, ManifestDigest: batch.ManifestDigest}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/compensation-adjustment-batches/"+batch.ID+"/transitions", structureJSON(t, transition), value.NewID()), http.StatusOK, &batch)
			if batch.State != "activated" {
				t.Fatalf("batch not activated: %#v", batch)
			}
			var current compensation.CurrentView
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/employees/"+employee.ID+"/compensation?as_of=2026-09-30", "", ""), http.StatusOK, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != "11000" {
				t.Fatalf("salary-before correction not projected historically: %#v", current)
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/employees/"+employee.ID+"/compensation?as_of=2026-10-01", "", ""), http.StatusOK, &current)
			if current.CurrentTerm == nil || current.CurrentTerm.Terms.AmountMinor == nil || *current.CurrentTerm.Terms.AmountMinor != "11500" {
				t.Fatalf("adjusted salary not projected: %#v", current)
			}
			if f.Count(t, "compensation_event") != 3 || f.Count(t, "compensation_terms_version") != 3 {
				t.Fatal("original salary, correction replacement and adjustment history were not all retained")
			}
			var corrections, adjustments int
			query := "SELECT COALESCE(SUM(CASE WHEN counts_as_adjustment=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN counts_as_adjustment=1 THEN 1 ELSE 0 END),0) FROM compensation_batch_event WHERE org_id=? AND batch_id=?"
			if f.Backend == "postgres" {
				query = "SELECT COALESCE(SUM(CASE WHEN NOT counts_as_adjustment THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN counts_as_adjustment THEN 1 ELSE 0 END),0) FROM compensation_batch_event WHERE org_id=$1 AND batch_id=$2"
			}
			if err := f.Repo.DB.QueryRowContext(t.Context(), query, f.OrgID, batch.ID).Scan(&corrections, &adjustments); err != nil || corrections != 1 || adjustments != 1 {
				t.Fatalf("batch event classification corrections=%d adjustments=%d err=%v", corrections, adjustments, err)
			}
		})
	}
}

func establishMonthlySalary(t *testing.T, f *testsupport.Fixture, employee, effective, amount string) {
	t.Helper()
	base := "/api/v1/employees/" + employee + "/compensation"
	var current compensation.CurrentView
	apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, base+"?as_of="+effective, "", ""), http.StatusOK, &current)
	command := compensation.ProposalCommand{Kind: "initial", EffectiveDate: effective, CompRevision: current.CompRevision, After: &compensation.Terms{Currency: "CNY", Scale: 0, AmountMinor: &amount, Unit: "month", PaymentFrequency: "monthly", TaxBasis: "gross", Components: []compensation.Component{}}, Reason: "INITIAL_SALARY", Members: []compensation.CorrectionMember{}}
	var proposal compensation.Result
	apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, base+"/proposals", structureJSON(t, command), value.NewID()), http.StatusCreated, &proposal)
	path := "/api/v1/compensation/proposals/" + proposal.ID + "/transitions"
	var submitted compensation.Result
	apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, compensation.TransitionCommand{Action: "submit", Revision: proposal.Revision, CompRevision: proposal.CompRevision}), value.NewID()), http.StatusOK, &submitted)
	apiSend(t, f, financeHTTPRequest(t, f, f.CompApprover, http.MethodPost, path, structureJSON(t, compensation.TransitionCommand{Action: "approve", Revision: submitted.Revision, CompRevision: submitted.CompRevision, DecisionReason: "INITIAL_APPROVAL"}), value.NewID()), http.StatusOK, &proposal)
}

func prepareBatchEmployee(t *testing.T, f *testsupport.Fixture, employee, staffCode, location, currency string) string {
	t.Helper()
	catalogPath := "/api/v1/orgs/" + f.OrgID + "/workforce-catalog-changes"
	create := `{"expected_catalog_revision":"1","expected_graph_revision":"1","changes":[{"action":"create","kind":"business_group","code":"BG","label":"Business Group","valid_from":"2020-01-01"},{"action":"create","kind":"division","code":"DIV","label":"Division","valid_from":"2020-01-01"},{"action":"create","kind":"department","code":"DEP","label":"Department","valid_from":"2020-01-01"},{"action":"create","kind":"job_family","code":"ENG","label":"Engineering","valid_from":"2020-01-01"},{"action":"create","kind":"career_level","code":"L1","label":"Level 1","rank":1,"valid_from":"2020-01-01"},{"action":"create","kind":"legal_entity","code":"BR","label":"Branch","valid_from":"2020-01-01"}]}`
	var units organization.CatalogChangeResult
	apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, catalogPath, create, value.NewID()), http.StatusCreated, &units)
	workforce := fmt.Sprintf(`{"expected_catalog_revision":"2","expected_graph_revision":"2","expected_employee_revisions":{%q:"1"},"reason":"Synthetic batch basis","changes":[{"action":"add","kind":"identifier","employee_id":%q,"staff_code":%q,"valid_from":"2020-01-01"},{"action":"add","kind":"employment","employee_id":%q,"legal_entity_id":%q,"employment_kind":"hire","location_code":%q,"valid_from":"2020-01-01"},{"action":"add","kind":"job_assignment","employee_id":%q,"department_id":%q,"job_family_id":%q,"career_level_id":%q,"position":{"title":"Engineer","position_code":"ENG-1"},"valid_from":"2020-01-01"}]}`, employee, employee, staffCode, employee, units.Items[5].ID, location, employee, units.Items[2].ID, units.Items[3].ID, units.Items[4].ID)
	apiSend(t, f, apiRequest(t, f, f.Owner, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/workforce-changes", workforce, value.NewID()), http.StatusCreated, nil)
	change := compensation.SalaryRangeChangeCommand{Changes: []compensation.SalaryRangeChange{{Action: "add", ExpectedRevision: "0", LegalEntityID: units.Items[5].ID, Location: location, JobFamilyID: units.Items[3].ID, CareerLevelID: units.Items[4].ID, Currency: currency, ValidFrom: "2020-01-01", Amounts: &compensation.SalaryRangeAmounts{Minimum: "0", Midpoint: "1000", Maximum: "1000000"}}}}
	apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, "/api/v1/orgs/"+f.OrgID+"/salary-range-changes", structureJSON(t, change), value.NewID()), http.StatusCreated, nil)
	return units.Items[5].ID
}

func financeHTTPRequestBytes(t *testing.T, f *testsupport.Fixture, credential testsupport.Credential, method, path string, body []byte, key, contentType string) *http.Request {
	t.Helper()
	request := apiRequest(t, f, credential, method, path, string(body), key)
	request.Header.Set("X-Access-Purpose", "compensation_management")
	request.Header.Set("Content-Type", contentType)
	return request
}

func batchWorkbook(t *testing.T, headers, row []string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range map[string]string{
		"xl/workbook.xml":            `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Adjustments" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
	} {
		manifestEntry, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, _ = fmt.Fprint(manifestEntry, body)
	}
	entry, err := writer.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprint(entry, `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for index, text := range headers {
		_, _ = fmt.Fprintf(entry, `<c r="%c1" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+index, text)
	}
	_, _ = fmt.Fprint(entry, `</row><row r="2">`)
	for index, text := range row {
		_, _ = fmt.Fprintf(entry, `<c r="%c2" t="inlineStr"><is><t>%s</t></is></c>`, 'A'+index, text)
	}
	_, _ = fmt.Fprint(entry, `</row></sheetData></worksheet>`)
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
