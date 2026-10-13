package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/compensation"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestSalaryRangeExactEncryptedLifecycleAndOverlap(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f := testsupport.NewHarness(t, backend)
			legal, family, level := value.NewID(), value.NewID(), value.NewID()
			statements := []string{
				"INSERT INTO legal_entity(org_id,id,code,kind) VALUES(?,?,?,'branch_company')",
				"INSERT INTO job_family(org_id,id,code) VALUES(?,?,?)",
				"INSERT INTO career_level(org_id,id,code) VALUES(?,?,?)",
			}
			if backend == "postgres" {
				statements = []string{
					"INSERT INTO legal_entity(org_id,id,code,kind) VALUES($1,$2,$3,'branch_company')",
					"INSERT INTO job_family(org_id,id,code) VALUES($1,$2,$3)",
					"INSERT INTO career_level(org_id,id,code) VALUES($1,$2,$3)",
				}
			}
			for i, args := range [][]any{{f.OrgID, legal, "SH-RANGE"}, {f.OrgID, family, "ENG"}, {f.OrgID, level, "L3"}} {
				if _, err := f.Repo.DB.Exec(statements[i], args...); err != nil {
					t.Fatal(err)
				}
			}
			amounts := &compensation.SalaryRangeAmounts{Minimum: "10000", Midpoint: "15000", Maximum: "20000"}
			add := compensation.SalaryRangeChangeCommand{Changes: []compensation.SalaryRangeChange{{Action: "add", ExpectedRevision: "0", LegalEntityID: legal, Location: "Shanghai", JobFamilyID: family, CareerLevelID: level, Currency: "CNY", ValidFrom: "2026-01-01", Amounts: amounts}}}
			var created struct {
				SalaryRanges []compensation.SalaryRangeView `json:"salary_ranges"`
			}
			path := "/api/v1/orgs/" + f.OrgID + "/salary-range-changes"
			addKey := value.NewID()
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, add), addKey), http.StatusCreated, &created)
			if len(created.SalaryRanges) != 1 || created.SalaryRanges[0].Amounts.Midpoint != "15000" || created.SalaryRanges[0].Revision != "1" {
				t.Fatalf("unexpected range: %#v", created)
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, add), addKey), http.StatusCreated, &created)
			raw, err := json.Marshal(add)
			if err != nil {
				t.Fatal(err)
			}
			unkeyed := sha256.Sum256(raw)
			digestQuery := "SELECT digest FROM salary_range_command_receipt WHERE key=?"
			if backend == "postgres" {
				digestQuery = "SELECT digest FROM salary_range_command_receipt WHERE key=$1"
			}
			var storedDigest []byte
			if err = f.Repo.DB.QueryRow(digestQuery, addKey).Scan(&storedDigest); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(storedDigest, unkeyed[:]) {
				t.Fatal("salary range idempotency digest must be purpose-keyed HMAC")
			}
			if len(created.SalaryRanges) != 1 || f.Count(t, "salary_range") != 1 || f.Count(t, "salary_range_command_receipt") != 1 {
				t.Fatal("salary range replay duplicated protected facts or receipt")
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, add), value.NewID()), http.StatusConflict, nil)
			id := created.SalaryRanges[0].ID
			end := compensation.SalaryRangeChangeCommand{Changes: []compensation.SalaryRangeChange{{Action: "end", ID: id, ExpectedRevision: "1", EffectiveTo: "2026-07-01"}}}
			apiSend(t, f, financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, end), value.NewID()), http.StatusCreated, &created)
			var query struct {
				SalaryRanges []compensation.SalaryRangeView `json:"salary_ranges"`
			}
			apiSend(t, f, financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/orgs/"+f.OrgID+"/salary-ranges?as_of=2026-08-01", "", ""), http.StatusOK, &query)
			if len(query.SalaryRanges) != 0 {
				t.Fatalf("ended range remained effective: %#v", query)
			}
			arrived, release := make(chan struct{}), make(chan struct{})
			f.FinancialKMS.BlockNextDecrypt(arrived, release)
			finished := make(chan *http.Response, 1)
			releaseRequest := financeHTTPRequest(t, f, f.FinR, http.MethodGet, "/api/v1/orgs/"+f.OrgID+"/salary-ranges", "", "")
			go func() {
				response, _ := f.Server.Client().Do(releaseRequest)
				finished <- response
			}()
			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				close(release)
				t.Fatal("salary range decrypt did not reach release barrier")
			}
			if err := f.Exec(t.Context(), "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=? AND id=?", "UPDATE subject SET auth_epoch=auth_epoch+1 WHERE org_id=$1 AND id=$2", f.OrgID, f.FinR.SubjectID); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			response := <-finished
			if response == nil {
				t.Fatal("salary range release returned no response")
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode == http.StatusOK || bytes.Contains(body, []byte("15000")) {
				t.Fatalf("revoked session released decrypted salary range: status=%d body=%q err=%v", response.StatusCode, body, readErr)
			}
		})
	}
}

func TestPostgresSalaryRangeConcurrentOverlapAllowsOneWriter(t *testing.T) {
	f := testsupport.NewHarness(t, "postgres")
	legal, family, level := value.NewID(), value.NewID(), value.NewID()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO legal_entity(org_id,id,code,kind) VALUES($1,$2,$3,'branch_company')", []any{f.OrgID, legal, "SH-RANGE-RACE"}},
		{"INSERT INTO job_family(org_id,id,code) VALUES($1,$2,$3)", []any{f.OrgID, family, "ENG-RACE"}},
		{"INSERT INTO career_level(org_id,id,code) VALUES($1,$2,$3)", []any{f.OrgID, level, "L4-RACE"}},
	} {
		if _, err := f.Repo.DB.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	command := compensation.SalaryRangeChangeCommand{Changes: []compensation.SalaryRangeChange{{Action: "add", ExpectedRevision: "0", LegalEntityID: legal, Location: "Shanghai", JobFamilyID: family, CareerLevelID: level, Currency: "CNY", ValidFrom: "2026-01-01", Amounts: &compensation.SalaryRangeAmounts{Minimum: "10000", Midpoint: "15000", Maximum: "20000"}}}}
	path := "/api/v1/orgs/" + f.OrgID + "/salary-range-changes"
	requests := []*http.Request{
		financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, command), value.NewID()),
		financeHTTPRequest(t, f, f.CompW, http.MethodPost, path, structureJSON(t, command), value.NewID()),
	}
	statuses := make([]int, 2)
	var wait sync.WaitGroup
	for index, request := range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := f.Server.Client().Do(request)
			if err != nil {
				statuses[index] = 0
				return
			}
			statuses[index] = response.StatusCode
			_ = response.Body.Close()
		}()
	}
	wait.Wait()
	sort.Ints(statuses)
	if statuses[0] != http.StatusCreated || statuses[1] != http.StatusConflict || f.Count(t, "salary_range") != 1 {
		t.Fatalf("concurrent overlap was not serialized: statuses=%v rows=%d", statuses, f.Count(t, "salary_range"))
	}
}
