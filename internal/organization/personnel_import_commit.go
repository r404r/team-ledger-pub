package organization

import (
	"context"
	"crypto/hmac"
	"strconv"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

type PersonnelImportCommitCommand struct {
	Rows                    []PersonnelImportReviewRow `json:"rows"`
	ExpectedCatalogRevision string                     `json:"expected_catalog_revision"`
	ExpectedGraphRevision   string                     `json:"expected_graph_revision"`
}

// personnelImportTransaction keeps the existing create and workforce commands inside the
// batch's native transaction. It never starts or commits a nested transaction.
type personnelImportTransaction struct{ Tx }

func (t personnelImportTransaction) WithTx(ctx context.Context, org string, fn func(Tx) error) error {
	return fn(t.Tx)
}
func (t personnelImportTransaction) AuditDenied(ctx context.Context, audit Audit) error {
	return t.Audit(ctx, audit)
}

func (s *Service) CommitPersonnelImport(ctx context.Context, request Request, org string, command PersonnelImportCommitCommand) (WorkforceChangeResult, error) {
	const operation = "OP-ORG-10"
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-05")
	if err != nil {
		return WorkforceChangeResult{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	if !value.ValidID(request.Key) || !validExpectedRevision(command.ExpectedCatalogRevision) || !validExpectedRevision(command.ExpectedGraphRevision) || len(command.Rows) == 0 || len(command.Rows) > personnelWorkbookRows {
		return WorkforceChangeResult{}, fault.Invalid
	}
	// Include an endpoint discriminator so a key reused for another workforce command conflicts.
	digest, err := s.digest(request, snapshot, operation, org, struct{ Import PersonnelImportCommitCommand }{command})
	if err != nil {
		return WorkforceChangeResult{}, err
	}
	var result WorkforceChangeResult
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
		if err := tx.LockGraph(ctx, org); err != nil {
			return err
		}
		if err := tx.LockSubjects(ctx, org, []string{snapshot.SubjectID}); err != nil {
			return err
		}
		current, err := s.authorize(ctx, tx, request, org, "", "OP-ORG-05")
		if err != nil {
			return err
		}
		if current.AuthEpoch != snapshot.AuthEpoch {
			return fault.Forbidden
		}
		if receipt, found, err := tx.WorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key); err != nil {
			return err
		} else if found {
			if !hmac.Equal(receipt.Digest, digest) {
				return fault.Conflict
			}
			result = receipt.Result
			return nil
		}
		scoped := *s
		scoped.Store = personnelImportTransaction{tx}
		preview, err := scoped.ReviewPersonnelImport(ctx, request, org, PersonnelImportReviewCommand{Rows: command.Rows})
		if err != nil {
			return err
		}
		if len(preview.Errors) != 0 {
			return fault.Invalid
		}
		if preview.CatalogRevision != command.ExpectedCatalogRevision || preview.GraphRevision != command.ExpectedGraphRevision {
			return fault.Conflict
		}
		ids := make(map[string]string, len(preview.Rows))
		expected := make(map[string]string, len(preview.Rows))
		result = WorkforceChangeResult{CatalogRevision: preview.CatalogRevision, GraphRevision: preview.GraphRevision, Items: make([]CatalogChangeItemResult, len(preview.Rows)), EmployeeRevisions: map[string]string{}}
		// Pass 1: persist all employee subjects and their initial facts, in source row order.
		// Initial facts and audit events roll back together on any later failure.
		for i, row := range preview.Rows {
			create := personnelRowCreateCommand(row, preview)
			employee := Employee{ID: value.NewID(), OrgID: org, Revision: 1, Lifecycle: create.Lifecycle}
			version, err := s.prepare(ctx, employee, create.Profile, "")
			if err != nil {
				return err
			}
			employee.HeadID = version.ID
			if err = tx.Create(ctx, employee, version); err != nil {
				return err
			}
			initial, _ := initialWorkforceCommand(create, employee.ID)
			if !validWorkforceChange(initial) {
				return fault.Invalid
			}
			if err = s.authorizeWorkforceEndpoints(ctx, tx, request, current, initial); err != nil {
				return err
			}
			write, err := s.prepareWorkforceWrite(ctx, org, current.SubjectID, initial)
			if err != nil {
				return err
			}
			catalog, _ := value.Revision(preview.CatalogRevision)
			graph, _ := value.Revision(preview.GraphRevision)
			_, _, revisions, err := tx.CommitWorkforceChange(ctx, org, catalog, graph, map[string]int64{employee.ID: 1}, write)
			if err != nil {
				return err
			}
			if err = tx.Audit(ctx, s.audit(request, current, employee.ID, "OP-ORG-05", "allowed")); err != nil {
				return err
			}
			ids[row.StaffCode] = employee.ID
			revision := strconv.FormatInt(revisions[employee.ID], 10)
			expected[employee.ID] = revision
			result.ID = write.ID
			result.Items[i] = CatalogChangeItemResult{Kind: "employee", ID: employee.ID}
			result.EmployeeRevisions[employee.ID] = revision
		}
		// Pass 2: resolve every HOD against the completed batch map or the current database.
		reportingKind := "administrative"
		reporting := WorkforceChangeCommand{ExpectedCatalogRevision: preview.CatalogRevision, ExpectedGraphRevision: preview.GraphRevision, ExpectedEmployeeRevision: map[string]string{}}
		for _, row := range preview.Rows {
			if row.ManagerStaffCode == "" {
				continue
			}
			manager := ids[row.ManagerStaffCode]
			if manager == "" {
				digest, keyID, version, err := s.staffCodeLookup(ctx, org, row.ManagerStaffCode)
				if err != nil {
					return err
				}
				manager, err = tx.StaffCodeEmployeeID(ctx, org, keyID, version, digest, row.HireDate)
				clear(digest)
				if err != nil {
					return err
				}
				if manager == "" {
					return fault.Invalid
				}
			}
			employee := ids[row.StaffCode]
			reporting.ExpectedEmployeeRevision[employee] = expected[employee]
			from := row.HireDate
			reporting.Changes = append(reporting.Changes, WorkforceChangeItem{Action: "add", Kind: "reporting", EmployeeID: employee, ManagerEmployeeID: &manager, ReportingKind: &reportingKind, ValidFrom: &from, ValidTo: row.DepartureDate})
		}
		if len(reporting.Changes) > 0 {
			nested := request
			nested.Key = value.NewID()
			bound, err := scoped.ChangeWorkforce(ctx, nested, org, reporting)
			if err != nil {
				return err
			}
			result.ID, result.GraphRevision = bound.ID, bound.GraphRevision
			for id, revision := range bound.EmployeeRevisions {
				result.EmployeeRevisions[id] = revision
			}
		}
		return tx.SaveWorkforceReceipt(ctx, org, current.SubjectID, operation, request.Key, WorkforceCommandReceipt{Digest: digest, Result: result})
	})
	if err != nil {
		return WorkforceChangeResult{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	return result, nil
}

func personnelRowCreateCommand(row PersonnelImportRow, preview PersonnelImportPreview) CreateCommand {
	profile := Profile{LocalName: row.LocalName, EnglishName: row.EnglishName, ProfileSummary: row.ProfileSummary}
	if row.Email != "" || row.Phone != "" {
		profile.WorkContact = &Contact{Email: row.Email, Phone: row.Phone}
	}
	command := CreateCommand{Profile: profile, Lifecycle: Lifecycle{ValidFrom: row.HireDate, ValidTo: row.DepartureDate}, StaffCode: &row.StaffCode, Employment: &InitialEmployment{LegalEntityID: row.BranchID, LocationCode: row.Location}, JobAssignment: &InitialJobAssignment{DepartmentID: row.DepartmentID}, ExpectedCatalogRevision: &preview.CatalogRevision, ExpectedGraphRevision: &preview.GraphRevision}
	if row.EducationLevel != "" {
		command.Education = &InitialEducation{Level: row.EducationLevel}
	}
	if row.JobFamilyID != "" {
		command.JobAssignment.JobFamilyID = &row.JobFamilyID
	}
	if row.CareerLevelID != "" {
		command.JobAssignment.CareerLevelID = &row.CareerLevelID
	}
	if row.Position != "" {
		command.JobAssignment.Position = &PositionPayload{Title: row.Position}
	}
	return command
}
