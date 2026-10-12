package organization

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"strconv"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

const exportByteLimit = 8 * 1024 * 1024

type profileExport struct {
	Kind     string `json:"kind"`
	ExportID string `json:"export_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Employee *View  `json:"employee_profile,omitempty"`
}
type preparedProfile struct {
	object   ExportObject
	employee Employee
	view     View
}

func encodeProfileExport(value profileExport) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fault.Unavailable
	}
	encoded = append(encoded, '\n')
	return encoded, nil
}

func buildProfileEvents(exportID string, records []preparedProfile) ([][]byte, error) {
	events := make([][]byte, 0, len(records)+2)
	header, _ := encodeProfileExport(profileExport{Kind: "header", ExportID: exportID, Status: "prepared"})
	events, total := append(events, header), len(header)
	for index := range records {
		encoded, err := encodeProfileExport(profileExport{Kind: "employee_profile", ExportID: exportID, Status: "ok", Employee: &records[index].view})
		if err != nil {
			return nil, err
		}
		total += len(encoded)
		if total > exportByteLimit {
			return nil, fault.Invalid
		}
		events = append(events, encoded)
	}
	complete, _ := encodeProfileExport(profileExport{Kind: "complete", ExportID: exportID, Status: "complete"})
	if total+len(complete) > exportByteLimit {
		return nil, fault.Invalid
	}
	return append(events, complete), nil
}

func (s *Service) exportAuthorized(snapshot authz.Snapshot, employee string) bool {
	now := s.clock()
	return snapshot.Allows("pii.read", "pii", employee, "organization_management", now) && snapshot.Allows("sensitive.export", "pii", employee, "organization_management", now)
}

func (s *Service) exportGuard(ctx context.Context, store ExportStore, request Request, initial authz.Snapshot, records []preparedProfile, auditOutcome string) error {
	return store.WithExportTx(ctx, initial.OrgID, func(tx ExportTx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		for _, record := range records {
			current, err := tx.Security(ctx, request.TokenHash, initial.OrgID, record.employee.ID)
			if err != nil || current.SubjectID != initial.SubjectID || current.SubjectEpoch != initial.SubjectEpoch || current.SessionEpoch != initial.SessionEpoch || !s.exportAuthorized(current, record.employee.ID) {
				return fault.Forbidden
			}
			latest, err := tx.Employee(ctx, record.employee.ID)
			if err != nil || latest.OrgID != record.employee.OrgID || latest.Revision != record.employee.Revision || latest.HeadID != record.employee.HeadID {
				return fault.Conflict
			}
		}
		if auditOutcome != "" {
			return tx.Audit(ctx, s.audit(request, initial, "", "OP-SEC-05", auditOutcome))
		}
		return nil
	})
}

func (s *Service) ExportProfiles(ctx context.Context, request Request, command ExportCommand, emit func(ExportEvent) error) (string, error) {
	store, ok := s.Store.(ExportStore)
	if !ok {
		return "", fault.Unavailable
	}
	initial, err := s.Session(ctx, request, "")
	if err != nil {
		return "", err
	}
	if request.Purpose != "organization_management" || !value.ValidID(request.Key) || command.Format != "ndjson" || len(command.Objects) < 1 || len(command.Objects) > 100 || emit == nil {
		return "", fault.Invalid
	}
	digest, err := s.digest(request, initial, "OP-SEC-05", "", command)
	if err != nil {
		return "", err
	}
	seen := map[string]struct{}{}
	records := make([]preparedProfile, 0, len(command.Objects))
	for _, object := range command.Objects {
		revision, valid := value.Revision(object.ExpectedRevision)
		if object.Kind != "employee_profile" || !value.ValidID(object.ID) || !valid {
			return "", fault.Invalid
		}
		key := object.Kind + "\x00" + object.ID
		if _, duplicate := seen[key]; duplicate {
			return "", fault.Invalid
		}
		seen[key] = struct{}{}
		employee, readErr := store.Employee(ctx, object.ID)
		if readErr != nil || employee.OrgID != initial.OrgID {
			return "", s.denied(ctx, request, initial, "OP-SEC-05", fault.NotFound)
		}
		current, securityErr := store.Security(ctx, request.TokenHash, initial.OrgID, employee.ID)
		if securityErr != nil || current.SubjectID != initial.SubjectID || !s.exportAuthorized(current, employee.ID) {
			return "", s.denied(ctx, request, initial, "OP-SEC-05", fault.Forbidden)
		}
		if employee.Revision != revision {
			return "", fault.Conflict
		}
		version, readErr := store.Version(ctx, employee.OrgID, employee.ID, employee.HeadID)
		if readErr != nil {
			return "", readErr
		}
		plaintext, openErr := s.Cipher.Open(ctx, profileBinding(employee, version.ID), version.Envelope)
		if openErr != nil {
			return "", fault.Unavailable
		}
		var payload ProfilePayload
		decodeErr := json.Unmarshal(plaintext, &payload)
		clear(plaintext)
		if decodeErr != nil || !validProfile(payload.Profile) {
			return "", fault.Unavailable
		}
		view := View{ID: employee.ID, OrgID: employee.OrgID, Revision: strconv.FormatInt(employee.Revision, 10), Lifecycle: employee.Lifecycle, AuthorizationDate: s.clock().Format("2006-01-02"), Profile: &payload.Profile}
		records = append(records, preparedProfile{object, employee, view})
	}
	exportID := value.NewID()
	if _, err = buildProfileEvents(exportID, records); err != nil {
		return "", err
	}
	err = store.WithExportTx(ctx, initial.OrgID, func(tx ExportTx) error {
		if lockErr := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); lockErr != nil {
			return lockErr
		}
		for _, record := range records {
			current, e := tx.Security(ctx, request.TokenHash, initial.OrgID, record.employee.ID)
			if e != nil || current.SubjectID != initial.SubjectID || current.SubjectEpoch != initial.SubjectEpoch || current.SessionEpoch != initial.SessionEpoch || !s.exportAuthorized(current, record.employee.ID) {
				return fault.Forbidden
			}
			latest, e := tx.Employee(ctx, record.employee.ID)
			if e != nil || latest.Revision != record.employee.Revision || latest.HeadID != record.employee.HeadID {
				return fault.Conflict
			}
		}
		if prior, found, e := tx.ExportReceipt(ctx, initial.OrgID, initial.SubjectID, request.Purpose, request.Key); e != nil {
			return e
		} else if found {
			if !hmac.Equal(prior.Digest, digest) {
				return fault.Mismatch
			}
			exportID = prior.ExportID
		} else if e = tx.SaveExportReceipt(ctx, initial.OrgID, initial.SubjectID, request.Purpose, request.Key, ExportReceipt{Digest: digest, ExportID: exportID}, s.clock()); e != nil {
			return e
		}
		return tx.Audit(ctx, s.audit(request, initial, "", "OP-SEC-05", "allowed"))
	})
	if err != nil {
		return "", s.denied(ctx, request, initial, "OP-SEC-05", err)
	}
	events, err := buildProfileEvents(exportID, records)
	if err != nil {
		return "", err
	}
	for index, encoded := range events {
		guard := records
		if index > 0 && index <= len(records) {
			guard = records[index-1 : index]
		}
		if err = s.exportGuard(ctx, store, request, initial, guard, ""); err != nil {
			return exportID, s.denied(ctx, request, initial, "OP-SEC-05", err)
		}
		if err = emit(ExportEvent{EncodedJSON: encoded}); err != nil {
			_ = s.exportGuard(context.WithoutCancel(ctx), store, request, initial, nil, "partial")
			partial, _ := encodeProfileExport(profileExport{Kind: "partial", ExportID: exportID, Status: "partial", Reason: "consumer_unavailable"})
			_ = emit(ExportEvent{EncodedJSON: partial})
			return exportID, err
		}
	}
	return exportID, nil
}
