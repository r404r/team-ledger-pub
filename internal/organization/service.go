package organization

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

type Service struct {
	Store     Store
	Cipher    sensitive.Cipher
	DigestKey []byte
	CursorKey []byte
	Now       func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

func (s *Service) Session(ctx context.Context, request Request, employee string) (authz.Snapshot, error) {
	if len(request.TokenHash) != 32 || s.Store == nil {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	if employee != "" && !value.ValidID(employee) {
		return authz.Snapshot{}, fault.Invalid
	}
	snapshot, err := s.Store.Security(ctx, request.TokenHash, "", employee)
	if err != nil {
		return authz.Snapshot{}, err
	}
	if !snapshot.Valid(s.clock()) {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	if employee != "" {
		if !snapshot.Allows("organization.read", "metadata", employee, "organization_management", s.clock()) {
			return authz.Snapshot{}, s.denied(ctx, request, snapshot, "OP-SEC-01", fault.NotFound)
		}
		object, err := s.Store.Employee(ctx, employee)
		if err != nil {
			return authz.Snapshot{}, s.denied(ctx, request, snapshot, "OP-SEC-01", err)
		}
		if object.OrgID != snapshot.OrgID {
			return authz.Snapshot{}, s.denied(ctx, request, snapshot, "OP-SEC-01", fault.NotFound)
		}
	}
	return snapshot, nil
}

func (s *Service) Create(ctx context.Context, request Request, org string, command CreateCommand) (Result, error) {
	snapshot, err := s.authorize(ctx, s.Store, request, org, "", "OP-ORG-05")
	if err != nil {
		return Result{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	if !value.ValidID(org) || !value.ValidID(request.Key) || !validProfile(command.Profile) || !validLifecycle(command.Lifecycle) {
		return Result{}, fault.Invalid
	}
	digest, err := s.digest(request, snapshot, "OP-ORG-05", org, command)
	if err != nil {
		return Result{}, err
	}
	if result, found, err := s.replay(ctx, request, snapshot, "", "OP-ORG-05", digest); found || err != nil {
		return result, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	employee := Employee{ID: value.NewID(), OrgID: org, Revision: 1, Lifecycle: command.Lifecycle}
	version, err := s.prepare(ctx, employee, command.Profile, "")
	if err != nil {
		return Result{}, err
	}
	var result Result
	err = s.Store.WithTx(ctx, org, func(tx Tx) error {
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
		if previous, found, err := tx.Receipt(ctx, org, current.SubjectID, "OP-ORG-05", request.Key); err != nil {
			return err
		} else if found {
			result, err = confirmReceipt(previous, digest)
			return err
		}
		employee.HeadID = version.ID
		if err := tx.Create(ctx, employee, version); err != nil {
			return err
		}
		result = Result{ID: employee.ID, Revision: "1"}
		if err := tx.SaveReceipt(ctx, org, current.SubjectID, "OP-ORG-05", request.Key, Receipt{Digest: digest, Result: result}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(request, current, employee.ID, "OP-ORG-05", "allowed"))
	})
	if err != nil {
		return Result{}, s.denied(ctx, request, snapshot, "OP-ORG-05", err)
	}
	return result, nil
}
func (s *Service) Read(ctx context.Context, request Request, id, asOf string, includeProfile bool) (View, error) {
	if _, err := s.Session(ctx, request, ""); err != nil {
		return View{}, err
	}
	if !value.ValidID(id) || !value.ValidDate(asOf) {
		return View{}, fault.Invalid
	}
	employee, err := s.Store.Employee(ctx, id)
	if err != nil {
		return View{}, err
	}
	snapshot, err := s.authorize(ctx, s.Store, request, employee.OrgID, id, "OP-ORG-06")
	if err != nil {
		return View{}, s.denied(ctx, request, snapshot, "OP-ORG-06", err)
	}
	graph, err := s.Store.GraphState(ctx, employee.OrgID)
	if err != nil {
		return View{}, err
	}
	view, err := s.prepareView(ctx, request, snapshot, employee, asOf, includeProfile, graph)
	if err != nil {
		return View{}, err
	}
	var pii []string
	if view.Profile != nil {
		pii = append(pii, id)
	}
	if err = s.releaseQuery(ctx, request, snapshot, graph, view.AuthorizationDate, "OP-ORG-06", []Employee{employee}, nil, nil, pii, false); err != nil {
		return View{}, s.denied(ctx, request, snapshot, "OP-ORG-06", err)
	}
	return view, nil
}
func (s *Service) Update(ctx context.Context, request Request, id string, command UpdateCommand) (Result, error) {
	if _, err := s.Session(ctx, request, ""); err != nil {
		return Result{}, err
	}
	if !value.ValidID(id) || !value.ValidID(request.Key) {
		return Result{}, fault.Invalid
	}
	employee, err := s.Store.Employee(ctx, id)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := s.authorize(ctx, s.Store, request, employee.OrgID, id, "OP-ORG-08")
	if err != nil {
		return Result{}, s.denied(ctx, request, snapshot, "OP-ORG-08", err)
	}
	expected, valid := value.Revision(command.ExpectedRevision)
	if !valid || !validProfile(command.Profile) || !utf8.ValidString(command.EditReason) || strings.TrimSpace(command.EditReason) == "" || len(command.EditReason) > 4096 {
		return Result{}, fault.Invalid
	}
	digest, err := s.digest(request, snapshot, "OP-ORG-08", id, command)
	if err != nil {
		return Result{}, err
	}
	if result, found, err := s.replay(ctx, request, snapshot, id, "OP-ORG-08", digest); found || err != nil {
		return result, s.denied(ctx, request, snapshot, "OP-ORG-08", err)
	}
	if employee.Revision != expected {
		return Result{}, fault.Conflict
	}
	if expected == int64(^uint64(0)>>1) {
		return Result{}, fault.Unavailable
	}
	next := employee
	next.Revision++
	version, err := s.prepare(ctx, next, command.Profile, command.EditReason)
	if err != nil {
		return Result{}, err
	}
	version.SupersedesID = employee.HeadID
	var result Result
	err = s.Store.WithTx(ctx, employee.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, employee.OrgID, []string{snapshot.SubjectID}); err != nil {
			return err
		}
		current, err := s.authorize(ctx, tx, request, employee.OrgID, id, "OP-ORG-08")
		if err != nil {
			return err
		}
		if current.AuthEpoch != snapshot.AuthEpoch {
			return fault.Forbidden
		}
		if previous, found, err := tx.Receipt(ctx, employee.OrgID, current.SubjectID, "OP-ORG-08", request.Key); err != nil {
			return err
		} else if found {
			result, err = confirmReceipt(previous, digest)
			return err
		}
		latest, err := tx.Employee(ctx, id)
		if err != nil {
			return err
		}
		if latest.OrgID != employee.OrgID || latest.Revision != expected || latest.HeadID != employee.HeadID {
			return fault.Conflict
		}
		next.HeadID = version.ID
		if err := tx.Replace(ctx, next, version, expected); err != nil {
			return err
		}
		result = Result{ID: id, Revision: strconv.FormatInt(next.Revision, 10)}
		if err := tx.SaveReceipt(ctx, employee.OrgID, current.SubjectID, "OP-ORG-08", request.Key, Receipt{Digest: digest, Result: result}); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(request, current, id, "OP-ORG-08", "allowed"))
	})
	if err != nil {
		return Result{}, s.denied(ctx, request, snapshot, "OP-ORG-08", err)
	}
	return result, nil
}

func (s *Service) authorize(ctx context.Context, reader Reader, request Request, org, employee, operation string) (authz.Snapshot, error) {
	if len(request.TokenHash) != 32 || reader == nil {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	snapshot, err := reader.Security(ctx, request.TokenHash, "", employee)
	if err != nil {
		return snapshot, err
	}
	now := s.clock()
	if !snapshot.Valid(now) {
		return snapshot, fault.Unauthenticated
	}
	if snapshot.OrgID != org {
		return snapshot, fault.NotFound
	}
	metadata := snapshot.Allows("organization.read", "metadata", employee, request.Purpose, now)
	pii := snapshot.Allows("pii.read", "pii", employee, request.Purpose, now)
	switch operation {
	case "OP-ORG-09":
		if !metadata {
			return snapshot, fault.NotFound
		}
	case "OP-ORG-06":
		if !metadata {
			return snapshot, fault.NotFound
		}
	case "OP-ORG-05":
		if !metadata {
			return snapshot, fault.NotFound
		}
		if !snapshot.Allows("organization.write", "metadata", employee, request.Purpose, now) || !pii || !snapshot.Allows("pii.write", "pii", employee, request.Purpose, now) {
			return snapshot, fault.Forbidden
		}
	case "OP-ORG-08":
		if !pii {
			if metadata {
				return snapshot, fault.Forbidden
			}
			return snapshot, fault.NotFound
		}
		if !snapshot.Allows("pii.write", "pii", employee, request.Purpose, now) {
			return snapshot, fault.Forbidden
		}
	default:
		return snapshot, fault.Forbidden
	}
	return snapshot, nil
}

func (s *Service) prepare(ctx context.Context, employee Employee, profile Profile, reason string) (Version, error) {
	payload, err := json.Marshal(ProfilePayload{Profile: profile, EditReason: reason})
	if err != nil || len(payload) > 16<<10 {
		clear(payload)
		return Version{}, fault.Invalid
	}
	defer clear(payload)
	version := Version{ID: value.NewID(), EmployeeID: employee.ID, OrgID: employee.OrgID, Number: employee.Revision, RecordedAt: s.clock()}
	version.Envelope, err = s.Cipher.Seal(ctx, profileBinding(employee, version.ID), payload)
	if err != nil {
		return Version{}, fault.Unavailable
	}
	return version, nil
}

func profileBinding(employee Employee, version string) sensitive.Context {
	return sensitive.Context{OrgID: employee.OrgID, EmployeeID: employee.ID, RecordID: employee.ID, VersionID: version, ObjectKind: "employee_profile", Purpose: "pii", SchemaType: "pii.profile.v1", SchemaVersion: 1}
}

func (s *Service) digest(request Request, snapshot authz.Snapshot, operation, object string, command any) ([]byte, error) {
	if len(s.DigestKey) != 32 {
		return nil, fault.Unavailable
	}
	data, err := json.Marshal(command)
	if err != nil {
		return nil, fault.Invalid
	}
	defer clear(data)
	mac := hmac.New(sha256.New, s.DigestKey)
	_, _ = mac.Write([]byte("TEAMLEDGER-COMMAND-V1"))
	var size [4]byte
	for _, part := range []string{snapshot.OrgID, snapshot.SubjectID, operation, object, request.Purpose} {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(part))
	}
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	_, _ = mac.Write(size[:])
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *Service) replay(ctx context.Context, request Request, snapshot authz.Snapshot, employee, operation string, digest []byte) (Result, bool, error) {
	_, found, err := s.Store.Receipt(ctx, snapshot.OrgID, snapshot.SubjectID, operation, request.Key)
	if err != nil || !found {
		return Result{}, false, err
	}
	var result Result
	err = s.Store.WithTx(ctx, snapshot.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, snapshot.OrgID, []string{snapshot.SubjectID}); err != nil {
			return err
		}
		current, err := s.authorize(ctx, tx, request, snapshot.OrgID, employee, operation)
		if err != nil {
			return err
		}
		receipt, exists, err := tx.Receipt(ctx, snapshot.OrgID, current.SubjectID, operation, request.Key)
		if err != nil {
			return err
		}
		if !exists {
			return fault.Unavailable
		}
		result, err = confirmReceipt(receipt, digest)
		return err
	})
	if err != nil {
		return Result{}, true, err
	}
	return result, true, nil
}

func confirmReceipt(receipt Receipt, digest []byte) (Result, error) {
	if subtle.ConstantTimeCompare(receipt.Digest, digest) != 1 {
		return Result{}, fault.Mismatch
	}
	return receipt.Result, nil
}

func validProfile(profile Profile) bool {
	if !utf8.ValidString(profile.DisplayName) || strings.TrimSpace(profile.DisplayName) == "" || len(profile.DisplayName) > 256 || len(profile.ProfileSummary) > 16<<10 || !utf8.ValidString(profile.ProfileSummary) {
		return false
	}
	if profile.WorkContact != nil {
		if !utf8.ValidString(profile.WorkContact.Email) || !utf8.ValidString(profile.WorkContact.Phone) || len(profile.WorkContact.Email) > 256 || len(profile.WorkContact.Phone) > 256 {
			return false
		}
	}
	return true
}
func validLifecycle(lifecycle Lifecycle) bool {
	return value.ValidDate(lifecycle.ValidFrom) && (lifecycle.ValidTo == nil || value.ValidDate(*lifecycle.ValidTo) && lifecycle.ValidFrom < *lifecycle.ValidTo)
}
func (s *Service) audit(request Request, snapshot authz.Snapshot, employee, operation, outcome string) Audit {
	purpose := request.Purpose
	if purpose != "organization_management" {
		purpose = ""
	}
	return Audit{ID: value.NewID(), OrgID: snapshot.OrgID, SubjectID: snapshot.SubjectID, EmployeeID: employee, Operation: operation, Purpose: purpose, RequestID: request.RequestID, Outcome: outcome, At: s.clock()}
}
func (s *Service) denied(ctx context.Context, request Request, snapshot authz.Snapshot, operation string, err error) error {
	if err != nil && (errors.Is(err, fault.NotFound) || errors.Is(err, fault.Forbidden) || errors.Is(err, fault.Unauthenticated)) && s.Store != nil {
		if auditErr := s.Store.AuditDenied(ctx, s.audit(request, snapshot, "", operation, "denied")); auditErr != nil {
			id := request.RequestID
			if !value.ValidID(id) {
				id = ""
			}
			log.Printf("DENIED_AUDIT_UNAVAILABLE request_id=%s operation=%s", id, operation)
		}
	}
	return err
}
