package compensation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func (s *Service) salaryRangeStore() (SalaryRangeStore, error) {
	store, ok := s.Batches.(SalaryRangeStore)
	if !ok {
		return nil, fault.Unavailable
	}
	return store, nil
}

func (s *Service) SalaryRanges(ctx context.Context, req Request, org string, query SalaryRangeQuery) ([]SalaryRangeView, error) {
	snapshot, err := s.batchSession(ctx, req, org, false)
	if err != nil {
		return nil, err
	}
	if query.AsOf != "" {
		if _, err := time.Parse("2006-01-02", query.AsOf); err != nil {
			return nil, fault.Invalid
		}
	}
	if query.Currency != "" && query.Currency != "CNY" && query.Currency != "JPY" {
		return nil, fault.Invalid
	}
	store, err := s.salaryRangeStore()
	if err != nil {
		return nil, err
	}
	records, err := store.SalaryRanges(ctx, org, query)
	if err != nil {
		return nil, err
	}
	out := make([]SalaryRangeView, 0, len(records))
	for _, record := range records {
		payload, err := store.SalaryRangePayload(ctx, org, record.PayloadID)
		if err != nil {
			return nil, err
		}
		var amounts SalaryRangeAmounts
		raw, err := s.Cipher.Open(ctx, salaryRangeBinding(org, record.ID, payload.ID), payload.Envelope)
		if err != nil {
			return nil, fault.Unavailable
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&amounts)
		clear(raw)
		if err != nil || ValidateSalaryRangeAmounts(amounts) != nil {
			return nil, fault.Unavailable
		}
		out = append(out, SalaryRangeView{ID: record.ID, LegalEntityID: record.LegalEntityID, Location: record.Location, JobFamilyID: record.JobFamilyID, CareerLevelID: record.CareerLevelID, Currency: record.Currency, ValidFrom: record.ValidFrom, ValidTo: record.ValidTo, Revision: strconv.FormatInt(record.Revision, 10), Amounts: amounts})
	}
	fresh, err := s.batchSession(ctx, req, org, false)
	if err != nil {
		return nil, err
	}
	if fresh.SubjectID != snapshot.SubjectID || fresh.OrgID != snapshot.OrgID {
		return nil, fault.Forbidden
	}
	return out, nil
}

func (s *Service) ChangeSalaryRanges(ctx context.Context, req Request, org string, command SalaryRangeChangeCommand) ([]SalaryRangeView, error) {
	snapshot, err := s.batchSession(ctx, req, org, true)
	if err != nil {
		return nil, err
	}
	if !value.ValidID(req.Key) || len(command.Changes) == 0 || len(command.Changes) > 100 {
		return nil, fault.Invalid
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return nil, fault.Invalid
	}
	digest, err := s.financialDigest("salary-range-command", raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	store, err := s.salaryRangeStore()
	if err != nil {
		return nil, err
	}
	previous, found, err := store.SalaryRangeReceipt(ctx, org, snapshot.SubjectID, req.Key)
	if err != nil {
		return nil, err
	}
	if found {
		if !hmac.Equal(previous.Digest, digest) {
			return nil, fault.Conflict
		}
		return s.SalaryRanges(ctx, req, org, SalaryRangeQuery{})
	}
	receipt := SalaryRangeReceipt{SubjectID: snapshot.SubjectID, Key: req.Key, RequestID: req.RequestID, Digest: append([]byte(nil), digest...), RecordedAt: s.clock()}
	// Receipt lookup precedes encryption so exact replays never contact KMS again.
	existing, err := store.SalaryRanges(ctx, org, SalaryRangeQuery{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]SalaryRangeRecord, len(existing))
	for _, record := range existing {
		byID[record.ID] = record
	}
	records := append([]SalaryRangeRecord(nil), existing...)
	payloads := make([]SalaryRangePayload, 0, len(command.Changes))
	for i := range command.Changes {
		change := &command.Changes[i]
		switch change.Action {
		case "add":
			if change.ID != "" || change.ExpectedRevision != "0" || !validSalaryRangeFields(*change) {
				return nil, fault.Invalid
			}
			change.ID = value.NewID()
			record, payload, err := s.prepareSalaryRange(ctx, org, change.ID, *change)
			if err != nil {
				return nil, err
			}
			records = append(records, record)
			payloads = append(payloads, payload)
		case "end":
			record, ok := byID[change.ID]
			revision, valid := rangeRevision(change.ExpectedRevision, false)
			if !ok || !valid || record.Revision != revision || record.ValidTo != nil || !validDate(change.EffectiveTo) || change.Amounts != nil {
				return nil, fault.Conflict
			}
		case "replace":
			record, ok := byID[change.ID]
			revision, valid := rangeRevision(change.ExpectedRevision, false)
			if !ok || !valid || record.Revision != revision || record.ValidTo != nil || !validDate(change.EffectiveTo) || !validSalaryRangeFields(*change) || change.ValidFrom != change.EffectiveTo {
				return nil, fault.Conflict
			}
			change.ReplacementID = value.NewID()
			replacement, payload, err := s.prepareSalaryRange(ctx, org, change.ReplacementID, *change)
			if err != nil {
				return nil, err
			}
			records = append(records, replacement)
			payloads = append(payloads, payload)
		default:
			return nil, fault.Invalid
		}
	}
	if err = store.ApplySalaryRangeChanges(ctx, org, records, payloads, command.Changes, receipt); err != nil {
		return nil, err
	}
	return s.SalaryRanges(ctx, req, org, SalaryRangeQuery{})
}

func (s *Service) prepareSalaryRange(ctx context.Context, org, id string, change SalaryRangeChange) (SalaryRangeRecord, SalaryRangePayload, error) {
	if change.Amounts == nil || ValidateSalaryRangeAmounts(*change.Amounts) != nil {
		return SalaryRangeRecord{}, SalaryRangePayload{}, fault.Invalid
	}
	raw, err := json.Marshal(change.Amounts)
	if err != nil {
		return SalaryRangeRecord{}, SalaryRangePayload{}, fault.Invalid
	}
	payloadID := value.NewID()
	envelope, err := s.Cipher.Seal(ctx, salaryRangeBinding(org, id, payloadID), raw)
	clear(raw)
	if err != nil {
		return SalaryRangeRecord{}, SalaryRangePayload{}, fault.Unavailable
	}
	record := SalaryRangeRecord{OrgID: org, ID: id, LegalEntityID: change.LegalEntityID, Location: change.Location, JobFamilyID: change.JobFamilyID, CareerLevelID: change.CareerLevelID, Currency: change.Currency, ValidFrom: change.ValidFrom, ValidTo: change.ValidTo, PayloadID: payloadID, Revision: 1}
	return record, SalaryRangePayload{OrgID: org, ID: payloadID, RangeID: id, Envelope: envelope, CreatedAt: s.clock()}, nil
}

func validSalaryRangeFields(change SalaryRangeChange) bool {
	if !value.ValidID(change.LegalEntityID) || !value.ValidID(change.JobFamilyID) || !value.ValidID(change.CareerLevelID) || change.Currency != "CNY" && change.Currency != "JPY" || change.Location != "Shanghai" && change.Location != "Wuxi" && change.Location != "Tokyo" || !validDate(change.ValidFrom) {
		return false
	}
	return change.ValidTo == nil || validDate(*change.ValidTo) && *change.ValidTo > change.ValidFrom
}

func validDate(value string) bool {
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

func salaryRangeBinding(org, rangeID, payloadID string) sensitive.Context {
	return sensitive.Context{OrgID: org, RecordID: rangeID, VersionID: payloadID, ObjectKind: "salary_range", Purpose: "financial", SchemaType: "compensation.salary_range.v1", SchemaVersion: 1}
}
