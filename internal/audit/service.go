package audit

import (
	"context"
	"errors"
	"log"
	"regexp"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/value"
)

type Service struct {
	Store     Store
	CursorKey []byte
	CursorMAC func([]byte) ([]byte, error)
	Now       func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

var operationPattern = regexp.MustCompile(`^(AUTH-(LOGIN|STEP-UP|LOGOUT|BIND|UNBIND)|OP-(ORG|SEC|INT|COMP|BONUS|AI)-[0-9]{2})$`)

func parseBound(text string) (*time.Time, bool) {
	if text == "" {
		return nil, true
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond()%1000 != 0 || parsed.Format(time.RFC3339Nano) != text {
		return nil, false
	}
	parsed = parsed.UTC().Truncate(time.Microsecond)
	return &parsed, true
}

func validFilter(filter Filter) (Query, bool) {
	query := Query{Filter: filter}
	if filter.Limit < 1 || filter.Limit > 100 || len(filter.Cursor) > 4096 {
		return Query{}, false
	}
	for _, id := range []string{filter.SubjectID, filter.EmployeeID, filter.GrantID} {
		if id != "" && !value.ValidID(id) {
			return Query{}, false
		}
	}
	if filter.Operation != "" && !operationPattern.MatchString(filter.Operation) || filter.Purpose != "" && filter.Purpose != "organization_management" && filter.Purpose != Purpose && filter.Purpose != "interview_followup" && filter.Purpose != "compensation_management" || filter.Outcome != "" && filter.Outcome != "allowed" && filter.Outcome != "denied" && filter.Outcome != "partial" {
		return Query{}, false
	}
	var ok bool
	query.FromTime, ok = parseBound(filter.From)
	if !ok {
		return Query{}, false
	}
	query.ToTime, ok = parseBound(filter.To)
	if !ok || query.FromTime != nil && query.ToTime != nil && !query.ToTime.After(*query.FromTime) {
		return Query{}, false
	}
	return query, true
}

func authorizationUntil(snapshot authz.Snapshot) time.Time {
	until := snapshot.ExpiresAt
	if snapshot.IdleExpiresAt.Before(until) {
		until = snapshot.IdleExpiresAt
	}
	if snapshot.MFAUntil.Before(until) {
		until = snapshot.MFAUntil
	}
	return until
}

func (s *Service) List(ctx context.Context, request Request, filter Filter) (Page, error) {
	if s.Store == nil || request.Purpose != Purpose || !value.ValidID(request.RequestID) {
		return Page{}, fault.Invalid
	}
	query, valid := validFilter(filter)
	if !valid {
		return Page{}, fault.Invalid
	}
	initial, err := s.Store.Security(ctx, request.TokenHash, "", filter.EmployeeID)
	if err != nil {
		return Page{}, s.denied(ctx, request, initial, err)
	}
	initialNow := s.clock()
	if !initial.Allows("audit.read", "audit", filter.EmployeeID, Purpose, initialNow) {
		return Page{}, s.denied(ctx, request, initial, fault.Forbidden)
	}
	var page Page
	err = s.Store.WithAuditTx(ctx, initial.OrgID, func(tx Tx) error {
		if lockErr := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); lockErr != nil {
			return lockErr
		}
		current, securityErr := tx.Security(ctx, request.TokenHash, initial.OrgID, filter.EmployeeID)
		authorizedAt := s.clock()
		if securityErr != nil || current.SubjectID != initial.SubjectID || !current.Allows("audit.read", "audit", filter.EmployeeID, Purpose, authorizedAt) {
			return fault.Forbidden
		}
		if filter.Cursor != "" {
			after, id, cursorErr := s.openCursor(filter.Cursor, current, filter, authorizedAt)
			if cursorErr != nil {
				return cursorErr
			}
			query.AfterTime, query.AfterID = &after, id
		}
		items, listErr := tx.AuditEvents(ctx, current.OrgID, query)
		if listErr != nil {
			return listErr
		}
		page = Page{Items: items, Consistency: "current", AuthorizationUntil: authorizationUntil(current)}
		if len(items) > filter.Limit {
			page.Items = items[:filter.Limit]
			cursor, cursorErr := s.sealCursor(current, filter, page.Items[len(page.Items)-1], authorizedAt)
			if cursorErr != nil {
				return cursorErr
			}
			page.NextCursor = &cursor
		}
		return tx.Audit(ctx, organization.Audit{ID: value.NewID(), OrgID: current.OrgID, SubjectID: current.SubjectID, EmployeeID: filter.EmployeeID, Operation: "OP-SEC-04", Purpose: Purpose, RequestID: request.RequestID, Outcome: "allowed", At: authorizedAt})
	})
	if err != nil {
		return Page{}, s.denied(ctx, request, initial, err)
	}
	if page.Items == nil {
		page.Items = []Event{}
	}
	return page, nil
}

func (s *Service) denied(ctx context.Context, request Request, snapshot authz.Snapshot, cause error) error {
	if cause == nil || !errors.Is(cause, fault.NotFound) && !errors.Is(cause, fault.Forbidden) && !errors.Is(cause, fault.Unauthenticated) {
		return cause
	}
	if auditErr := s.Store.AuditDenied(ctx, organization.Audit{ID: value.NewID(), OrgID: snapshot.OrgID, SubjectID: snapshot.SubjectID, Operation: "OP-SEC-04", Purpose: Purpose, RequestID: request.RequestID, Outcome: "denied", At: s.clock()}); auditErr != nil {
		requestID := request.RequestID
		if !value.ValidID(requestID) {
			requestID = ""
		}
		log.Printf("DENIED_AUDIT_UNAVAILABLE request_id=%s operation=OP-SEC-04", requestID)
	}
	return cause
}
