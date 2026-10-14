package assessment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

type Service struct {
	Store            Store
	DigestKey        []byte
	CommandMAC       func([]byte) ([]byte, error)
	GenerationMAC    func([]byte) ([]byte, error)
	Now              func() time.Time
	Cipher           sensitive.Cipher
	ProviderPolicies map[string]ProviderPolicy
	Workers          map[string]WorkerIdentity
	ServiceSubjects  map[string]ServiceIdentity
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

func (s *Service) audit(q Request, a authz.Snapshot, employee, op, outcome string) organization.Audit {
	return organization.Audit{ID: value.NewID(), OrgID: a.OrgID, SubjectID: a.SubjectID, EmployeeID: employee, Operation: op, Purpose: q.Purpose, RequestID: q.RequestID, Outcome: outcome, At: s.clock()}
}

func (s *Service) session(ctx context.Context, r Reader, q Request, org, employee string) (authz.Snapshot, error) {
	if r == nil || len(q.TokenHash) != sha256.Size {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	a, err := r.Security(ctx, q.TokenHash, org, employee)
	if err != nil {
		return a, err
	}
	if !a.Valid(s.clock()) {
		return a, fault.Unauthenticated
	}
	if q.Purpose != "interview_followup" {
		return a, fault.Forbidden
	}
	return a, nil
}

func (s *Service) employee(ctx context.Context, q Request, id string) (authz.Snapshot, error) {
	if !value.ValidID(id) {
		return authz.Snapshot{}, fault.Invalid
	}
	a, err := s.session(ctx, s.Store, q, "", id)
	if err != nil {
		return a, err
	}
	employee, err := s.Store.Employee(ctx, id)
	if err != nil || employee.OrgID != a.OrgID {
		return a, fault.NotFound
	}
	return a, nil
}

func (s *Service) denied(ctx context.Context, q Request, a authz.Snapshot, op string, err error) error {
	if err != nil && a.OrgID != "" && (errors.Is(err, fault.NotFound) || errors.Is(err, fault.Forbidden) || errors.Is(err, fault.Unauthenticated)) {
		if auditErr := s.Store.AuditDenied(ctx, s.audit(q, a, "", op, "denied")); auditErr != nil {
			return auditErr
		}
	}
	return err
}

func parseRevision(raw string) (int64, error) {
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 0 || revision == 1<<63-1 || strconv.FormatInt(revision, 10) != raw {
		return 0, fault.Invalid
	}
	return revision, nil
}

func policyView(policy Policy) PolicyView {
	return PolicyView{Revision: strconv.FormatInt(policy.Revision, 10), Cadence: policy.Cadence, AnchorDate: policy.AnchorDate, Timezone: policy.Timezone, DueOffsetDays: policy.DueOffsetDays, LocalDueTime: policy.LocalDueTime, WindowThrough: policy.WindowThrough, PauseIntervals: append([]PauseInterval{}, policy.PauseIntervals...), Purpose: policy.Purpose, AIMode: policy.AIMode, RequiredFields: append([]string{}, policy.RequiredFields...), Standing: policy.Standing, UpdatedBy: policy.UpdatedBy, UpdatedAt: policy.UpdatedAt}
}

func windowView(window Window) WindowView {
	return WindowView{ID: window.ID, PolicyRevision: strconv.FormatInt(window.PolicyRevision, 10), LocalStart: window.LocalStart, LocalEnd: window.LocalEnd, StartAt: window.StartAt, EndAt: window.EndAt, DueAt: window.DueAt, Paused: window.Paused}
}

func (s *Service) mac(frame []byte, generation bool) ([]byte, error) {
	callback := s.CommandMAC
	if generation {
		callback = s.GenerationMAC
	}
	if callback != nil {
		return callback(frame)
	}
	if len(s.DigestKey) < sha256.Size {
		return nil, fault.Unavailable
	}
	mac := hmac.New(sha256.New, s.DigestKey)
	mac.Write(frame)
	return mac.Sum(nil), nil
}

func (s *Service) policyDigest(q Request, a authz.Snapshot, employee string, command PolicyCommand) ([]byte, error) {
	if !value.ValidID(q.Key) || !value.ValidID(q.RequestID) {
		return nil, fault.Invalid
	}
	frame := []byte("TEAMLEDGER-ASSESSMENT-POLICY\x00V1\x00")
	for _, part := range []string{a.OrgID, a.SubjectID, employee, q.Purpose, command.ExpectedRevision, canonicalPolicy(command)} {
		frame = append(frame, []byte(strconv.Itoa(len(part)))...)
		frame = append(frame, ':')
		frame = append(frame, part...)
	}
	defer clear(frame)
	return s.mac(frame, false)
}

func (s *Service) PutPolicy(ctx context.Context, q Request, employee string, command PolicyCommand) (PolicyView, error) {
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return PolicyView{}, s.denied(ctx, q, a, "OP-AI-01", err)
	}
	if !a.Allows("interview_policy.manage", "metadata", employee, "interview_followup", s.clock()) || !a.Allows("interview.read", "metadata", employee, "interview_followup", s.clock()) {
		return PolicyView{}, s.denied(ctx, q, a, "OP-AI-01", fault.NotFound)
	}
	expected, err := parseRevision(command.ExpectedRevision)
	if err != nil {
		return PolicyView{}, err
	}
	command.RequiredFields = append([]string(nil), command.RequiredFields...)
	sort.Strings(command.RequiredFields)
	if command.AIMode == "periodic_structured_v1" && command.Standing != nil {
		if !value.ValidID(command.Standing.ServiceSubjectID) || !value.ValidID(command.Standing.ProviderPolicyID) || command.Standing.ServiceSubjectID == a.SubjectID || command.Standing.TemplateVersion != "periodic_structured_v1" {
			return PolicyView{}, fault.Invalid
		}
		expires, parseErr := time.Parse(time.RFC3339Nano, command.Standing.ExpiresAt)
		provider, providerOK := s.ProviderPolicies[command.Standing.ProviderPolicyID]
		identity, serviceOK := s.ServiceSubjects[command.Standing.ServiceSubjectID]
		if parseErr != nil || !expires.After(s.clock()) || expires.After(s.clock().AddDate(1, 0, 0)) || !providerOK || !provider.Enabled || !s.clock().Before(provider.ExpiresAt) || provider.Audience != command.Standing.Audience || !serviceOK || len(identity.TokenHash) != sha256.Size {
			return PolicyView{}, fault.Forbidden
		}
		serviceActor, securityErr := s.Store.Security(ctx, identity.TokenHash, a.OrgID, employee)
		if securityErr != nil || serviceActor.SubjectID != command.Standing.ServiceSubjectID || !serviceActor.Allows("assessment.request", "metadata", employee, "interview_followup", s.clock()) || !serviceActor.Allows("assessment.read", "metadata", employee, "interview_followup", s.clock()) {
			return PolicyView{}, fault.Forbidden
		}
	} else if command.AIMode != "periodic_structured_v1" && command.Standing != nil {
		return PolicyView{}, fault.Invalid
	}
	windows, err := GenerateWindows(command, expected+1)
	if err != nil {
		return PolicyView{}, fault.Invalid
	}
	for index := range windows {
		windows[index].OrgID, windows[index].EmployeeID, windows[index].ID = a.OrgID, employee, value.NewID()
	}
	digest, err := s.policyDigest(q, a, employee, command)
	if err != nil {
		return PolicyView{}, err
	}
	var output Policy
	err = s.Store.WithAssessmentTx(ctx, a.OrgID, func(tx Tx) error {
		if lockErr := tx.LockSubjects(ctx, a.OrgID, []string{a.SubjectID}); lockErr != nil {
			return lockErr
		}
		if lockErr := tx.LockInterviewEmployee(ctx, a.OrgID, employee); lockErr != nil {
			return lockErr
		}
		current, sessionErr := s.session(ctx, tx, q, a.OrgID, employee)
		if sessionErr != nil {
			return sessionErr
		}
		if current.SubjectID != a.SubjectID || current.AuthEpoch != a.AuthEpoch || current.SubjectEpoch != a.SubjectEpoch || current.SessionEpoch != a.SessionEpoch || !current.Allows("interview_policy.manage", "metadata", employee, "interview_followup", s.clock()) || !current.Allows("interview.read", "metadata", employee, "interview_followup", s.clock()) {
			return fault.Forbidden
		}
		if receipt, found, receiptErr := tx.AssessmentReceipt(ctx, a.OrgID, current.SubjectID, q.Key); receiptErr != nil {
			return receiptErr
		} else if found {
			if !hmac.Equal(receipt.Digest, digest) || receipt.Policy.EmployeeID != employee {
				return fault.Mismatch
			}
			output = receipt.Policy
			return nil
		}
		prior, found, readErr := tx.AssessmentPolicy(ctx, a.OrgID, employee)
		if readErr != nil {
			return readErr
		}
		actual := int64(0)
		if found {
			actual = prior.Revision
		}
		if actual != expected {
			return fault.Conflict
		}
		output = Policy{OrgID: a.OrgID, EmployeeID: employee, Revision: expected + 1, PolicyCommand: command, UpdatedBy: current.SubjectID, UpdatedAt: s.clock()}
		if saveErr := tx.SaveAssessmentPolicy(ctx, output, windows); saveErr != nil {
			return saveErr
		}
		if saveErr := tx.SaveAssessmentReceipt(ctx, a.OrgID, current.SubjectID, q.Key, Receipt{Digest: digest, Policy: output}); saveErr != nil {
			return saveErr
		}
		return tx.Audit(ctx, s.audit(q, current, employee, "OP-AI-01", "allowed"))
	})
	if err != nil {
		return PolicyView{}, s.denied(ctx, q, a, "OP-AI-01", err)
	}
	return policyView(output), nil
}

func containsField(fields []string, field string) bool {
	index := sort.SearchStrings(fields, field)
	return index < len(fields) && fields[index] == field
}

func filterWindows(windows []Window, query StatusQuery, now time.Time) ([]Window, error) {
	if query.WindowID != "" {
		if !value.ValidID(query.WindowID) || query.From != "" || query.To != "" {
			return nil, fault.Invalid
		}
		for _, window := range windows {
			if window.ID == query.WindowID {
				return []Window{window}, nil
			}
		}
		return nil, fault.NotFound
	}
	if (query.From == "") != (query.To == "") {
		return nil, fault.Invalid
	}
	if query.From == "" {
		for _, window := range windows {
			if !now.Before(window.StartAt) && now.Before(window.EndAt) {
				return []Window{window}, nil
			}
		}
		return []Window{}, nil
	}
	from, fromErr := parseDate(query.From)
	to, toErr := parseDate(query.To)
	if fromErr != nil || toErr != nil || !to.After(from) {
		return nil, fault.Invalid
	}
	selected := make([]Window, 0)
	for _, window := range windows {
		if window.LocalEnd > query.From && window.LocalStart < query.To {
			selected = append(selected, window)
		}
	}
	if len(selected) > 100 {
		return nil, fault.Invalid
	}
	return selected, nil
}

func factState(window Window, facts DeterministicFacts, partial bool, now time.Time) string {
	if window.Paused {
		return "paused"
	}
	if partial {
		return "partial_access"
	}
	if facts.UnknownCount != 0 {
		return "unknown"
	}
	if facts.OccurredCount != 0 {
		return "completed"
	}
	if facts.ScheduledCount != 0 {
		return "scheduled_not_occurred"
	}
	if !now.Before(window.DueAt) {
		return "overdue"
	}
	return "not_scheduled"
}

func (s *Service) Status(ctx context.Context, q Request, employee string, query StatusQuery) (StatusView, error) {
	initial, err := s.employee(ctx, q, employee)
	if err != nil {
		return StatusView{}, s.denied(ctx, q, initial, "OP-AI-02", err)
	}
	if !initial.Allows("interview.read", "metadata", employee, "interview_followup", s.clock()) {
		return StatusView{}, s.denied(ctx, q, initial, "OP-AI-02", fault.NotFound)
	}
	var out StatusView
	err = s.Store.WithAssessmentTx(ctx, initial.OrgID, func(tx Tx) error {
		if lockErr := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); lockErr != nil {
			return lockErr
		}
		if lockErr := tx.LockInterviewEmployee(ctx, initial.OrgID, employee); lockErr != nil {
			return lockErr
		}
		current, sessionErr := s.session(ctx, tx, q, initial.OrgID, employee)
		if sessionErr != nil || current.SubjectID != initial.SubjectID || current.AuthEpoch != initial.AuthEpoch || current.SubjectEpoch != initial.SubjectEpoch || current.SessionEpoch != initial.SessionEpoch || !current.Allows("interview.read", "metadata", employee, "interview_followup", s.clock()) {
			return fault.Forbidden
		}
		policy, configured, readErr := tx.AssessmentPolicy(ctx, current.OrgID, employee)
		if readErr != nil {
			return readErr
		}
		if !configured {
			out = StatusView{State: "unconfigured", Items: []WindowStatus{}, Coverage: Coverage{Interviews: "complete", Actions: "unknown", Notes: "unknown"}, AIState: "disabled"}
			return tx.Audit(ctx, s.audit(q, current, employee, "OP-AI-02", "allowed"))
		}
		windows, readErr := tx.AssessmentWindows(ctx, current.OrgID, employee, policy.Revision)
		if readErr != nil {
			return readErr
		}
		windows, readErr = filterWindows(windows, query, s.clock())
		if readErr != nil {
			return readErr
		}
		canReadActions := current.Allows("action.read", "shared", employee, "interview_followup", s.clock())
		needsNotes := containsField(policy.RequiredFields, "shared_published_note")
		canReadNotes := !needsNotes || current.Allows("note.read", "shared", employee, "interview_followup", s.clock())
		coverage := Coverage{Interviews: "complete", Actions: "partial_access", Notes: "not_required"}
		if canReadActions {
			coverage.Actions = "complete"
		}
		if needsNotes {
			coverage.Notes = "partial_access"
			if canReadNotes {
				coverage.Notes = "complete"
			}
		}
		actions := []ActionFact{}
		if canReadActions {
			actions, readErr = tx.AssessmentActionFacts(ctx, current.OrgID, employee, true)
			if readErr != nil {
				return readErr
			}
		}
		loc, locationErr := time.LoadLocation(policy.Timezone)
		if locationErr != nil {
			return fault.Unavailable
		}
		today := s.clock().In(loc).Format("2006-01-02")
		items := make([]WindowStatus, 0, len(windows))
		for _, window := range windows {
			rows, factsErr := tx.AssessmentInterviewFacts(ctx, current.OrgID, employee, window, needsNotes && canReadNotes)
			if factsErr != nil {
				return factsErr
			}
			facts := DeterministicFacts{}
			for _, row := range rows {
				if !row.ScheduledAt.Before(window.StartAt) && row.ScheduledAt.Before(window.EndAt) {
					facts.ScheduledCount++
				}
				if row.ActualStartedAt == nil || row.ActualStartedAt.Before(window.StartAt) || !row.ActualStartedAt.Before(window.EndAt) {
					continue
				}
				facts.OccurredCount++
				if row.Backfilled {
					facts.BackfilledCount++
				}
				complete := true
				if (containsField(policy.RequiredFields, "actual_started_at") && row.ActualStartedAt == nil) || (containsField(policy.RequiredFields, "actual_ended_at") && row.ActualEndedAt == nil) {
					complete = false
				}
				if needsNotes {
					if !canReadNotes {
						facts.UnknownCount++
						continue
					}
					complete = complete && row.HasPublishedSharedNote
				}
				if complete {
					facts.CompleteCount++
				} else {
					facts.IncompleteCount++
				}
			}
			for _, action := range actions {
				if action.OccurredAt.Before(window.StartAt) || !action.OccurredAt.Before(window.EndAt) || action.Status == "done" || action.Status == "cancelled" {
					continue
				}
				facts.OpenActionCount++
				if action.DueDate != nil && *action.DueDate < window.LocalEnd {
					facts.DueActionCount++
					if *action.DueDate < today {
						facts.OverdueActionCount++
					}
				}
			}
			partial := !canReadActions || !canReadNotes
			items = append(items, WindowStatus{Window: windowView(window), State: factState(window, facts, partial, s.clock()), Facts: facts})
		}
		aiState, block := "disabled", ""
		if policy.AIMode == "manual_approved" {
			aiState = "awaiting_manual_input"
		} else if policy.AIMode == "periodic_structured_v1" {
			aiState = "ready"
			if policy.Standing == nil {
				aiState, block = "blocked", "automation_not_enabled"
			} else if expires, parseErr := time.Parse(time.RFC3339Nano, policy.Standing.ExpiresAt); parseErr != nil || !s.clock().Before(expires) {
				aiState, block = "blocked", "policy_expired"
			} else if provider, ok := s.ProviderPolicies[policy.Standing.ProviderPolicyID]; !ok || !provider.Enabled || !s.clock().Before(provider.ExpiresAt) || provider.Audience != policy.Standing.Audience {
				aiState, block = "blocked", "provider_not_approved"
			} else if identity, ok := s.ServiceSubjects[policy.Standing.ServiceSubjectID]; !ok || len(identity.TokenHash) != sha256.Size {
				aiState, block = "blocked", "authorization_unavailable"
			}
		}
		policyOutput := policyView(policy)
		out = StatusView{State: "configured", Policy: &policyOutput, Items: items, Coverage: coverage, AIState: aiState, AIBlockReason: block}
		return tx.Audit(ctx, s.audit(q, current, employee, "OP-AI-02", "allowed"))
	})
	return out, s.denied(ctx, q, initial, "OP-AI-02", err)
}
