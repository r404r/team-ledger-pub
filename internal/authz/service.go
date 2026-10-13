package authz

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"math"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/value"
)

type Service struct {
	Store                Store
	DigestKey, CursorKey []byte
	Now                  func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

func (s *Service) session(ctx context.Context, r Reader, request Request) (Snapshot, error) {
	if r == nil || len(request.TokenHash) != 32 {
		return Snapshot{}, fault.Unauthenticated
	}
	current, err := r.Security(ctx, request.TokenHash, "", "")
	if err != nil {
		return current, err
	}
	if !current.Valid(s.clock()) {
		return current, fault.Unauthenticated
	}
	return current, nil
}

// Current approval facts are distinct from their effective intersection with
// management assignments/grants. Only the latter is used for SQL visibility.
func (s *Service) managedScopes(ctx context.Context, r Reader, current Snapshot, now time.Time) ([]Scope, error) {
	if !current.Valid(now) || !now.Before(current.MFAUntil) {
		return nil, nil
	}
	scopes := make([]Scope, 0)
	seen := map[Scope]bool{}
	for _, assignment := range current.Assignments {
		if assignment.Capability != "access_grant.manage" {
			continue
		}
		for _, grant := range current.Grants {
			if grant.ObjectRef != nil || grant.Capability != "access_grant.manage" || grant.Category != "audit" || grant.Purpose != ManagementPurpose || grant.Revoked || now.Before(grant.ValidFrom) || !now.Before(grant.ExpiresAt) || !current.relationQualified(grant, now) {
				continue
			}
			left, right := Scope{Kind: assignment.ScopeKind, ID: assignment.ScopeID}, Scope{Kind: grant.ScopeKind, ID: grant.ScopeID}
			forward, err := r.ScopeCovered(ctx, current.OrgID, left, right, now)
			if err != nil {
				return nil, err
			}
			scope := right
			if !forward {
				reverse, err := r.ScopeCovered(ctx, current.OrgID, right, left, now)
				if err != nil {
					return nil, err
				}
				if !reverse {
					continue
				}
				scope = left
			}
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
			if len(scopes) > 1000 {
				return nil, fault.Unavailable
			}
		}
	}
	return scopes, nil
}

func (s *Service) authorization(ctx context.Context, r Reader, request Request) (Snapshot, []AuthorityHint, []Authority, error) {
	current, err := s.session(ctx, r, request)
	if err != nil {
		return current, nil, nil, err
	}
	if request.Purpose != ManagementPurpose {
		return current, nil, nil, fault.Forbidden
	}
	scopes, err := s.managedScopes(ctx, r, current, s.clock())
	if err != nil {
		return current, nil, nil, err
	}
	if len(scopes) == 0 {
		return current, nil, nil, fault.Forbidden
	}
	all, err := r.Authorities(ctx, current.OrgID, current.SubjectID, s.clock())
	if err != nil {
		return current, nil, nil, err
	}
	facts := make([]AuthorityHint, 0, len(all))
	coverage := make([]Authority, 0, len(all))
	for _, a := range all {
		hint := AuthorityHint{Authority: a}
		for _, m := range scopes {
			scope := a.Scope
			forward, err := r.ScopeCovered(ctx, current.OrgID, scope, m, s.clock())
			if err != nil {
				return current, nil, nil, err
			}
			if forward {
				scope = m
			} else {
				reverse, err := r.ScopeCovered(ctx, current.OrgID, m, scope, s.clock())
				if err != nil {
					return current, nil, nil, err
				}
				if !reverse {
					continue
				}
			}
			owned, err := r.OwnsScope(ctx, current.OrgID, scope, s.clock())
			if err != nil {
				return current, nil, nil, err
			}
			if !owned {
				continue
			}
			part := a
			part.Scope = scope
			coverage = append(coverage, part)
			hint.DelegableScopes = append(hint.DelegableScopes, scope)
			if len(coverage) > 1000 {
				return current, nil, nil, fault.Unavailable
			}
		}
		if len(hint.DelegableScopes) != 0 {
			slices.SortFunc(hint.DelegableScopes, func(a, b Scope) int {
				if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
					return n
				}
				return cmp.Compare(a.ID, b.ID)
			})
			hint.DelegableScopes = slices.Compact(hint.DelegableScopes)
			facts = append(facts, hint)
		}
	}
	if len(coverage) == 0 {
		return current, nil, nil, fault.Forbidden
	}
	return current, facts, coverage, nil
}

func (s *Service) SessionAuthorities(ctx context.Context, request Request) ([]AuthorityHint, error) {
	request.Purpose = ManagementPurpose
	initial, err := s.session(ctx, s.Store, request)
	if err != nil {
		return nil, err
	}
	// The transaction path computes department/employee intersections against
	// canonical assignments; an empty-target session snapshot is intentionally
	// not expanded into a department roster here.
	var facts []AuthorityHint
	err = s.Store.WithGrantTx(ctx, initial.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		_, current, _, err := s.authorization(ctx, tx, request)
		if errors.Is(err, fault.Forbidden) {
			facts = []AuthorityHint{}
			return nil
		}
		facts = current
		return err
	})
	return facts, err
}

func (s *Service) List(ctx context.Context, request Request, filter Filter) (Page, error) {
	initial, err := s.session(ctx, s.Store, request)
	if err != nil {
		return Page{}, s.denied(ctx, request, initial, "OP-SEC-06", err)
	}
	if !validFilter(filter) {
		return Page{}, fault.Invalid
	}
	var page Page
	err = s.Store.WithGrantTx(ctx, initial.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		current, facts, coverage, err := s.authorization(ctx, tx, request)
		if err != nil {
			return err
		}
		now := s.clock()
		zone, err := time.LoadLocation(current.Timezone)
		if err != nil {
			return fault.Unavailable
		}
		day := now.In(zone).Format("2006-01-02")
		after := ""
		if filter.Cursor != "" {
			after, err = s.openCursor(filter.Cursor, current, filter, day, now)
			if err != nil {
				return err
			}
		}
		items, err := tx.VisibleGrants(ctx, current.OrgID, coverage, filter, after, now)
		if err != nil {
			return err
		}
		if filter.GrantID != "" && len(items) == 0 {
			return fault.NotFound
		}
		page = Page{Items: items, Authorities: facts, AsOf: day, Consistency: "current", AuthEpoch: strconv.FormatInt(current.AuthEpoch, 10)}
		if len(items) > filter.Limit {
			page.Items = items[:filter.Limit]
			cursor, err := s.sealCursor(current, filter, day, page.Items[len(page.Items)-1].ID, now)
			if err != nil {
				return err
			}
			page.NextCursor = &cursor
		}
		return tx.GrantAudit(ctx, s.audit(request, current, filter.GrantID, "OP-SEC-06", "allowed"))
	})
	if err != nil {
		return Page{}, s.denied(ctx, request, initial, "OP-SEC-06", err)
	}
	return page, nil
}

var utcTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$`)

func parseTimestamp(text string) (time.Time, bool) {
	if !utcTimestamp.MatchString(text) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, text)
	return t, err == nil && t.Year() >= 1 && t.Nanosecond()%1000 == 0
}

func validFilter(f Filter) bool {
	if f.Limit < 1 || f.Limit > 100 || len(f.Cursor) > 4096 {
		return false
	}
	for _, id := range []string{f.SubjectID, f.ScopeID, f.GrantID, f.ObjectID} {
		if id != "" && !value.ValidID(id) {
			return false
		}
	}
	if (f.ScopeKind == "") != (f.ScopeID == "") || f.ScopeKind != "" && f.ScopeKind != "org" && f.ScopeKind != "employee" && f.ScopeKind != "department" {
		return false
	}
	if f.Category != "" && f.Category != "metadata" && f.Category != "pii" && f.Category != "audit" && f.Category != "financial" && !noteCategory(f.Category) {
		return false
	}
	if f.Purpose != "" && f.Purpose != "organization_management" && f.Purpose != ManagementPurpose && f.Purpose != "interview_followup" && f.Purpose != "compensation_management" {
		return false
	}
	if f.ObjectKind != "" && f.ObjectKind != "interview" && f.ObjectKind != "note_head" && f.ObjectKind != "note_version" && f.ObjectKind != "action_item" && !financialObjectKind(f.ObjectKind) || f.ObjectID != "" && f.ObjectKind == "" {
		return false
	}
	if f.Capability != "" && f.Capability != "organization.read" && f.Capability != "organization.write" && f.Capability != "pii.read" && f.Capability != "pii.write" && f.Capability != "access_grant.manage" && f.Capability != "audit.read" && f.Capability != "interview.read" && f.Capability != "interview.write" && f.Capability != "interview_policy.manage" && f.Capability != "note.read" && f.Capability != "note.write" && f.Capability != "note.publish" && f.Capability != "action.read" && f.Capability != "action.write" && f.Capability != "sensitive.export" && f.Capability != "compensation.read" && f.Capability != "compensation.propose" && f.Capability != "compensation.approve" && f.Capability != "bonus.target.manage" && f.Capability != "bonus.propose" && f.Capability != "bonus.approve" && f.Capability != "bonus.payment.record" && f.Capability != "compensation.extension.manage" {
		return false
	}
	return f.State == "" || f.State == "current" || f.State == "future" || f.State == "expired" || f.State == "revoked"
}

func grantStatus(g GrantDTO, now time.Time) string {
	if g.Status == "revoked" {
		return "revoked"
	}
	if now.Before(g.ValidFrom) {
		return "future"
	}
	if !now.Before(g.ExpiresAt) {
		return "expired"
	}
	return "current"
}

func validRelation(bound bool, ref *RelationReference, scope Scope) bool {
	if !bound {
		return ref == nil
	}
	return ref != nil && value.ValidID(ref.ID) && (ref.Kind == "reporting_line" && scope.Kind == "employee" || ref.Kind == "job_assignment" && scope.Kind == "department")
}

func (s *Service) covered(ctx context.Context, r Reader, grant GrantDTO, authorities []Authority, org, authorityID string) (bool, error) {
	for _, a := range authorities {
		if authorityID != "" && a.ID != authorityID || a.Capability != grant.Capability || a.Category != grant.Category || a.Purpose != grant.Purpose {
			continue
		}
		ok, err := r.ScopeCovered(ctx, org, a.Scope, grant.Scope, s.clock())
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func (s *Service) Issue(ctx context.Context, request Request, command IssueCommand) (Result, error) {
	initial, err := s.session(ctx, s.Store, request)
	if err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-02", err)
	}
	expected, valid := value.Revision(command.ExpectedRevision)
	from, validFrom := parseTimestamp(command.ValidFrom)
	to, validTo := parseTimestamp(command.ExpiresAt)
	if !valid || !validFrom || !validTo || !to.After(from) || !value.ValidID(request.Key) || !value.ValidID(command.SubjectID) || !value.ValidID(command.AuthorityID) || !value.ValidID(command.Scope.ID) || (command.Scope.Kind != "org" && command.Scope.Kind != "employee" && command.Scope.Kind != "department") || !validRelation(command.RelationBound, command.RelationRef, command.Scope) || !normalizeObjectCommand(&command) || !SupportedPair(command.Capability, command.Category, command.Purpose) || command.Capability == "access_grant.manage" {
		return Result{}, fault.Invalid
	}
	command.ValidFrom, command.ExpiresAt = from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano)
	var result Result
	err = s.Store.WithGrantTx(ctx, initial.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID, command.SubjectID}); err != nil {
			return err
		}
		current, facts, coverage, err := s.authorization(ctx, tx, request)
		if err != nil {
			return err
		}
		if command.SubjectID == current.SubjectID {
			return fault.Forbidden
		}
		g := GrantDTO{OrgID: current.OrgID, SubjectID: command.SubjectID, Capability: command.Capability, Category: command.Category, Scope: command.Scope, Purpose: command.Purpose, ValidFrom: from, ExpiresAt: to, MFARequired: command.MFARequired, RelationBound: command.RelationBound, RelationRef: command.RelationRef, ObjectRef: command.ObjectRef, ApprovedSourceRefs: command.ApprovedSourceRefs, Revision: "1"}
		covered, err := s.covered(ctx, tx, g, coverage, current.OrgID, command.AuthorityID)
		if err != nil {
			return err
		}
		if !covered {
			return fault.Forbidden
		}
		var authority Authority
		for _, a := range facts {
			if a.ID == command.AuthorityID {
				authority = a.Authority
				break
			}
		}
		if from.Before(authority.ValidFrom) || to.After(authority.ExpiresAt) || authority.MFARequired && !command.MFARequired {
			return fault.Forbidden
		}
		owned, err := tx.OwnsScope(ctx, current.OrgID, command.Scope, s.clock())
		if err != nil {
			return err
		}
		if !owned {
			return fault.Forbidden
		}
		if err := tx.LockScope(ctx, current.OrgID, command.Scope); err != nil {
			return err
		}
		if err := s.approveObjects(ctx, tx, current, &g); err != nil {
			return err
		}
		digest, err := s.digest(request, current, "OP-SEC-02", "", command)
		if err != nil {
			return err
		}
		if previous, found, err := tx.GrantReceipt(ctx, current.OrgID, current.SubjectID, "OP-SEC-02", request.Key); err != nil {
			return err
		} else if found {
			if subtle.ConstantTimeCompare(previous.Digest, digest) != 1 {
				return fault.Mismatch
			}
			result = previous.Result
			return tx.GrantAudit(ctx, s.audit(request, current, result.ID, "OP-SEC-02", "allowed"))
		}
		qualified, err := tx.Qualified(ctx, current.OrgID, command.SubjectID, command.Capability, command.Scope, s.clock())
		if err != nil {
			return err
		}
		if !qualified {
			return fault.Forbidden
		}
		if command.RelationBound {
			qualified, err := tx.RelationQualified(ctx, current.OrgID, command.SubjectID, command.Scope, *command.RelationRef, s.clock())
			if err != nil {
				return err
			}
			if !qualified {
				return fault.Forbidden
			}
		}
		if current.AuthEpoch != expected {
			return fault.Conflict
		}
		if current.AuthEpoch == math.MaxInt64 {
			return fault.Unavailable
		}
		g.ID = value.NewID()
		now := s.clock()
		g.AuthorityID, g.IssuedBy, g.IssuedAt = &authority.ID, &current.SubjectID, &now
		g.Status = grantStatus(g, now)
		if err := tx.InsertGrant(ctx, g); err != nil {
			return err
		}
		epoch, err := tx.BumpEpoch(ctx, current.OrgID, expected)
		if err != nil {
			return err
		}
		result = Result{ID: g.ID, Revision: "1", Status: g.Status, AuthEpoch: strconv.FormatInt(epoch, 10)}
		if err := tx.SaveGrantReceipt(ctx, current.OrgID, current.SubjectID, "OP-SEC-02", request.Key, Receipt{digest, result}); err != nil {
			return err
		}
		return tx.GrantAudit(ctx, s.audit(request, current, result.ID, "OP-SEC-02", "allowed"))
	})
	if err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-02", err)
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, request Request, id string, command RevokeCommand) (Result, error) {
	initial, err := s.session(ctx, s.Store, request)
	if err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-03", err)
	}
	revision, validRevision := value.Revision(command.ExpectedRevision)
	epoch, validEpoch := value.Revision(command.ExpectedAuthEpoch)
	if !validRevision || !validEpoch || !value.ValidID(id) || !value.ValidID(request.Key) || (command.Reason != "access_no_longer_required" && command.Reason != "policy_change" && command.Reason != "incorrect_grant") {
		return Result{}, fault.Invalid
	}
	if _, _, _, err := s.authorization(ctx, s.Store, request); err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-03", err)
	}
	planned, err := s.Store.Grant(ctx, initial.OrgID, id)
	if err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-03", err)
	}
	var result Result
	err = s.Store.WithGrantTx(ctx, initial.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID, planned.SubjectID}); err != nil {
			return err
		}
		current, _, coverage, err := s.authorization(ctx, tx, request)
		if err != nil {
			return err
		}
		if err := tx.LockScope(ctx, current.OrgID, planned.Scope); err != nil {
			return err
		}
		grant, err := tx.Grant(ctx, current.OrgID, id)
		if err != nil {
			return err
		}
		covered, err := s.covered(ctx, tx, grant, coverage, current.OrgID, "")
		if err != nil {
			return err
		}
		if !covered {
			return fault.NotFound
		}
		if grant.SubjectID != planned.SubjectID {
			return fault.Conflict
		}
		digest, err := s.digest(request, current, "OP-SEC-03", id, command)
		if err != nil {
			return err
		}
		if previous, found, err := tx.GrantReceipt(ctx, current.OrgID, current.SubjectID, "OP-SEC-03", request.Key); err != nil {
			return err
		} else if found {
			if subtle.ConstantTimeCompare(previous.Digest, digest) != 1 {
				return fault.Mismatch
			}
			result = previous.Result
			return tx.GrantAudit(ctx, s.audit(request, current, id, "OP-SEC-03", "allowed"))
		}
		actualRevision, valid := value.Revision(grant.Revision)
		if !valid {
			return fault.Unavailable
		}
		if grant.Status == "revoked" || actualRevision != revision || current.AuthEpoch != epoch {
			return fault.Conflict
		}
		if epoch == math.MaxInt64 || revision == math.MaxInt64 {
			return fault.Unavailable
		}
		if err := tx.RevokeGrant(ctx, current.OrgID, id, revision, current.SubjectID, s.clock(), command.Reason); err != nil {
			return err
		}
		next, err := tx.BumpEpoch(ctx, current.OrgID, epoch)
		if err != nil {
			return err
		}
		result = Result{ID: id, Revision: strconv.FormatInt(revision+1, 10), Status: "revoked", AuthEpoch: strconv.FormatInt(next, 10)}
		if err := tx.SaveGrantReceipt(ctx, current.OrgID, current.SubjectID, "OP-SEC-03", request.Key, Receipt{digest, result}); err != nil {
			return err
		}
		return tx.GrantAudit(ctx, s.audit(request, current, id, "OP-SEC-03", "allowed"))
	})
	if err != nil {
		return Result{}, s.denied(ctx, request, initial, "OP-SEC-03", err)
	}
	return result, nil
}

func (s *Service) digest(request Request, current Snapshot, operation, object string, command any) ([]byte, error) {
	if len(s.DigestKey) != 32 {
		return nil, fault.Unavailable
	}
	body, err := json.Marshal(command)
	if err != nil {
		return nil, fault.Invalid
	}
	defer clear(body)
	mac := hmac.New(sha256.New, s.DigestKey)
	mac.Write([]byte("TEAMLEDGER-GRANT-COMMAND\x00V1\x00"))
	var size [4]byte
	for _, field := range []string{current.OrgID, current.SubjectID, request.Purpose, operation, object} {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		mac.Write(size[:])
		mac.Write([]byte(field))
	}
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	mac.Write(size[:])
	mac.Write(body)
	return mac.Sum(nil), nil
}

func (s *Service) audit(request Request, current Snapshot, grantID, operation, outcome string) Audit {
	purpose := request.Purpose
	if purpose != ManagementPurpose {
		purpose = ""
	}
	return Audit{ID: value.NewID(), OrgID: current.OrgID, SubjectID: current.SubjectID, GrantID: grantID, Operation: operation, Purpose: purpose, RequestID: request.RequestID, Outcome: outcome, At: s.clock()}
}

func (s *Service) denied(ctx context.Context, request Request, current Snapshot, operation string, err error) error {
	if err != nil && s.Store != nil && (errors.Is(err, fault.NotFound) || errors.Is(err, fault.Forbidden) || errors.Is(err, fault.Unauthenticated)) {
		if s.Store.GrantAuditDenied(ctx, s.audit(request, current, "", operation, "denied")) != nil {
			id := request.RequestID
			if !value.ValidID(id) {
				id = ""
			}
			log.Printf("DENIED_AUDIT_UNAVAILABLE request_id=%s operation=%s", id, operation)
		}
	}
	return err
}
