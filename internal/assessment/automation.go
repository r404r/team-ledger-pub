package assessment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

func (s *Service) automation() (AutomationStore, error) {
	store, ok := s.Store.(AutomationStore)
	if !ok || s.Cipher.Wrapper == nil || len(s.DigestKey) < sha256.Size {
		return nil, fault.Unavailable
	}
	return store, nil
}

func (s *Service) auditAutomationRead(ctx context.Context, q Request, actor authz.Snapshot, employee string) error {
	return s.Store.WithAssessmentTx(ctx, actor.OrgID, func(tx Tx) error {
		return tx.Audit(ctx, s.audit(q, actor, employee, "OP-AI-08", "allowed"))
	})
}
func (s *Service) releaseAssessmentResult(ctx context.Context, q Request, initial authz.Snapshot, result Result) error {
	return s.Store.WithAssessmentTx(ctx, initial.OrgID, func(tx Tx) error {
		if err := tx.LockSubjects(ctx, initial.OrgID, []string{initial.SubjectID}); err != nil {
			return err
		}
		if err := tx.LockInterviewEmployee(ctx, initial.OrgID, result.EmployeeID); err != nil {
			return err
		}
		current, err := s.session(ctx, tx, q, initial.OrgID, result.EmployeeID)
		if err != nil || current.SubjectID != initial.SubjectID || !current.Allows("assessment.read", "metadata", result.EmployeeID, "interview_followup", s.clock()) {
			return fault.NotFound
		}
		if err = tx.AssessmentResultCurrent(ctx, initial.OrgID, result.EmployeeID, result.ID, result.Revision, result.SourceDigest); err != nil {
			return err
		}
		return tx.Audit(ctx, s.audit(q, current, result.EmployeeID, "OP-AI-08", "allowed"))
	})
}

func (s *Service) structuredInput(ctx context.Context, q Request, employee, windowID string) (Window, StructuredInput, []byte, []byte, int64, error) {
	if !value.ValidID(windowID) {
		return Window{}, StructuredInput{}, nil, nil, 0, fault.Invalid
	}
	store, err := s.automation()
	if err != nil {
		return Window{}, StructuredInput{}, nil, nil, 0, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return Window{}, StructuredInput{}, nil, nil, 0, err
	}
	sourceEpoch, err := store.AssessmentSourceEpoch(ctx, a.OrgID, employee)
	if err != nil {
		return Window{}, StructuredInput{}, nil, nil, 0, err
	}
	status, err := s.Status(ctx, q, employee, StatusQuery{WindowID: windowID})
	if err != nil || len(status.Items) != 1 {
		if err == nil {
			err = fault.NotFound
		}
		return Window{}, StructuredInput{}, nil, nil, 0, err
	}
	window, err := s.Store.AssessmentWindow(ctx, a.OrgID, employee, windowID)
	if err != nil {
		return Window{}, StructuredInput{}, nil, nil, 0, err
	}
	input := StructuredInput{Window: status.Items[0].Window, Facts: status.Items[0].Facts, Template: "periodic_structured_v1"}
	raw, err := json.Marshal(input)
	if err != nil {
		return Window{}, StructuredInput{}, nil, nil, 0, fault.Invalid
	}
	source := sha256.Sum256(append([]byte("TEAMLEDGER-ASSESSMENT-SOURCE\x00V1\x00"), raw...))
	input.SourceDigest = hex.EncodeToString(source[:])
	raw, _ = json.Marshal(input)
	mac := hmac.New(sha256.New, s.DigestKey)
	mac.Write([]byte("TEAMLEDGER-ASSESSMENT-GENERATION\x00V1\x00"))
	for _, part := range []string{a.OrgID, employee, windowID, strconv.FormatInt(window.PolicyRevision, 10), a.SubjectID, strconv.FormatInt(a.SubjectEpoch, 10), strconv.FormatInt(a.AuthEpoch, 10), strconv.FormatInt(sourceEpoch, 10), string(raw)} {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	return window, input, mac.Sum(nil), source[:], sourceEpoch, nil
}

func (s *Service) RequestAssessment(ctx context.Context, q Request, employee string, command AssessmentCommand) (InputView, error) {
	store, err := s.automation()
	if err != nil {
		return InputView{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return InputView{}, s.denied(ctx, q, a, "OP-AI-03", err)
	}
	now := s.clock()
	if !a.Allows("assessment.request", "metadata", employee, "interview_followup", now) || !a.Allows("assessment.read", "metadata", employee, "interview_followup", now) {
		return InputView{}, s.denied(ctx, q, a, "OP-AI-03", fault.NotFound)
	}
	window, input, generation, source, sourceEpoch, err := s.structuredInput(ctx, q, employee, command.WindowID)
	if err != nil {
		return InputView{}, err
	}
	if window.Paused {
		return InputView{}, fault.Conflict
	}
	out, err := store.CreateAssessmentInput(ctx, a, q.TokenHash, sourceEpoch, window, input, generation, source, now, s.audit(q, a, employee, "OP-AI-03", "allowed"))
	return out, s.denied(ctx, q, a, "OP-AI-03", err)
}

func (s *Service) ApproveAssessment(ctx context.Context, q Request, employee string, command ApproveCommand) (JobView, error) {
	store, err := s.automation()
	if err != nil {
		return JobView{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return JobView{}, s.denied(ctx, q, a, "OP-AI-04", err)
	}
	now := s.clock()
	if !a.Allows("assessment.input.approve", "metadata", employee, "interview_followup", now) || !a.Allows("assessment.read", "metadata", employee, "interview_followup", now) {
		return JobView{}, s.denied(ctx, q, a, "OP-AI-04", fault.NotFound)
	}
	policy, ok := s.ProviderPolicies[command.ProviderPolicyID]
	if !ok || !policy.Enabled || !s.clock().Before(policy.ExpiresAt) || policy.ID != command.ProviderPolicyID || policy.Audience != command.Audience {
		return JobView{}, fault.Forbidden
	}
	job, err := store.ApproveAssessmentInput(ctx, a, command.InputID, command.ProviderPolicyID, command.Audience, now, s.audit(q, a, employee, "OP-AI-04", "allowed"))
	if err != nil {
		return JobView{}, s.denied(ctx, q, a, "OP-AI-04", err)
	}
	return jobView(job), nil
}

func (s *Service) worker(q WorkerRequest) (WorkerIdentity, error) {
	identity, ok := s.Workers[q.WorkerID]
	if !ok || len(q.CertDigest) != sha256.Size || len(identity.CertDigest) != sha256.Size || !hmac.Equal(q.CertDigest, identity.CertDigest) || !value.ValidID(identity.OrgID) {
		return WorkerIdentity{}, fault.Unauthenticated
	}
	return identity, nil
}

func (s *Service) Claim(ctx context.Context, q WorkerRequest) (Lease, error) {
	store, err := s.automation()
	if err != nil {
		return Lease{}, err
	}
	identity, err := s.worker(q)
	if err != nil {
		return Lease{}, err
	}
	job, token, err := store.ClaimAssessmentJob(ctx, identity.OrgID, q.WorkerID, q.Key, s.DigestKey, s.clock(), 2*time.Minute)
	if err != nil {
		return Lease{}, err
	}
	policy, ok := s.ProviderPolicies[job.ProviderPolicyID]
	if !ok || !policy.Enabled || !s.clock().Before(policy.ExpiresAt) || policy.Audience != job.Audience {
		hash, hashErr := leaseHash(token)
		if hashErr == nil {
			_ = store.FailAssessmentJob(ctx, identity.OrgID, q.WorkerID, job.ID, job.Fence, hash, "provider_rejected", s.clock())
		}
		return Lease{}, fault.Forbidden
	}
	return Lease{JobID: job.ID, EmployeeID: job.EmployeeID, ProviderPolicyID: job.ProviderPolicyID, Audience: job.Audience, Attempt: job.Attempt, Fence: job.Fence, Token: token, ExpiresAt: job.LeaseExpiresAt, DeadlineAt: job.DeadlineAt, Input: job.Input}, nil
}

func leaseHash(token string) ([]byte, error) {
	if len(token) != 64 {
		return nil, fault.Invalid
	}
	h := sha256.Sum256([]byte(token))
	return h[:], nil
}

func (s *Service) Heartbeat(ctx context.Context, q WorkerRequest, job, token string, fence int64) (time.Time, error) {
	store, err := s.automation()
	if err != nil {
		return time.Time{}, err
	}
	identity, err := s.worker(q)
	if err != nil {
		return time.Time{}, err
	}
	hash, err := leaseHash(token)
	if err != nil {
		return time.Time{}, err
	}
	return store.HeartbeatAssessmentJob(ctx, identity.OrgID, q.WorkerID, job, fence, hash, s.clock(), 2*time.Minute)
}

var prohibitedAssessmentTerms = [...]string{"score", "rating", "rank", "performance", "loyal", "psychological", "mental health", "health diagnosis", "salary", "compensation", "terminate", "fire", "评分", "评级", "排名", "绩效", "忠诚", "心理", "健康诊断", "工资", "薪酬", "解雇"}

func prohibitedAssessmentText(text string) bool {
	folded := strings.ToLower(text)
	for _, term := range prohibitedAssessmentTerms {
		if strings.Contains(folded, term) {
			return true
		}
	}
	return false
}

func validDocument(document ResultDocument) bool {
	if document.Summary == "" || len(document.Summary) > 4000 || !utf8.ValidString(document.Summary) || len(document.Claims) == 0 || len(document.Claims) > 20 || len(document.Sources) == 0 || len(document.Sources) > 50 {
		return false
	}
	for _, claim := range document.Claims {
		if claim == "" || len(claim) > 1000 || !utf8.ValidString(claim) {
			return false
		}
	}
	if prohibitedAssessmentText(document.Summary) {
		return false
	}
	for _, claim := range document.Claims {
		if prohibitedAssessmentText(claim) {
			return false
		}
	}
	for _, source := range document.Sources {
		if source.Kind != "followup_window" || !value.ValidID(source.ID) || source.Version == "" || len(source.Version) > 64 {
			return false
		}
	}
	return true
}
func approvedCitations(document, approved ResultDocument) bool {
	allowed := make(map[string]struct{}, len(approved.Sources))
	for _, source := range approved.Sources {
		allowed[source.Kind+"\x00"+source.ID+"\x00"+source.Version] = struct{}{}
	}
	for _, source := range document.Sources {
		if _, ok := allowed[source.Kind+"\x00"+source.ID+"\x00"+source.Version]; !ok {
			return false
		}
	}
	return true
}

func (s *Service) workerReceiptDigest(q WorkerRequest, lease Lease, document ResultDocument) ([]byte, error) {
	if !value.ValidID(q.Key) || len(s.DigestKey) < sha256.Size {
		return nil, fault.Invalid
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fault.Invalid
	}
	mac := hmac.New(sha256.New, s.DigestKey)
	mac.Write([]byte("TEAMLEDGER-ASSESSMENT-WORKER-RESULT\x00V1\x00"))
	for _, part := range []string{q.WorkerID, q.Key, lease.JobID, strconv.FormatInt(lease.Fence, 10), string(raw)} {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	return mac.Sum(nil), nil
}

func (s *Service) Submit(ctx context.Context, q WorkerRequest, lease Lease, document ResultDocument) (ResultView, error) {
	store, err := s.automation()
	if err != nil {
		return ResultView{}, err
	}
	identity, err := s.worker(q)
	if err != nil {
		return ResultView{}, err
	}
	if !validDocument(document) || !value.ValidID(lease.JobID) || !value.ValidID(lease.EmployeeID) {
		return ResultView{}, fault.Invalid
	}
	for _, citation := range document.Sources {
		if citation.ID != lease.Input.Window.ID || citation.Version != lease.Input.Window.PolicyRevision {
			return ResultView{}, fault.Invalid
		}
	}
	hash, err := leaseHash(lease.Token)
	if err != nil {
		return ResultView{}, err
	}
	receiptDigest, err := s.workerReceiptDigest(q, lease, document)
	if err != nil {
		return ResultView{}, err
	}
	if prior, found, receiptErr := store.AssessmentJobResultReceipt(ctx, identity.OrgID, q.WorkerID, q.Key, receiptDigest); receiptErr != nil {
		return ResultView{}, receiptErr
	} else if found {
		prior.Document = document
		return resultView(prior), nil
	}
	result := Result{OrgID: identity.OrgID, EmployeeID: lease.EmployeeID, ID: value.NewID(), JobID: lease.JobID, Status: "draft", Revision: 1, Document: document, CreatedAt: s.clock(), UpdatedAt: s.clock()}
	source, err := hex.DecodeString(lease.Input.SourceDigest)
	if err != nil || len(source) != sha256.Size {
		return ResultView{}, fault.Invalid
	}
	result.SourceDigest = source
	raw, err := json.Marshal(document)
	if err != nil {
		return ResultView{}, fault.Invalid
	}
	binding := sensitive.Context{OrgID: result.OrgID, EmployeeID: result.EmployeeID, RecordID: result.ID, VersionID: value.NewID(), ObjectKind: "assessment_result", Purpose: "interview", SchemaType: "assessment.result.v1", SchemaVersion: 1}
	envelope, err := s.Cipher.Seal(ctx, binding, raw)
	if err != nil {
		return ResultView{}, fault.Unavailable
	}
	result, err = store.CompleteAssessmentJob(ctx, q.WorkerID, q.Key, lease.JobID, lease.Fence, hash, receiptDigest, EncryptedResult{Result: result, Envelope: envelope}, s.clock())
	if err != nil {
		return ResultView{}, err
	}
	return resultView(result), nil
}

func (s *Service) Fail(ctx context.Context, q WorkerRequest, lease Lease, code string) error {
	store, err := s.automation()
	if err != nil {
		return err
	}
	identity, err := s.worker(q)
	if err != nil {
		return err
	}
	hash, err := leaseHash(lease.Token)
	if err != nil {
		return err
	}
	return store.FailAssessmentJob(ctx, identity.OrgID, q.WorkerID, lease.JobID, lease.Fence, hash, code, s.clock())
}

func (s *Service) GetResult(ctx context.Context, q Request, employee, id string) (ResultView, error) {
	store, err := s.automation()
	if err != nil {
		return ResultView{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return ResultView{}, s.denied(ctx, q, a, "OP-AI-08", err)
	}
	if !a.Allows("assessment.read", "metadata", employee, "interview_followup", s.clock()) {
		return ResultView{}, s.denied(ctx, q, a, "OP-AI-08", fault.NotFound)
	}
	result, envelope, err := store.AssessmentResult(ctx, a.OrgID, id)
	if err != nil || result.EmployeeID != employee {
		if err == nil {
			err = fault.NotFound
		}
		return ResultView{}, err
	}
	if result.Status == "invalidated" || result.Status == "discarded" {
		return ResultView{}, fault.NotFound
	}
	raw, err := s.Cipher.Open(ctx, envelope.Context, envelope)
	if err != nil {
		return ResultView{}, fault.Unavailable
	}
	defer clear(raw)
	if json.Unmarshal(raw, &result.Document) != nil || !validDocument(result.Document) {
		return ResultView{}, fault.Unavailable
	}
	if err = s.releaseAssessmentResult(ctx, q, a, result); err != nil {
		return ResultView{}, err
	}
	return resultView(result), nil
}

func (s *Service) TransitionResult(ctx context.Context, q Request, employee string, command ResultCommand) (ResultView, error) {
	store, err := s.automation()
	if err != nil {
		return ResultView{}, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return ResultView{}, s.denied(ctx, q, a, "OP-AI-08", err)
	}
	if command.Action != "edit" && command.Action != "publish" && command.Action != "discard" {
		return ResultView{}, fault.Invalid
	}
	if !a.Allows("assessment.publish", "metadata", employee, "interview_followup", s.clock()) {
		return ResultView{}, s.denied(ctx, q, a, "OP-AI-08", fault.NotFound)
	}
	expected, err := parseRevision(command.ExpectedRevision)
	if err != nil || expected < 1 {
		return ResultView{}, fault.Invalid
	}
	result, oldEnvelope, err := store.AssessmentResult(ctx, a.OrgID, command.ResultID)
	if err != nil || result.EmployeeID != employee {
		return ResultView{}, fault.NotFound
	}
	if result.Status != "draft" {
		return ResultView{}, fault.Conflict
	}
	result.Revision = expected
	envelope := oldEnvelope
	if command.Action == "edit" {
		if !validDocument(command.Document) {
			return ResultView{}, fault.Invalid
		}
		priorRaw, openErr := s.Cipher.Open(ctx, oldEnvelope.Context, oldEnvelope)
		if openErr != nil {
			return ResultView{}, fault.Unavailable
		}
		var prior ResultDocument
		decodeErr := json.Unmarshal(priorRaw, &prior)
		clear(priorRaw)
		if decodeErr != nil || !validDocument(prior) || !approvedCitations(command.Document, prior) {
			return ResultView{}, fault.Invalid
		}
		result.Document = command.Document
		raw, _ := json.Marshal(command.Document)
		binding := oldEnvelope.Context
		binding.VersionID = value.NewID()
		envelope, err = s.Cipher.Seal(ctx, binding, raw)
		if err != nil {
			return ResultView{}, fault.Unavailable
		}
	}
	result, err = store.SaveAssessmentResult(ctx, a, q.TokenHash, result, envelope, command.Action, s.clock(), s.audit(q, a, employee, "OP-AI-08", "allowed"))
	if err != nil {
		return ResultView{}, err
	}
	return resultView(result), nil
}

func (s *Service) Jobs(ctx context.Context, q Request, employee string) ([]JobView, error) {
	store, err := s.automation()
	if err != nil {
		return nil, err
	}
	a, err := s.employee(ctx, q, employee)
	if err != nil {
		return nil, s.denied(ctx, q, a, "OP-AI-08", err)
	}
	if !a.Allows("assessment.read", "metadata", employee, "interview_followup", s.clock()) {
		return nil, fault.NotFound
	}
	jobs, err := store.ListAssessmentJobs(ctx, a.OrgID, employee)
	if err != nil {
		return nil, err
	}
	if err = s.auditAutomationRead(ctx, q, a, employee); err != nil {
		return nil, err
	}
	out := make([]JobView, len(jobs))
	for i := range jobs {
		out[i] = jobView(jobs[i])
	}
	return out, nil
}

func jobView(job Job) JobView {
	return JobView{ID: job.ID, EmployeeID: job.EmployeeID, ResultID: job.ResultID, WindowID: job.WindowID, State: job.State, ProviderPolicyID: job.ProviderPolicyID, Audience: job.Audience, Attempt: job.Attempt, MaxAttempts: job.MaxAttempts, CreatedAt: job.CreatedAt, CompletedAt: job.CompletedAt, ErrorCode: job.ErrorCode}
}
func resultView(result Result) ResultView {
	return ResultView{ID: result.ID, JobID: result.JobID, Status: result.Status, Revision: strconv.FormatInt(result.Revision, 10), Document: result.Document, CreatedAt: result.CreatedAt, UpdatedAt: result.UpdatedAt}
}

func (s *Service) ScanDue(ctx context.Context) (ScanReport, error) {
	store, err := s.automation()
	if err != nil {
		return ScanReport{}, err
	}
	now := s.clock()
	due, err := store.DueAssessmentWindows(ctx, now)
	if err != nil {
		return ScanReport{}, err
	}
	report := ScanReport{Scanned: len(due)}
	for _, scheduled := range due {
		identity, ok := s.ServiceSubjects[scheduled.ServiceSubjectID]
		provider, providerOK := s.ProviderPolicies[scheduled.ProviderPolicyID]
		reason := ""
		switch {
		case scheduled.ServiceSubjectID == "":
			reason = "automation_not_enabled"
		case !now.Before(scheduled.ExpiresAt):
			reason = "policy_expired"
		case !providerOK || !provider.Enabled || !now.Before(provider.ExpiresAt) || provider.Audience != scheduled.Audience:
			reason = "provider_not_approved"
		case !ok || len(identity.TokenHash) != sha256.Size:
			reason = "authorization_unavailable"
		}
		if reason != "" {
			if err = store.RecordAssessmentScan(ctx, scheduled, reason, now); err != nil {
				return report, err
			}
			report.Blocked++
			continue
		}
		request := Request{TokenHash: identity.TokenHash, Purpose: "interview_followup", Key: value.NewID(), RequestID: value.NewID()}
		actor, securityErr := s.Store.Security(ctx, identity.TokenHash, scheduled.OrgID, scheduled.EmployeeID)
		if securityErr != nil || actor.SubjectID != scheduled.ServiceSubjectID || !actor.Allows("assessment.request", "metadata", scheduled.EmployeeID, "interview_followup", now) || !actor.Allows("assessment.read", "metadata", scheduled.EmployeeID, "interview_followup", now) {
			if err = store.RecordAssessmentScan(ctx, scheduled, "authorization_unavailable", now); err != nil {
				return report, err
			}
			report.Blocked++
			continue
		}
		window, input, generation, source, sourceEpoch, buildErr := s.structuredInput(ctx, request, scheduled.EmployeeID, scheduled.ID)
		if buildErr != nil || window.PolicyRevision != scheduled.PolicyRevision {
			if err = store.RecordAssessmentScan(ctx, scheduled, "authorization_unavailable", now); err != nil {
				return report, err
			}
			report.Blocked++
			continue
		}
		created, createErr := store.CreateScheduledAssessment(ctx, actor, identity.TokenHash, sourceEpoch, scheduled, input, generation, source, now)
		if createErr != nil {
			return report, createErr
		}
		if created {
			report.Enqueued++
		}
	}
	return report, nil
}
