import { uuid, validDate, validRevision, timestamp } from './interviewDTO'
export { uuid, validDate, validRevision, timestamp }
export const financialCapabilities = ['compensation.read', 'compensation.propose', 'compensation.approve', 'sensitive.export'] as const
export type Permission = { capability: string; category: string }
export type Component = { code: string; unit: string; payment_frequency: string; tax_basis: string; amount_minor: string | null; rate: string | null }
export type Terms = { currency: string; scale: number; amount_minor: string | null; rate: string | null; unit: string; payment_frequency: string; tax_basis: string; components: Component[] }
export type BeforeRef = { term_id: string | null; member_key: string | null }
export type CorrectionMember = { member_key: string; action: 'replace' | 'reverse'; original_event_id: string; effective_date: string; before_ref: BeforeRef | null; after: Terms | null }
export type ProposalCommand = { kind: 'initial' | 'adjustment' | 'correction'; effective_date: string; comp_revision: string; before_term_id: string | null; after: Terms | null; reason: string; members: CorrectionMember[] }
export type DraftCommand = ProposalCommand & { revision: string }
export type TransitionCommand = { action: 'submit' | 'withdraw' | 'approve' | 'reject'; revision: string; comp_revision: string; decision_reason: string }
export type TermView = { id: string; revision: string; employee_id: string; effective_date: string; valid_to: string | null; event_id: string; terms: Terms }
export type ProposalRevision = { revision: string; status: string; recorded_at: string; command: ProposalCommand; decision_reason: string }
export type ProposalView = ProposalCommand & { id: string; employee_id: string; status: string; revision: string; author_subject_id: string; recorded_at: string; decision_reason: string; approval_id: string | null; permissions: Permission[] }
export type CurrentView = { employee_id: string; as_of: string; comp_revision: string; authorization_until: string; current_term: TermView | null; future_terms: TermView[]; permissions: Permission[] }
export type ApprovalEvent = { id: string; revision: string; kind: string; effective_date: string; before_term_id: string | null; after_term_id: string | null; corrects_event_id: string | null; before: TermView | null; after: TermView | null; member_key: string }
export type MemberMapping = { member_key: string; event_id: string; term_id: string | null }
export type ApprovalView = { id: string; employee_id: string; proposal_id: string; proposal_revision: string; comp_revision: string; approver_subject_id: string; approved_at: string; decision_reason: string; reason: string; events: ApprovalEvent[]; members: MemberMapping[] }
export type ChangesView = { record_kind: 'proposals' | 'approvals' | 'proposal_revisions'; comp_revision: string; proposals: ProposalView[]; approvals: ApprovalView[]; revisions: ProposalRevision[]; next_cursor: string; authorization_until: string }
export type Result = { id: string; revision: string; comp_revision: string; status: string; proposal: ProposalView | null; members: MemberMapping[] }
export type ExportObject = { kind: 'compensation_proposal' | 'compensation_event' | 'compensation_term'; id: string; expected_revision: string }
export type Session = { subject_id: string; org_id: string; auth_epoch: string; csrf_token: string; mfa_recent: boolean; mfa_valid_until: string; sensitivity_valid_until?: string; compensation_permissions?: Permission[] }
export const memberKey = /^[a-z0-9_]{1,32}$/
export const statuses = ['draft', 'submitted', 'approved', 'rejected', 'withdrawn']
const bytes = (s: string) => new TextEncoder().encode(s).length
export function validMoney(value: unknown): value is string { return typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 19 && BigInt(value) <= 9223372036854775807n }
export function validRate(value: unknown): value is string { return typeof value === 'string' && /^(0|[1-9][0-9]{0,17})(\.[0-9]{0,8}[1-9])?$/.test(value) }
export function validCompRevision(value: unknown): value is string { return value === '0' || validRevision(value) }
function nullableID(id: unknown): boolean { return id === null || typeof id === 'string' && uuid.test(id) }
function text(value: unknown, max: number): value is string { return typeof value === 'string' && bytes(value) <= max }
function measure(value: Component): boolean { return Boolean(value && text(value.unit, 64) && value.unit && text(value.payment_frequency, 64) && value.payment_frequency && ['gross', 'net', 'not_applicable'].includes(value.tax_basis) && (value.amount_minor === null ? validRate(value.rate) : value.rate === null && validMoney(value.amount_minor))) }
export function validTerms(value: Terms): boolean {
  return Boolean(value && /^[A-Z]{3}$/.test(value.currency) && Number.isInteger(value.scale) && value.scale >= 0 && value.scale <= 9 && measure(value as Terms & Component) && Array.isArray(value.components) && value.components.length <= 20 && value.components.every(c => c && text(c.code, 64) && c.code && measure(c)) && new Set(value.components.map(c => c.code)).size === value.components.length)
}
export function validMember(m: CorrectionMember): boolean {
  return Boolean(m && memberKey.test(m.member_key) && uuid.test(m.original_event_id) && validDate(m.effective_date) && (m.action === 'reverse' ? m.after === null && m.before_ref === null : m.action === 'replace' && m.after && validTerms(m.after) && (m.before_ref === null || m.before_ref && (m.before_ref.term_id === null ? typeof m.before_ref.member_key === 'string' && memberKey.test(m.before_ref.member_key) : m.before_ref.member_key === null && uuid.test(m.before_ref.term_id)))))
}
export function validCommand(p: ProposalCommand): boolean {
  return Boolean(p && ['initial', 'adjustment', 'correction'].includes(p.kind) && validDate(p.effective_date) && validCompRevision(p.comp_revision) && nullableID(p.before_term_id) && text(p.reason, 4096) && p.reason.trim() && Array.isArray(p.members) && p.members.length <= 100 && (p.kind === 'correction' ? p.before_term_id === null && p.after === null && p.members.length > 0 && p.members.every(validMember) && new Set(p.members.map(m => m.member_key)).size === p.members.length && new Set(p.members.map(m => m.original_event_id)).size === p.members.length && p.members.every(m => !m.before_ref?.member_key || p.members.some(other => other.member_key === m.before_ref!.member_key && other.action === 'replace' && other.member_key !== m.member_key)) : p.members.length === 0 && p.after && validTerms(p.after) && (p.kind === 'initial' ? p.before_term_id === null : typeof p.before_term_id === 'string' && uuid.test(p.before_term_id))))
}
export function validTerm(t: TermView, employee: string): boolean { return Boolean(t && uuid.test(t.id) && validRevision(t.revision) && t.employee_id === employee && uuid.test(t.event_id) && validDate(t.effective_date) && (t.valid_to === null || validDate(t.valid_to) && t.effective_date < t.valid_to) && validTerms(t.terms)) }
export function validProposal(p: ProposalView, employee: string): boolean { return Boolean(p && !('revisions' in p) && validCommand(p) && uuid.test(p.id) && p.employee_id === employee && statuses.includes(p.status) && validRevision(p.revision) && uuid.test(p.author_subject_id) && timestamp(p.recorded_at) && text(p.decision_reason, 4096) && nullableID(p.approval_id) && validPermissions(p.permissions)) }
export function validProposalRevision(r: ProposalRevision): boolean { return Boolean(r && validRevision(r.revision) && statuses.includes(r.status) && timestamp(r.recorded_at) && validCommand(r.command) && text(r.decision_reason, 4096)) }
export function validMapping(m: MemberMapping): boolean { return Boolean(m && memberKey.test(m.member_key) && uuid.test(m.event_id) && nullableID(m.term_id)) }
export function validEvent(e: ApprovalEvent, employee: string): boolean { return Boolean(e && uuid.test(e.id) && validRevision(e.revision) && ['initial', 'adjustment', 'correction_replacement', 'correction_reversal'].includes(e.kind) && validDate(e.effective_date) && nullableID(e.before_term_id) && nullableID(e.after_term_id) && nullableID(e.corrects_event_id) && (e.before === null || validTerm(e.before, employee) && e.before.id === e.before_term_id) && (e.after === null || validTerm(e.after, employee) && e.after.id === e.after_term_id) && typeof e.member_key === 'string' && (!e.member_key || memberKey.test(e.member_key))) }
export function validApproval(a: ApprovalView, employee: string): boolean { return Boolean(a && uuid.test(a.id) && a.employee_id === employee && uuid.test(a.proposal_id) && validRevision(a.proposal_revision) && validCompRevision(a.comp_revision) && uuid.test(a.approver_subject_id) && timestamp(a.approved_at) && text(a.reason, 4096) && text(a.decision_reason, 4096) && Array.isArray(a.events) && a.events.length <= 100 && a.events.every(e => validEvent(e, employee)) && Array.isArray(a.members) && a.members.length <= 100 && a.members.every(validMapping)) }
export function validPermissions(p: Permission[]): boolean { return Array.isArray(p) && p.length <= 4 && p.every(item => item && financialCapabilities.includes(item.capability as typeof financialCapabilities[number]) && item.category === 'financial') }
export function validCurrent(v: CurrentView, employee: string): boolean { return Boolean(v && v.employee_id === employee && validDate(v.as_of) && validCompRevision(v.comp_revision) && timestamp(v.authorization_until) && (v.current_term === null || validTerm(v.current_term, employee) && v.current_term.effective_date <= v.as_of && (v.current_term.valid_to === null || v.as_of < v.current_term.valid_to)) && Array.isArray(v.future_terms) && v.future_terms.length <= 100 && v.future_terms.every(t => validTerm(t, employee) && t.effective_date > v.as_of) && validPermissions(v.permissions) && v.permissions.some(p => p.capability === 'compensation.read')) }
export function validChanges(v: ChangesView, employee: string, kind: string, proposalID = '', limit = 100): boolean {
  if (!v || v.record_kind !== kind || !validCompRevision(v.comp_revision) || !timestamp(v.authorization_until) || typeof v.next_cursor !== 'string' || !Array.isArray(v.proposals) || v.proposals.length > 100 || !Array.isArray(v.approvals) || v.approvals.length > 100 || !Array.isArray(v.revisions) || v.revisions.length > limit || v.revisions.length > 100) return false
  if (kind === 'proposals') return !v.approvals.length && !v.revisions.length && v.proposals.every(p => validProposal(p, employee))
  if (kind === 'approvals') return !v.proposals.length && !v.revisions.length && v.approvals.every(a => validApproval(a, employee))
  if (kind !== 'proposal_revisions' || v.approvals.length || v.proposals.length !== 1) return false
  const head = v.proposals[0]!
  return validProposal(head, employee) && (!proposalID || head.id === proposalID) && v.revisions.every((r, index) => validProposalRevision(r) && BigInt(r.revision) <= BigInt(head.revision) && (index === 0 || BigInt(r.revision) < BigInt(v.revisions[index - 1]!.revision))) && (!v.next_cursor || v.revisions.length > 0)
}
export function validSession(s: Session): boolean { return Boolean(s && uuid.test(s.subject_id) && uuid.test(s.org_id) && validRevision(s.auth_epoch) && typeof s.csrf_token === 'string' && s.csrf_token && typeof s.mfa_recent === 'boolean' && timestamp(s.mfa_valid_until) && (s.sensitivity_valid_until === undefined || timestamp(s.sensitivity_valid_until)) && (s.compensation_permissions === undefined || validPermissions(s.compensation_permissions))) }
export function sameIdentity(a: Session, b: Session): boolean { return a.subject_id === b.subject_id && a.org_id === b.org_id }
export type TermsForm = { currency: string; scale: string; mode: string; amount: string; rate: string; unit: string; frequency: string; tax: string; components: ComponentForm[] }
export type ComponentForm = { code: string; mode: string; amount: string; rate: string; unit: string; frequency: string; tax: string }
export function emptyComponent(): ComponentForm { return { code: '', mode: '', amount: '', rate: '', unit: '', frequency: '', tax: '' } }
export function emptyTerms(): TermsForm { return { currency: '', scale: '', mode: '', amount: '', rate: '', unit: '', frequency: '', tax: '', components: [] } }
export function termsForm(t: Terms): TermsForm { return { currency: t.currency, scale: String(t.scale), mode: t.amount_minor === null ? 'rate' : 'amount', amount: t.amount_minor ?? '', rate: t.rate ?? '', unit: t.unit, frequency: t.payment_frequency, tax: t.tax_basis, components: t.components.map(c => ({ code: c.code, mode: c.amount_minor === null ? 'rate' : 'amount', amount: c.amount_minor ?? '', rate: c.rate ?? '', unit: c.unit, frequency: c.payment_frequency, tax: c.tax_basis })) } }
export function formTerms(f: TermsForm): Terms | null {
  if (!/^[0-9]$/.test(f.scale) || !['amount', 'rate'].includes(f.mode) || f.components.some(c => !['amount', 'rate'].includes(c.mode))) return null
  const t: Terms = { currency: f.currency, scale: Number(f.scale), amount_minor: f.mode === 'amount' ? f.amount : null, rate: f.mode === 'rate' ? f.rate : null, unit: f.unit, payment_frequency: f.frequency, tax_basis: f.tax, components: f.components.map(c => ({ code: c.code, amount_minor: c.mode === 'amount' ? c.amount : null, rate: c.mode === 'rate' ? c.rate : null, unit: c.unit, payment_frequency: c.frequency, tax_basis: c.tax })) }
  return validTerms(t) ? t : null
}
