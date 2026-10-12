import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CompensationPage from './CompensationPage.vue'
import App from './App.vue'
import IdentityGate from './IdentityGate.vue'
import { validMoney, validRate, validCommand, validChanges, type Terms, type CurrentView, type ChangesView, type ProposalView, type ProposalRevision, type ApprovalView, type Session } from './compensationDTO'
const ORG = '10000000-0000-4000-8000-000000000001', SUBJECT = '10000000-0000-4000-8000-000000000002', EMPLOYEE = '10000000-0000-4000-8000-000000000003', OTHER = '10000000-0000-4000-8000-000000000004', PROPOSAL = '10000000-0000-4000-8000-000000000005', TERM = '10000000-0000-4000-8000-000000000006', EVENT = '10000000-0000-4000-8000-000000000007', APPROVAL = '10000000-0000-4000-8000-000000000008', FUTURE = '10000000-0000-4000-8000-000000000009'
const B = '9007199254740993', R = '9007199254740994', MONEY = '9007199254740993'
const permissions = ['compensation.read', 'compensation.propose', 'compensation.approve', 'sensitive.export'].map(capability => ({ capability, category: 'financial' }))
const terms: Terms = { currency: 'ZZZ', scale: 3, amount_minor: MONEY, rate: null, unit: 'synthetic_month', payment_frequency: 'synthetic_monthly', tax_basis: 'gross', components: [] }
const term = { id: TERM, revision: R, employee_id: EMPLOYEE, effective_date: '2026-01-01', valid_to: null, event_id: EVENT, terms }
const event = { id: EVENT, revision: B, kind: 'initial', effective_date: '2026-01-01', before_term_id: null, after_term_id: TERM, corrects_event_id: null, before: null, after: term, member_key: '' }
const initialSession: Session = { subject_id: SUBJECT, org_id: ORG, auth_epoch: B, csrf_token: 'synthetic-csrf', mfa_recent: true, mfa_valid_until: '2026-10-12T00:00:00Z', sensitivity_valid_until: '2026-10-12T00:00:00Z', compensation_permissions: permissions }
function proposal(status = 'draft'): ProposalView { return { id: PROPOSAL, employee_id: EMPLOYEE, kind: 'initial', status, revision: R, comp_revision: B, author_subject_id: OTHER, recorded_at: '2026-10-01T00:00:00Z', effective_date: '2026-01-01', before_term_id: null, after: terms, reason: 'synthetic immutable reason', members: [], decision_reason: '', approval_id: status === 'approved' ? APPROVAL : null, permissions: permissions.map(p => ({ ...p })) } }
function approval(): ApprovalView { return { id: APPROVAL, employee_id: EMPLOYEE, proposal_id: PROPOSAL, proposal_revision: R, comp_revision: B, approver_subject_id: OTHER, approved_at: '2026-01-01T00:00:00Z', reason: 'synthetic immutable reason', decision_reason: 'synthetic independent decision', events: [event], members: [] } }
function response(status: number, body: unknown) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
type RequestRecord = { url: URL; method: string; body: string | undefined; headers: Headers; signal: AbortSignal | null | undefined }
let session: Session, current: CurrentView, proposals: ChangesView, approvals: ChangesView, requests: RequestRecord[], pages: VueWrapper[], currentStatus: number, sessionStatus: number
let mutationReply: (request: RequestRecord) => Promise<Response>, currentReply: (() => Promise<Response>) | null
let revisionReply: (request: RequestRecord) => Promise<Response>
function revision(head: ProposalView, r: string, status = 'draft'): ProposalRevision {
  const command = { kind: head.kind, effective_date: head.effective_date, comp_revision: head.comp_revision, before_term_id: head.before_term_id, after: head.after, reason: `synthetic original reason ${head.id} R${r}`, members: head.members }
  return { revision: r, status, recorded_at: head.recorded_at, command, decision_reason: status === 'rejected' ? `synthetic rejection R${r}` : '' }
}
function revisionView(head: ProposalView, rows: ProposalRevision[], cursor = ''): ChangesView {
  return { record_kind: 'proposal_revisions', comp_revision: B, proposals: [head], approvals: [], revisions: rows, next_cursor: cursor, authorization_until: initialSession.mfa_valid_until }
}
async function settle() { await flushPromises(); await nextTick() }
function button(page: VueWrapper, text: string) { const found = page.findAll('button').filter(b => b.text() === text); expect(found).toHaveLength(1); return found[0]! }
async function open(app = false) { history.replaceState({}, '', `/employees/${EMPLOYEE}/compensation?as_of=2026-10-11`); const page = mount(app ? App : CompensationPage, { attachTo: document.body }); pages.push(page); await settle(); return page }
async function query(page: VueWrapper) { await page.get('#comp-from').setValue('2026-01-01T00:00:00.000001Z'); await page.get('#comp-to').setValue('2027-01-01T00:00:00Z'); await page.get('[aria-label="薪酬查询条件"]').trigger('submit'); await settle() }
async function fillTerms(page: VueWrapper, prefix = 'comp-after', amount = MONEY) { await page.get(`#${prefix}-currency`).setValue('ZZZ'); await page.get(`#${prefix}-scale`).setValue('3'); await page.get(`#${prefix}-mode`).setValue('amount'); await page.get(`#${prefix}-amount`).setValue(amount); await page.get(`#${prefix}-unit`).setValue('synthetic_month'); await page.get(`#${prefix}-frequency`).setValue('synthetic_monthly'); await page.get(`#${prefix}-tax`).setValue('gross') }
async function draft(page: VueWrapper) { await button(page, '创建明确薪酬提案').trigger('click'); await page.get('#comp-effective').setValue('2026-01-01'); await fillTerms(page); await page.get('#comp-reason').setValue('synthetic explicit proposal'); await page.get('#comp-save-confirm').setValue(true) }
function mutations() { return requests.filter(r => ['POST', 'PATCH'].includes(r.method) && !r.url.pathname.includes('/auth/')) }
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] }); vi.setSystemTime(new Date('2026-10-11T12:00:00Z'))
  session = { ...initialSession, compensation_permissions: permissions.map(p => ({ ...p })) }; current = { employee_id: EMPLOYEE, as_of: '2026-10-11', comp_revision: B, authorization_until: '2026-10-12T00:00:00Z', current_term: term, future_terms: [{ ...term, id: FUTURE, effective_date: '2027-01-01', terms: { ...terms, amount_minor: '120' } }], permissions: permissions.map(p => ({ ...p })) }
  proposals = { record_kind: 'proposals', comp_revision: B, proposals: [proposal()], approvals: [], revisions: [], next_cursor: '', authorization_until: '2026-10-12T00:00:00Z' }
  approvals = { record_kind: 'approvals', comp_revision: B, proposals: [], approvals: [approval()], revisions: [], next_cursor: '', authorization_until: '2026-10-12T00:00:00Z' }
  requests = []; pages = []; currentStatus = 200; sessionStatus = 200; currentReply = null
  revisionReply = async request => {
    const head = proposals.proposals.find(p => p.id === request.url.searchParams.get('proposal_id'))!
    return response(200, revisionView(head, [revision(head, head.revision)]))
  }
  mutationReply = async request => {
    const states: Record<string, string> = { submit: 'submitted', withdraw: 'withdrawn', approve: 'approved', reject: 'rejected' }
    return response(200, { id: PROPOSAL, revision: R, comp_revision: B, status: states[JSON.parse(request.body!).action] ?? 'draft', proposal: null, members: [] })
  }
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const request: RequestRecord = { url: new URL(String(input), location.href), method: init?.method ?? 'GET', body: init?.body as string | undefined, headers: new Headers(init?.headers), signal: init?.signal }; requests.push(request)
    if (request.url.pathname === '/api/v1/session') return response(sessionStatus, session)
    if (request.method !== 'GET') return mutationReply(request)
    if (request.url.pathname.endsWith('/compensation/changes')) {
      if (request.url.searchParams.get('record_kind') === 'proposal_revisions') return revisionReply(request)
      return response(200, request.url.searchParams.get('record_kind') === 'proposals' ? proposals : approvals)
    }
    if (request.url.pathname.endsWith('/compensation')) { if (currentReply) { const reply = currentReply; currentReply = null; return reply() } return response(currentStatus, current) }
    throw new Error('Unexpected synthetic HTTP request')
  })
})
afterEach(() => { pages.forEach(page => page.unmount()); document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers() })
describe('P-COMP-01 financial consumer boundaries', () => {
  it('uses exact UTC recorded-at history window and never sends proposal status to approvals', async () => {
    const page = await open(); await page.get('#comp-status').setValue('submitted'); await query(page)
    const history = requests.filter(r => r.url.pathname.endsWith('/changes'))
    expect(history).toHaveLength(2); expect(history[0]!.url.searchParams.get('from')).toBe('2026-01-01T00:00:00.000001Z')
    expect(history.find(r => r.url.searchParams.get('record_kind') === 'approvals')!.url.searchParams.has('status')).toBe(false)
    expect(history.find(r => r.url.searchParams.get('record_kind') === 'proposals')!.url.searchParams.get('status')).toBe('submitted')
  })
  it('keeps independent read/propose/approve/export capabilities separate from role or session authentication', async () => {
    session.compensation_permissions = [{ capability: 'compensation.read', category: 'financial' }]; current.permissions = session.compensation_permissions
    proposals.proposals[0]!.permissions = session.compensation_permissions
    const page = await open(); await query(page)
    expect(page.find('[aria-label="明确财务对象导出"]').exists()).toBe(false); expect(page.find('[aria-label="完整薪酬提案编辑"]').exists()).toBe(false)
    expect(page.findAll('button').some(b => /创建明确|独立审阅|编辑草稿/.test(b.text()))).toBe(false)
    expect(page.get('[data-approval]').find('button').exists()).toBe(false)
  })
  for (const amount of ['9223372036854775808', '01', '1e3', '-1', '1.2']) it(`rejects noncanonical/out-of-int64 amount ${amount} without HTTP mutation`, async () => {
    const page = await open(); await draft(page); await page.get('#comp-after-amount').setValue(amount); await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle(); expect(mutations()).toHaveLength(0)
  })
  it('edits only draft using its original revision string; submitted and approved payloads have no patch action', async () => {
    const page = await open(); await query(page); await page.get(`[aria-label="编辑草稿 ${PROPOSAL}"]`).trigger('click'); await page.get('#comp-reason').setValue('synthetic revised reason'); await page.get('#comp-save-confirm').setValue(true)
    await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(mutations()[0]!.method).toBe('PATCH'); expect(JSON.parse(mutations()[0]!.body!).revision).toBe(R)
    proposals.proposals = [proposal('submitted')]; await button(page, '手动刷新当前授权与事实（清空草稿）').trigger('click'); await settle(); expect(page.find(`[aria-label="编辑草稿 ${PROPOSAL}"]`).exists()).toBe(false)
    proposals.proposals = [proposal('approved')]; await button(page, '手动刷新当前授权与事实（清空草稿）').trigger('click'); await settle(); expect(page.find(`[aria-label="编辑草稿 ${PROPOSAL}"]`).exists()).toBe(false)
  })
  for (const action of ['submit', 'withdraw', 'approve', 'reject'] as const) it(`requires explicit independent ${action} confirmation and preserves R/B`, async () => {
    proposals.proposals = [proposal(action === 'submit' ? 'draft' : 'submitted')]; const page = await open(); await query(page)
    const label = action === 'submit' ? '提交' : action === 'withdraw' ? '撤回' : action === 'approve' ? '批准' : '拒绝'
    await page.get(`[aria-label="${label}提案 ${PROPOSAL}"]`).trigger('click'); expect(mutations()).toHaveLength(0)
    if (action !== 'submit') await page.get('#comp-decision-reason').setValue('synthetic reviewed decision')
    await page.get('#comp-decision-confirm').setValue(true); await page.get('[aria-label="独立提案状态确认"]').trigger('submit'); await settle()
    expect(JSON.parse(mutations()[0]!.body!)).toEqual({ action, revision: R, comp_revision: B, decision_reason: action === 'submit' ? '' : 'synthetic reviewed decision' })
  })
  it('does not offer self approval even when proposer also holds independent approval capability', async () => {
    proposals.proposals = [{ ...proposal('submitted'), author_subject_id: SUBJECT }]; const page = await open(); await query(page)
    expect(page.get(`[aria-label="批准提案 ${PROPOSAL}"]`).attributes('disabled')).toBeDefined(); expect(mutations()).toHaveLength(0)
  })
  it('real 409 discards sensitive editor/confirmation and requires manual refresh without rebase or automatic retry', async () => {
    const page = await open(); await draft(page); mutationReply = async () => response(409, { code: 'DEPENDENCY_INCOMPLETE' }); await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(mutations()).toHaveLength(1); expect(page.find('[aria-label="完整薪酬提案编辑"]').exists()).toBe(false); expect(page.find('[data-approval]').exists()).toBe(false)
    expect(page.find('[aria-label="财务命令结果尚未确认"]').exists()).toBe(false); expect(page.text()).toContain('409')
  })
  it('confirms a lost committed mutation only after explicit same-key same-body confirmation, despite new auth epoch and basis', async () => {
    const page = await open(); await draft(page); mutationReply = async () => { throw new TypeError('Synthetic lost committed reply') }
    await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle(); expect(page.find('[aria-label="财务命令结果尚未确认"]').exists()).toBe(true); expect(page.text()).not.toContain('synthetic immutable reason')
    await button(page, '确认原命令结果').trigger('click'); await settle(); expect(mutations()).toHaveLength(1)
    session.auth_epoch = '9007199254740995'; current.comp_revision = '9007199254740996'; mutationReply = async () => response(200, { id: PROPOSAL, revision: R, comp_revision: B, status: 'draft', proposal: null, members: [] })
    await page.get('#comp-replay-confirm').setValue(true); await button(page, '确认原命令结果').trigger('click'); await settle()
    expect(mutations()).toHaveLength(2); expect(mutations()[1]!.body).toBe(mutations()[0]!.body); expect(mutations()[1]!.headers.get('Idempotency-Key')).toBe(mutations()[0]!.headers.get('Idempotency-Key')); expect(JSON.parse(mutations()[1]!.body!).comp_revision).toBe(B)
  })
  it('never resends uncertain bytes after current purpose/scope grants are revoked', async () => {
    const page = await open(); await draft(page); mutationReply = async () => { throw new TypeError('Lost reply') }; await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    session.compensation_permissions = []; current.permissions = []
    await page.get('#comp-replay-confirm').setValue(true); await button(page, '确认原命令结果').trigger('click'); await settle(); expect(mutations()).toHaveLength(1); expect(page.find('[aria-label="财务命令结果尚未确认"]').exists()).toBe(false)
  })
  for (const status of [401, 403]) it(`clears every pane, editor, output and pending command on ${status}`, async () => {
    const page = await open(); await query(page); await draft(page); mutationReply = async () => response(status, { code: 'DENIED' }); await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(page.text()).not.toContain(MONEY); expect(page.find('#comp-reason').exists()).toBe(false); expect(page.find('[data-approval]').exists()).toBe(false)
    if (status === 401) expect(page.emitted('session-expired')).toHaveLength(1)
  })
  it('keeps exact authorized immutable event history when aggregate current is 404 and does not imply full aggregate access', async () => {
    currentStatus = 404; session.compensation_permissions = [permissions[0]!, permissions[3]!]; proposals.proposals = []
    const page = await open(); await query(page)
    expect(page.get('[aria-label="指定日现状"]').text()).toContain('未获授权'); expect(page.get(`[data-event="${EVENT}"]`).text()).toContain(MONEY)
    expect(page.findAll('button').some(b => b.text() === '创建明确薪酬提案')).toBe(false)
  })
  it('rejects mismatched financial exported revisions without claiming complete or retaining plaintext', async () => {
    const page = await open(); const exportID = OTHER
    mutationReply = async () => new Response([{ kind: 'header', export_id: exportID, status: 'prepared' }, { kind: 'object', export_id: exportID, status: 'prepared', compensation_term: { ...term, revision: '1' } }, { kind: 'complete', export_id: exportID, status: 'complete' }].map(e => JSON.stringify(e)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get(`[value="compensation_term:${TERM}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(page.find('[aria-label="当前内存财务 NDJSON 输出"]').exists()).toBe(false); expect(page.text()).not.toContain('导出完成')
  })
  it('partial financial stream clears received plaintext and never presents it as complete export', async () => {
    const page = await open(); const exportID = OTHER
    mutationReply = async () => new Response([{ kind: 'header', export_id: exportID, status: 'prepared' }, { kind: 'object', export_id: exportID, status: 'prepared', compensation_term: term }, { kind: 'partial', export_id: exportID, status: 'partial', reason: 'RELEASE_DENIED' }].map(e => JSON.stringify(e)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get(`[value="compensation_term:${TERM}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(page.find('[aria-label="当前内存财务 NDJSON 输出"]').exists()).toBe(false); expect(page.text()).not.toContain(MONEY); expect(page.text()).not.toContain('导出完成')
  })
  it('discards ignored-abort late mutation response after employee route departure', async () => {
    const page = await open(); await draft(page); let resolve!: (value: Response) => void; mutationReply = () => new Promise(yes => { resolve = yes })
    await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle(); const command = mutations()[0]!
    history.pushState({}, '', `/employees/${OTHER}/compensation`); window.dispatchEvent(new PopStateEvent('popstate')); await settle(); expect(command.signal?.aborted).toBe(true)
    resolve(response(200, { id: PROPOSAL, revision: R, comp_revision: B, status: 'draft', proposal: null, members: [] })); await settle()
    expect(page.text()).not.toContain('synthetic explicit proposal'); expect(page.text()).not.toContain('服务器已确认')
  })
  it('expiration invalidates in-flight generations and destroys forms and old financial bytes', async () => {
    const page = await open(); await draft(page); let resolve!: (value: Response) => void; mutationReply = () => new Promise(yes => { resolve = yes })
    await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle(); vi.setSystemTime(new Date('2026-10-12T00:00:00Z')); await vi.advanceTimersByTimeAsync(250)
    expect(mutations()[0]!.signal?.aborted).toBe(true); resolve(response(200, { id: PROPOSAL, revision: R, comp_revision: B, status: 'draft', proposal: null, members: [] })); await settle()
    expect(page.text()).not.toContain(MONEY); expect(page.text()).not.toContain('服务器已确认'); expect(page.find('#comp-reason').exists()).toBe(false)
  })
  it('financial MFA step-up selects finite intent and safe return route, destroys workbench and never automatically mutates', async () => {
    const page = await open(true); await query(page); await draft(page)
    await page.get('#compensation-stepup-intent').setValue('compensation.approve')
    mutationReply = async () => response(503, { code: 'UNAVAILABLE' })
    await button(page, '重新验证财务 MFA').trigger('click'); await settle()
    const request = requests.find(r => r.url.pathname === '/api/v1/auth/step-up')!
    expect(JSON.parse(request.body!)).toEqual({ action: 'compensation.approve', return_to: `/employees/${EMPLOYEE}/compensation?as_of=2026-10-11` })
    expect(page.findComponent(CompensationPage).exists()).toBe(false); expect(mutations()).toHaveLength(0); expect(page.findComponent(IdentityGate).exists()).toBe(true)
  })
})
describe('strict financial value protocol', () => {
  it('requires canonical int64 money and canonical exact nonnegative decimals without floating conversion', () => {
    expect(validMoney(MONEY)).toBe(true); expect(validMoney('9223372036854775807')).toBe(true); expect(validMoney('9223372036854775808')).toBe(false); expect(validMoney(100)).toBe(false)
    for (const rate of ['0', '0.125', '999999999999999999.123456789']) expect(validRate(rate)).toBe(true)
    for (const rate of ['0.0', '1.20', '1e2', '+1', '-1', '01', '1.1234567891', '1000000000000000000']) expect(validRate(rate)).toBe(false)
  })
  it('rejects duplicate correction originals, nonexistent/self local dependencies and ambiguous before refs', () => {
    const base = proposal(); const m = { member_key: 'first', action: 'replace' as const, original_event_id: EVENT, effective_date: '2026-01-01', before_ref: null, after: terms }
    expect(validCommand({ ...base, kind: 'correction', after: null, members: [m, { ...m, member_key: 'other' }] })).toBe(false)
    expect(validCommand({ ...base, kind: 'correction', after: null, members: [{ ...m, before_ref: { term_id: TERM, member_key: 'first' } }] })).toBe(false)
    expect(validCommand({ ...base, kind: 'correction', after: null, members: [{ ...m, before_ref: { term_id: null, member_key: 'missing' } }] })).toBe(false)
  })
})

describe('R4 exact scope, zero basis and current release regressions', () => {
  it('preserves unestablished aggregate B0 through create and confirmed result without treating it as zero salary', async () => {
    current.comp_revision = '0'; current.current_term = null; current.future_terms = []
    mutationReply = async () => response(201, { id: PROPOSAL, revision: '1', comp_revision: '0', status: 'draft', proposal: null, members: [] })
    const page = await open(); await draft(page); await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(JSON.parse(mutations()[0]!.body!).comp_revision).toBe('0')
    expect(page.get('[aria-label="指定日现状"]').text()).toContain('未建立有效条款')
    expect(page.find('[aria-label="财务命令结果尚未确认"]').exists()).toBe(false)
  })
  it('allows only exact proposal propose hints without aggregate read, approval or export', async () => {
    currentStatus = 404; session.compensation_permissions = []
    proposals.proposals[0]!.permissions = permissions.filter(p => ['compensation.read', 'compensation.propose'].includes(p.capability))
    const page = await open(); await query(page)
    expect(page.findAll('button').some(b => b.text() === '创建明确薪酬提案')).toBe(false)
    await page.get(`[aria-label="编辑草稿 ${PROPOSAL}"]`).trigger('click')
    await page.get('#comp-save-confirm').setValue(true); await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(mutations()[0]!.method).toBe('PATCH')
    expect(JSON.parse(mutations()[0]!.body!)).toMatchObject({ revision: R, comp_revision: B })
    expect(page.find(`[aria-label="批准提案 ${PROPOSAL}"]`).exists()).toBe(false)
  })
  it('uses exact proposal approval hints and Changes current B rather than frozen proposal basis or session broad hints', async () => {
    currentStatus = 404; session.compensation_permissions = []
    proposals.proposals = [{ ...proposal('submitted'), comp_revision: '0', permissions: permissions.filter(p => ['compensation.read', 'compensation.approve'].includes(p.capability)) }]
    const page = await open(); await query(page)
    await page.get(`[aria-label="批准提案 ${PROPOSAL}"]`).trigger('click')
    await page.get('#comp-decision-reason').setValue('synthetic exact independent approval'); await page.get('#comp-decision-confirm').setValue(true)
    await page.get('[aria-label="独立提案状态确认"]').trigger('submit'); await settle()
    expect(JSON.parse(mutations()[0]!.body!)).toMatchObject({ action: 'approve', revision: R, comp_revision: B })
    expect(page.findAll('button').some(b => b.text() === '创建明确薪酬提案')).toBe(false)
  })
  it('does not infer exact proposal action rights from broad role hints or visible readonly payload', async () => {
    currentStatus = 404
    proposals.proposals = [{ ...proposal('submitted'), permissions: [permissions[0]!] }]
    const page = await open(); await query(page)
    expect(page.find(`[aria-label="批准提案 ${PROPOSAL}"]`).exists()).toBe(false)
    expect(page.find(`[aria-label="撤回提案 ${PROPOSAL}"]`).exists()).toBe(false); expect(mutations()).toHaveLength(0)
  })
  it('exports an exact authorized event despite empty broad session hints, without aggregate or shared group reason leakage', async () => {
    currentStatus = 404; session.compensation_permissions = []; proposals.proposals = []
    approvals.approvals = [{ ...approval(), reason: '', decision_reason: '', members: [] }]
    const page = await open(); await query(page)
    mutationReply = async () => new Response([
      { kind: 'header', export_id: OTHER, status: 'prepared' },
      { kind: 'object', export_id: OTHER, status: 'prepared', compensation_event: event, approval: { id: APPROVAL, approver_subject_id: OTHER, approved_at: '2026-01-01T00:00:00Z' } },
      { kind: 'complete', export_id: OTHER, status: 'complete' },
    ].map(e => JSON.stringify(e)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get(`[value="compensation_event:${EVENT}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(JSON.parse(mutations()[0]!.body!)).toEqual({ format: 'ndjson', objects: [{ kind: 'compensation_event', id: EVENT, expected_revision: B }] })
    const output = page.get('[aria-label="当前内存财务 NDJSON 输出"]').text()
    expect(output).toContain(MONEY); expect(output).not.toContain('synthetic immutable reason'); expect(output).not.toContain('members'); expect(output).not.toContain(PROPOSAL)
  })
  it('explicit exact export request still fails safely when server denies independent export permission', async () => {
    currentStatus = 404; session.compensation_permissions = []; proposals.proposals = []
    const page = await open(); await query(page); mutationReply = async () => response(403, { code: 'FORBIDDEN' })
    await page.get(`[value="compensation_event:${EVENT}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(mutations()).toHaveLength(1); expect(page.find('[aria-label="当前内存财务 NDJSON 输出"]').exists()).toBe(false)
    expect(page.text()).not.toContain(MONEY); expect(page.text()).not.toContain('导出完成')
  })
  it('destroys blocked financial page and offers MFA read intent without releasing salary or creating permissions', async () => {
    session.mfa_recent = false; session.compensation_permissions = []
    const page = await open(true)
    expect(requests.filter(r => r.url.pathname.endsWith('/compensation'))).toHaveLength(0)
    expect(page.find('#compensation-stepup-intent').exists()).toBe(true)
    expect((page.get('#compensation-stepup-intent').element as HTMLSelectElement).value).toBe('compensation.read')
    expect(page.text()).not.toContain(MONEY); expect(mutations()).toHaveLength(0)
  })
  it('drops a late current response from an unmounted generation instead of releasing it into a new session', async () => {
    const page = await open()
    let resolve!: (value: Response) => void; currentReply = () => new Promise(accept => { resolve = accept })
    await button(page, '手动刷新当前授权与事实（清空草稿）').trigger('click'); await settle()
    const request = requests.filter(r => r.url.pathname.endsWith('/compensation')).at(-1)!
    page.unmount(); pages = pages.filter(p => p !== page)
    expect(request.signal?.aborted).toBe(true); resolve(response(200, current)); await settle()
    expect(document.body.textContent).not.toContain(MONEY)
  })
  it('rejects export object smuggling even with a valid terminal complete marker', async () => {
    const page = await open()
    mutationReply = async () => new Response([
      { kind: 'header', export_id: OTHER, status: 'prepared' },
      { kind: 'object', export_id: OTHER, status: 'prepared', compensation_term: { ...term, id: FUTURE } },
      { kind: 'complete', export_id: OTHER, status: 'complete' },
    ].map(e => JSON.stringify(e)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get(`[value="compensation_term:${TERM}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(page.find('[aria-label="当前内存财务 NDJSON 输出"]').exists()).toBe(false); expect(page.text()).not.toContain('导出完成')
  })
})

describe('R4 exact financial export inputs and dependency presentation', () => {
  it('exports a manually confirmed exact term/version without requiring an aggregate or approval history grant', async () => {
    currentStatus = 404; session.compensation_permissions = []; proposals.proposals = []; approvals.approvals = []
    const page = await open(); await query(page)
    await button(page, '输入明确已知导出对象').trigger('click')
    await page.get('#comp-export-0-kind').setValue('compensation_term'); await page.get('#comp-export-0-id').setValue(TERM); await page.get('#comp-export-0-revision').setValue(R)
    mutationReply = async () => new Response([
      { kind: 'header', export_id: OTHER, status: 'prepared' },
      { kind: 'object', export_id: OTHER, status: 'prepared', compensation_term: term },
      { kind: 'complete', export_id: OTHER, status: 'complete' },
    ].map(e => JSON.stringify(e)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    expect(JSON.parse(mutations()[0]!.body!)).toEqual({ format: 'ndjson', objects: [{ kind: 'compensation_term', id: TERM, expected_revision: R }] })
    expect(page.get('[aria-label="当前内存财务 NDJSON 输出"]').text()).toContain(MONEY)
    expect(page.get('[aria-label="当前内存财务 NDJSON 输出"]').text()).not.toContain(PROPOSAL)
    expect(page.get('[aria-label="指定日现状"]').text()).not.toContain(MONEY)
  })
  it('rejects zero/nonstring revision and duplicate manually selected exact export targets without coercion or silent dedupe', async () => {
    const page = await open()
    await button(page, '输入明确已知导出对象').trigger('click')
    await page.get('#comp-export-0-kind').setValue('compensation_term'); await page.get('#comp-export-0-id').setValue(TERM); await page.get('#comp-export-0-revision').setValue('0')
    await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle(); expect(mutations()).toHaveLength(0)
    await page.get('#comp-export-0-revision').setValue(R); await page.get(`[value="compensation_term:${TERM}"]`).setValue(true)
    await button(page, '导出所选财务对象').trigger('click'); await settle(); expect(mutations()).toHaveLength(0)
  })
  it('passes the opaque cursor only on the same typed history query and discards it on explicit filter refresh', async () => {
    proposals.next_cursor = 'synthetic-opaque-current-rights-cursor'
    const page = await open(); await query(page)
    await button(page, '下一页获准提案').trigger('click'); await settle()
    const pageQuery = requests.filter(r => r.url.pathname.endsWith('/changes')).at(-1)!
    expect(pageQuery.url.searchParams.get('cursor')).toBe('synthetic-opaque-current-rights-cursor')
    expect(pageQuery.url.searchParams.get('record_kind')).toBe('proposals')
    await page.get('#comp-status').setValue('submitted'); await page.get('[aria-label="薪酬查询条件"]').trigger('submit'); await settle()
    expect(requests.filter(r => r.url.pathname.endsWith('/changes')).at(-1)!.url.searchParams.has('cursor')).toBe(false)
  })
  it('shows original before/after and visible downstream identity dependencies without inserting omitted correction members', async () => {
    const laterTerm = { ...term, id: FUTURE, event_id: OTHER, effective_date: '2027-01-01', terms: { ...terms, amount_minor: '130' } }
    approvals.approvals.push({ ...approval(), id: OTHER, events: [{ ...event, id: OTHER, kind: 'adjustment', effective_date: '2027-01-01', before_term_id: TERM, after_term_id: FUTURE, before: term, after: laterTerm }] })
    const page = await open(); await query(page); await draft(page); await page.get('#comp-kind').setValue('correction'); await button(page, '增加纠错成员').trigger('click')
    await page.get('#comp-member-0-key').setValue('replace_initial'); await page.get('#comp-member-0-original').setValue(EVENT); await page.get('#comp-member-0-date').setValue('2026-01-01'); await fillTerms(page, 'comp-member-0-after', '125')
    const dependencies = page.get('[aria-label="获准原事件与可见下游依赖"]').text()
    expect(dependencies).toContain(EVENT); expect(dependencies).toContain(OTHER); expect(dependencies).toContain('尚未列入'); expect(dependencies).toContain('2027-01-01')
    await page.get('#comp-save-confirm').setValue(true); mutationReply = async () => response(409, { code: 'DEPENDENCY_INCOMPLETE' })
    await page.get('[aria-label="完整薪酬提案编辑"]').trigger('submit'); await settle()
    expect(JSON.parse(mutations()[0]!.body!).members).toHaveLength(1)
    expect(page.find('[aria-label="完整薪酬提案编辑"]').exists()).toBe(false)
  })
  it('erases earlier export chunks at authorization deadline and drops subsequent ignored-abort stream bytes', async () => {
    const page = await open()
    let stream!: ReadableStreamDefaultController<Uint8Array>
    mutationReply = async () => new Response(new ReadableStream<Uint8Array>({ start(controller) { stream = controller } }), { headers: { 'Content-Type': 'application/x-ndjson' } })
    await page.get(`[value="compensation_term:${TERM}"]`).setValue(true); await page.get('#comp-export-confirm').setValue(true); await button(page, '导出所选财务对象').trigger('click'); await settle()
    stream.enqueue(new TextEncoder().encode([{ kind: 'header', export_id: OTHER, status: 'prepared' }, { kind: 'object', export_id: OTHER, status: 'prepared', compensation_term: term }].map(e => JSON.stringify(e)).join('\n') + '\n')); await settle()
    expect(page.get('[aria-label="当前内存财务 NDJSON 输出"]').text()).toContain(MONEY)
    vi.setSystemTime(new Date('2026-10-12T00:00:00Z')); await vi.advanceTimersByTimeAsync(250)
    stream.enqueue(new TextEncoder().encode(JSON.stringify({ kind: 'complete', export_id: OTHER, status: 'complete' }) + '\n')); stream.close(); await settle()
    expect(mutations()[0]!.signal?.aborted).toBe(true)
    expect(page.find('[aria-label="当前内存财务 NDJSON 输出"]').exists()).toBe(false); expect(page.text()).not.toContain(MONEY); expect(page.text()).not.toContain('导出完成')
  })
})

describe('bounded proposal revision history consumer', () => {
  it('shows only the selected page, retains actual revision facts and returns explicitly to the latest page', async () => {
    const head = proposal()
    const latest = Array.from({ length: 20 }, (_, i) => revision(head, (BigInt(R) - BigInt(i)).toString(), i === 3 ? 'rejected' : 'draft'))
    const older = revision(head, (BigInt(R) - 20n).toString())
    revisionReply = async request => response(200, revisionView(head, request.url.searchParams.has('cursor') ? [older] : latest, request.url.searchParams.has('cursor') ? '' : 'synthetic-older-cursor'))
    const page = await open(); await query(page)
    expect(page.find('[data-revision]').exists()).toBe(false)
    await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    const historyPage = () => page.get(`[aria-label="提案修订历史 ${PROPOSAL}"]`)
    expect(historyPage().findAll('[data-revision]')).toHaveLength(20)
    expect(historyPage().get(`[data-revision="${latest[3]!.revision}"]`).text()).toContain('rejected')
    expect(historyPage().get(`[data-revision="${latest[3]!.revision}"]`).text()).toContain(latest[3]!.decision_reason)
    expect(historyPage().get(`[data-revision="${R}"]`).text()).toContain(latest[0]!.command.reason)
    expect(historyPage().get(`[data-revision="${R}"]`).text()).toContain(MONEY)
    await page.get(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(historyPage().findAll('[data-revision]')).toHaveLength(1)
    expect(historyPage().get('[data-revision]').attributes('data-revision')).toBe(older.revision)
    expect(historyPage().text()).not.toContain(latest[0]!.command.reason)
    expect(page.get(`[data-proposal="${PROPOSAL}"] > p`).text()).toContain(R)
    expect(page.find(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).exists()).toBe(false)
    await page.get(`[aria-label="重载最新修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(historyPage().findAll('[data-revision]')).toHaveLength(20)
    expect(historyPage().find(`[data-revision="${older.revision}"]`).exists()).toBe(false)
  })
  it('replaces a proposal selection and refuses ignored-abort late bytes from the previous proposal', async () => {
    const first = proposal(), second = { ...proposal(), id: OTHER, revision: '4', reason: 'synthetic second head' }
    proposals.proposals = [first, second]
    let resolve!: (value: Response) => void
    revisionReply = request => request.url.searchParams.get('proposal_id') === PROPOSAL ? new Promise(yes => { resolve = yes }) : Promise.resolve(response(200, revisionView(second, [revision(second, '4')])))
    const page = await open(); await query(page)
    await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    const firstRequest = requests.find(r => r.url.searchParams.get('record_kind') === 'proposal_revisions')!
    await page.get(`[aria-label="查看修订历史 ${OTHER}"]`).trigger('click'); await settle()
    expect(firstRequest.signal?.aborted).toBe(true)
    resolve(response(200, revisionView(first, [revision(first, R)]))); await settle()
    expect(page.find(`[aria-label="提案修订历史 ${PROPOSAL}"]`).exists()).toBe(false)
    expect(page.get(`[aria-label="提案修订历史 ${OTHER}"]`).get('[data-revision]').attributes('data-revision')).toBe('4')
    expect(page.find(`[data-revision="${R}"]`).exists()).toBe(false)
  })
  for (const status of [409, 422]) it(`destroys an invalidated older page on ${status} without automatically joining a new head`, async () => {
    const head = proposal()
    revisionReply = async request => request.url.searchParams.has('cursor') ? response(status, { code: 'CONFLICT' }) : response(200, revisionView(head, [revision(head, R)], 'synthetic-older-cursor'))
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    await page.get(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false)
    expect(page.get(`[aria-label="提案修订历史 ${PROPOSAL}"]`).find('[role="alert"]').exists()).toBe(true)
    expect(requests.filter(r => r.url.searchParams.get('record_kind') === 'proposal_revisions')).toHaveLength(2)
    expect(page.find(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).exists()).toBe(false)
  })
  for (const expiry of ['mfa', 'authorization']) it(`rejects a late older page and destroys all financial state when ${expiry} expires`, async () => {
    const head = proposal(), latest = revisionView(head, [revision(head, R)], 'synthetic-older-cursor')
    if (expiry === 'mfa') session.mfa_valid_until = '2026-10-11T12:00:01Z'
    else latest.authorization_until = '2026-10-11T12:00:01Z'
    let resolve!: (value: Response) => void
    revisionReply = request => request.url.searchParams.has('cursor') ? new Promise(yes => { resolve = yes }) : Promise.resolve(response(200, latest))
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    await page.get(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    const request = requests.filter(r => r.url.searchParams.get('record_kind') === 'proposal_revisions').at(-1)!
    vi.setSystemTime(new Date('2026-10-11T12:00:01Z')); await vi.advanceTimersByTimeAsync(250)
    expect(request.signal?.aborted).toBe(true)
    resolve(response(200, revisionView(head, [revision(head, '1')]))); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false); expect(page.find('[data-proposal]').exists()).toBe(false)
    expect(page.text()).not.toContain(MONEY)
  })
  it('does not continue revision cursors after the current authorization epoch changes', async () => {
    const head = proposal()
    revisionReply = async () => response(200, revisionView(head, [revision(head, R)], 'synthetic-older-cursor'))
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    session.auth_epoch = '9007199254740995'
    await page.get(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false); expect(page.find('[data-proposal]').exists()).toBe(false)
    expect(requests.filter(r => r.url.searchParams.get('record_kind') === 'proposal_revisions')).toHaveLength(1)
  })
  it('refuses an independently returned different head instead of attaching its history to the displayed proposal', async () => {
    const changed = { ...proposal(), revision: (BigInt(R) + 1n).toString(), reason: 'synthetic changed head' }
    revisionReply = async () => response(200, revisionView(changed, [revision(changed, changed.revision)]))
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false)
    expect(page.get(`[aria-label="提案修订历史 ${PROPOSAL}"]`).find('[role="alert"]').exists()).toBe(true)
    expect(page.text()).not.toContain(changed.reason)
    expect(page.get(`[data-proposal="${PROPOSAL}"] > p`).text()).toContain(R)
  })
  it('destroys a loaded revision page and rejects ignored-abort bytes when the employee route changes', async () => {
    const head = proposal()
    let resolve!: (value: Response) => void
    revisionReply = request => request.url.searchParams.has('cursor') ? new Promise(yes => { resolve = yes }) : Promise.resolve(response(200, revisionView(head, [revision(head, R)], 'synthetic-older-cursor')))
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    await page.get(`[aria-label="下一旧修订页 ${PROPOSAL}"]`).trigger('click'); await settle()
    const request = requests.filter(r => r.url.searchParams.get('record_kind') === 'proposal_revisions').at(-1)!
    history.pushState({}, '', `/employees/${OTHER}/compensation`); window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    expect(request.signal?.aborted).toBe(true)
    resolve(response(200, revisionView(head, [revision(head, '1')]))); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false); expect(page.text()).not.toContain(MONEY)
  })
  for (const status of [401, 403, 404]) it(`clears existing financial bytes when current revision authority rejects with ${status}`, async () => {
    const page = await open(); await query(page)
    revisionReply = async () => response(status, { code: 'DENIED' })
    await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    expect(page.find('[data-revision]').exists()).toBe(false); expect(page.find('[data-proposal]').exists()).toBe(false); expect(page.text()).not.toContain(MONEY)
  })
  it('discards a late revision page after unmount', async () => {
    let resolve!: (value: Response) => void
    revisionReply = () => new Promise(yes => { resolve = yes })
    const page = await open(); await query(page); await page.get(`[aria-label="查看修订历史 ${PROPOSAL}"]`).trigger('click'); await settle()
    const request = requests.find(r => r.url.searchParams.get('record_kind') === 'proposal_revisions')!
    page.unmount(); pages = pages.filter(p => p !== page)
    expect(request.signal?.aborted).toBe(true)
    resolve(response(200, revisionView(proposal(), [revision(proposal(), R)]))); await settle()
    expect(document.body.textContent).not.toContain(MONEY)
  })
  it('rejects oversized, mixed-mode, wrong-parent and noncanonical or unordered revision pages', () => {
    const head = proposal(), row = revision(head, R), valid = revisionView(head, [row])
    expect(validChanges(valid, EMPLOYEE, 'proposal_revisions', PROPOSAL, 20)).toBe(true)
    for (const invalid of [
      { ...valid, approvals: [approval()] },
      { ...valid, proposals: [] },
      { ...valid, proposals: [head, head] },
      { ...valid, proposals: [{ ...head, id: OTHER }] },
      { ...valid, proposals: [{ ...head, revisions: [] }] },
      { ...valid, revisions: Array.from({ length: 21 }, (_, i) => revision(head, (BigInt(R) - BigInt(i)).toString())) },
      { ...valid, revisions: [row, row] },
      { ...valid, revisions: [revision(head, '1'), row] },
      { ...valid, revisions: [{ ...row, revision: '9223372036854775808' }] },
      { ...valid, revisions: [{ ...row, revision: (BigInt(R) + 1n).toString() }] },
      { ...valid, revisions: [{ ...row, revision: '01' }] },
      { ...valid, revisions: [{ ...row, revision: '0' }] },
    ]) expect(validChanges(invalid, EMPLOYEE, 'proposal_revisions', PROPOSAL, 20)).toBe(false)
    expect(validChanges({ ...proposals, revisions: [row] }, EMPLOYEE, 'proposals')).toBe(false)
    expect(validChanges({ ...approvals, revisions: [row] }, EMPLOYEE, 'approvals')).toBe(false)
  })
})
