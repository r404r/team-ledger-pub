import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import InterviewPage from './InterviewPage.vue'
import GrantPage from './GrantPage.vue'
import App from './App.vue'
import type { Detail, Interview, Note, Permission, ActionItem } from './interviewDTO'

const ORG = '10000000-0000-4000-8000-000000000001', SUBJECT = '10000000-0000-4000-8000-000000000002', EMPLOYEE = '10000000-0000-4000-8000-000000000003', INT = '10000000-0000-4000-8000-000000000004', HEAD = '10000000-0000-4000-8000-000000000005', VERSION = '10000000-0000-4000-8000-000000000006', ACTION = '10000000-0000-4000-8000-000000000007', PRIVATE_HEAD = '10000000-0000-4000-8000-000000000008', PRIVATE_VERSION = '10000000-0000-4000-8000-000000000009'
const permissions: Permission[] = [
  { capability: 'interview.read', category: 'metadata' }, { capability: 'interview.write', category: 'metadata' },
  { capability: 'note.read', category: 'shared' }, { capability: 'note.write', category: 'shared' }, { capability: 'note.publish', category: 'shared' },
  { capability: 'action.read', category: 'shared' }, { capability: 'action.write', category: 'shared' }, { capability: 'sensitive.export', category: 'shared' },
]
const session = { subject_id: SUBJECT, org_id: ORG, auth_epoch: '9007199254740993', csrf_token: 'synthetic-csrf', capabilities: [...new Set(permissions.map(item => item.capability))], mfa_recent: true, mfa_valid_until: '2027-01-01T00:00:00Z', sensitivity_valid_until: '2026-10-12T00:00:00Z', interview_permissions: permissions }
const interview: Interview = { id: INT, employee_id: EMPLOYEE, status: 'in_progress', revision: '9007199254740994', scheduled_at: '2026-10-01T09:00:00Z', actual_started_at: '2026-10-01T09:01:00Z', actual_ended_at: null, backfilled: false, recorded_at: '2026-09-30T00:00:00Z', author_subject_id: SUBJECT, participants: [{ kind: 'subject', id: SUBJECT }] }
const note: Note = { id: VERSION, head_id: HEAD, interview_id: INT, employee_id: EMPLOYEE, category: 'shared', status: 'published', version_no: '9007199254740995', text: 'Synthetic shared statement', edit_reason: 'explicit historical correction', author_subject_id: SUBJECT, recorded_at: '2026-10-02T00:00:00Z', source_refs: [], supersedes_version_id: null }
const action: ActionItem = { id: ACTION, interview_id: INT, employee_id: EMPLOYEE, revision: '2', status: 'todo', minimal_shared_text: 'Synthetic minimal action', safe_blocker_text: '', owner: { kind: 'employee', id: EMPLOYEE }, due_date: '2026-10-02', overdue: true, recorded_at: '2026-10-01T10:00:00Z', source_refs: [], events: [{ id: ACTION, revision: '1', status: 'todo', author_subject_id: SUBJECT, recorded_at: '2026-10-01T10:00:00Z', safe_blocker_text: '' }] }
function detail(): Detail {
  return {
    interview: { ...interview },
    interview_events: [
      { id: INT, status: 'scheduled', revision: '9007199254740993', author_subject_id: SUBJECT, recorded_at: interview.recorded_at, actual_started_at: null, actual_ended_at: null, backfilled: false },
      { id: HEAD, status: 'in_progress', revision: interview.revision, author_subject_id: SUBJECT, recorded_at: '2026-10-01T09:01:00Z', actual_started_at: interview.actual_started_at, actual_ended_at: null, backfilled: false },
    ],
    sections: [{ head_id: HEAD, category: 'shared', head_revision: '7', versions: [{ ...note }], published_version_id: VERSION }],
    action_items: [{ ...action }], permissions: permissions.map(item => ({ ...item })), next_cursor: null,
  }
}
function response(status: number, body: unknown) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
type RequestRecord = { path: string; method: string; body?: string; headers: Headers; signal?: AbortSignal | null; url: URL }
let current: Detail, sessionValue: typeof session & { grant_authorities?: unknown[] }, requests: RequestRecord[], postReply: () => Promise<Response>, versionReply: () => Promise<Response>, wrappers: VueWrapper[]
let sessionStatus: number, deferredDetail: Promise<Response> | null, directoryAllowed: boolean
async function settle() { await flushPromises(); await nextTick() }
function button(page: VueWrapper, text: string) { const found = page.findAll('button').filter(item => item.text() === text); expect(found).toHaveLength(1); return found[0]! }
async function open(path = `/interviews/${INT}`) { history.replaceState({}, '', path); const page = mount(InterviewPage, { attachTo: document.body }); wrappers.push(page); await settle(); return page }
async function draft(page: VueWrapper) { await page.get('#note-category').setValue('shared'); await page.get('#note-supersedes').setValue(VERSION); await page.get('#note-text').setValue('Human entered minimal text'); await page.get('#note-reason').setValue('explicit correction'); }
function posts() { return requests.filter(request => request.method === 'POST') }
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] }); vi.setSystemTime(new Date('2026-10-11T12:00:00Z'))
  current = detail(); sessionValue = { ...session }; requests = []; wrappers = []; sessionStatus = 200; deferredDetail = null; directoryAllowed = true
  postReply = async () => response(201, { id: VERSION, revision: '8', status: 'draft', head_id: HEAD, head_revision: '8', version_no: '8' })
  versionReply = async () => response(200, note)
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), location.href), method = init?.method ?? 'GET'
    requests.push({ path: url.pathname, method, body: init?.body as string | undefined, headers: new Headers(init?.headers), signal: init?.signal, url })
    if (url.pathname === '/api/v1/session') return response(url.searchParams.has('employee_id') && !directoryAllowed ? 404 : sessionStatus, sessionValue)
    if (method === 'POST') return postReply()
    if (url.pathname === '/api/v1/access-grants') return response(200, { items: [], next_cursor: null, consistency: 'current', as_of: '2026-10-11', auth_epoch: sessionValue.auth_epoch, authorities: sessionValue.grant_authorities ?? [] })
    if (url.pathname === `/api/v1/interviews/${INT}`) { if (deferredDetail) { const pending = deferredDetail; deferredDetail = null; return pending } return response(200, current) }
    if (url.pathname === `/api/v1/note-versions/${VERSION}`) return versionReply()
    if (url.pathname === `/api/v1/employees/${EMPLOYEE}/interviews`) return response(200, { items: [current.interview], next_cursor: null, consistency: 'current', as_of: '2026-10-11', permissions: [{ capability: 'interview.read', category: 'metadata' }, { capability: 'interview.write', category: 'metadata' }] })
    throw new Error('Unexpected external HTTP boundary')
  })
})
afterEach(() => { for (const page of wrappers) page.unmount(); document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers() })

describe('P-INT-01 real component consumers', () => {
  it('renders authorized shared versions without private section labels, IDs, source summaries or counts', async () => {
    current.permissions = current.permissions.filter(item => item.capability === 'note.read' || item.capability === 'interview.read')
    current.action_items = []
    const page = await open()
    expect(page.text()).toContain(note.text)
    expect(page.find('[aria-label="manager_private 授权版本历史"]').exists()).toBe(false)
    expect(page.find('[aria-label="hr_confidential 授权版本历史"]').exists()).toBe(false)
    expect(page.text()).not.toContain(PRIVATE_VERSION)
    expect(page.find('#note-category').exists()).toBe(false)
    expect(requests.every(item => !item.url.href.includes(note.text))).toBe(true)
    expect(window.localStorage.length).toBe(0); expect(window.sessionStorage.length).toBe(0)
  })
  it('reads and exports an exact immutable version with no head authority or current pointer', async () => {
    const { head_id: _headID, ...exact } = note
    current.sections = [{ category: 'shared', versions: [exact] }]
    current.action_items = []
    current.permissions = current.permissions.filter(item => ['interview.read', 'note.read', 'sensitive.export'].includes(item.capability))
    versionReply = async () => response(200, exact)
    const page = await open()
    expect(page.text()).toContain(note.text)
    expect(page.find('#note-category').exists()).toBe(false)
    await button(page, '重取此授权历史版本').trigger('click'); await settle()
    expect(page.get('[aria-label="独立重取的授权历史版本"]').text()).toContain(note.text)
    await page.get(`[value="note_version:${VERSION}"]`).setValue(true)
    const exportID = '10000000-0000-4000-8000-000000000010'
    postReply = async () => new Response([
      { kind: 'header', export_id: exportID, status: 'prepared' },
      { kind: 'object', export_id: exportID, note_version: exact },
      { kind: 'complete', export_id: exportID, status: 'complete' },
    ].map(event => JSON.stringify(event)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await button(page, '导出所选对象').trigger('click'); await settle()
    expect(page.text()).toContain('所选对象导出完成')
    const output = page.get('[aria-label="当前内存 NDJSON 输出"]').text()
    expect(output).toContain(note.text)
    expect(output).not.toContain(HEAD)
    expect(output).not.toContain('head_id')
  })
  it('shows only the specifically authorized old version, not unrelated current head revision or other history', async () => {
    current.sections[0]!.head_revision = null; delete current.sections[0]!.published_version_id
    current.permissions = [{ capability: 'interview.read', category: 'metadata' }, { capability: 'note.read', category: 'shared' }]
    current.action_items = []
    const page = await open()
    expect(page.text()).toContain(note.version_no); expect(page.text()).not.toContain('当前 head revision')
    await page.get(`[aria-label="重取历史版本 ${VERSION}"]`).trigger('click'); await settle()
    expect(page.get('[aria-label="独立重取的授权历史版本"]').text()).toContain(note.text)
    expect(requests.filter(item => item.path.includes('note-versions')).map(item => item.path)).toEqual([`/api/v1/note-versions/${VERSION}`])
  })
  it('publishes immutable new version with original head CAS, explicit reason and no grant fields; reloads authorized history', async () => {
    const page = await open(); await draft(page); await page.get('#note-supersedes').setValue(VERSION); await page.get('#note-publish-confirm').setValue(true)
    postReply = async () => { current.sections[0]!.head_revision = '8'; current.sections[0]!.versions.push({ ...note, id: PRIVATE_VERSION, version_no: '8', text: 'Human entered minimal text' }); return response(201, { id: PRIVATE_VERSION, revision: '8', status: 'published' }) }
    await button(page, '发布新版本').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ head_id: HEAD, category: 'shared', expected_head_revision: '7', text: 'Human entered minimal text', edit_reason: 'explicit correction', action: 'publish', supersedes_version_id: VERSION, source_refs: [], confirm_minimized: false })
    expect(page.text()).toContain(note.text); expect(page.text()).toContain('Human entered minimal text'); expect(page.text()).toContain('此面谈命令已保存')
  })
  it('completed facts retain actual/recorded timestamps and overdue actions, allow correction but never reopen or create actions', async () => {
    current.interview.status = 'completed'; current.interview.actual_ended_at = '2026-10-01T10:00:00Z'; current.interview.backfilled = true
    const page = await open()
    expect(page.get('[aria-label="面谈事实"]').text()).toContain('2026-09-30T00:00:00Z')
    expect(page.text()).toContain('当前组织日已逾期'); expect(page.find('[aria-label="面谈状态转换"]').exists()).toBe(false); expect(page.find('[aria-label="创建共享行动"]').exists()).toBe(false)
    await draft(page); await page.get('#note-reason').setValue(''); await button(page, '保存新草稿').trigger('click'); await settle(); expect(posts()).toHaveLength(0)
    await page.get('#note-reason').setValue('Completed interview correction'); await button(page, '保存新草稿').trigger('click'); await settle(); expect(posts()).toHaveLength(1)
  })
  it('finishes an action independently after interview completion preserving due date and immutable history', async () => {
    current.interview.status = 'completed'; current.interview.actual_ended_at = '2026-10-01T10:00:00Z'
    const page = await open()
    postReply = async () => { current.action_items[0] = { ...action, status: 'done', revision: '3', overdue: false, events: [...action.events, { ...action.events[0]!, id: VERSION, revision: '3', status: 'done' }] }; return response(200, { id: ACTION, revision: '3', status: 'done' }) }
    await page.get(`[aria-label="完成行动 ${ACTION}"]`).trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ action: 'complete', expected_revision: '2', safe_blocker_text: '' })
    expect(page.get(`[data-action-item="${ACTION}"]`).text()).toContain('2026-10-02'); expect(page.get(`[data-action-item="${ACTION}"]`).text()).toContain('未逾期'); expect(page.get(`[data-action-item="${ACTION}"]`).find('button').exists()).toBe(false)
  })
  it('uses null for genuinely unset due date, never invents overdue', async () => {
    const page = await open(); await page.get('#action-text').setValue('Human shared action'); await page.get('#action-owner-id').setValue(SUBJECT)
    await button(page, '创建共享行动').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!).due_date).toBeNull()
  })
  it('receives genuine server 409 for competing original head and does not overwrite or automatically retry', async () => {
    const page = await open(); await draft(page)
    postReply = async () => response(409, { code: 'conflict' })
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(posts()).toHaveLength(1); expect(JSON.parse(posts()[0]!.body!).expected_head_revision).toBe('7')
    expect(page.text()).toContain('真实版本冲突'); expect(page.find('#note-text').exists()).toBe(false); expect(page.find('[aria-label="shared 授权版本历史"]').exists()).toBe(false)
  })
  it('unknown network outcome explicitly replays byte-identical original body/key after fresh current authorization and reload', async () => {
    const page = await open(); await draft(page); postReply = async () => { throw new TypeError('Synthetic dropped reply') }
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(page.find('[aria-label="面谈命令结果尚未确认"]').exists()).toBe(true); expect(page.text()).not.toContain(note.text)
    sessionValue = { ...sessionValue, auth_epoch: '9007199254740994' }
    postReply = async () => response(201, { id: VERSION, revision: '8', status: 'draft' })
    await button(page, '重试原命令').trigger('click'); await settle()
    expect(posts()).toHaveLength(2); expect(posts()[1]!.body).toBe(posts()[0]!.body); expect(posts()[1]!.headers.get('Idempotency-Key')).toBe(posts()[0]!.headers.get('Idempotency-Key')); expect(page.text()).toContain('此面谈命令已保存')
  })
  it('does not replay unknown command after current permission revocation', async () => {
    const page = await open(); await draft(page); postReply = async () => { throw new TypeError('Dropped') }
    await button(page, '保存新草稿').trigger('click'); await settle()
    sessionValue = { ...sessionValue, capabilities: ['interview.read'] }; current.permissions = [{ capability: 'interview.read', category: 'metadata' }]
    current.sections = []; current.action_items = []
    await button(page, '重试原命令').trigger('click'); await settle()
    expect(posts()).toHaveLength(1); expect(page.text()).toContain('许可已改变'); expect(page.text()).not.toContain(note.text)
  })
  it('discards ignored-abort late 200 after navigation and never revives plaintext or success', async () => {
    const page = await open(); await draft(page)
    let resolve!: (response: Response) => void
    postReply = () => new Promise<Response>(yes => { resolve = yes })
    await button(page, '保存新草稿').trigger('click'); await settle()
    const command = posts()[0]!
    history.pushState({}, '', '/interviews'); window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    expect(command.signal?.aborted).toBe(true)
    resolve(response(201, { id: VERSION, revision: '8', status: 'draft' })); await settle()
    expect(page.text()).not.toContain(note.text); expect(page.text()).not.toContain('此面谈命令已保存'); expect(page.find('#note-text').exists()).toBe(false)
  })
  it('401 and clock expiry clear sensitive inputs and reject deferred response revival', async () => {
    const page = await open(); await draft(page)
    let resolve!: (response: Response) => void
    postReply = () => new Promise<Response>(yes => { resolve = yes })
    await button(page, '保存新草稿').trigger('click'); await settle()
    vi.setSystemTime(new Date('2027-01-01T00:00:00Z')); vi.advanceTimersByTime(1000); await settle()
    expect(page.text()).not.toContain(note.text); expect(posts()[0]!.signal?.aborted).toBe(true)
    resolve(response(201, { id: VERSION, revision: '8', status: 'draft' })); await settle(); expect(page.text()).not.toContain('此面谈命令已保存')
    sessionStatus = 401; await button(page, '刷新面谈').trigger('click'); await settle(); expect(page.emitted('session-expired')).toHaveLength(1)
  })
  it('never automatically copies selected private source text and submits only explicit immutable source ref after human minimization', async () => {
    current.sections.push({ head_id: PRIVATE_HEAD, category: 'manager_private', head_revision: '1', versions: [{ ...note, id: PRIVATE_VERSION, head_id: PRIVATE_HEAD, category: 'manager_private', version_no: '1', text: 'Synthetic private source marker' }] })
    current.permissions.push({ capability: 'note.read', category: 'manager_private' })
    const page = await open(); await draft(page); await page.get('#note-sources').setValue([PRIVATE_VERSION]); await page.get('#note-minimized').setValue(true); await page.get('#note-publish-confirm').setValue(true)
    expect((page.get('#note-text').element as HTMLTextAreaElement).value).toBe('Human entered minimal text')
    await button(page, '发布新版本').trigger('click'); await settle()
    const body = JSON.parse(posts()[0]!.body!)
    expect(body.source_refs).toEqual([{ kind: 'note_version', id: PRIVATE_VERSION, expected_version: '1' }]); expect(body.confirm_minimized).toBe(true); expect(posts()[0]!.body).not.toContain('Synthetic private source marker')
    expect(requests.some(item => item.path === `/api/v1/note-versions/${PRIVATE_VERSION}`)).toBe(false)
  })
  it('shows independent approved-grant success separately from later publish failure, with no aggregate success', async () => {
    const authority = { id: PRIVATE_HEAD, capability: 'note.publish', category: 'shared', purpose: 'interview_followup', scope: { kind: 'employee', id: EMPLOYEE }, delegable_scopes: [{ kind: 'employee', id: EMPLOYEE }], valid_from: '2026-01-01T00:00:00Z', expires_at: '2027-01-01T00:00:00Z', mfa_required: true, approved_by: PRIVATE_VERSION, approved_at: '2025-12-01T00:00:00Z', policy_version: 'synthetic-source-approval' }
    sessionValue = { ...sessionValue, capabilities: [...sessionValue.capabilities, 'access_grant.manage'], grant_authorities: [authority] }
    const page = await open()
    await button(page, '独立授权与最小来源批准（P-SEC-01）').trigger('click'); await settle()
    const grantPage = page.findComponent(GrantPage)
    await button(grantPage, '新建授权').trigger('click')
    await grantPage.get('#grant-subject').setValue(EMPLOYEE)
    await grantPage.get('#grant-start').setValue('2026-10-11T00:00:00Z'); await grantPage.get('#grant-end').setValue('2026-12-01T00:00:00Z')
    await grantPage.get('#grant-object-kind').setValue('note_head'); await grantPage.get('#grant-object-id').setValue(HEAD); await grantPage.get('#grant-source-ids').setValue(PRIVATE_VERSION)
    await button(grantPage, '预览授权').trigger('click'); await settle()
    postReply = async () => { sessionValue = { ...sessionValue, auth_epoch: '9007199254740994' }; return response(201, { id: PRIVATE_HEAD, revision: '1', status: 'current', auth_epoch: sessionValue.auth_epoch }) }
    await button(grantPage, '确认授予').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!).approved_source_refs).toEqual([{ kind: 'note_version', id: PRIVATE_VERSION }])
    expect(page.get('[aria-label="独立授权结果"]').text()).toContain('独立授权请求已成功'); expect(page.text()).not.toContain(note.text)
    await button(page, '刷新面谈').trigger('click'); await settle(); await draft(page); await page.get('#note-publish-confirm').setValue(true)
    postReply = async () => response(403, { code: 'forbidden' })
    await button(page, '发布新版本').trigger('click'); await settle()
    expect(page.get('[aria-label="独立授权结果"]').text()).toContain('笔记尚未发布'); expect(page.text()).toContain('许可已改变'); expect(page.text()).not.toContain('此面谈命令已保存')
  })
  it('consumes actual bounded NDJSON partial output for explicitly selected note, no hidden metadata export', async () => {
    const page = await open(); await page.get(`[value="note_version:${VERSION}"]`).setValue(true)
    const exportID = '10000000-0000-4000-8000-000000000010'
    postReply = async () => new Response([JSON.stringify({ kind: 'header', export_id: exportID, status: 'prepared' }), JSON.stringify({ kind: 'object', export_id: exportID, note_version: note }), JSON.stringify({ kind: 'partial', export_id: exportID, status: 'partial', reason: 'DEPENDENCY_UNAVAILABLE' })].join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await button(page, '导出所选对象').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ objects: [{ kind: 'note_version', id: VERSION, expected_revision: note.version_no }], format: 'ndjson' })
    expect(page.text()).toContain('导出部分完成'); expect(page.get('[aria-label="当前内存 NDJSON 输出"]').text()).toContain(note.text); expect(page.text()).not.toContain('所选对象导出完成')
    history.pushState({}, '', '/interviews'); window.dispatchEvent(new PopStateEvent('popstate')); await settle(); expect(page.find('pre').exists()).toBe(false); expect(window.localStorage.length).toBe(0)
  })
  it('creates historical backfill with actual timestamps distinct from server recorded facts', async () => {
    const page = await open(`/employees/${EMPLOYEE}/interviews`)
    await page.get('#interview-scheduled').setValue('2026-09-01T09:00:00Z'); await page.get('#interview-backfilled').setValue(true); await page.get('#interview-actual-start').setValue('2026-09-01T09:05:00Z'); await page.get('#interview-actual-end').setValue('2026-09-01T10:00:00Z')
    postReply = async () => response(201, { id: INT, revision: '1', status: 'completed' })
    await button(page, '补录面谈').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ scheduled_at: '2026-09-01T09:00:00Z', participants: [], backfilled: true, actual_started_at: '2026-09-01T09:05:00Z', actual_ended_at: '2026-09-01T10:00:00Z' })
    expect(posts()[0]!.body).not.toContain('recorded_at')
  })
})

describe('P-INT-01 sensitive selection and terminal consumers', () => {
  it('uses three independent immutable heads only when each current category is authorized', async () => {
    const hrHead = '10000000-0000-4000-8000-000000000011', hrVersion = '10000000-0000-4000-8000-000000000012'
    current.sections.push(
      { category: 'manager_private', head_id: PRIVATE_HEAD, head_revision: '2', versions: [{ ...note, id: PRIVATE_VERSION, head_id: PRIVATE_HEAD, category: 'manager_private', version_no: '2', text: 'Synthetic manager-only statement' }] },
      { category: 'hr_confidential', head_id: hrHead, head_revision: '3', versions: [{ ...note, id: hrVersion, head_id: hrHead, category: 'hr_confidential', version_no: '3', text: 'Synthetic confidential HR statement' }] },
    )
    for (const category of ['manager_private', 'hr_confidential']) for (const capability of ['note.read', 'note.write', 'note.publish']) current.permissions.push({ capability, category })
    const page = await open()
    expect(page.get('[aria-label="manager_private 授权版本历史"]').text()).toContain('Synthetic manager-only statement')
    expect(page.get('[aria-label="hr_confidential 授权版本历史"]').text()).toContain('Synthetic confidential HR statement')
    await page.get('#note-category').setValue('manager_private'); await page.get('#note-text').setValue('Manual manager correction'); await page.get('#note-reason').setValue('Manager explicit reason'); await page.get('#note-supersedes').setValue(PRIVATE_VERSION)
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toMatchObject({ category: 'manager_private', head_id: PRIVATE_HEAD, expected_head_revision: '2', supersedes_version_id: PRIVATE_VERSION })
    await page.get('#note-category').setValue('hr_confidential'); await page.get('#note-text').setValue('Manual confidential correction'); await page.get('#note-reason').setValue('HR explicit reason'); await page.get('#note-supersedes').setValue(hrVersion)
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(JSON.parse(posts()[1]!.body!)).toMatchObject({ category: 'hr_confidential', head_id: hrHead, expected_head_revision: '3', supersedes_version_id: hrVersion })
    expect(JSON.parse(posts()[0]!.body!).head_id).not.toBe(JSON.parse(posts()[1]!.body!).head_id)
  })
  it('switching selected note category aborts ignored-abort write and discards late success', async () => {
    const page = await open(); await draft(page)
    let resolve!: (value: Response) => void
    postReply = () => new Promise<Response>(yes => { resolve = yes })
    await button(page, '保存新草稿').trigger('click'); await settle()
    await page.get('#note-category').setValue('')
    expect(posts()[0]!.signal?.aborted).toBe(true)
    resolve(response(201, { id: VERSION, revision: '8', status: 'draft' })); await settle()
    expect(page.text()).not.toContain('此面谈命令已保存'); expect(page.find('#note-text').exists()).toBe(false)
  })
  it('fresh denied current session discards late transition 200, clearing facts instead of reviving terminal success', async () => {
    const page = await open(); await page.get('#transition-end').setValue('2026-10-01T10:00:00Z')
    let resolve!: (value: Response) => void
    postReply = () => new Promise<Response>(yes => { resolve = yes })
    await button(page, '完成面谈').trigger('click'); await settle()
    sessionStatus = 403
    await button(page, '刷新面谈').trigger('click'); await settle()
    expect(posts()[0]!.signal?.aborted).toBe(true)
    resolve(response(200, { id: INT, revision: '9007199254740995', status: 'completed' })); await settle()
    expect(page.find('[aria-label="面谈事实"]').exists()).toBe(false); expect(page.text()).not.toContain('此面谈命令已保存'); expect(page.text()).not.toContain(note.text)
  })
  it('changing selected historical version discards ignored-abort late plaintext from prior read', async () => {
    const page = await open()
    let resolve!: (value: Response) => void
    versionReply = () => new Promise<Response>(yes => { resolve = yes })
    await page.get(`[aria-label="重取历史版本 ${VERSION}"]`).trigger('click'); await settle()
    await page.get('#note-category').setValue('shared')
    resolve(response(200, { ...note, text: 'Synthetic late historical marker' })); await settle()
    expect(page.find('[aria-label="独立重取的授权历史版本"]').exists()).toBe(false); expect(page.text()).not.toContain('Synthetic late historical marker')
  })
})

describe('P-INT-01 real cursor and export release consumers', () => {
  it('retains original combined cursor filters, then starts a fresh category-bound cursor on explicit scope switch', async () => {
    current.next_cursor = 'synthetic-current-cursor'
    const page = await open()
    current.next_cursor = null
    await button(page, '下一页获准内容').trigger('click'); await settle()
    const reads = requests.filter(request => request.path === `/api/v1/interviews/${INT}`)
    expect(reads[1]!.url.searchParams.get('cursor')).toBe('synthetic-current-cursor')
    expect(reads[1]!.url.searchParams.get('category')).toBeNull()
    expect(reads[1]!.url.searchParams.get('include_sections')).toBe(reads[0]!.url.searchParams.get('include_sections'))
    await page.get('#interview-history-scope').setValue('shared'); await settle()
    const latest = requests.filter(request => request.path === `/api/v1/interviews/${INT}`).at(-1)!
    expect(latest.url.searchParams.get('category')).toBe('shared'); expect(latest.url.searchParams.has('cursor')).toBe(false)
  })
  it('real ACCESS_LOST partial terminal clears previously released plaintext, original command and in-memory output', async () => {
    const page = await open(); await page.get(`[value="note_version:${VERSION}"]`).setValue(true)
    const exportID = '10000000-0000-4000-8000-000000000010'
    postReply = async () => new Response([JSON.stringify({ kind: 'header', export_id: exportID, status: 'prepared' }), JSON.stringify({ kind: 'object', export_id: exportID, note_version: note }), JSON.stringify({ kind: 'partial', export_id: exportID, status: 'partial', reason: 'ACCESS_LOST' })].join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await button(page, '导出所选对象').trigger('click'); await settle()
    expect(page.text()).toContain('当前访问已失效')
    expect(page.text()).not.toContain(note.text); expect(page.find('pre').exists()).toBe(false)
    expect(page.find('[aria-label="面谈命令结果尚未确认"]').exists()).toBe(false)
    expect(posts()[0]!.signal?.aborted).toBe(true)
  })
})

describe('P-INT-01 exact object capabilities and complete finite output', () => {
  it('honors authoritative exact head write permission when broad employee session hints omit note.write', async () => {
    sessionValue = { ...sessionValue, capabilities: ['interview.read'], interview_permissions: [{ capability: 'interview.read', category: 'metadata' }] }
    const page = await open(); await draft(page)
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(posts()).toHaveLength(1)
    expect(JSON.parse(posts()[0]!.body!)).toMatchObject({ head_id: HEAD, expected_head_revision: '7', action: 'save_draft' })
    expect(page.text()).toContain('此面谈命令已保存')
  })
  it('requires matching selected immutable revision and real complete terminal before showing finite export success', async () => {
    const page = await open(); await page.get(`[value="note_version:${VERSION}"]`).setValue(true)
    const exportID = '10000000-0000-4000-8000-000000000010'
    postReply = async () => new Response([JSON.stringify({ kind: 'header', export_id: exportID, status: 'prepared' }), JSON.stringify({ kind: 'object', export_id: exportID, note_version: note }), JSON.stringify({ kind: 'complete', export_id: exportID, status: 'complete' })].join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await button(page, '导出所选对象').trigger('click'); await settle()
    expect(page.text()).toContain('所选对象导出完成')
    const output = page.get('[aria-label="当前内存 NDJSON 输出"]').text().split('\n').filter(Boolean).map(line => JSON.parse(line))
    expect(output.map(event => event.kind)).toEqual(['header', 'object', 'complete'])
    expect(output[1].note_version.id).toBe(VERSION); expect(output[1].note_version.version_no).toBe(note.version_no)
    expect(window.localStorage.length).toBe(0); expect(window.sessionStorage.length).toBe(0)
  })
  it('exports the explicitly handed-over old shared version without unrelated employee directory authority', async () => {
    directoryAllowed = false
    current.sections[0]!.head_revision = null
    current.permissions = [{ capability: 'interview.read', category: 'metadata' }, { capability: 'note.read', category: 'shared' }, { capability: 'sensitive.export', category: 'shared' }]
    current.action_items = []
    sessionValue = { ...sessionValue, capabilities: [], interview_permissions: [] }
    const page = await open()
    expect(page.text()).toContain(note.text)
    await page.get(`[value="note_version:${VERSION}"]`).setValue(true)
    const exportID = '10000000-0000-4000-8000-000000000010'
    postReply = async () => new Response([JSON.stringify({ kind: 'header', export_id: exportID, status: 'prepared' }), JSON.stringify({ kind: 'object', export_id: exportID, note_version: note }), JSON.stringify({ kind: 'complete', export_id: exportID, status: 'complete' })].join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } })
    await button(page, '导出所选对象').trigger('click'); await settle()
    expect(page.text()).toContain('所选对象导出完成')
    expect(page.get('[aria-label="当前内存 NDJSON 输出"]').text()).toContain(note.text)
    expect(page.find('[aria-label="manager_private 授权版本历史"]').exists()).toBe(false)
    expect(page.find('#note-category').exists()).toBe(false)
  })
})

describe('P-INT-01 current server sensitivity deadline', () => {
  it('clears on actual server-bound grant/session/calendar deadline even while MFA remains recent and discards late write', async () => {
    sessionValue = { ...sessionValue, sensitivity_valid_until: '2026-10-11T12:00:02Z' }
    const page = await open(); await draft(page)
    let resolve!: (value: Response) => void
    postReply = () => new Promise<Response>(yes => { resolve = yes })
    await button(page, '保存新草稿').trigger('click'); await settle()
    vi.advanceTimersByTime(2000); await settle()
    expect(page.find('#note-text').exists()).toBe(false); expect(page.text()).not.toContain(note.text)
    expect(posts()[0]!.signal?.aborted).toBe(true)
    expect(page.text()).toContain('当前敏感显示期限')
    resolve(response(201, { id: VERSION, revision: '8', status: 'draft' })); await settle()
    expect(page.text()).not.toContain('此面谈命令已保存')
    expect(page.find('[aria-label="面谈命令结果尚未确认"]').exists()).toBe(false)
  })
  it('retains confirmed write success separately when current authorized reload fails', async () => {
    const page = await open(); await draft(page)
    postReply = async () => { sessionStatus = 503; return response(201, { id: VERSION, revision: '8', status: 'draft' }) }
    await button(page, '保存新草稿').trigger('click'); await settle()
    expect(page.text()).toContain('此面谈命令已保存，但当前授权回读未成功')
    expect(page.text()).not.toContain(note.text)
    expect(page.find('[aria-label="面谈命令结果尚未确认"]').exists()).toBe(false)
    expect(posts()).toHaveLength(1)
  })
})

describe('P-INT-01 full transition and reason history consumers', () => {
  it('explicitly completes scheduled historical backfill with both actual times and required fact, preserving later recorded history', async () => {
    current.interview = { ...interview, status: 'scheduled', actual_started_at: null, actual_ended_at: null }
    current.interview_events = [current.interview_events[0]!]
    const page = await open()
    expect(page.findAll('button').some(item => item.text() === '历史补录完成')).toBe(false)
    await page.get('#transition-start').setValue('2026-09-01T09:00:00Z')
    await page.get('#transition-backfill-confirm').setValue(true)
    await page.get('#transition-backfill-end').setValue('2026-09-01T10:00:00Z')
    postReply = async () => {
      current.interview = { ...current.interview, status: 'completed', revision: '9007199254740995', backfilled: true, actual_started_at: '2026-09-01T09:00:00Z', actual_ended_at: '2026-09-01T10:00:00Z' }
      current.interview_events.push({ id: VERSION, status: 'completed', revision: '9007199254740995', author_subject_id: SUBJECT, recorded_at: '2026-10-11T12:00:00Z', actual_started_at: current.interview.actual_started_at, actual_ended_at: current.interview.actual_ended_at, backfilled: true })
      return response(200, { id: INT, status: 'completed', revision: '9007199254740995' })
    }
    await button(page, '历史补录完成').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ action: 'complete', expected_revision: interview.revision, actual_started_at: '2026-09-01T09:00:00Z', actual_ended_at: '2026-09-01T10:00:00Z', backfilled: true, reason: '' })
    const facts = page.get('[aria-label="不可变面谈状态历史"]').text()
    expect(facts).toContain('2026-09-01T09:00:00Z'); expect(facts).toContain('2026-10-11T12:00:00Z'); expect(facts).toContain('明确历史补录')
    expect(page.find('[aria-label="面谈状态转换"]').exists()).toBe(false)
    expect(page.text()).toContain('当前组织日已逾期')
  })
  it('ordinary completion explicitly sends backfilled=false, preserving actual start and independent action state', async () => {
    const page = await open(); await page.get('#transition-end').setValue('2026-10-01T10:00:00Z')
    postReply = async () => response(409, { code: 'REVISION_STALE' })
    await button(page, '完成面谈').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!)).toEqual({ action: 'complete', expected_revision: interview.revision, actual_started_at: null, actual_ended_at: '2026-10-01T10:00:00Z', backfilled: false, reason: '' })
    expect(posts()).toHaveLength(1)
  })
  it('retains cancellation reason only in independently authorized shared history, never in metadata-only projection', async () => {
    const page = await open(); await page.get('#transition-reason').setValue('Synthetic safe cancellation reason')
    postReply = async () => {
      current.interview.status = 'cancelled'; current.interview.revision = '9007199254740995'
      current.interview_events.push({ id: VERSION, status: 'cancelled', revision: '9007199254740995', author_subject_id: SUBJECT, recorded_at: '2026-10-11T12:00:00Z', actual_started_at: interview.actual_started_at, actual_ended_at: null, backfilled: false, reason: 'Synthetic safe cancellation reason' })
      return response(200, { id: INT, status: 'cancelled', revision: '9007199254740995' })
    }
    await button(page, '取消面谈').trigger('click'); await settle()
    expect(JSON.parse(posts()[0]!.body!).backfilled).toBe(false)
    expect(page.get('[aria-label="不可变面谈状态历史"]').text()).toContain('Synthetic safe cancellation reason')
    current.permissions = [{ capability: 'interview.read', category: 'metadata' }]; current.sections = []; current.action_items = []
    for (const event of current.interview_events) delete event.reason
    await button(page, '刷新面谈').trigger('click'); await settle()
    expect(page.text()).not.toContain('Synthetic safe cancellation reason')
    expect(page.get('[aria-label="不可变面谈状态历史"]').text()).toContain('cancelled')
  })
})

describe('P-INT-01 composition-root navigation consumer', () => {
  it('dispatches main navigation selector, legal selected employee list and object detail to the real protected page', async () => {
    history.replaceState({}, '', '/interviews')
    const page = mount(App, { attachTo: document.body }); wrappers.push(page); await settle()
    expect(page.findComponent(InterviewPage).exists()).toBe(true)
    expect(page.find('[aria-label="选择面谈员工"]').exists()).toBe(true)
    await page.get('#interview-employee').setValue(EMPLOYEE); await button(page, '读取员工面谈').trigger('click'); await settle()
    expect(location.pathname).toBe(`/employees/${EMPLOYEE}/interviews`)
    expect(page.find('[aria-label="获准面谈列表"]').exists()).toBe(true)
    await page.get(`a[href="/interviews/${INT}"]`).trigger('click'); await settle()
    expect(location.pathname).toBe(`/interviews/${INT}`)
    expect(page.get('[aria-label="shared 授权版本历史"]').text()).toContain(note.text)
    expect(page.find('[aria-label="共同身份与会话"]').attributes('data-identity-state')).toBe('authenticated')
    expect(location.search).toBe('')
    expect(requests.some(request => request.url.href.includes(note.text))).toBe(false)
  })
})
