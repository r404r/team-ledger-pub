import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import OrganizationPage from './OrganizationPage.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const SUBJECT = '10000000-0000-4000-8000-000000000002'
const EMPLOYEE = '10000000-0000-4000-8000-000000000003'
const MANAGER = '10000000-0000-4000-8000-000000000004'
const TEAM = '10000000-0000-4000-8000-000000000005'
const OTHER_TEAM = '10000000-0000-4000-8000-000000000006'
const MEMBERSHIP = '10000000-0000-4000-8000-000000000007'
const REPORTING = '10000000-0000-4000-8000-000000000008'
const CHANGE = '10000000-0000-4000-8000-000000000009'
const PARENT = '10000000-0000-4000-8000-000000000010'
const POSITION = '10000000-0000-4000-8000-000000000011'
const AS_OF = '2026-10-11'
const FROM = '2026-01-01'
const TRANSFER = '2026-11-01'
const PRIVATE_NAME = '合成短期内存姓名'
const TREE_PATH = `/api/v1/orgs/${ORG}/tree`
const QUERY_PATH = `/api/v1/orgs/${ORG}/employees/query`
const CHANGE_PATH = `/api/v1/orgs/${ORG}/structure-changes`
const TEAM_PATH = `/api/v1/orgs/${ORG}/teams`
const HISTORY_PATH = `/api/v1/employees/${EMPLOYEE}/organization-history`
const initialSession = { subject_id: SUBJECT, org_id: ORG, auth_epoch: '3', csrf_token: 'synthetic-org-csrf', capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'] }
const membership = { id: MEMBERSHIP, employee_id: EMPLOYEE, team_id: TEAM, is_primary: true, valid_from: FROM, valid_to: null }
const reporting = { id: REPORTING, employee_id: EMPLOYEE, manager_employee_id: MANAGER, kind: 'administrative', valid_from: FROM, valid_to: null }
function tree(epoch = '3', graph = '4') {
  return { org_id: ORG, as_of: AS_OF, authorization_date: AS_OF, graph_revision: graph, auth_epoch: epoch,
    nodes: [{ id: TEAM, code: 'engineering', lifecycle: { valid_from: FROM, valid_to: null } }, { id: OTHER_TEAM, code: 'operations', lifecycle: { valid_from: FROM, valid_to: null } }],
    edges: [{ id: PARENT, child_team_id: TEAM, parent_team_id: OTHER_TEAM, valid_from: FROM, valid_to: null }], employees: [{ id: EMPLOYEE, team_id: TEAM }] }
}
function employee(sensitive = false) {
  return { id: EMPLOYEE, org_id: ORG, lifecycle: { valid_from: FROM, valid_to: null }, as_of: AS_OF, authorization_date: AS_OF,
    memberships: [membership], positions: sensitive ? [{ id: POSITION, employee_id: EMPLOYEE, team_id: TEAM, is_primary: true, valid_from: FROM, valid_to: null, position: { title: '合成获准职位' } }] : [], reporting_lines: [reporting],
    ...(sensitive ? { profile: { display_name: PRIVATE_NAME }, profile_revision: '19' } : {}) }
}
function directory(items = [employee()], cursor: string | null = null, partial = false, epoch = '3', graph = '4') {
  return { items, next_cursor: cursor, search_incomplete: partial, as_of: AS_OF, authorization_date: AS_OF, consistency: 'current', graph_revision: graph, auth_epoch: epoch }
}
function historyPage() {
  return { items: [{ id: CHANGE, actor_subject_id: SUBJECT, recorded_at: '2026-10-11T01:02:03.123456Z', graph_before: '3', graph_after: '4', items: [
    { action: 'add', kind: 'membership', ...membership, superseded: false },
    { action: 'replace', ...reporting, kind: 'reporting_line', reporting_kind: 'administrative', supersedes_id: POSITION, superseded: true },
  ] }], next_cursor: null, as_of: AS_OF, authorization_date: AS_OF, consistency: 'current', graph_revision: '4', auth_epoch: '3' }
}
function response(status: number, body: unknown) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }) }
function deferred() {
  let resolve!: (value: Response) => void
  let reject!: (cause: Error) => void
  const promise = new Promise<Response>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve: (status: number, body: unknown) => resolve(response(status, body)), reject: () => reject(new TypeError('Synthetic unknown commit')) }
}
type RecordRequest = { url: URL; method: string; body?: string; headers: Headers; signal: AbortSignal | null; cache?: RequestCache }
class ExternalHTTP {
  session = { ...initialSession }
  sessionStatus = 200
  graph = '4'
  requests: RecordRequest[] = []
  unexpected: string[] = []
  replies: { method: string; path: string; promise: Promise<Response> }[] = []
  reply(method: string, path: string, status: number, body: unknown) { this.replies.push({ method, path, promise: Promise.resolve(response(status, body)) }) }
  defer(method: string, path: string) { const pending = deferred(); this.replies.push({ method, path, promise: pending.promise }); return pending }
  matching(method: string, path: string) { return this.requests.filter((item) => item.method === method && item.url.pathname === path) }
  mutations() { return this.requests.filter((item) => item.method === 'POST' && item.url.pathname !== QUERY_PATH) }
  fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), location.href), method = init?.method ?? 'GET'
    this.requests.push({ url, method, body: init?.body as string | undefined, headers: new Headers(init?.headers), signal: init?.signal ?? null, cache: init?.cache })
    const index = this.replies.findIndex((item) => item.method === method && item.path === url.pathname)
    // The transport deliberately ignores abort; late response guards must remain effective.
    if (index >= 0) return this.replies.splice(index, 1)[0]!.promise
    if (url.pathname === '/api/v1/session') return response(this.sessionStatus, this.session)
    if (method === 'GET' && url.pathname === TREE_PATH) return response(200, tree(this.session.auth_epoch, this.graph))
    if (method === 'POST' && url.pathname === QUERY_PATH) return response(200, directory([employee()], null, false, this.session.auth_epoch, this.graph))
    if (method === 'GET' && url.pathname === HISTORY_PATH) return response(200, historyPage())
    this.unexpected.push(`${method} ${url.pathname}`); throw new Error('Unconfigured HTTP boundary')
  }
}
let api: ExternalHTTP
let pages: VueWrapper[]
async function settle() { await flushPromises(); await nextTick() }
async function open(route = `/orgs/${ORG}/tree?as_of=${AS_OF}`) {
  window.history.replaceState({}, '', route)
  const page = mount(OrganizationPage, { attachTo: document.body }); pages.push(page); await settle(); return page
}
function action(page: VueWrapper, label: RegExp) {
  const controls = page.findAll('button').filter((item) => item.isVisible() && label.test(item.attributes('aria-label') ?? item.text()))
  expect(controls, `Accessible action ${label}`).toHaveLength(1); return controls[0]!
}
function row(page: VueWrapper, index: number) { return page.find(`[aria-label="变更项 ${index}"]`) }
async function rowValue(page: VueWrapper, index: number, field: string, value: string) { await row(page, index).find(`[id$="-${field}"]`).setValue(value) }
async function teamDraft(page: VueWrapper) {
  await page.find('#team-code').setValue('new_team')
  await page.find('#team-from').setValue(FROM)
  await page.find('[aria-label="创建稳定团队"]').trigger('submit'); await settle()
}
async function membershipDraft(page: VueWrapper) {
  await action(page, /^添加变更项$/).trigger('click')
  await rowValue(page, 1, 'employee', EMPLOYEE); await rowValue(page, 1, 'team', OTHER_TEAM); await rowValue(page, 1, 'from', TRANSFER)
  await page.find('[aria-label="原子组织结构变更"]').trigger('submit'); await settle()
}
beforeEach(() => { pages = []; api = new ExternalHTTP(); vi.stubGlobal('fetch', api.fetch) })
afterEach(() => { for (const page of pages) page.unmount(); document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks(); expect(api.unexpected).toEqual([]) })

describe('DEV-007 current-authority organization consumers', () => {
  it('requires an explicit business date and shows only bounded authorized metadata, never a guessed manager or hidden count', async () => {
    const page = await open(`/orgs/${ORG}/tree`)
    expect(page.find('[role="alert"]').text()).toContain('明确有效日期')
    expect(api.matching('GET', TREE_PATH)).toHaveLength(0)
    await page.find('#org-as-of').setValue(AS_OF)
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(page.find('[aria-label="当前获准组织树"]').text()).toContain(PARENT)
    expect(page.text()).not.toContain(PRIVATE_NAME)
    expect(page.text()).not.toContain('profile_revision')
    const request = api.matching('GET', TREE_PATH)[0]!
    expect(request.url.searchParams.get('include_labels')).toBe('false')
    expect(request.headers.get('X-Access-Purpose')).toBe('organization_management')
    expect(request.cache).toBe('no-store')
    expect(api.mutations()).toHaveLength(0)
  })
  it('creates a real typed team only after preview confirmation and reloads actual session rather than adopting receipt epoch', async () => {
    const page = await open(); await teamDraft(page)
    expect(api.mutations()).toHaveLength(0)
    expect(page.find('[aria-label="未提交组织命令预览"]').text()).toContain('未提交')
    const pending = api.defer('POST', TEAM_PATH)
    await action(page, /^确认提交原命令$/).trigger('click'); await settle()
    const submitted = api.mutations()[0]!
    expect(JSON.parse(submitted.body!)).toEqual({ code: 'new_team', lifecycle: { valid_from: FROM, valid_to: null } })
    expect(submitted.headers.get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/)
    expect(submitted.headers.get('X-CSRF-Token')).toBe(initialSession.csrf_token)
    api.session = { ...initialSession, auth_epoch: '7' }; api.graph = '8'
    pending.resolve(201, { id: OTHER_TEAM, graph_revision: '5', auth_epoch: '4' }); await settle()
    expect(page.text()).toContain('当前获准 graph_revision 8')
    expect(page.text()).toContain('epoch 7')
    expect(page.find('[aria-label="已确认原命令安全回执"]').text()).toContain('原 auth_epoch 4')
    expect(page.find<HTMLInputElement>('#team-code').element.value).toBe('')
  })
  it('submits ordinary transfer, administrative manager and lifecycle changes as one typed atomic command with exact original IDs', async () => {
    const page = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}`)
    const tenure = page.find('[aria-label="当前获准员工目录"]').findAll('li').find((item) => item.text().includes(MEMBERSHIP))!
    await tenure.find('button').trigger('click')
    await rowValue(page, 1, 'end', TRANSFER)
    await action(page, /^添加变更项$/).trigger('click')
    await rowValue(page, 2, 'employee', EMPLOYEE); await rowValue(page, 2, 'team', OTHER_TEAM); await rowValue(page, 2, 'from', TRANSFER)
    await action(page, /^添加变更项$/).trigger('click'); await rowValue(page, 3, 'kind', 'reporting_line')
    await rowValue(page, 3, 'employee', EMPLOYEE); await rowValue(page, 3, 'manager', MANAGER); await rowValue(page, 3, 'from', TRANSFER)
    await action(page, /^添加变更项$/).trigger('click'); await rowValue(page, 4, 'kind', 'employee_lifecycle')
    await rowValue(page, 4, 'employee', EMPLOYEE); await rowValue(page, 4, 'from', FROM); await rowValue(page, 4, 'to', '2027-01-01')
    await page.find('[aria-label="原子组织结构变更"]').trigger('submit'); await settle()
    expect(api.mutations()).toHaveLength(0)
    api.reply('POST', CHANGE_PATH, 422, { code: 'GRAPH_INVALID' })
    await action(page, /^确认提交原命令$/).trigger('click'); await settle()
    const command = JSON.parse(api.mutations()[0]!.body!)
    expect(command.expected_graph_revision).toBe('4')
    expect(command).not.toHaveProperty('reason')
    expect(command.changes).toEqual([
      { action: 'end', kind: 'membership', ref: MEMBERSHIP, end_date: TRANSFER },
      { action: 'add', kind: 'membership', employee_id: EMPLOYEE, team_id: OTHER_TEAM, is_primary: true, lifecycle: { valid_from: TRANSFER, valid_to: null } },
      { action: 'add', kind: 'reporting_line', employee_id: EMPLOYEE, manager_employee_id: MANAGER, reporting_kind: 'administrative', lifecycle: { valid_from: TRANSFER, valid_to: null } },
      { action: 'lifecycle', kind: 'employee_lifecycle', employee_id: EMPLOYEE, lifecycle: { valid_from: FROM, valid_to: '2027-01-01' } },
    ])
    expect(page.find('[aria-label="组织命令结果未知"]').exists()).toBe(false)
    expect(page.find('[aria-label="已确认原命令安全回执"]').exists()).toBe(false)
  })
  it('uses explicit correction and encrypted employee position plus org reason fields, without copying an old decrypted title', async () => {
    const page = await open(); await action(page, /^添加变更项$/).trigger('click')
    await rowValue(page, 1, 'kind', 'position'); await rowValue(page, 1, 'action', 'replace'); await rowValue(page, 1, 'ref', POSITION)
    await rowValue(page, 1, 'employee', EMPLOYEE); await rowValue(page, 1, 'from', FROM); await rowValue(page, 1, 'title', '合成更正职位'); await rowValue(page, 1, 'description', '合成加密描述')
    const reasonToggle = page.findAll<HTMLInputElement>('input[type="checkbox"]').find((item) => item.element.parentElement?.textContent?.includes('包含加密全局理由'))!
    await reasonToggle.setValue(true); await page.find('#structure-reason').setValue('合成全局加密理由')
    await page.find('[aria-label="原子组织结构变更"]').trigger('submit')
    api.reply('POST', CHANGE_PATH, 422, { code: 'PII_SCOPE_REQUIRED' })
    await action(page, /^确认提交原命令$/).trigger('click'); await settle()
    const command = JSON.parse(api.mutations()[0]!.body!)
    expect(command.reason).toBe('合成全局加密理由')
    expect(command.changes[0]).toEqual({ action: 'replace', kind: 'position', ref: POSITION, employee_id: EMPLOYEE, is_primary: true, lifecycle: { valid_from: FROM, valid_to: null }, position: { title: '合成更正职位', description: '合成加密描述' } })
    expect(page.text()).not.toContain('已确认原命令')
  })
  it('keeps names body-only and pages incomplete zero-hit scans with the exact original safe filters and name', async () => {
    const page = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}`)
    await page.find('#directory-profile').setValue(true); await page.find('#directory-q').setValue(PRIVATE_NAME)
    api.reply('POST', QUERY_PATH, 200, directory([], 'opaque-scan-cursor', true))
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(page.find('[aria-label="当前获准员工目录"]').text()).toContain('有界候选扫描尚未完成')
    api.reply('POST', QUERY_PATH, 200, directory([employee(true)]))
    await action(page, /^继续扫描下一页$/).trigger('click'); await settle()
    expect(page.text()).toContain(PRIVATE_NAME); expect(page.text()).toContain('合成获准职位')
    const requests = api.matching('POST', QUERY_PATH)
    expect(JSON.parse(requests.at(-1)!.body!)).toMatchObject({ q: PRIVATE_NAME, include_profile: true, cursor: 'opaque-scan-cursor', as_of: AS_OF })
    expect(requests.every((item) => !item.url.search && item.headers.get('Idempotency-Key') === null)).toBe(true)
    expect(window.location.href).not.toContain(encodeURIComponent(PRIVATE_NAME))
    expect(api.mutations()).toHaveLength(0)
  })
  it('does not bind changed filter drafts to an old cursor, and contextual team reads never infer descendant entitlement', async () => {
    const page = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}`)
    await page.find('#directory-team').setValue(TEAM)
    api.reply('POST', QUERY_PATH, 200, directory([], 'old-cursor', true))
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(api.matching('GET', '/api/v1/session').at(-1)!.url.searchParams.get('team_id')).toBe(TEAM)
    await page.find('#directory-team').setValue(OTHER_TEAM)
    const count = api.requests.length
    await action(page, /^继续扫描下一页$/).trigger('click'); await settle()
    expect(api.requests).toHaveLength(count)
    expect(page.find('[role="alert"]').text()).toContain('筛选草稿已改变')
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(JSON.parse(api.matching('POST', QUERY_PATH).at(-1)!.body!)).not.toHaveProperty('cursor')
  })
  it('retries unknown mutation using immutable exact UUID/body across epoch changes and never revives old sensitive tree labels', async () => {
    const page = await open()
    const labelToggle = page.findAll<HTMLInputElement>('input[type="checkbox"]').find((item) => item.element.parentElement?.textContent?.includes('请求获准的加密团队名称'))!
    await labelToggle.setValue(true)
    const safe = tree()
    api.reply('GET', TREE_PATH, 200, { ...safe, nodes: safe.nodes.map((node) => ({ ...node, label: PRIVATE_NAME })) })
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(page.find('[aria-label="当前获准组织树"]').text()).toContain(PRIVATE_NAME)
    await membershipDraft(page)
    const pending = api.defer('POST', CHANGE_PATH)
    await action(page, /^确认提交原命令$/).trigger('click'); await settle(); pending.reject(); await settle()
    expect(page.find('[aria-label="组织命令结果未知"]').exists()).toBe(true)
    expect(page.find('[aria-label="当前获准组织树"]').exists()).toBe(false)
    expect(page.text()).not.toContain(PRIVATE_NAME)
    const original = api.mutations()[0]!
    api.sessionStatus = 503
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    expect(api.mutations()).toHaveLength(1)
    expect(page.find('[aria-label="组织命令结果未知"]').exists()).toBe(true)
    api.sessionStatus = 200
    api.session = { ...initialSession, auth_epoch: '7' }; api.graph = '8'
    api.reply('POST', CHANGE_PATH, 200, { id: CHANGE, graph_revision: '5', auth_epoch: '4', items: [{ kind: 'membership', id: MEMBERSHIP }] })
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    const replay = api.mutations()[1]!
    expect(replay.body).toBe(original.body)
    expect(replay.headers.get('Idempotency-Key')).toBe(original.headers.get('Idempotency-Key'))
    expect(page.text()).toContain('当前获准 graph_revision 8')
    expect(page.find('[aria-label="组织命令结果未知"]').exists()).toBe(false)
    expect(page.find('[aria-label="已确认原命令安全回执"]').text()).toContain(MEMBERSHIP)
    expect(page.text()).not.toContain(PRIVATE_NAME)
  })
  it('requires conflict refresh and a new preview/key rather than silently altering an old command', async () => {
    const page = await open(); await membershipDraft(page)
    api.reply('POST', CHANGE_PATH, 409, { code: 'GRAPH_REVISION_CONFLICT' })
    await action(page, /^确认提交原命令$/).trigger('click'); await settle()
    expect(page.find('[aria-label="未提交组织命令预览"]').exists()).toBe(false)
    expect(page.find('[aria-label="组织命令结果未知"]').exists()).toBe(false)
    api.session = { ...initialSession, auth_epoch: '5' }; api.graph = '6'
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle(); await membershipDraft(page)
    api.reply('POST', CHANGE_PATH, 422, { code: 'GRAPH_INVALID' })
    await action(page, /^确认提交原命令$/).trigger('click'); await settle()
    expect(api.mutations()).toHaveLength(2)
    expect(JSON.parse(api.mutations()[1]!.body!).expected_graph_revision).toBe('6')
    expect(api.mutations()[1]!.headers.get('Idempotency-Key')).not.toBe(api.mutations()[0]!.headers.get('Idempotency-Key'))
  })
  it('retains original history IDs and immutable correction facts, not an inferred current manager', async () => {
    const page = await open(`/employees/${EMPLOYEE}/organization-history`)
    const view = page.find('[aria-label="获准组织历史"]')
    expect(view.text()).toContain(MEMBERSHIP); expect(view.text()).toContain(REPORTING)
    expect(view.text()).toContain('已永久被更正'); expect(view.text()).toContain('更正自')
    expect(view.text()).not.toContain(PRIVATE_NAME)
    expect(api.matching('GET', '/api/v1/session')[0]!.url.searchParams.get('employee_id')).toBe(EMPLOYEE)
    await action(page, /^按原 ID 结束任职$/).trigger('click')
    expect(row(page, 1).find<HTMLInputElement>('[id$="-ref"]').element.value).toBe(MEMBERSHIP)
    expect(api.mutations()).toHaveLength(0)
  })
  it('aborts route work and rejects late plaintext after a different route or session expiry', async () => {
    const pending = api.defer('POST', QUERY_PATH)
    const page = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}`)
    const earlier = api.matching('POST', QUERY_PATH)[0]!
    window.history.pushState({}, '', `/orgs/${ORG}/tree?as_of=${AS_OF}`); window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    expect(earlier.signal?.aborted).toBe(true)
    pending.resolve(200, directory([employee(true)])); await settle()
    expect(page.text()).not.toContain(PRIVATE_NAME)
    api.sessionStatus = 401
    await page.find('[aria-label="组织查询"]').trigger('submit'); await settle()
    expect(page.emitted('session-expired')).toHaveLength(1)
    expect(page.find('[aria-label="当前获准组织树"]').exists()).toBe(false)
    expect(page.find('[aria-label="原子组织结构变更"]').exists()).toBe(false)
  })
  it('reports oversized tree boundaries without displaying truncated topology or pretending success', async () => {
    api.reply('GET', TREE_PATH, 413, { code: 'TOO_LARGE' })
    const page = await open()
    expect(page.find('[role="alert"]').text()).toContain('没有截断拓扑')
    expect(page.find('[aria-label="当前获准组织树"]').exists()).toBe(false)
    expect(page.find('[aria-label="已确认原命令安全回执"]').exists()).toBe(false)
  })
  it('metadata-only directory ignores profile revision and exposes original relations without titles or manager inference', async () => {
    api.session = { ...initialSession, capabilities: ['organization.read', 'organization.write'] }
    api.reply('POST', QUERY_PATH, 200, directory([{ ...employee(), profile_revision: '987654321', reporting_lines: [] }]))
    const page = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}&q=${encodeURIComponent(PRIVATE_NAME)}`)
    expect(window.location.search).toBe(`?as_of=${AS_OF}`)
    expect(page.find<HTMLInputElement>('#directory-q').element.value).toBe('')
    const view = page.find('[aria-label="当前获准员工目录"]')
    expect(view.text()).toContain(MEMBERSHIP)
    expect(view.text()).toContain('查询日无获准经理关系')
    expect(page.text()).not.toContain('987654321')
    expect(page.text()).not.toContain(PRIVATE_NAME)
    expect(page.text()).not.toContain('合成获准职位')
    expect(page.find('#structure-reason').exists()).toBe(false)
    expect(page.find('#team-label').exists()).toBe(false)
    await action(page, /^添加变更项$/).trigger('click')
    expect(page.find('option[value="position"]').attributes()).toHaveProperty('disabled')
  })
  it('does not release unexpected position text or global reason under a metadata-only history session', async () => {
    api.session = { ...initialSession, capabilities: ['organization.read'] }
    const safe = historyPage()
    api.reply('GET', HISTORY_PATH, 200, { ...safe, items: safe.items.map((item) => ({ ...item, reason: '合成不获准理由', items: [{ action: 'add', kind: 'position', id: POSITION, employee_id: EMPLOYEE, valid_from: FROM, valid_to: null, position: { title: '合成不获准职位' } }] })) })
    const page = await open(`/employees/${EMPLOYEE}/organization-history`)
    expect(page.find('[aria-label="获准组织历史"]').exists()).toBe(false)
    expect(page.text()).not.toContain('合成不获准理由')
    expect(page.text()).not.toContain('合成不获准职位')
    expect(page.find('[role="alert"]').exists()).toBe(true)
  })
})
