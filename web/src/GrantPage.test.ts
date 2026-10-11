import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const MANAGER = '10000000-0000-4000-8000-000000000002'
const READER = '10000000-0000-4000-8000-000000000003'
const EMPLOYEE = '10000000-0000-4000-8000-000000000004'
const AUTHORITY = '10000000-0000-4000-8000-000000000005'
const GRANT = '10000000-0000-4000-8000-000000000006'
const OTHER = '10000000-0000-4000-8000-000000000007'
const EPOCH = '9007199254740993'
const REVISION = '9007199254740995'
const NEXT_EPOCH = '9007199254740994'
const START = '2026-10-11T00:00:00.123456Z'
const END = '2026-10-12T00:00:00.654321Z'
const authority = {
  id: AUTHORITY, capability: 'pii.read', category: 'pii', scope: { kind: 'employee', id: EMPLOYEE },
  purpose: 'organization_management', valid_from: '2026-01-01T00:00:00Z', expires_at: '2027-01-01T00:00:00Z',
  mfa_required: true, approved_by: OTHER, approved_at: '2025-12-01T00:00:00Z', policy_version: 'approved-policy-1',
  delegable_scopes: [{ kind: 'employee', id: EMPLOYEE }],
}
const session = {
  subject_id: MANAGER, org_id: ORG, auth_epoch: EPOCH, capabilities: ['access_grant.manage'],
  csrf_token: 'synthetic-grant-csrf', grant_authorities: [authority],
  mfa_recent: true, mfa_valid_until: '2027-01-01T00:00:00Z',
}
function grant(id = GRANT, status = 'current', revision = REVISION) {
  return {
    id, org_id: ORG, subject_id: READER, capability: 'pii.read', category: 'pii',
    scope: { kind: 'employee', id: EMPLOYEE }, purpose: 'organization_management',
    valid_from: START, expires_at: END, mfa_required: true, relation_bound: false,
    relation_ref: null, object_ref: null, revision, status, authority_id: AUTHORITY,
    policy_version: authority.policy_version, approved_by: OTHER, approved_at: authority.approved_at,
    issued_by: MANAGER, issued_at: START, revoked_by: status === 'revoked' ? MANAGER : null,
    revoked_at: status === 'revoked' ? END : null, revoke_reason: status === 'revoked' ? 'policy_change' : null,
  }
}
function list(items = [grant()], epoch = EPOCH, cursor: string | null = null, authorities = [authority]) {
  return { items, next_cursor: cursor, as_of: '2026-10-11', consistency: 'current', auth_epoch: epoch, authorities }
}
function response(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
function deferred() {
  let resolve!: (value: Response) => void
  let reject!: (cause: Error) => void
  const promise = new Promise<Response>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve: (status: number, body: unknown) => resolve(response(status, body)), reject: () => reject(new TypeError('Synthetic transport uncertainty')) }
}
type RequestRecord = { url: URL; method: string; headers: Headers; body: string | undefined; cache: RequestCache | undefined }
class ExternalHTTP {
  session: unknown = session
  sessionStatus = 200
  requests: RequestRecord[] = []
  unexpected: string[] = []
  replies: { method: string; path: string; reply: Promise<Response> }[] = []
  reply(method: string, path: string, status: number, body: unknown) {
    this.replies.push({ method, path, reply: Promise.resolve(response(status, body)) })
  }
  defer(method: string, path: string) {
    const pending = deferred()
    this.replies.push({ method, path, reply: pending.promise })
    return pending
  }
  commands() { return this.requests.filter((item) => item.method === 'POST') }
  fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), location.href)
    const method = init?.method ?? 'GET'
    this.requests.push({ url, method, headers: new Headers(init?.headers), body: init?.body as string | undefined, cache: init?.cache })
    if (url.pathname === '/api/v1/session') return response(this.sessionStatus, this.session)
    const index = this.replies.findIndex((item) => item.method === method && item.path === url.pathname)
    if (index < 0) { this.unexpected.push(`${method} ${url.pathname}`); throw new Error('Unconfigured HTTP response') }
    return this.replies.splice(index, 1)[0]!.reply
  }
}
let api: ExternalHTTP
let pages: VueWrapper[]
async function settle() { await flushPromises(); await nextTick() }
function action(page: VueWrapper, name: RegExp) {
  const found = page.findAll('button').filter((item) => item.isVisible() && name.test(item.attributes('aria-label') ?? item.text()))
  expect(found, `Accessible action ${name}`).toHaveLength(1)
  return found[0]!
}
function field(page: VueWrapper, name: RegExp) {
  const found = page.findAll<HTMLInputElement | HTMLSelectElement>('input,select').filter((item) => {
    const labels = Array.from(item.element.labels ?? []).map((label) => label.textContent).join(' ')
    return item.isVisible() && name.test(item.attributes('aria-label') ?? labels)
  })
  expect(found, `Accessible field ${name}`).toHaveLength(1)
  return found[0]!
}
async function open() {
  const page = mount(App, { attachTo: document.body }); pages.push(page)
  await settle()
  return page
}
async function draft(page: VueWrapper) {
  await action(page, /^新建授权$/).trigger('click')
  await field(page, /批准依据|authority/i).setValue(AUTHORITY)
  await field(page, /受授权主体/).setValue(READER)
  await field(page, /生效时间/).setValue(START)
  await field(page, /到期时间/).setValue(END)
  await action(page, /^预览授权$/).trigger('click')
  await settle()
}
async function select(page: VueWrapper, id = GRANT) {
  api.reply('GET', '/api/v1/access-grants', 200, list([grant(id)]))
  await action(page, new RegExp(`查看授权 ${id}`)).trigger('click'); await settle()
}
function cleared(page: VueWrapper) {
  expect(page.find('[aria-label="授权列表"]').exists()).toBe(false)
  expect(page.find('[aria-label="授权详情"]').exists()).toBe(false)
  for (const input of page.findAll<HTMLInputElement>('input')) expect(input.element.value).not.toContain(READER)
  expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
  expect(page.text()).not.toMatch(/授予成功|撤销成功/)
}
beforeEach(() => {
  pages = []; api = new ExternalHTTP(); vi.stubGlobal('fetch', api.fetch)
  history.replaceState({}, '', '/security/grants')
  api.reply('GET', '/api/v1/access-grants', 200, list())
})
afterEach(() => {
  for (const page of pages) page.unmount()
  document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks()
  expect(api.unexpected, 'Only configured external HTTP boundaries may be contacted').toEqual([])
})

describe('P-SEC-01 current independent grant management', () => {
  it('shows only safe current grant facts and independently approved authority without opening employee PII', async () => {
    const page = await open()
    expect(page.text()).toContain(GRANT); expect(page.text()).toContain(REVISION)
    expect(page.text()).toContain(authority.policy_version)
    await select(page)
    const detail = page.find('[aria-label="授权详情"]')
    expect(detail.text()).toContain(START); expect(detail.text()).toContain(END)
    expect(detail.text()).toContain(READER); expect(detail.text()).toContain('pii.read')
    expect(page.findAll(`a[href*="${EMPLOYEE}"]`)).toHaveLength(0)
    expect(api.requests.some((request) => request.url.pathname.includes('/employees/'))).toBe(false)
    expect(api.requests.every((request) => request.cache === 'no-store')).toBe(true)
  })
  it('requires preview and human confirmation, then reads committed grant under the intentionally changed epoch', async () => {
    const page = await open(); await draft(page)
    expect(api.commands()).toHaveLength(0)
    expect(page.find('[aria-label="授权预览"]').text()).toContain(READER)
    const pending = api.defer('POST', '/api/v1/access-grants')
    await action(page, /^确认授予$/).trigger('click'); await settle()
    const submitted = JSON.parse(api.commands()[0]!.body!)
    expect(submitted.valid_from).toBe(START); expect(submitted.expires_at).toBe(END)
    expect(submitted.expected_revision).toBe(EPOCH); expect(submitted.mfa_required).toBe(true)
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    api.reply('GET', '/api/v1/access-grants', 200, list([grant()], NEXT_EPOCH))
    pending.resolve(201, { id: GRANT, revision: REVISION, status: 'current', auth_epoch: NEXT_EPOCH }); await settle()
    expect(page.text()).toMatch(/授予成功/); expect(page.text()).toContain(GRANT)
    expect(page.find('[role="alert"]').exists()).toBe(false)
  })
  it('revoke requires a selected server detail and impact confirmation, and displays committed revoked state', async () => {
    const page = await open(); await select(page)
    await action(page, /^撤销此授权$/).trigger('click')
    await field(page, /撤销原因/).setValue('policy_change')
    expect(api.commands()).toHaveLength(0)
    const pending = api.defer('POST', `/api/v1/access-grants/${GRANT}/revoke`)
    await action(page, /^确认撤销$/).trigger('click'); await settle()
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(GRANT, 'revoked', '9007199254740996')], NEXT_EPOCH))
    pending.resolve(200, { id: GRANT, revision: '9007199254740996', status: 'revoked', auth_epoch: NEXT_EPOCH }); await settle()
    expect(page.text()).toMatch(/撤销成功/); expect(page.find('[aria-label="授权列表"]').text()).toContain('revoked')
    expect(api.commands()[0]!.body).toContain(REVISION)
  })
  it('filters and pages current safe results, then discards the cursor on a new filter', async () => {
    const page = await open()
    await field(page, /筛选状态/).setValue('future')
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(GRANT, 'future')], EPOCH, 'opaque-page'))
    await action(page, /^应用筛选$/).trigger('click'); await settle()
    expect(page.find('[aria-label="授权列表"]').text()).toContain('future')
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(OTHER, 'future')]))
    await action(page, /^下一页$/).trigger('click'); await settle()
    expect(page.find('[aria-label="授权列表"]').text()).toContain(OTHER)
    expect(page.find('[aria-label="授权列表"]').text()).not.toContain(GRANT)
    await field(page, /筛选状态/).setValue('revoked')
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(GRANT, 'revoked')]))
    await action(page, /^应用筛选$/).trigger('click'); await settle()
    const gets = api.requests.filter((request) => request.url.pathname === '/api/v1/access-grants')
    expect(gets.at(-2)!.url.searchParams.get('cursor')).toBe('opaque-page')
    expect(gets.at(-1)!.url.searchParams.has('cursor')).toBe(false)
    expect(page.text()).toContain('revoked')
  })
  it('409 discards confirmation and requires manual refresh plus a new preview rather than auto-resubmitting', async () => {
    const page = await open(); await draft(page)
    api.reply('POST', '/api/v1/access-grants', 409, { code: 'REVISION_CONFLICT' })
    await action(page, /^确认授予$/).trigger('click'); await settle()
    expect(page.find('[role="alert"]').text()).toMatch(/冲突/)
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
    expect(api.commands()).toHaveLength(1)
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    api.reply('GET', '/api/v1/access-grants', 200, list([], NEXT_EPOCH))
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    expect(api.commands()).toHaveLength(1)
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
  })
  for (const status of [401, 403, 404]) {
    it(`${status} clears list, detail, draft and pending confirmation`, async () => {
      const page = await open(); await draft(page)
      api.reply('POST', '/api/v1/access-grants', status, { code: 'DENIED' })
      await action(page, /^确认授予$/).trigger('click'); await settle()
      cleared(page); expect(page.find('[role="alert"]').exists()).toBe(true)
      if (status === 401) {
        expect(page.find('nav').exists()).toBe(false)
        expect(page.find('main').exists()).toBe(false)
        const requestCount = api.requests.length
        window.dispatchEvent(new Event('focus')); await settle()
        expect(api.requests).toHaveLength(requestCount)
        expect(page.find('main').exists()).toBe(false)
      }
    })
  }
  for (const change of ['epoch', 'subject', 'org', 'authority', 'management', 'mfa'] as const) {
    it(`${change} loss during confirmation clears data and never sends a command`, async () => {
      const page = await open(); await draft(page)
      api.session = {
        ...session, auth_epoch: change === 'epoch' ? NEXT_EPOCH : EPOCH,
        subject_id: change === 'subject' ? OTHER : MANAGER, org_id: change === 'org' ? OTHER : ORG,
        grant_authorities: change === 'authority' ? [] : [authority], capabilities: change === 'management' ? [] : session.capabilities,
        mfa_recent: change !== 'mfa',
      }
      await action(page, /^确认授予$/).trigger('click'); await settle()
      expect(api.commands()).toHaveLength(0); cleared(page)
    })
  }
  it('uncertain transport offers only explicit same-key same-body retry while context is unchanged', async () => {
    const page = await open(); await draft(page)
    const pending = api.defer('POST', '/api/v1/access-grants')
    await action(page, /^确认授予$/).trigger('click'); await settle(); pending.reject(); await settle()
    expect(page.text()).not.toMatch(/授予成功/); expect(api.commands()).toHaveLength(1)
    api.reply('POST', '/api/v1/access-grants', 503, { code: 'UNAVAILABLE' })
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    const commands = api.commands()
    expect(commands).toHaveLength(2); expect(commands[1]!.body).toBe(commands[0]!.body)
    expect(commands[1]!.headers.get('Idempotency-Key')).toBe(commands[0]!.headers.get('Idempotency-Key'))
    expect(page.text()).not.toMatch(/授予成功/)
  })
  it.each([NEXT_EPOCH, '9007199254740997'])('confirms an uncertain committed issue with its original command at current epoch %s', async (currentEpoch) => {
    const page = await open(); await draft(page)
    const pending = api.defer('POST', '/api/v1/access-grants')
    await action(page, /^确认授予$/).trigger('click'); await settle()
    // The server committed; only its response was lost. Later unrelated writes
    // may advance the epoch further without changing this command's receipt.
    api.session = { ...session, auth_epoch: currentEpoch }
    pending.reject(); await settle()
    expect(page.text()).not.toMatch(/授予成功/)
    api.reply('POST', '/api/v1/access-grants', 200, { id: GRANT, revision: REVISION, status: 'current', auth_epoch: NEXT_EPOCH })
    api.reply('GET', '/api/v1/access-grants', 200, list([grant()], currentEpoch))
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    const commands = api.commands()
    expect(commands).toHaveLength(2)
    expect(commands[1]!.body).toBe(commands[0]!.body)
    expect(commands[1]!.headers.get('Idempotency-Key')).toBe(commands[0]!.headers.get('Idempotency-Key'))
    expect(page.find('[aria-label="授权列表"]').text()).toContain(GRANT)
    expect(page.find('[role="alert"]').exists()).toBe(false)
    expect(page.text()).toMatch(/授予成功/)
  })
  it('confirms a committed revoke after its response was lost without creating a new revoke', async () => {
    const page = await open(); await select(page)
    await action(page, /^撤销此授权$/).trigger('click')
    const path = `/api/v1/access-grants/${GRANT}/revoke`
    const pending = api.defer('POST', path)
    await action(page, /^确认撤销$/).trigger('click'); await settle()
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    pending.reject(); await settle()
    api.reply('POST', path, 200, { id: GRANT, revision: '9007199254740996', status: 'revoked', auth_epoch: NEXT_EPOCH })
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(GRANT, 'revoked', '9007199254740996')], NEXT_EPOCH))
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    const commands = api.commands()
    expect(commands).toHaveLength(2)
    expect(commands[1]!.body).toBe(commands[0]!.body)
    expect(commands[1]!.headers.get('Idempotency-Key')).toBe(commands[0]!.headers.get('Idempotency-Key'))
    expect(page.find('[aria-label="授权列表"]').text()).toContain('revoked')
    expect(page.find('[role="alert"]').exists()).toBe(false)
  })
  it('a stale uncertain command without a committed receipt stays conflicted and is never replaced', async () => {
    const page = await open(); await draft(page)
    api.reply('POST', '/api/v1/access-grants', 503, { code: 'UNAVAILABLE' })
    await action(page, /^确认授予$/).trigger('click'); await settle()
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    api.reply('POST', '/api/v1/access-grants', 409, { code: 'STALE_REVISION' })
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    const commands = api.commands()
    expect(commands).toHaveLength(2); expect(commands[1]!.body).toBe(commands[0]!.body)
    expect(commands[1]!.headers.get('Idempotency-Key')).toBe(commands[0]!.headers.get('Idempotency-Key'))
    cleared(page)
  })
  it.each(['subject', 'org', 'authority', 'management', 'mfa'] as const)('an uncertain retry still refuses current %s loss before any retransmission', async (change) => {
    const page = await open(); await draft(page)
    api.reply('POST', '/api/v1/access-grants', 503, { code: 'UNAVAILABLE' })
    await action(page, /^确认授予$/).trigger('click'); await settle()
    api.session = {
      ...session, auth_epoch: NEXT_EPOCH, subject_id: change === 'subject' ? OTHER : MANAGER,
      org_id: change === 'org' ? OTHER : ORG, grant_authorities: change === 'authority' ? [] : [authority],
      capabilities: change === 'management' ? [] : session.capabilities, mfa_recent: change !== 'mfa',
    }
    await action(page, /^重试原命令$/).trigger('click'); await settle()
    expect(api.commands()).toHaveLength(1); cleared(page)
  })
  it('an org approval intersected with employee management cannot preview another employee', async () => {
    const restricted = { ...authority, scope: { kind: 'org', id: ORG } }
    api.session = { ...session, grant_authorities: [restricted] }
    api.replies.splice(0); api.reply('GET', '/api/v1/access-grants', 200, list([grant()], EPOCH, null, [restricted]))
    const page = await open()
    await action(page, /^新建授权$/).trigger('click')
    await field(page, /受授权主体/).setValue(READER)
    await field(page, /^授权 scope 类型$/).setValue('employee')
    await field(page, /^授权 scope ID$/).setValue(OTHER)
    await field(page, /生效时间/).setValue(START); await field(page, /到期时间/).setValue(END)
    await action(page, /^预览授权$/).trigger('click'); await settle()
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
    expect(api.commands()).toHaveLength(0)
    expect(page.find('[role="alert"]').exists()).toBe(true)
  })
  it('late list response cannot revive data after an authorization-denied newer refresh', async () => {
    const page = await open()
    const pending = api.defer('GET', '/api/v1/access-grants')
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    api.sessionStatus = 403
    window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    pending.resolve(200, list([grant(OTHER)])); await settle()
    cleared(page); expect(page.text()).not.toContain(OTHER)
  })
  it('list epoch mismatch clears safe metadata and never trusts stale authorities', async () => {
    const page = await open()
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(OTHER)], NEXT_EPOCH))
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    cleared(page); expect(page.text()).not.toContain(OTHER)
  })
  it('does not infer management or approved authority from an otherwise valid session', async () => {
    api.session = { ...session, capabilities: [], grant_authorities: [] }
    const page = await open(); cleared(page)
    expect(page.findAll('button').some((button) => /新建授权/.test(button.text()))).toBe(false)
    expect(api.commands()).toHaveLength(0)
  })
  it('rejects over-microsecond precision without silently rounding the grant interval', async () => {
    const page = await open(); await draft(page)
    await action(page, /^返回修改$/).trigger('click')
    await field(page, /生效时间/).setValue('2026-10-11T00:00:00.1234567Z')
    await action(page, /^预览授权$/).trigger('click'); await settle()
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
    expect(api.commands()).toHaveLength(0); expect(page.find('[role="alert"]').exists()).toBe(true)
  })
  it('leaving the route unmounts draft and ignores an old reply, then returning starts empty', async () => {
    const page = await open(); await draft(page)
    const pending = api.defer('POST', '/api/v1/access-grants')
    await action(page, /^确认授予$/).trigger('click'); await settle()
    history.pushState({}, '', '/unavailable'); window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    pending.resolve(201, { id: GRANT, revision: REVISION, status: 'current', auth_epoch: NEXT_EPOCH }); await settle()
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false); expect(page.text()).not.toContain(GRANT)
    api.reply('GET', '/api/v1/access-grants', 200, list([]))
    history.pushState({}, '', '/security/grants'); window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
    expect(page.text()).not.toMatch(/授予成功/)
  })
  it('navigation preserves the existing employee profile route and performs no grant-to-PII implicit linking', async () => {
    const page = await open()
    api.session = { ...session, capabilities: ['organization.read', 'pii.read'] }
    api.reply('GET', `/api/v1/employees/${EMPLOYEE}`, 200, {
      id: EMPLOYEE, org_id: ORG, profile_revision: '1', lifecycle: { valid_from: '2026-01-01', valid_to: null },
      as_of: '2026-10-11', authorization_date: '2026-10-11', profile: { display_name: '合成可读资料' },
    })
    history.pushState({}, '', `/employees/${EMPLOYEE}/profile?as_of=2026-10-11`)
    window.dispatchEvent(new PopStateEvent('popstate')); await settle()
    expect(page.text()).toContain('合成可读资料')
    expect(page.text()).not.toContain(GRANT)
  })
  it('stale revoke revision does not claim revocation or preserve a reusable confirmation', async () => {
    const page = await open(); await select(page)
    await action(page, /^撤销此授权$/).trigger('click')
    api.reply('POST', `/api/v1/access-grants/${GRANT}/revoke`, 409, { code: 'REVISION_CONFLICT' })
    await action(page, /^确认撤销$/).trigger('click'); await settle()
    expect(page.find('[aria-label="撤销影响"]').exists()).toBe(false)
    expect(page.text()).not.toMatch(/撤销成功/)
    expect(api.commands()).toHaveLength(1)
    api.reply('GET', '/api/v1/access-grants', 200, list([grant(GRANT, 'current', '9007199254740996')]))
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    expect(page.text()).toContain('9007199254740996'); expect(api.commands()).toHaveLength(1)
  })
  it('a committed receipt followed by unavailable current read never promotes preview to saved facts', async () => {
    const page = await open(); await draft(page)
    const pending = api.defer('POST', '/api/v1/access-grants')
    await action(page, /^确认授予$/).trigger('click'); await settle()
    api.session = { ...session, auth_epoch: NEXT_EPOCH }
    api.reply('GET', '/api/v1/access-grants', 503, { code: 'UNAVAILABLE' })
    pending.resolve(201, { id: OTHER, revision: '1', status: 'current', auth_epoch: NEXT_EPOCH }); await settle()
    expect(page.text()).not.toContain(OTHER); expect(page.text()).not.toMatch(/授予成功/)
    expect(page.find('[aria-label="授权列表"]').exists()).toBe(false)
    expect(page.findAll('button').some((button) => /重试原命令/.test(button.text()))).toBe(false)
  })
  it('a late selected detail cannot overwrite a newer denied session', async () => {
    const page = await open()
    const pending = api.defer('GET', '/api/v1/access-grants')
    await action(page, new RegExp(`查看授权 ${GRANT}`)).trigger('click'); await settle()
    api.sessionStatus = 401
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    pending.resolve(200, list([grant()])); await settle()
    cleared(page); expect(page.text()).not.toContain(GRANT)
  })
  it('historical unknown approval facts remain unknown rather than borrowing the current authority', async () => {
    const page = await open()
    const historical = { ...grant(), authority_id: null, policy_version: null, approved_by: null, approved_at: null, issued_by: null, issued_at: null }
    api.reply('GET', '/api/v1/access-grants', 200, { ...list(), items: [historical] })
    await action(page, new RegExp(`查看授权 ${GRANT}`)).trigger('click'); await settle()
    const detail = page.find('[aria-label="授权详情"]')
    expect(detail.text()).toContain(GRANT)
    expect(detail.text()).not.toContain(authority.policy_version); expect(detail.text()).not.toContain(OTHER)
  })
  it('a server response with non-independent references is not shown as an accepted independent grant', async () => {
    const page = await open()
    api.reply('GET', '/api/v1/access-grants', 200, { ...list(), items: [{ ...grant(OTHER), relation_bound: true, relation_ref: { kind: 'reporting_line', id: EMPLOYEE } }] })
    await action(page, /^刷新授权$/).trigger('click'); await settle()
    expect(page.text()).not.toContain(OTHER); expect(page.find('[aria-label="授权列表"]').exists()).toBe(false)
    expect(page.find('[role="alert"]').exists()).toBe(true)
  })
  for (const boundary of ['self', 'outside', 'invalid-date'] as const) {
    it(`rejects ${boundary} preview without issuing a command`, async () => {
      const page = await open(); await draft(page)
      await action(page, /^返回修改$/).trigger('click')
      if (boundary === 'self') await field(page, /受授权主体/).setValue(MANAGER)
      if (boundary === 'outside') await field(page, /到期时间/).setValue('2027-01-02T00:00:00Z')
      if (boundary === 'invalid-date') await field(page, /生效时间/).setValue('2026-02-30T00:00:00Z')
      await action(page, /^预览授权$/).trigger('click'); await settle()
      expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
      expect(api.commands()).toHaveLength(0); expect(page.find('[role="alert"]').exists()).toBe(true)
    })
  }
  it('never persists grant facts, session hints or unsubmitted drafts in browser storage', async () => {
    const persist = vi.spyOn(Storage.prototype, 'setItem')
    const page = await open(); await select(page); await draft(page)
    expect(persist).not.toHaveBeenCalled()
    expect(page.find('[aria-label="授权预览"]').text()).toContain(READER)
    await page.find('a[href="/"]').trigger('click'); await settle()
    expect(persist).not.toHaveBeenCalled()
    expect(page.text()).not.toContain(READER)
  })
  it('uses SPA main navigation to leave and reopen grants without recovering the old draft', async () => {
    const page = await open(); await draft(page)
    await page.find('a[href="/"]').trigger('click'); await settle()
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
    api.reply('GET', '/api/v1/access-grants', 200, list([]))
    await page.find('a[href="/security/grants"]').trigger('click'); await settle()
    expect(location.pathname).toBe('/security/grants')
    expect(page.find('[aria-label="授权列表"]').exists()).toBe(true)
    expect(page.find('[aria-label="授权预览"]').exists()).toBe(false)
  })
  it('narrows a preapproved org authority to an explicit employee without requiring manager PII rights', async () => {
    const orgAuthority = { ...authority, scope: { kind: 'org', id: ORG }, delegable_scopes: [{ kind: 'org', id: ORG }] }
    api.session = { ...session, grant_authorities: [orgAuthority] }
    api.replies = []
    api.reply('GET', '/api/v1/access-grants', 200, list([], EPOCH, null, [orgAuthority]))
    const page = await open()
    await action(page, /^新建授权$/).trigger('click')
    await field(page, /受授权主体/).setValue(READER)
    await field(page, /^授权 scope 类型/).setValue('employee')
    await field(page, /^授权 scope ID/).setValue(EMPLOYEE)
    await field(page, /生效时间/).setValue(START)
    await field(page, /到期时间/).setValue(END)
    await action(page, /^预览授权$/).trigger('click'); await settle()
    expect(page.find('[aria-label="授权预览"]').text()).toContain(EMPLOYEE)
    expect(page.find('[aria-label="授权预览"]').text()).toContain('employee')
    api.reply('POST', '/api/v1/access-grants', 503, { code: 'UNAVAILABLE' })
    await action(page, /^确认授予$/).trigger('click'); await settle()
    expect(JSON.parse(api.commands()[0]!.body!).scope).toEqual({ kind: 'employee', id: EMPLOYEE })
    expect(api.requests.some((request) => request.url.pathname.includes('/employees'))).toBe(false)
    expect(page.text()).not.toMatch(/授予成功/)
  })
})
