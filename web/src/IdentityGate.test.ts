import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Mock } from 'vitest'
import App from './App.vue'
import ProfilePage from './ProfilePage.vue'
import IdentityGate from './IdentityGate.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const SUBJECT = '10000000-0000-4000-8000-000000000002'
const EMPLOYEE = '10000000-0000-4000-8000-000000000003'
const OTHER = '10000000-0000-4000-8000-000000000004'
const AS_OF = '2026-10-11'
const PROFILE_PATH = `/api/v1/employees/${EMPLOYEE}`
const SAVED_NAME = '合成身份会话资料'
const DRAFT_NAME = '合成尚未提交资料'
const PROVIDER_URL = 'https://identity.example.invalid/authorize?transaction=synthetic-browser-bound'
const initialSession = {
  subject_id: SUBJECT, org_id: ORG, auth_epoch: '1', csrf_token: 'synthetic-csrf-initial',
  capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'],
  scope_kind: 'org', scope_id: ORG, mfa_recent: false, mfa_valid_until: '2026-10-11T00:00:00Z',
  grant_authorities: [], identity_available: true,
  sensitivity_valid_until: undefined as string | undefined,
}
function profile(name = SAVED_NAME, org = ORG) {
  return {
    id: EMPLOYEE, org_id: org, profile_revision: '1',
    lifecycle: { valid_from: '2026-10-01', valid_to: null }, as_of: AS_OF, authorization_date: AS_OF,
    profile: { local_name: name, work_contact: { email: 'synthetic-identity@example.invalid' } },
    identifiers: [], employment: [], education: [], job_assignments: [], reporting_lines: [],
  }
}
function response(status: number, body?: unknown, headers?: Record<string, string>) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  })
}
function deferred() {
  let resolve!: (value: Response) => void
  let reject!: (cause: Error) => void
  const promise = new Promise<Response>((accept, fail) => { resolve = accept; reject = fail })
  return {
    promise,
    resolve: (status: number, body?: unknown) => resolve(response(status, body)),
    reject: () => reject(new TypeError('Synthetic connection failure')),
  }
}
type RequestRecord = { url: URL; method: string; headers: Headers; body: string | undefined; signal: AbortSignal | null }
class ExternalHTTP {
  session = { ...initialSession }
  contextCapabilities: string[] | null = null
  requests: RequestRecord[] = []
  unexpected: string[] = []
  beforeLogout: (() => void) | null = null
  replies: { method: string; path: string; promise: Promise<Response> }[] = []
  reply(method: string, path: string, status: number, body?: unknown) {
    this.replies.push({ method, path, promise: Promise.resolve(response(status, body)) })
  }
  defer(method: string, path: string) {
    const pending = deferred()
    this.replies.push({ method, path, promise: pending.promise })
    return pending
  }
  matching(method: string, path: string) {
    return this.requests.filter((request) => request.method === method && request.url.pathname === path)
  }
  fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), window.location.href)
    const method = init?.method ?? 'GET'
    this.requests.push({ url, method, headers: new Headers(init?.headers), body: init?.body as string | undefined, signal: init?.signal ?? null })
    if (url.pathname === '/api/v1/auth/logout') this.beforeLogout?.()
    const index = this.replies.findIndex((reply) => reply.method === method && reply.path === url.pathname)
    // Deliberately deliver queued responses even when aborted: the client must reject late bytes.
    if (index >= 0) return this.replies.splice(index, 1)[0]!.promise
    if (url.pathname === '/api/v1/session') {
      const capabilities = url.searchParams.get('employee_id') === EMPLOYEE && this.contextCapabilities
        ? this.contextCapabilities : this.session.capabilities
      return response(200, { ...this.session, capabilities })
    }
    this.unexpected.push(`${method} ${url.pathname}`)
    throw new Error('Unconfigured external response')
  }
}
let api: ExternalHTTP
let pages: VueWrapper[]
let providerNavigation: Mock<(url: string) => void>
async function settled() { await flushPromises(); await nextTick() }
async function open() {
  const page = mount(App, { attachTo: document.body })
  pages.push(page)
  await settled()
  return page
}
function action(page: VueWrapper, name: RegExp) {
  const found = page.findAll('button').filter((item) => item.isVisible() && name.test(item.attributes('aria-label') ?? item.text()))
  expect(found, `Accessible action ${name}`).toHaveLength(1)
  return found[0]!
}
function identityState(page: VueWrapper) {
  return page.find('[aria-label="共同身份与会话"]').attributes('data-identity-state')
}
function closed(page: VueWrapper) {
  expect(page.find('nav').exists()).toBe(false)
  expect(page.findComponent(ProfilePage).exists()).toBe(false)
  expect(page.find('main').exists()).toBe(false)
  expect(page.text()).not.toContain(SAVED_NAME)
  expect(page.text()).not.toContain(DRAFT_NAME)
  expect(page.findAll('input,textarea')).toHaveLength(0)
}
async function edit(page: VueWrapper) {
  await action(page, /更正资料/).trigger('click')
  await page.find('#profile-local-name').setValue(DRAFT_NAME)
  await page.find('#profile-edit-reason').setValue('合成手工更正理由')
}
async function submit(page: VueWrapper) {
  const form = page.findAll('form').find((item) => item.find('#profile-local-name').exists())!
  await form.trigger('submit')
  await settled()
}
beforeEach(() => {
  api = new ExternalHTTP(); pages = []; providerNavigation = vi.fn<(url: string) => void>()
  history.replaceState({}, '', `/employees/${EMPLOYEE}?as_of=${AS_OF}`)
  vi.stubGlobal('fetch', api.fetch)
  // Mock only the browser navigation boundary, not a local login or MFA authority.
  const browserWindow = window
  const browserLocation = browserWindow.location
  const navigationLocation = {
    get href() { return browserLocation.href },
    get pathname() { return browserLocation.pathname },
    assign: providerNavigation,
  }
  vi.stubGlobal('window', new Proxy(browserWindow, {
    get(target, key) {
      if (key === 'location') return navigationLocation
      const value = Reflect.get(target, key)
      return typeof value === 'function' ? value.bind(target) : value
    },
  }))
})
afterEach(() => {
  for (const page of pages) page.unmount()
  document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers()
  expect(api.unexpected, 'Configure all external HTTP boundaries').toEqual([])
})

describe('shared protected identity interaction', () => {
  it('does not create protected consumers before the actual session check completes', async () => {
    const checking = api.defer('GET', '/api/v1/session')
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    expect(identityState(page)).toBe('checking'); closed(page)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(0)
    checking.resolve(200, initialSession); await settled()
    expect(identityState(page)).toBe('authenticated')
    expect(page.find('nav').exists()).toBe(true)
    expect(page.text()).toContain(SAVED_NAME)
  })

  it.each([401, 503])('keeps consumers closed after session HTTP %s until an explicit fresh check', async (status) => {
    api.reply('GET', '/api/v1/session', status, { code: 'UNAVAILABLE' })
    const page = await open()
    closed(page); expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(0)
    if (status === 401) {
      window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PopStateEvent('popstate')); await settled()
      expect(api.matching('GET', '/api/v1/session')).toHaveLength(1)
      closed(page)
    }
    api.reply('GET', PROFILE_PATH, 200, profile('合成重新核对后的资料'))
    await action(page, /^重新核对会话$/).trigger('click'); await settled()
    expect(page.text()).toContain('合成重新核对后的资料')
  })

  it('a newer session denial supersedes an earlier checking response without mounting a protected consumer', async () => {
    const earlier = api.defer('GET', '/api/v1/session')
    const page = await open()
    const oldCheck = api.matching('GET', '/api/v1/session')[0]!
    api.reply('GET', '/api/v1/session', 401, { code: 'UNAUTHENTICATED' })
    window.dispatchEvent(new Event('focus')); await settled()
    expect(oldCheck.signal?.aborted).toBe(true)
    expect(identityState(page)).toBe('expired'); closed(page)
    earlier.resolve(200, initialSession); await settled()
    expect(identityState(page)).toBe('expired'); closed(page)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(0)
  })

  it('a malformed session cannot open a protected page or issue identity mutations', async () => {
    api.reply('GET', '/api/v1/session', 200, { ...initialSession, csrf_token: '', auth_epoch: '1e3' })
    const page = await open()
    expect(identityState(page)).toBe('unavailable'); closed(page)
    expect(api.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(0)
  })

  it('does not use root capabilities as employee permissions', async () => {
    api.session = { ...initialSession, capabilities: [] }
    api.contextCapabilities = ['organization.read', 'pii.read', 'pii.write']
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    expect(page.text()).toContain(SAVED_NAME)
    await edit(page)
    expect(page.find('#profile-local-name').element).toHaveProperty('value', DRAFT_NAME)
  })

  it('destroys the edited consumer and aborts its command before logout, then rejects late success', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    const saving = api.defer('PATCH', `${PROFILE_PATH}/profile`)
    await submit(page)
    const command = api.matching('PATCH', `${PROFILE_PATH}/profile`)[0]!
    const revoking = api.defer('POST', '/api/v1/auth/logout')
    api.beforeLogout = () => { closed(page); expect(command.signal?.aborted).toBe(true) }
    await action(page, /^注销本会话$/).trigger('click'); await settled()
    expect(identityState(page)).toBe('logging-out'); closed(page)
    const logout = api.matching('POST', '/api/v1/auth/logout')[0]!
    expect(logout.headers.get('X-CSRF-Token')).toBe(initialSession.csrf_token)
    saving.resolve(200, { id: EMPLOYEE, profile_revision: '2' }); await settled()
    closed(page); expect(api.matching('GET', PROFILE_PATH)).toHaveLength(1)
    revoking.resolve(204); await settled()
    expect(identityState(page)).toBe('logged-out'); closed(page)
    window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PopStateEvent('popstate')); await settled()
    expect(identityState(page)).toBe('logged-out'); closed(page)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(1)
  })

  it.each([200, 401, 403, 503, 'network'] as const)('never labels unconfirmed revocation %s as logout success or reopens old pages', async (failure) => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    const revoking = api.defer('POST', '/api/v1/auth/logout')
    await action(page, /^注销本会话$/).trigger('click'); await settled()
    if (failure === 'network') revoking.reject()
    else revoking.resolve(failure, { code: 'UNAVAILABLE' })
    await settled()
    expect(identityState(page)).toBe('logout-failed'); closed(page)
    expect(page.find('[role="alert"]').exists()).toBe(true)
    const requests = api.requests.length
    window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PopStateEvent('popstate')); await settled()
    closed(page); expect(api.requests).toHaveLength(requests)
    api.reply('POST', '/api/v1/auth/logout', 204)
    await action(page, /^重试注销本会话$/).trigger('click'); await settled()
    expect(identityState(page)).toBe('logged-out'); closed(page)
  })

  it('rejects an earlier session response after logout has confirmed revocation', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    const checking = api.defer('GET', '/api/v1/session')
    await action(page, /^重新核对会话/).trigger('click'); await settled()
    const oldCheck = api.matching('GET', '/api/v1/session').at(-1)!
    closed(page)
    api.reply('POST', '/api/v1/auth/logout', 204)
    await action(page, /^注销本会话$/).trigger('click'); await settled()
    expect(oldCheck.signal?.aborted).toBe(true)
    checking.resolve(200, initialSession); await settled()
    expect(identityState(page)).toBe('logged-out'); closed(page)
    expect(api.matching('GET', PROFILE_PATH)).toHaveLength(1)
  })

  it.each(['subject', 'org', 'epoch'] as const)('destroys old data on a changed %s and requires a separate current-context check', async (change) => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    api.session = {
      ...initialSession, subject_id: change === 'subject' ? OTHER : SUBJECT,
      org_id: change === 'org' ? OTHER : ORG, auth_epoch: change === 'epoch' ? '2' : '1',
    }
    await action(page, /^重新核对会话/).trigger('click'); await settled()
    expect(identityState(page)).toBe('changed'); closed(page)
    expect(api.matching('PATCH', `${PROFILE_PATH}/profile`)).toHaveLength(0)
    api.reply('GET', PROFILE_PATH, 200, profile('合成新身份当前资料', api.session.org_id))
    await action(page, /^重新核对会话$/).trigger('click'); await settled()
    expect(page.text()).toContain('合成新身份当前资料')
    expect(page.text()).not.toContain(DRAFT_NAME)
  })

  it('a profile 401 closes the common gate, not just the child, without automatic session resurrection', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    api.reply('PATCH', `${PROFILE_PATH}/profile`, 401, { code: 'UNAUTHENTICATED' })
    await submit(page)
    expect(identityState(page)).toBe('expired'); closed(page)
    const requests = api.requests.length
    window.dispatchEvent(new Event('focus')); await settled()
    expect(api.requests).toHaveLength(requests); closed(page)
  })

  it('a newer denied session rejects an older profile response even if transport ignores cancellation', async () => {
    const oldProfile = api.defer('GET', PROFILE_PATH)
    const page = await open()
    const pendingRead = api.matching('GET', PROFILE_PATH)[0]!
    api.reply('GET', '/api/v1/session', 401, { code: 'UNAUTHENTICATED' })
    await action(page, /^重新核对会话/).trigger('click'); await settled()
    expect(identityState(page)).toBe('expired'); closed(page)
    expect(pendingRead.signal?.aborted).toBe(true)
    oldProfile.resolve(200, profile()); await settled()
    expect(identityState(page)).toBe('expired'); closed(page)
  })

  it('starts real provider MFA navigation using current CSRF, discards drafts and never submits business work', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    const starting = api.defer('POST', '/api/v1/auth/step-up')
    await action(page, /重新验证资料写入 MFA/).trigger('click'); await settled()
    expect(identityState(page)).toBe('mfa-starting'); closed(page)
    expect(providerNavigation).not.toHaveBeenCalled()
    const request = api.matching('POST', '/api/v1/auth/step-up')[0]!
    expect(request.headers.get('X-CSRF-Token')).toBe(initialSession.csrf_token)
    expect(JSON.parse(request.body!)).toEqual({ action: 'pii.write', return_to: `/employees/${EMPLOYEE}?as_of=${AS_OF}` })
    starting.resolve(200, { authorization_url: PROVIDER_URL }); await settled()
    expect(identityState(page)).toBe('mfa-redirecting'); closed(page)
    expect(providerNavigation).toHaveBeenCalledOnce()
    expect(api.matching('PATCH', `${PROFILE_PATH}/profile`)).toHaveLength(0)
    // A callback is a new document: only its fresh server session can restore pages.
    page.unmount(); pages = []
    api.session = { ...initialSession, csrf_token: 'synthetic-csrf-rotated', mfa_recent: true }
    api.reply('GET', PROFILE_PATH, 200, profile('合成认证返回重新读取资料'))
    const returned = await open()
    expect(identityState(returned)).toBe('authenticated')
    expect(returned.text()).toContain('合成认证返回重新读取资料')
    expect(returned.text()).not.toContain(DRAFT_NAME)
    expect(api.matching('PATCH', `${PROFILE_PATH}/profile`)).toHaveLength(0)
    api.reply('POST', '/api/v1/auth/logout', 204)
    await action(returned, /^注销本会话$/).trigger('click'); await settled()
    expect(api.matching('POST', '/api/v1/auth/logout')[0]!.headers.get('X-CSRF-Token')).toBe('synthetic-csrf-rotated')
  })

  it.each([
    [403, { code: 'MFA_REQUIRED' }], [503, { code: 'UNAVAILABLE' }],
    [200, { authorization_url: 'http://identity.example.invalid/authorize' }],
    [200, { authorization_url: 'https://identity.example.invalid/authorize#unsafe' }],
    [200, {}],
  ])('failed or unusable provider MFA response %s cannot locally restore sensitive pages', async (status, body) => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    api.reply('POST', '/api/v1/auth/step-up', status as number, body)
    await action(page, /重新验证资料写入 MFA/).trigger('click'); await settled()
    expect(identityState(page)).toBe('mfa-failed'); closed(page)
    expect(providerNavigation).not.toHaveBeenCalled()
    expect(api.matching('PATCH', `${PROFILE_PATH}/profile`)).toHaveLength(0)
  })

  it('MFA session expiry closes the gate rather than offering a locally authenticated page', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    api.reply('POST', '/api/v1/auth/step-up', 401, { code: 'UNAUTHENTICATED' })
    await action(page, /重新验证资料写入 MFA/).trigger('click'); await settled()
    expect(identityState(page)).toBe('expired'); closed(page)
    expect(providerNavigation).not.toHaveBeenCalled()
    const requestCount = api.requests.length
    window.dispatchEvent(new Event('focus')); await settled()
    expect(api.requests).toHaveLength(requestCount)
  })

  it('grant-management MFA remains a real identity interaction even when no delegated business grant is available', async () => {
    history.replaceState({}, '', '/security/grants')
    api.session = { ...initialSession, capabilities: ['access_grant.manage'] }
    const page = await open()
    expect(page.find('[aria-label="授权列表"]').exists()).toBe(false)
    expect(page.find('[role="alert"]').exists()).toBe(true)
    const starting = api.defer('POST', '/api/v1/auth/step-up')
    await action(page, /重新验证授权管理 MFA/).trigger('click'); await settled()
    expect(identityState(page)).toBe('mfa-starting'); closed(page)
    const request = api.matching('POST', '/api/v1/auth/step-up')[0]!
    expect(JSON.parse(request.body!)).toEqual({ action: 'access_grant.manage', return_to: '/security/grants' })
    starting.resolve(200, { authorization_url: PROVIDER_URL }); await settled()
    expect(identityState(page)).toBe('mfa-redirecting'); closed(page)
    expect(providerNavigation).toHaveBeenCalledOnce()
    expect(api.matching('POST', '/api/v1/access-grants')).toHaveLength(0)
  })

  it('logout supersedes pending MFA and rejects the earlier provider redirect', async () => {
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    const starting = api.defer('POST', '/api/v1/auth/step-up')
    await action(page, /重新验证资料写入 MFA/).trigger('click'); await settled()
    const earlier = api.matching('POST', '/api/v1/auth/step-up')[0]!
    api.reply('POST', '/api/v1/auth/logout', 204)
    await action(page, /^注销本会话$/).trigger('click'); await settled()
    expect(earlier.signal?.aborted).toBe(true)
    starting.resolve(200, { authorization_url: PROVIDER_URL }); await settled()
    expect(providerNavigation).not.toHaveBeenCalled()
    expect(identityState(page)).toBe('logged-out'); closed(page)
  })

  it.each([
    `as_of=${AS_OF}&display_name=synthetic-unapproved-query`,
    `as_of=${AS_OF}&as_of=2026-10-12`,
  ])('does not forward unrecognized or duplicated return parameters (%s) into MFA', async (query) => {
    history.replaceState({}, '', `/employees/${EMPLOYEE}?${query}`)
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open()
    api.reply('POST', '/api/v1/auth/step-up', 503, { code: 'UNAVAILABLE' })
    await action(page, /重新验证资料写入 MFA/).trigger('click'); await settled()
    const request = api.matching('POST', '/api/v1/auth/step-up')[0]!
    expect(JSON.parse(request.body!).return_to).toBe(`/employees/${EMPLOYEE}`)
    expect(request.body).not.toContain('synthetic-unapproved-query')
    expect(request.url.search).toBe('')
    closed(page)
  })
  it.each([
    [`/orgs/${ORG}/tree/?as_of=${AS_OF}`, `/orgs/${ORG}/tree?as_of=${AS_OF}`],
    [`/orgs/${ORG}/employees?as_of=${AS_OF}&q=synthetic-private-name`, `/orgs/${ORG}/employees`],
    [`/employees/${EMPLOYEE}/organization-history/?to=2026-11-01&from=2026-10-01`, `/employees/${EMPLOYEE}/organization-history?from=2026-10-01&to=2026-11-01`],
    [`/employees/${EMPLOYEE}/organization-history?from=2026-10-01&from=2026-10-02&to=2026-11-01`, `/employees/${EMPLOYEE}/organization-history`],
    [`/orgs/${ORG}/not-registered?as_of=${AS_OF}`, '/'],
  ])('keeps only canonical organization return paths and explicit safe dates (%s)', async (route, expected) => {
    history.replaceState({}, '', route)
    api.reply('GET', '/api/v1/session', 401, { code: 'UNAUTHENTICATED' })
    const page = await open()
    expect(identityState(page)).toBe('expired')
    const login = page.find('a[href^="/api/v1/auth/login"]')
    const target = new URL(login.attributes('href')!, location.href)
    expect(target.searchParams.get('return_to')).toBe(expected)
    expect(target.href).not.toContain('synthetic-private-name')
    expect(api.requests).toHaveLength(1)
  })
  it('renders local credentials after a mode-bound denial and submits only to the local login endpoint', async () => {
    api.replies.push({ method: 'GET', path: '/api/v1/session', promise: Promise.resolve(response(401, { code: 'UNAUTHENTICATED' }, { 'X-TeamLedger-Identity-Mode': 'local' })) })
    api.reply('POST', '/api/v1/auth/local/login', 200, { return_to: `/employees/${EMPLOYEE}` })
    const page = await open()
    expect(identityState(page)).toBe('expired')
    await page.get('#local-username').setValue('admin.user')
    await page.get('#local-password').setValue('correct horse battery staple')
    await page.get('form').trigger('submit')
    await settled()
    const request = api.matching('POST', '/api/v1/auth/local/login')[0]!
    expect(JSON.parse(request.body!)).toEqual({ username: 'admin.user', password: 'correct horse battery staple', return_to: `/employees/${EMPLOYEE}?as_of=${AS_OF}` })
    expect(providerNavigation).toHaveBeenCalledWith(`/employees/${EMPLOYEE}`)
  })

  it('changes a local password with session CSRF and closes the protected surface after server revocation', async () => {
    api.session = { ...api.session, identity_mode: 'local', identity_available: false } as typeof api.session
    api.reply('GET', PROFILE_PATH, 200, profile())
    api.reply('POST', '/api/v1/auth/local/password', 204)
    const page = await open()
    await page.get('#current-password').setValue('correct horse battery staple')
    await page.get('#new-password').setValue('replacement horse battery staple')
    await page.get('form').trigger('submit')
    await settled()
    const request = api.matching('POST', '/api/v1/auth/local/password')[0]!
    expect(request.headers.get('X-CSRF-Token')).toBe(initialSession.csrf_token)
    expect(JSON.parse(request.body!)).toEqual({ current_password: 'correct horse battery staple', new_password: 'replacement horse battery staple' })
    expect(identityState(page)).toBe('logged-out')
    expect(page.find('nav').exists()).toBe(false)
    expect(page.findComponent(ProfilePage).exists()).toBe(false)
    expect(page.text()).not.toContain(SAVED_NAME)
  })

})

describe('R3 session-wide interview MFA intents', () => {
  it.each([
    ['/interviews', 'note.publish', '重新验证笔记发布 MFA'],
    [`/employees/${EMPLOYEE}/interviews`, 'sensitive.export', '重新验证敏感导出 MFA'],
    [`/interviews/${OTHER}`, 'note.publish', '重新验证笔记发布 MFA'],
  ])('retains legal return route %s and submits only current session intent %s', async (route, intent, label) => {
    history.replaceState({}, '', `${route}?untrusted_body=must-not-return`)
    const page = mount(IdentityGate, { attachTo: document.body, slots: { default: '<p>受保护业务插槽</p>' } }); pages.push(page)
    await settled()
    await page.get('#interview-stepup-intent').setValue(intent)
    const starting = api.defer('POST', '/api/v1/auth/step-up')
    await action(page, new RegExp(`^${label}$`)).trigger('click'); await settled()
    expect(JSON.parse(api.matching('POST', '/api/v1/auth/step-up')[0]!.body!)).toEqual({ action: intent, return_to: route })
    expect(page.text()).not.toContain('受保护业务插槽')
    starting.resolve(200, { authorization_url: PROVIDER_URL }); await settled()
    expect(providerNavigation).toHaveBeenCalledOnce()
    expect(api.requests.filter(request => request.method === 'POST')).toHaveLength(1)
    expect(api.requests.some(request => request.url.pathname.includes('note-versions') || request.url.pathname.includes('sensitive-exports'))).toBe(false)
  })
  it('does not falsely report missing identity facilities on legal interview route', async () => {
    history.replaceState({}, '', '/interviews')
    const page = mount(IdentityGate, { attachTo: document.body }); pages.push(page); await settled()
    expect(page.text()).toContain('MFA 是会话级近期认证')
    expect(page.text()).not.toContain('可信登录与 MFA 设施未启用')
  })
})

describe('shared gate current sensitivity clock boundary', () => {
  it('destroys real protected profile and aborts pending write at server expiry without locally inventing token validity', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] }); vi.setSystemTime(new Date('2026-10-11T12:00:00Z'))
    api.session = { ...initialSession, sensitivity_valid_until: '2026-10-11T12:00:02Z' }
    api.reply('GET', PROFILE_PATH, 200, profile())
    const page = await open(); await edit(page)
    const pending = api.defer('PATCH', `${PROFILE_PATH}/profile`)
    await submit(page)
    const command = api.matching('PATCH', `${PROFILE_PATH}/profile`)[0]!
    const readsBeforeBoundary = api.matching('GET', '/api/v1/session').length
    vi.advanceTimersByTime(2000); await settled()
    expect(identityState(page)).toBe('changed'); closed(page); expect(command.signal?.aborted).toBe(true)
    pending.resolve(200, { id: EMPLOYEE, profile_revision: '2', profile: profile().profile }); await settled()
    closed(page)
    expect(api.matching('GET', '/api/v1/session')).toHaveLength(readsBeforeBoundary)
  })
})

describe('R4 financial MFA intents and strict safe return routes', () => {
  it.each(['compensation.read', 'compensation.propose', 'compensation.approve', 'sensitive.export'])('submits finite %s intent without issuing any financial operation', async intent => {
    history.replaceState({}, '', `/employees/${EMPLOYEE}/compensation?as_of=${AS_OF}`)
    const page = mount(IdentityGate, { attachTo: document.body, slots: { default: '<p>financial protected slot</p>' } }); pages.push(page); await settled()
    expect(api.matching('GET', '/api/v1/session')[0]!.headers.get('X-Access-Purpose')).toBe('compensation_management')
    await page.get('#compensation-stepup-intent').setValue(intent)
    const pending = api.defer('POST', '/api/v1/auth/step-up')
    await action(page, /^重新验证财务 MFA$/).trigger('click'); await settled()
    expect(JSON.parse(api.matching('POST', '/api/v1/auth/step-up')[0]!.body!)).toEqual({ action: intent, return_to: `/employees/${EMPLOYEE}/compensation?as_of=${AS_OF}` })
    expect(page.text()).not.toContain('financial protected slot')
    pending.resolve(200, { authorization_url: PROVIDER_URL }); await settled()
    expect(providerNavigation).toHaveBeenCalledOnce(); expect(api.requests.filter(request => request.method === 'POST')).toHaveLength(1)
  })
  it.each([
    [`/employees/${EMPLOYEE}/compensation/?as_of=${AS_OF}`, `/employees/${EMPLOYEE}/compensation?as_of=${AS_OF}`],
    [`/employees/${EMPLOYEE}/compensation?as_of=${AS_OF}&reason=synthetic-financial-secret`, `/employees/${EMPLOYEE}/compensation`],
    [`/employees/${EMPLOYEE}/compensation?as_of=2026-02-30`, `/employees/${EMPLOYEE}/compensation`],
    [`/employees/not-a-uuid/compensation`, '/'],
    [`/orgs/${ORG}/compensation-adjustments/`, `/orgs/${ORG}/compensation-adjustments`],
    ['/orgs/not-a-uuid/compensation-adjustments', '/'],
  ])('retains only canonical financial route/date (%s)', async (route, expected) => {
    history.replaceState({}, '', route); api.reply('GET', '/api/v1/session', 401, { code: 'UNAUTHENTICATED' })
    const page = await open(); const login = page.get('a[href^="/api/v1/auth/login"]')
    expect(new URL(login.attributes('href')!, location.href).searchParams.get('return_to')).toBe(expected)
    expect(login.attributes('href')).not.toContain('synthetic-financial-secret')
  })
})
