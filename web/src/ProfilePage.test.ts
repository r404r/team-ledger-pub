import { flushPromises, mount } from '@vue/test-utils'
import type { DOMWrapper, VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ProfilePage from './ProfilePage.vue'

const ORG_ID = '10000000-0000-4000-8000-000000000001'
const EMPLOYEE_ID = '10000000-0000-4000-8000-000000000010'
const OTHER_EMPLOYEE_ID = '10000000-0000-4000-8000-000000000011'
const SUBJECT_ID = '10000000-0000-4000-8000-000000000020'
const REQUEST_ID = '10000000-0000-4000-8000-000000000030'
const AS_OF = '2026-10-11'
const VALID_FROM = '2026-10-01'
const EMPLOYEE_PATH = `/api/v1/employees/${EMPLOYEE_ID}`
const OTHER_EMPLOYEE_PATH = `/api/v1/employees/${OTHER_EMPLOYEE_ID}`
const CREATE_PATH = `/api/v1/orgs/${ORG_ID}/employees`
const CORRECTION_PATH = `${EMPLOYEE_PATH}/profile`
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

const SESSION = {
  subject_id: SUBJECT_ID,
  org_id: ORG_ID,
  auth_epoch: '1',
  capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'],
  csrf_token: 'synthetic-csrf-token',
}

const ORIGINAL_PROFILE = {
  display_name: '合成资料甲',
  work_contact: { email: 'fixture-a@example.invalid', phone: '+00-000-0001' },
  profile_summary: '仅用于测试的合成资料摘要甲',
}
const DRAFT_NAME = '合成未提交资料乙'
const DRAFT_REASON = '合成资料更正理由'

function employee(
  profile = ORIGINAL_PROFILE,
  revision = '1',
  id = EMPLOYEE_ID,
) {
  return {
    id,
    org_id: ORG_ID,
    profile_revision: revision,
    lifecycle: { valid_from: VALID_FROM, valid_to: null },
    as_of: AS_OF,
    authorization_date: AS_OF,
    profile,
  }
}

function error(code: string) {
  return { code, request_id: REQUEST_ID }
}

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  let reject!: (cause: Error) => void
  const promise = new Promise<Response>((accept, fail) => {
    resolve = accept
    reject = fail
  })
  return {
    promise,
    resolve: (status: number, body: unknown) => resolve(jsonResponse(status, body)),
    reject: () => reject(new TypeError('Synthetic external network failure')),
  }
}

type NetworkRequest = {
  method: string
  url: URL
  headers: Headers
  body: unknown
  signal: AbortSignal | null
}

class NetworkFixture {
  requests: NetworkRequest[] = []
  unexpected: string[] = []
  session: unknown = SESSION
  sessionStatus = 200
  private replies: { method: string; path: string; response: Promise<Response> }[] = []
  private fallbacks: { method: string; path: string; status: number; body: unknown }[] = []

  respond(method: string, path: string, status: number, body: unknown) {
    this.replies.push({ method, path, response: Promise.resolve(jsonResponse(status, body)) })
  }

  respondRepeatedly(method: string, path: string, status: number, body: unknown) {
    this.fallbacks.push({ method, path, status, body })
  }

  defer(method: string, path: string) {
    const response = deferredResponse()
    this.replies.push({ method, path, response: response.promise })
    return response
  }

  matching(method: string, path: string) {
    return this.requests.filter((request) => request.method === method && request.url.pathname === path)
  }

  fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : null
    const url = new URL(request ? request.url : String(input), window.location.href)
    const method = (init?.method ?? request?.method ?? 'GET').toUpperCase()
    const rawBody = init?.body ?? (request ? await request.clone().text() : null)
    this.requests.push({
      method,
      url,
      headers: new Headers(init?.headers ?? request?.headers),
      body: typeof rawBody === 'string' && rawBody !== '' ? JSON.parse(rawBody) : undefined,
      signal: init?.signal ?? request?.signal ?? null,
    })
    if (method === 'GET' && url.pathname === '/api/v1/session') {
      const body = typeof this.session === 'function' ? this.session(url) : this.session
      return jsonResponse(this.sessionStatus, body)
    }
    const index = this.replies.findIndex((reply) => reply.method === method && reply.path === url.pathname)
    if (index === -1) {
      const fallback = this.fallbacks.find((reply) => reply.method === method && reply.path === url.pathname)
      if (fallback) return jsonResponse(fallback.status, fallback.body)
      this.unexpected.push(`${method} ${url.pathname}`)
      throw new Error('Unconfigured external network request')
    }
    // Do not honor abort here: a reply already on the wire can still arrive.
    return this.replies.splice(index, 1)[0]!.response
  }
}

type FormControl = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
let api: NetworkFixture
let mounted: { page: VueWrapper; host: HTMLElement }[]

async function settled() {
  await flushPromises()
  await nextTick()
}

function accessibleName(element: Element) {
  const ariaLabel = element.getAttribute('aria-label')
  if (ariaLabel) return ariaLabel
  const labelledBy = element.getAttribute('aria-labelledby')
  if (labelledBy) {
    return labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ')
  }
  if ('labels' in element) {
    const labels = Array.from((element as FormControl).labels ?? [])
    if (labels.length) return labels.map((label) => label.textContent ?? '').join(' ')
  }
  return element.textContent ?? element.getAttribute('value') ?? ''
}

function field(page: VueWrapper, label: RegExp): DOMWrapper<FormControl> {
  const controls = page.findAll<FormControl>('input:not([type="hidden"]),textarea,select')
    .filter((control) => control.isVisible() && label.test(accessibleName(control.element)))
  expect(controls, `Users must be able to enter the field labelled ${label}`).toHaveLength(1)
  return controls[0]!
}

function action(page: VueWrapper, label: RegExp) {
  const buttons = page.findAll('button,[role="button"],input[type="submit"]')
    .filter((button) => button.isVisible() && label.test(accessibleName(button.element)))
  expect(buttons, `Users must have an accessible ${label} action`).toHaveLength(1)
  return buttons[0]!
}

async function submitProfile(page: VueWrapper) {
  const name = field(page, /姓名|display_name/i)
  const forms = page.findAll('form').filter((form) => form.element.contains(name.element))
  expect(forms, 'The profile fields must support user form submission').toHaveLength(1)
  await forms[0]!.trigger('submit')
  await settled()
}

function expectDetails(page: VueWrapper, name: string, revision: string) {
  expect(page.text(), 'A loaded profile must display the authoritative GET result').toContain(name)
  const labelledRevision = new RegExp(
    `(?:(?:profile[_ ]?)?revision|资料版本|资料修订|版本|修订号)[^0-9]{0,24}${revision}(?![0-9])`,
    'i',
  )
  expect(page.text(), 'Users must see the exact committed revision beside its semantic label').toMatch(labelledRevision)
}

function expectSensitiveCleared(page: VueWrapper, values: string[]) {
  for (const value of values) {
    expect(page.text(), 'Revoked or departed pages must not retain sensitive details').not.toContain(value)
    for (const control of page.findAll<FormControl>('input,textarea,select')) {
      expect(control.element.value, 'Sensitive form values must be cleared, not merely hidden').not.toContain(value)
    }
  }
}

function expectMutation(request: NetworkRequest) {
  expect(request.headers.get('Content-Type')).toMatch(/^application\/json(?:;|$)/)
  expect(request.headers.get('X-CSRF-Token')).toBe(SESSION.csrf_token)
  expect(request.headers.get('X-Access-Purpose')).toBe('organization_management')
  expect(request.headers.get('Idempotency-Key')).toMatch(UUID)
}

async function openPage(path = `/employees/${EMPLOYEE_ID}?as_of=${AS_OF}`) {
  window.history.replaceState({}, '', path)
  const host = document.createElement('div')
  document.body.append(host)
  const page = mount(ProfilePage, { attachTo: host })
  mounted.push({ page, host })
  await settled()
  return page
}

async function navigate(path: string) {
  window.history.pushState({}, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
  await settled()
}

async function startCorrection(page: VueWrapper) {
  await action(page, /更正|编辑|edit/i).trigger('click')
  await field(page, /姓名|display_name/i).setValue(DRAFT_NAME)
  await field(page, /更正理由|修改原因|edit_reason/i).setValue(DRAFT_REASON)
}

beforeEach(() => {
  api = new NetworkFixture()
  mounted = []
  vi.stubGlobal('fetch', api.fetch)
})

afterEach(() => {
  for (const { page, host } of mounted) {
    page.unmount()
    host.remove()
  }
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
  expect(api.unexpected, 'Tests must configure every external API response').toEqual([])
})

describe('F-ORG-001 / F-SEC-001: authorized profile consumers', () => {
  it('reloads an employee from the real GET result and displays its exact profile revision', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee(ORIGINAL_PROFILE, '9007199254740993'))
    const page = await openPage()

    expectDetails(page, ORIGINAL_PROFILE.display_name, '9007199254740993')
    expect(page.text()).toContain(ORIGINAL_PROFILE.work_contact.email)
    expect(page.text()).toContain(ORIGINAL_PROFILE.work_contact.phone)
    expect(page.text()).toContain(ORIGINAL_PROFILE.profile_summary)
    const [read] = api.matching('GET', EMPLOYEE_PATH)
    expect(read!.url.searchParams.get('as_of')).toBe(AS_OF)
    expect(read!.url.searchParams.get('include_profile')).toBe('true')
    expect(read!.headers.get('X-Access-Purpose')).toBe('organization_management')
  })

  it('allows an employee-only reader/writer to reload and correct its approved employee without organization-wide capabilities', async () => {
    api.session = (url: URL) => ({
      ...SESSION,
      capabilities: url.searchParams.get('employee_id') === EMPLOYEE_ID
        ? ['organization.read', 'pii.read', 'pii.write']
        : [],
    })
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '2' })
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, display_name: '合成员工范围保存结果' }, '2'))
    await submitProfile(page)
    expectDetails(page, '合成员工范围保存结果', '2')
    expect(page.text()).not.toContain(DRAFT_NAME)
  })

  it('creates from user inputs and confirms saved details only by loading the real GET result', async () => {
    const created = api.defer('POST', CREATE_PATH)
    const reloaded = api.defer('GET', EMPLOYEE_PATH)
    const serverProfile = {
      display_name: '合成服务端读取结果丙',
      work_contact: { email: 'fixture-server@example.invalid', phone: '+00-000-0003' },
      profile_summary: '服务端实际读取的合成摘要',
    }
    const page = await openPage(`/?as_of=${AS_OF}`)
    await field(page, /姓名|display_name/i).setValue(DRAFT_NAME)
    await field(page, /邮箱|email/i).setValue('fixture-create@example.invalid')
    await field(page, /电话|phone/i).setValue('+00-000-0002')
    await field(page, /摘要|简介|profile_summary/i).setValue('合成创建摘要')
    await field(page, /生效日|开始日期|valid_from/i).setValue(VALID_FROM)
    await field(page, /结束日|结束日期|valid_to/i).setValue('')
    await submitProfile(page)

    const commands = api.matching('POST', CREATE_PATH)
    expect(commands).toHaveLength(1)
    expectMutation(commands[0]!)
    expect(commands[0]!.body).toEqual({
      profile: {
        display_name: DRAFT_NAME,
        work_contact: { email: 'fixture-create@example.invalid', phone: '+00-000-0002' },
        profile_summary: '合成创建摘要',
      },
      lifecycle: { valid_from: VALID_FROM, valid_to: null },
    })
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(0)

    created.resolve(201, { id: EMPLOYEE_ID, profile_revision: '1' })
    await settled()
    const reads = api.matching('GET', EMPLOYEE_PATH)
    expect(reads, 'A create receipt is not a saved profile: the UI must actually reload it').toHaveLength(1)
    expect(reads[0]!.url.searchParams.get('as_of')).toBe(AS_OF)
    expect(reads[0]!.url.searchParams.get('include_profile')).toBe('true')
    expect(page.text()).not.toContain(serverProfile.display_name)

    reloaded.resolve(200, employee(serverProfile))
    await settled()
    expectDetails(page, serverProfile.display_name, '1')
    expect(page.text()).toContain(serverProfile.work_contact.email)
    expect(page.text()).toContain(serverProfile.profile_summary)
    expect(page.text()).not.toContain(DRAFT_NAME)
    for (const request of api.requests) {
      expect(request.url.href).not.toContain(encodeURIComponent(DRAFT_NAME))
      expect(request.url.href).not.toContain('fixture-create')
    }
  })

  it('submits a complete correction, omits cleared optional fields, and reloads without rounding the revision', async () => {
    const oldRevision = '9007199254740993'
    const newRevision = '9007199254740994'
    api.respond('GET', EMPLOYEE_PATH, 200, employee(ORIGINAL_PROFILE, oldRevision))
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, oldRevision)
    await startCorrection(page)
    await field(page, /邮箱|email/i).setValue('')
    await field(page, /电话|phone/i).setValue('')
    await field(page, /摘要|简介|profile_summary/i).setValue('')
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: newRevision })
    const reload = api.defer('GET', EMPLOYEE_PATH)
    await submitProfile(page)

    const [command] = api.matching('PATCH', CORRECTION_PATH)
    expectMutation(command!)
    expect(command!.body).toEqual({
      expected_profile_revision: oldRevision,
      profile: { display_name: DRAFT_NAME },
      edit_reason: DRAFT_REASON,
    })
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(2)
    const authoritativeName = '合成更正后实际读取资料丁'
    expect(page.text()).not.toContain(authoritativeName)
    reload.resolve(200, {
      ...employee(ORIGINAL_PROFILE, newRevision),
      profile: { display_name: authoritativeName },
    })
    await settled()

    expectDetails(page, authoritativeName, newRevision)
    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
    ])
  })

  it.each([
    [422, 'INVALID_INPUT'],
    [503, 'UNAVAILABLE'],
  ])('does not show a failed correction as saved after HTTP %s', async (status, code) => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    api.respondRepeatedly('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    const failed = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    failed.resolve(status, error(code))
    await settled()

    expect(page.find('[role="alert"]').exists(), 'A rejected save must remain visibly unsuccessful').toBe(true)
    expect(field(page, /姓名|display_name/i).element.value).toBe(DRAFT_NAME)
    expect(field(page, /更正理由|修改原因|edit_reason/i).element.value).toBe(DRAFT_REASON)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    expect(page.text()).not.toContain(DRAFT_NAME)
  })

  it('keeps an external network failure unsuccessful and preserves the authorized unsaved edit', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    api.respondRepeatedly('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    const failed = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    failed.reject()
    await settled()

    expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(field(page, /姓名|display_name/i).element.value).toBe(DRAFT_NAME)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('does not confirm a committed correction when its authoritative reload fails', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '2' })
    api.respond('GET', EMPLOYEE_PATH, 503, error('UNAVAILABLE'))
    await submitProfile(page)

    expect(page.find('[role="alert"]').exists(), 'Save acknowledgement alone cannot confirm reloaded details').toBe(true)
    expect(page.text()).not.toContain(DRAFT_NAME)
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, display_name: '合成后续确认资料戊' }, '2'))
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, '合成后续确认资料戊', '2')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('rejects stale revisions without overwriting and requires a fresh server revision for a manual retry', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    api.respondRepeatedly('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 409, error('CONFLICT'))
    await submitProfile(page)

    expect(page.find('[role="alert"]').exists(), 'A stale revision must be visibly rejected').toBe(true)
    expect(field(page, /姓名|display_name/i).element.value).toBe(DRAFT_NAME)
    expect(field(page, /更正理由|修改原因|edit_reason/i).element.value).toBe(DRAFT_REASON)
    const firstCommands = api.matching('PATCH', CORRECTION_PATH)
    expect(firstCommands, 'Conflict handling must never retry or overwrite automatically').toHaveLength(1)
    expect(firstCommands[0]!.body).toMatchObject({ expected_profile_revision: '1' })

    const otherWriter = { ...ORIGINAL_PROFILE, display_name: '合成另一维护者已提交资料己' }
    api.respond('GET', EMPLOYEE_PATH, 200, employee(otherWriter, '2'))
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, otherWriter.display_name, '2')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '3' })
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, display_name: DRAFT_NAME }, '3'))
    await submitProfile(page)

    const commands = api.matching('PATCH', CORRECTION_PATH)
    expect(commands).toHaveLength(2)
    expect(commands[1]!.body).toMatchObject({ expected_profile_revision: '2', edit_reason: DRAFT_REASON })
    expect(commands[1]!.headers.get('Idempotency-Key')).not.toBe(commands[0]!.headers.get('Idempotency-Key'))
    expectMutation(commands[1]!)
    expectDetails(page, DRAFT_NAME, '3')
  })

  it.each([
    [401, 'UNAUTHENTICATED'],
    [403, 'FORBIDDEN'],
    [404, 'NOT_FOUND'],
  ])('clears sensitive details and all editing values when a save loses authorization with HTTP %s', async (status, code) => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, status, error(code))
    await submitProfile(page)

    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.display_name,
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
      DRAFT_NAME,
      DRAFT_REASON,
    ])
    expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(1)
  })

  it('removes a previously visible profile and its edit when a refresh returns metadata without PII', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    const { profile: _profile, profile_revision: _privateRevision, ...metadataOnly } = employee()
    api.respond('GET', EMPLOYEE_PATH, 200, metadataOnly)
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()

    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.display_name,
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
      DRAFT_NAME,
      DRAFT_REASON,
    ])
    expect(page.text()).toContain(EMPLOYEE_ID)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(0)
  })
  it('shows as_of primary memberships, position and administrative manager using stable IDs with history navigation', async () => {
    const membership = { id: REQUEST_ID, employee_id: EMPLOYEE_ID, team_id: ORG_ID, is_primary: true, valid_from: VALID_FROM, valid_to: null }
    const position = { ...membership, id: SUBJECT_ID, position: { title: '合成获准职位正文', description: '合成获准任职描述' } }
    const manager = { id: OTHER_EMPLOYEE_ID, employee_id: EMPLOYEE_ID, manager_employee_id: OTHER_EMPLOYEE_ID, kind: 'administrative', valid_from: VALID_FROM, valid_to: null }
    api.respond('GET', EMPLOYEE_PATH, 200, { ...employee(), graph_revision: '23', memberships: [membership], positions: [position], reporting_lines: [manager] })
    const page = await openPage()
    const organization = page.find('[aria-label="查询日任职与经理"]')
    expect(organization.text()).toContain(AS_OF)
    expect(organization.text()).toContain(REQUEST_ID)
    expect(organization.text()).toContain('合成获准职位正文')
    expect(organization.text()).toContain(`administrative`)
    expect(organization.text()).toContain(OTHER_EMPLOYEE_ID)
    expect(page.find(`a[href="/employees/${EMPLOYEE_ID}/organization-history"]`).exists()).toBe(true)
    expect(page.find(`a[href="/employees/${EMPLOYEE_ID}/compensation"]`).exists()).toBe(true)
    expect(page.find(`a[href="/orgs/${ORG_ID}/tree?as_of=${AS_OF}"]`).exists()).toBe(true)
    expect(page.text()).toContain('图版本 23')
  })
  it('metadata-only organization projection exposes stable IDs but no profile revision, title or invented manager', async () => {
    api.session = { ...SESSION, capabilities: ['organization.read'] }
    const { profile: _profile, profile_revision: _revision, ...metadata } = employee()
    api.respond('GET', EMPLOYEE_PATH, 200, { ...metadata, graph_revision: '5', memberships: [{ id: REQUEST_ID, employee_id: EMPLOYEE_ID, team_id: ORG_ID, is_primary: true, valid_from: VALID_FROM, valid_to: null }], positions: [], reporting_lines: [] })
    const page = await openPage()
    const organization = page.find('[aria-label="查询日任职与经理"]')
    expect(organization.text()).toContain(REQUEST_ID)
    expect(organization.text()).toContain('查询日无获准经理关系')
    expect(page.text()).not.toContain('profile_revision')
    expect(page.text()).not.toContain(ORIGINAL_PROFILE.display_name)
    expect(page.text()).not.toContain('合成获准职位正文')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(0)
  })

  it('discards a late old-employee GET after navigation and never replaces the new employee details', async () => {
    const oldRead = api.defer('GET', EMPLOYEE_PATH)
    const page = await openPage()
    const oldRequests = api.matching('GET', EMPLOYEE_PATH)
    expect(oldRequests, 'Opening an employee must request its real profile').toHaveLength(1)
    const newProfile = { ...ORIGINAL_PROFILE, display_name: '合成新路由资料庚' }
    api.respond('GET', OTHER_EMPLOYEE_PATH, 200, employee(newProfile, '7', OTHER_EMPLOYEE_ID))
    await navigate(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expectDetails(page, newProfile.display_name, '7')
    expect(oldRequests[0]!.signal?.aborted, 'Navigation must cancel the old employee request').toBe(true)

    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, display_name: '合成迟到旧资料辛' }))
    await settled()
    expectDetails(page, newProfile.display_name, '7')
    expectSensitiveCleared(page, ['合成迟到旧资料辛'])
  })

  it('does not restore sensitive data or issue a save reload when a late correction arrives after revoked access', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    const oldSave = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    const [command] = api.matching('PATCH', CORRECTION_PATH)
    api.respond('GET', OTHER_EMPLOYEE_PATH, 403, error('FORBIDDEN'))
    await navigate(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.display_name, DRAFT_NAME, DRAFT_REASON])
    expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(command!.signal?.aborted).toBe(true)

    oldSave.resolve(200, { id: EMPLOYEE_ID, profile_revision: '2' })
    await settled()
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.display_name, DRAFT_NAME, DRAFT_REASON])
    expect(page.find('[role="alert"]').exists(), 'A stale success must not erase the authorization error').toBe(true)
    expect(api.matching('GET', EMPLOYEE_PATH), 'A revoked old save must not trigger any sensitive reload').toHaveLength(1)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('clears the page and unsaved form on route departure and discards a late save response', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.display_name, '1')
    await startCorrection(page)
    const oldSave = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    const [command] = api.matching('PATCH', CORRECTION_PATH)
    await navigate('/security/audit')
    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.display_name,
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
      DRAFT_NAME,
      DRAFT_REASON,
    ])
    expect(command!.signal?.aborted).toBe(true)

    oldSave.resolve(200, { id: EMPLOYEE_ID, profile_revision: '2' })
    await settled()
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.display_name, DRAFT_NAME, DRAFT_REASON])
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(1)
  })

  it('rejects a pending profile response after the same page observes a revoked session', async () => {
    const oldRead = api.defer('GET', EMPLOYEE_PATH)
    const page = await openPage()
    const [request] = api.matching('GET', EMPLOYEE_PATH)
    expect(request, 'The profile read must be in flight before session revocation').toBeDefined()
    api.sessionStatus = 401
    api.session = error('UNAUTHENTICATED')
    api.respond('GET', OTHER_EMPLOYEE_PATH, 401, error('UNAUTHENTICATED'))
    await navigate(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expect(page.find('[role="alert"]').exists(), 'A revoked session must be visibly denied').toBe(true)
    expect(request!.signal?.aborted).toBe(true)

    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, display_name: '合成撤销会话迟到资料癸' }))
    await settled()
    expectSensitiveCleared(page, [
      '合成撤销会话迟到资料癸',
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
    ])
    expect(page.find('[role="alert"]').exists(), 'A late profile cannot erase the session denial').toBe(true)
  })

  it('cancels an unmounted page request and never leaks its late result into a new revoked page', async () => {
    const oldRead = api.defer('GET', EMPLOYEE_PATH)
    const oldPage = await openPage()
    const [request] = api.matching('GET', EMPLOYEE_PATH)
    expect(request, 'Mounting the employee page must perform the external GET').toBeDefined()
    oldPage.unmount()
    mounted[0]!.host.remove()
    mounted = []
    expect(request!.signal?.aborted, 'Unmount must cancel the sensitive request').toBe(true)

    api.sessionStatus = 401
    api.session = error('UNAUTHENTICATED')
    const newPage = await openPage(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expect(newPage.find('[role="alert"]').exists()).toBe(true)
    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, display_name: '合成已卸载迟到资料壬' }))
    await settled()
    expectSensitiveCleared(newPage, ['合成已卸载迟到资料壬', ORIGINAL_PROFILE.work_contact.email])
    expect(api.matching('GET', OTHER_EMPLOYEE_PATH), 'An unauthenticated page must not load sensitive data').toHaveLength(0)
  })
})
