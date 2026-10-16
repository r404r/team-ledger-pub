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
const CATALOG_PATH = `/api/v1/orgs/${ORG_ID}/workforce-catalogs`
const DIRECTORY_PATH = `/api/v1/orgs/${ORG_ID}/employees/query`
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LEGAL_ENTITY_ID = '10000000-0000-4000-8000-000000000040'
const BUSINESS_GROUP_ID = '10000000-0000-4000-8000-000000000041'
const DIVISION_ID = '10000000-0000-4000-8000-000000000042'
const DEPARTMENT_ID = '10000000-0000-4000-8000-000000000043'
const JOB_FAMILY_ID = '10000000-0000-4000-8000-000000000044'
const CAREER_LEVEL_ID = '10000000-0000-4000-8000-000000000045'
const CATALOGS = {
  as_of: AS_OF,
  catalog_revision: '4',
  graph_revision: '9',
  legal_entities: [{ id: LEGAL_ENTITY_ID, code: 'BRANCH-A', display_name: '合成法分公司', valid_from: '2020-01-01', valid_to: null, active: true }],
  locations: ['Shanghai', 'Wuxi', 'Tokyo'],
  org_units: [
    { id: BUSINESS_GROUP_ID, code: 'BG-A', label: '合成业务单元', kind: 'business_group', valid_from: '2020-01-01', valid_to: null, active: true },
    { id: DIVISION_ID, code: 'DIV-A', label: '合成事业部', kind: 'division', valid_from: '2020-01-01', valid_to: null, active: true },
    { id: DEPARTMENT_ID, code: 'DEP-A', label: '合成部门', kind: 'department', valid_from: '2020-01-01', valid_to: null, active: true },
  ],
  org_unit_parents: [
    { child_unit_id: DIVISION_ID, parent_unit_id: BUSINESS_GROUP_ID, active: true },
    { child_unit_id: DEPARTMENT_ID, parent_unit_id: DIVISION_ID, active: true },
  ],
  education_levels: [{ code: 'Master', rank: 3 }],
  job_families: [{ id: JOB_FAMILY_ID, code: 'JF-A', label: '合成职系', valid_from: '2020-01-01', valid_to: null, active: true }],
  career_levels: [{ id: CAREER_LEVEL_ID, code: 'P1', label: '合成职级', valid_from: '2020-01-01', valid_to: null, active: true }],
}

const SESSION = {
  subject_id: SUBJECT_ID,
  org_id: ORG_ID,
  auth_epoch: '1',
  capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'],
  csrf_token: 'synthetic-csrf-token',
}

const ORIGINAL_PROFILE = {
  local_name: '合成资料甲',
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
    identifiers: [],
    employment: [],
    education: [],
    job_assignments: [],
    reporting_lines: [],
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
  const { promise, resolve, reject } = Promise.withResolvers<Response>()
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
async function fillRequiredWorkforce(page: VueWrapper) {
  await field(page, /入职日|Date of Employment/i).setValue(VALID_FROM)
  await settled()
  await field(page, /所在公司|Branch English/i).setValue(LEGAL_ENTITY_ID)
  await field(page, /地点|Location/i).setValue('Shanghai')
  await field(page, /组织层级|Business Group/i).setValue(DEPARTMENT_ID)
  await field(page, /学历|Latest Education/i).setValue('Master')
  await field(page, /职位|Position/i).setValue('合成顾问')
  await field(page, /职系|Job Family/i).setValue(JOB_FAMILY_ID)
  await field(page, /职级|Career Level/i).setValue(CAREER_LEVEL_ID)
}

function action(page: VueWrapper, label: RegExp) {
  const buttons = page.findAll('button,[role="button"],input[type="submit"]')
    .filter((button) => button.isVisible() && label.test(accessibleName(button.element)))
  expect(buttons, `Users must have an accessible ${label} action`).toHaveLength(1)
  return buttons[0]!
}

async function submitProfile(page: VueWrapper) {
  const name = field(page, /本地姓名|local_name/i)
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

async function openPage(path = `/employees/${EMPLOYEE_ID}?as_of=${AS_OF}`, props: { queryDate?: string } = {}) {
  window.history.replaceState({}, '', path)
  const host = document.createElement('div')
  document.body.append(host)
  const page = mount(ProfilePage, { attachTo: host, props })
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
  await field(page, /本地姓名|local_name/i).setValue(DRAFT_NAME)
  await field(page, /更正理由|修改原因|edit_reason/i).setValue(DRAFT_REASON)
}

beforeEach(() => {
  api = new NetworkFixture()
  mounted = []
  api.respondRepeatedly('GET', CATALOG_PATH, 200, CATALOGS)
  api.respondRepeatedly('POST', DIRECTORY_PATH, 200, {
    items: [{ ...employee({ ...ORIGINAL_PROFILE, local_name: '合成直属主管' }, '3', OTHER_EMPLOYEE_ID), identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: 'MGR-001', valid_from: VALID_FROM, valid_to: null }] }], next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
  })
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

    expectDetails(page, ORIGINAL_PROFILE.local_name, '9007199254740993')
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
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '2' })
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, local_name: '合成员工范围保存结果' }, '2'))
    await submitProfile(page)
    expectDetails(page, '合成员工范围保存结果', '2')
    expect(page.text()).not.toContain(DRAFT_NAME)
  })

  it('atomically creates a profile, Staff Code, and selected direct manager before reloading the saved employee', async () => {
    api.respond('GET', CATALOG_PATH, 200, CATALOGS)
    api.respond('POST', DIRECTORY_PATH, 200, {
      items: [{ ...employee({ ...ORIGINAL_PROFILE, local_name: '合成直属主管' }, '3', OTHER_EMPLOYEE_ID), identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: 'MGR-001', valid_from: VALID_FROM, valid_to: null }] }],
      next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
    })
    const created = api.defer('POST', CREATE_PATH)
    const reloaded = api.defer('GET', EMPLOYEE_PATH)
    const page = await openPage(`/?as_of=${AS_OF}`)
    await field(page, /本地姓名|local_name/i).setValue(DRAFT_NAME)
    await field(page, /邮箱|email/i).setValue('fixture-create@example.invalid')
    await field(page, /电话|phone/i).setValue('+00-000-0002')
    await field(page, /摘要|简介|profile_summary/i).setValue('合成创建摘要')
    await field(page, /工号 · 必填/i).setValue('EMP-0007')
    await fillRequiredWorkforce(page)
    await field(page, /直属主管|HOD/i).setValue(OTHER_EMPLOYEE_ID)
    await field(page, /退职日|Departure Date/i).setValue('')
    await submitProfile(page)

    const commands = api.matching('POST', CREATE_PATH)
    expect(commands).toHaveLength(1)
    expectMutation(commands[0]!)
    expect(commands[0]!.body).toEqual({
      profile: {
        local_name: DRAFT_NAME,
        work_contact: { email: 'fixture-create@example.invalid', phone: '+00-000-0002' },
        profile_summary: '合成创建摘要',
      },
      lifecycle: { valid_from: VALID_FROM, valid_to: null },
      staff_code: 'EMP-0007',
      employment: { legal_entity_id: LEGAL_ENTITY_ID, location_code: 'Shanghai' },
      education: { level: 'Master' },
      job_assignment: {
        department_id: DEPARTMENT_ID,
        job_family_id: JOB_FAMILY_ID,
        career_level_id: CAREER_LEVEL_ID,
        position: { title: '合成顾问' },
      },
      manager_employee_id: OTHER_EMPLOYEE_ID,
      expected_catalog_revision: '4',
      expected_graph_revision: '9',
    })
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(0)

    created.resolve(201, { id: EMPLOYEE_ID, profile_revision: '1', workforce_revision: '2', graph_revision: '10' })
    api.session = { ...SESSION, auth_epoch: '2' }
    await settled()
    expect(api.matching('GET', EMPLOYEE_PATH), 'A create receipt is not saved employee data: the UI must reload').toHaveLength(1)
    const manager = { id: REQUEST_ID, employee_id: EMPLOYEE_ID, manager_employee_id: OTHER_EMPLOYEE_ID, kind: 'administrative', valid_from: VALID_FROM, valid_to: null }
    reloaded.resolve(200, {
      ...employee({ ...ORIGINAL_PROFILE, local_name: '合成服务端读取结果丙' }),
      graph_revision: '10',
      identifiers: [{ id: SUBJECT_ID, kind: 'staff_code', staff_code: 'EMP-0007', valid_from: VALID_FROM, valid_to: null }],
      reporting_lines: [manager], direct_manager: manager, hod: manager,
    })
    await settled()
    expectDetails(page, '合成服务端读取结果丙', '1')
    expect(page.text()).toContain('EMP-0007')
    expect(page.text()).toContain(OTHER_EMPLOYEE_ID)
    expect(page.text()).not.toContain(DRAFT_NAME)
    for (const request of api.requests) {
      expect(request.url.href).not.toContain(encodeURIComponent(DRAFT_NAME))
      expect(request.url.href).not.toContain('fixture-create')
    }
  })

  it.each([
    [409, 'Staff Code 已被占用', false],
    [404, '所选直属主管不存在', true],
  ])('keeps the unsaved create form after an atomic create failure (%s)', async (status, expectedMessage, selectManager) => {
    api.respond('GET', CATALOG_PATH, 200, CATALOGS)
    api.respond('POST', DIRECTORY_PATH, 200, {
      items: [{ ...employee({ ...ORIGINAL_PROFILE, local_name: '合成直属主管' }, '3', OTHER_EMPLOYEE_ID), identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: 'MGR-001', valid_from: VALID_FROM, valid_to: null }] }],
      next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
    })
    api.respond('POST', CREATE_PATH, status, {})
    const page = await openPage(`/?as_of=${AS_OF}`)
    await field(page, /本地姓名|local_name/i).setValue(DRAFT_NAME)
    await field(page, /工号 · 必填/i).setValue('EMP-0007')
    await fillRequiredWorkforce(page)
    if (selectManager) await field(page, /直属主管|HOD/i).setValue(OTHER_EMPLOYEE_ID)
    await submitProfile(page)
    expect(page.text()).toContain(expectedMessage)
    expect(field(page, /本地姓名|local_name/i).element.value).toBe(DRAFT_NAME)
    expect(field(page, /工号 · 必填/i).element.value).toBe('EMP-0007')
    expect(window.location.pathname).toBe('/')
  })


  it('replays the exact create command after a lost response and same-identity epoch advance', async () => {
    api.respond('GET', CATALOG_PATH, 200, CATALOGS)
    api.respond('POST', DIRECTORY_PATH, 200, {
      items: [], next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
    })
    const lost = api.defer('POST', CREATE_PATH)
    const page = await openPage(`/?as_of=${AS_OF}`)
    await field(page, /本地姓名|local_name/i).setValue(DRAFT_NAME)
    await field(page, /工号 · 必填/i).setValue('EMP-0008')
    await fillRequiredWorkforce(page)
    await submitProfile(page)
    const first = api.matching('POST', CREATE_PATH)[0]!

    lost.reject()
    api.session = { ...SESSION, auth_epoch: '2' }
    await settled()
    expect(action(page, /确认原提交/).exists()).toBe(true)
    expect(field(page, /工号 · 必填/i).attributes('readonly')).toBeDefined()
    expect(action(page, /^查找$/).attributes('disabled')).toBeDefined()
    api.sessionStatus = 502
    await submitProfile(page)
    expect(api.matching('POST', CREATE_PATH)).toHaveLength(1)
    expect(action(page, /确认原提交/).exists()).toBe(true)
    expect(field(page, /工号 · 必填/i).attributes('readonly')).toBeDefined()
    api.sessionStatus = 200
    api.respond('POST', CREATE_PATH, 504, {})
    await submitProfile(page)
    expect(action(page, /确认原提交/).exists()).toBe(true)
    expect(field(page, /工号 · 必填/i).attributes('readonly')).toBeDefined()
    api.respond('POST', CREATE_PATH, 201, { id: EMPLOYEE_ID, profile_revision: '1', workforce_revision: '2', graph_revision: '10' })
    api.respond('GET', EMPLOYEE_PATH, 200, {
      ...employee({ ...ORIGINAL_PROFILE, local_name: '合成断线确认结果' }),
      graph_revision: '10',
      identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: 'EMP-0008', valid_from: VALID_FROM, valid_to: null }],
    })
    await submitProfile(page)

    const commands = api.matching('POST', CREATE_PATH)
    expect(commands).toHaveLength(3)
    for (const replay of commands.slice(1)) {
      expect(replay.headers.get('Idempotency-Key')).toBe(first.headers.get('Idempotency-Key'))
      expect(replay.body).toEqual(first.body)
    }
    expectDetails(page, '合成断线确认结果', '1')
  })

  it('clears a selected manager when a new search no longer returns that candidate', async () => {
    api.respond('GET', CATALOG_PATH, 200, CATALOGS)
    api.respond('POST', DIRECTORY_PATH, 200, {
      items: [{ ...employee({ ...ORIGINAL_PROFILE, local_name: '合成直属主管' }, '3', OTHER_EMPLOYEE_ID), identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: 'MGR-001', valid_from: VALID_FROM, valid_to: null }] }],
      next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
    })
    const page = await openPage(`/?as_of=${AS_OF}`)
    const manager = field(page, /直属主管|HOD/i)
    await manager.setValue(OTHER_EMPLOYEE_ID)
    api.respond('GET', CATALOG_PATH, 200, CATALOGS)
    api.respond('POST', DIRECTORY_PATH, 200, {
      items: [], next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '9', auth_epoch: '1', search_incomplete: false,
    })
    await field(page, /查找主管/i).setValue('无人匹配')
    await action(page, /^查找$/).trigger('click')
    await settled()
    expect(manager.element.value).toBe('')
  })
  it('submits a complete correction, omits cleared optional fields, and reloads without rounding the revision', async () => {
    const oldRevision = '9007199254740993'
    const newRevision = '9007199254740994'
    api.respond('GET', EMPLOYEE_PATH, 200, employee(ORIGINAL_PROFILE, oldRevision))
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, oldRevision)
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
      profile: { local_name: DRAFT_NAME },
      edit_reason: DRAFT_REASON,
    })
    expect(api.matching('GET', EMPLOYEE_PATH)).toHaveLength(2)
    const authoritativeName = '合成更正后实际读取资料丁'
    expect(page.text()).not.toContain(authoritativeName)
    reload.resolve(200, {
      ...employee(ORIGINAL_PROFILE, newRevision),
      profile: { local_name: authoritativeName },
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
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    const failed = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    failed.resolve(status, error(code))
    await settled()

    expect(page.find('[role="alert"]').exists(), 'A rejected save must remain visibly unsuccessful').toBe(true)
    expect(field(page, /本地姓名|local_name/i).element.value).toBe(DRAFT_NAME)
    expect(field(page, /更正理由|修改原因|edit_reason/i).element.value).toBe(DRAFT_REASON)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    expect(page.text()).not.toContain(DRAFT_NAME)
  })

  it('keeps an external network failure unsuccessful and preserves the authorized unsaved edit', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    api.respondRepeatedly('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    const failed = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    failed.reject()
    await settled()

    expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(field(page, /本地姓名|local_name/i).element.value).toBe(DRAFT_NAME)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('queues a global date change without abandoning an unconfirmed profile command', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage(`/employees/${EMPLOYEE_ID}`, { queryDate: AS_OF })
    await startCorrection(page)
    const failed = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    await page.setProps({ queryDate: '2026-10-12' })
    expect(page.text()).toContain('当前人员资料命令结果明确后加载')

    failed.reject()
    await settled()
    expect(field(page, /本地姓名|local_name/i).element.value).toBe(DRAFT_NAME)
    expect(page.text()).toContain('当前人员资料命令结果明确后加载')
    const first = api.matching('PATCH', CORRECTION_PATH)[0]!

    api.respond('PATCH', CORRECTION_PATH, 422, error('INVALID_INPUT'))
    api.respond('GET', EMPLOYEE_PATH, 200, { ...employee(), as_of: '2026-10-12' })
    await submitProfile(page)
    await settled()
    const commands = api.matching('PATCH', CORRECTION_PATH)
    expect(commands).toHaveLength(2)
    expect(commands[1]!.headers.get('Idempotency-Key')).toBe(first.headers.get('Idempotency-Key'))
    expect(commands[1]!.body).toEqual(first.body)
    expect(api.matching('GET', EMPLOYEE_PATH).at(-1)!.url.searchParams.get('as_of')).toBe('2026-10-12')
  })

  it('does not confirm a committed correction when its authoritative reload fails', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '2' })
    api.respond('GET', EMPLOYEE_PATH, 503, error('UNAVAILABLE'))
    await submitProfile(page)

    expect(page.find('[role="alert"]').exists(), 'Save acknowledgement alone cannot confirm reloaded details').toBe(true)
    expect(page.text()).not.toContain(DRAFT_NAME)
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, local_name: '合成后续确认资料戊' }, '2'))
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, '合成后续确认资料戊', '2')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('rejects stale revisions without overwriting and requires a fresh server revision for a manual retry', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    api.respondRepeatedly('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 409, error('CONFLICT'))
    await submitProfile(page)

    expect(page.find('[role="alert"]').exists(), 'A stale revision must be visibly rejected').toBe(true)
    expect(field(page, /本地姓名|local_name/i).element.value).toBe(DRAFT_NAME)
    expect(field(page, /更正理由|修改原因|edit_reason/i).element.value).toBe(DRAFT_REASON)
    const firstCommands = api.matching('PATCH', CORRECTION_PATH)
    expect(firstCommands, 'Conflict handling must never retry or overwrite automatically').toHaveLength(1)
    expect(firstCommands[0]!.body).toMatchObject({ expected_profile_revision: '1' })

    const otherWriter = { ...ORIGINAL_PROFILE, local_name: '合成另一维护者已提交资料己' }
    api.respond('GET', EMPLOYEE_PATH, 200, employee(otherWriter, '2'))
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()
    expectDetails(page, otherWriter.local_name, '2')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, 200, { id: EMPLOYEE_ID, profile_revision: '3' })
    api.respond('GET', EMPLOYEE_PATH, 200, employee({ ...ORIGINAL_PROFILE, local_name: DRAFT_NAME }, '3'))
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
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    api.respond('PATCH', CORRECTION_PATH, status, error(code))
    await submitProfile(page)

    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.local_name,
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
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    const { profile: _profile, profile_revision: _privateRevision, ...metadataOnly } = employee()
    api.respond('GET', EMPLOYEE_PATH, 200, metadataOnly)
    await action(page, /刷新|重新加载|重载|refresh|reload/i).trigger('click')
    await settled()

    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.local_name,
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
      DRAFT_NAME,
      DRAFT_REASON,
    ])
    expect(page.text()).toContain(EMPLOYEE_ID)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(0)
  })
  it('shows Staff Code, employment, education, the single assignment and the shared direct-manager/HOD fact', async () => {
    const manager = { id: OTHER_EMPLOYEE_ID, employee_id: EMPLOYEE_ID, manager_employee_id: SUBJECT_ID, kind: 'administrative', valid_from: VALID_FROM, valid_to: null }
    api.respond('GET', EMPLOYEE_PATH, 200, { ...employee(), graph_revision: '23',
      identifiers: [{ id: REQUEST_ID, kind: 'staff_code', staff_code: '0007', valid_from: VALID_FROM, valid_to: null }],
      employment: [{ id: SUBJECT_ID, legal_entity_id: ORG_ID, location_code: 'Shanghai', kind: 'hire', valid_from: VALID_FROM, valid_to: null }],
      education: [{ id: ORG_ID, level: 'Master', institution: '合成大学', valid_from: VALID_FROM, valid_to: null }],
      job_assignments: [{ id: SUBJECT_ID, department_id: ORG_ID, valid_from: VALID_FROM, valid_to: null, position: { title: '合成获准职位正文' } }],
      reporting_lines: [manager], direct_manager: manager, hod: manager,
    })
    const page = await openPage()
    const organization = page.find('[aria-label="查询日员工主数据"]')
    expect(organization.text()).toContain('0007')
    expect(organization.text()).toContain('Shanghai')
    expect(organization.text()).toContain('Master')
    expect(organization.text()).toContain('合成获准职位正文')
    expect(organization.text()).toContain(SUBJECT_ID)
    expect(page.find(`a[href="/employees/${EMPLOYEE_ID}/organization-history"]`).exists()).toBe(true)
    expect(page.find(`a[href="/employees/${EMPLOYEE_ID}/compensation"]`).exists()).toBe(true)
    expect(page.find(`a[href="/orgs/${ORG_ID}/tree?as_of=${AS_OF}"]`).exists()).toBe(true)
    expect(page.text()).toContain('图版本 23')
  })
  it('metadata-only workforce projection exposes assignment and employment IDs but no PII or invented manager', async () => {
    api.session = { ...SESSION, capabilities: ['organization.read'] }
    const { profile: _profile, profile_revision: _revision, ...metadata } = employee()
    api.respond('GET', EMPLOYEE_PATH, 200, { ...metadata, graph_revision: '5',
      employment: [{ id: REQUEST_ID, legal_entity_id: ORG_ID, location_code: 'Wuxi', kind: 'transfer', valid_from: VALID_FROM, valid_to: null }],
      job_assignments: [{ id: SUBJECT_ID, department_id: ORG_ID, valid_from: VALID_FROM, valid_to: null }],
    })
    const page = await openPage()
    const organization = page.find('[aria-label="查询日员工主数据"]')
    expect(organization.text()).toContain(REQUEST_ID)
    expect(organization.text()).toContain('查询日无直属主管')
    expect(page.text()).not.toContain('profile_revision')
    expect(page.text()).not.toContain(ORIGINAL_PROFILE.local_name)
    expect(page.text()).not.toContain('合成获准职位正文')
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(0)
  })

  it('discards a late old-employee GET after navigation and never replaces the new employee details', async () => {
    const oldRead = api.defer('GET', EMPLOYEE_PATH)
    const page = await openPage()
    const oldRequests = api.matching('GET', EMPLOYEE_PATH)
    expect(oldRequests, 'Opening an employee must request its real profile').toHaveLength(1)
    const newProfile = { ...ORIGINAL_PROFILE, local_name: '合成新路由资料庚' }
    api.respond('GET', OTHER_EMPLOYEE_PATH, 200, employee(newProfile, '7', OTHER_EMPLOYEE_ID))
    await navigate(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expectDetails(page, newProfile.local_name, '7')
    expect(oldRequests[0]!.signal?.aborted, 'Navigation must cancel the old employee request').toBe(true)

    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, local_name: '合成迟到旧资料辛' }))
    await settled()
    expectDetails(page, newProfile.local_name, '7')
    expectSensitiveCleared(page, ['合成迟到旧资料辛'])
  })

  it('does not restore sensitive data or issue a save reload when a late correction arrives after revoked access', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    const oldSave = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    const [command] = api.matching('PATCH', CORRECTION_PATH)
    api.respond('GET', OTHER_EMPLOYEE_PATH, 403, error('FORBIDDEN'))
    await navigate(`/employees/${OTHER_EMPLOYEE_ID}?as_of=${AS_OF}`)
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.local_name, DRAFT_NAME, DRAFT_REASON])
    expect(page.find('[role="alert"]').exists()).toBe(true)
    expect(command!.signal?.aborted).toBe(true)

    oldSave.resolve(200, { id: EMPLOYEE_ID, profile_revision: '2' })
    await settled()
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.local_name, DRAFT_NAME, DRAFT_REASON])
    expect(page.find('[role="alert"]').exists(), 'A stale success must not erase the authorization error').toBe(true)
    expect(api.matching('GET', EMPLOYEE_PATH), 'A revoked old save must not trigger any sensitive reload').toHaveLength(1)
    expect(api.matching('PATCH', CORRECTION_PATH)).toHaveLength(1)
  })

  it('clears the page and unsaved form on route departure and discards a late save response', async () => {
    api.respond('GET', EMPLOYEE_PATH, 200, employee())
    const page = await openPage()
    expectDetails(page, ORIGINAL_PROFILE.local_name, '1')
    await startCorrection(page)
    const oldSave = api.defer('PATCH', CORRECTION_PATH)
    await submitProfile(page)
    const [command] = api.matching('PATCH', CORRECTION_PATH)
    await navigate('/security/audit')
    expectSensitiveCleared(page, [
      ORIGINAL_PROFILE.local_name,
      ORIGINAL_PROFILE.work_contact.email,
      ORIGINAL_PROFILE.work_contact.phone,
      ORIGINAL_PROFILE.profile_summary,
      DRAFT_NAME,
      DRAFT_REASON,
    ])
    expect(command!.signal?.aborted).toBe(true)

    oldSave.resolve(200, { id: EMPLOYEE_ID, profile_revision: '2' })
    await settled()
    expectSensitiveCleared(page, [ORIGINAL_PROFILE.local_name, DRAFT_NAME, DRAFT_REASON])
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

    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, local_name: '合成撤销会话迟到资料癸' }))
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
    oldRead.resolve(200, employee({ ...ORIGINAL_PROFILE, local_name: '合成已卸载迟到资料壬' }))
    await settled()
    expectSensitiveCleared(newPage, ['合成已卸载迟到资料壬', ORIGINAL_PROFILE.work_contact.email])
    expect(api.matching('GET', OTHER_EMPLOYEE_PATH), 'An unauthenticated page must not load sensitive data').toHaveLength(0)
  })
})
