import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import OrganizationPage from './OrganizationPage.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const SUBJECT = '10000000-0000-4000-8000-000000000002'
const BG = '10000000-0000-4000-8000-000000000003'
const DIV = '10000000-0000-4000-8000-000000000004'
const DEP = '10000000-0000-4000-8000-000000000005'
const EMPLOYEE = '10000000-0000-4000-8000-000000000006'
const MANAGER = '10000000-0000-4000-8000-000000000007'
const AS_OF = '2026-10-11'
const session = { subject_id: SUBJECT, org_id: ORG, auth_epoch: '7', csrf_token: 'csrf', capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'] }
const catalogs = { as_of: AS_OF, catalog_revision: '4', graph_revision: '5', legal_entities: [], locations: ['Shanghai', 'Tokyo', 'Wuxi'], education_levels: [], job_families: [], career_levels: [], org_units: [], org_unit_parents: [] }
const tree = {
  org_id: ORG, as_of: AS_OF, authorization_date: AS_OF, graph_revision: '5', auth_epoch: '7',
  nodes: [
    { id: BG, code: 'BG', kind: 'business_group', label: '业务组', valid_from: '2026-01-01', valid_to: null },
    { id: DIV, code: 'DIV', kind: 'division', label: '事业部', valid_from: '2026-01-01', valid_to: null },
    { id: DEP, code: 'DEP', kind: 'department', label: '部门', valid_from: '2026-01-01', valid_to: null },
  ],
  edges: [
    { id: crypto.randomUUID(), child_unit_id: DIV, parent_unit_id: BG, valid_from: '2026-01-01', valid_to: null },
    { id: crypto.randomUUID(), child_unit_id: DEP, parent_unit_id: DIV, valid_from: '2026-01-01', valid_to: null },
  ],
  employees: [{ id: EMPLOYEE, department_id: DEP, profile: { local_name: '合成员工', english_name: 'Synthetic Employee' } }],
}
const employee = {
  id: EMPLOYEE, org_id: ORG, profile_revision: '2', lifecycle: { valid_from: '2026-01-01', valid_to: null }, as_of: AS_OF, authorization_date: AS_OF, graph_revision: '5',
  profile: { local_name: '合成员工', english_name: 'Synthetic Employee' },
  identifiers: [{ id: crypto.randomUUID(), kind: 'staff_code', staff_code: '0007', valid_from: '2026-01-01', valid_to: null }],
  employment: [{ id: crypto.randomUUID(), legal_entity_id: crypto.randomUUID(), location_code: 'Shanghai', kind: 'hire', valid_from: '2026-01-01', valid_to: null }],
  education: [], job_assignments: [{ id: crypto.randomUUID(), department_id: DEP, valid_from: '2026-01-01', valid_to: null, position: { title: 'Engineer' } }],
  reporting_lines: [], direct_manager: { id: crypto.randomUUID(), employee_id: EMPLOYEE, manager_employee_id: MANAGER, kind: 'administrative', valid_from: '2026-01-01', valid_to: null },
}

type Seen = { method: string; url: URL; body?: unknown }
let seen: Seen[] = []
let page: VueWrapper | null = null
function response(body: unknown, status = 200) { return Promise.resolve(new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) }
function installAPI() {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, location.origin)
    const method = init?.method ?? 'GET'; const body = init?.body ? JSON.parse(String(init.body)) : undefined
    seen.push({ method, url, body })
    if (url.pathname === '/api/v1/session') return response(session)
    if (url.pathname.endsWith('/workforce-catalogs')) return response(catalogs)
    if (url.pathname.endsWith('/tree')) return response(tree)
    if (url.pathname.endsWith('/employees/query')) return response({ items: [employee], next_cursor: null, as_of: AS_OF, consistency: 'current', authorization_date: AS_OF, graph_revision: '5', auth_epoch: '7', search_incomplete: false })
    if (url.pathname.endsWith('/workforce-catalog-changes') && method === 'POST') return response({ id: crypto.randomUUID(), catalog_revision: '5', graph_revision: '6', items: [] }, 201)
    throw new Error(`unexpected ${method} ${url.pathname}`)
  }))
}
async function settle() { await flushPromises(); await flushPromises() }
async function open(route: string) { window.history.replaceState({}, '', route); page = mount(OrganizationPage, { attachTo: document.body }); await settle(); return page }
function button(wrapper: VueWrapper, label: RegExp) { const values = wrapper.findAll('button').filter((item) => label.test(item.text())); expect(values).toHaveLength(1); return values[0]! }

beforeEach(() => { seen = []; installAPI() })
afterEach(() => { page?.unmount(); page = null; vi.unstubAllGlobals(); document.body.innerHTML = '' })

describe('DEV-015 workforce organization consumers', () => {
  it('renders the fixed BG → Division → Department hierarchy and department employee projection', async () => {
    const wrapper = await open(`/orgs/${ORG}/tree?as_of=${AS_OF}`)
    expect(wrapper.text()).toContain('business_group · BG')
    expect(wrapper.text()).toContain('division · DIV')
    expect(wrapper.text()).toContain('department · DEP')
    expect(wrapper.text()).toContain('合成员工')
    expect(wrapper.text()).toContain(`Department ${DEP}`)
    expect(seen.some((entry) => entry.url.pathname.endsWith('/tree') && entry.url.searchParams.get('depth') === '3')).toBe(true)
  })

  it('uses department_id and body-only name/Staff Code search, then renders HOD from the administrative manager fact', async () => {
    const wrapper = await open(`/orgs/${ORG}/employees?as_of=${AS_OF}`)
    const inputs = wrapper.findAll('input')
    await inputs.find((item) => item.element.parentElement?.textContent?.includes('Department ID'))!.setValue(DEP)
    await inputs.find((item) => item.element.parentElement?.textContent?.includes('姓名或Staff Code'))!.setValue('0007')
    await inputs.find((item) => item.element.parentElement?.textContent?.includes('请求PII资料'))!.setValue(true)
    await button(wrapper, /刷新权威投影/).trigger('submit'); await settle()
    const request = seen.filter((entry) => entry.url.pathname.endsWith('/employees/query')).at(-1)!
    expect(request.url.search).toBe('')
    expect(request.body).toMatchObject({ as_of: AS_OF, department_id: DEP, q: '0007', include_profile: true })
    expect(wrapper.text()).toContain('0007')
    expect(wrapper.text()).toContain(`直属主管/HOD：${MANAGER}`)
  })

  it('previews and submits catalog changes with current catalog/graph revisions and CSRF/idempotency headers', async () => {
    const wrapper = await open(`/orgs/${ORG}/tree?as_of=${AS_OF}`)
    const textareas = wrapper.findAll('textarea')
    await textareas[0]!.setValue(JSON.stringify([{ action: 'create', kind: 'department', code: 'NEW', label: '新部门', valid_from: AS_OF }]))
    await button(wrapper, /预览目录变更/).trigger('click')
    expect(wrapper.text()).toContain('1 项原子变更')
    await button(wrapper, /确认原子提交/).trigger('click'); await settle()
    const command = seen.find((entry) => entry.method === 'POST' && entry.url.pathname.endsWith('/workforce-catalog-changes'))!
    expect(command.body).toMatchObject({ expected_catalog_revision: '4', expected_graph_revision: '5' })
    if (!command.body || typeof command.body !== 'object' || !('changes' in command.body) || !Array.isArray(command.body.changes)) throw new Error('catalog command was not a validated object')
    expect(command.body.changes).toHaveLength(1)
    expect(wrapper.text()).toContain('图版本 5')
  })
})
