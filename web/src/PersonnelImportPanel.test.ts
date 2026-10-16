import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import PersonnelImportPanel from './PersonnelImportPanel.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const SUBJECT = '10000000-0000-4000-8000-000000000002'
const MANAGER = '10000000-0000-4000-8000-000000000010'
const EMPLOYEE = '10000000-0000-4000-8000-000000000011'
const AS_OF = '2026-10-16'
const SESSION = { subject_id: SUBJECT, org_id: ORG, auth_epoch: '1', capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'], csrf_token: 'csrf' }

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
function workbookFile() {
  return new File(['synthetic workbook'], 'people.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}
async function selectAndPreview(page: ReturnType<typeof mount>) {
  const input = page.get('input[type=file]')
  Object.defineProperty(input.element, 'files', { value: [workbookFile()] })
  await input.trigger('change')
  await page.findAll('button').find(button => button.text() === '校验并预览')!.trigger('click')
  await flushPromises()
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  document.body.replaceChildren()
})

describe('personnel batch import panel', () => {
  it('replays an uncertain reporting command once, then keeps the completed batch terminal', async () => {
    const requests: { path: string; method: string; headers: Headers; body: unknown }[] = []
    let createCount = 0
    let reportingAttempt = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const method = init.method ?? 'GET'
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
      requests.push({ path, method, headers: new Headers(init.headers), body })
      if (path.endsWith('/import-preview')) return json(200, { row_count: 2, errors: [], rows: [
        { row_number: 2, staff_code: 'MGR-001', local_name: '合成主管', hire_date: AS_OF, departure_date: null },
        { row_number: 3, staff_code: 'EMP-001', local_name: '合成员工', english_name: 'Synthetic Employee', email: 'employee@example.test', phone: '+86 21 5555 0100', profile_summary: '跨团队交付', manager_staff_code: 'MGR-001', hire_date: AS_OF, departure_date: null },
      ] })
      if (path === '/api/v1/session') return json(200, { ...SESSION, auth_epoch: requests.some(request => request.path.endsWith('/workforce-changes')) ? '2' : '1' })
      if (path.endsWith('/workforce-catalogs')) return json(200, { catalog_revision: '4', graph_revision: '9' })
      if (path === `/api/v1/orgs/${ORG}/employees`) {
        createCount++
        return json(201, { id: createCount === 1 ? MANAGER : EMPLOYEE, profile_revision: '1', workforce_revision: '2', graph_revision: '9' })
      }
      if (path.endsWith('/workforce-changes')) {
        reportingAttempt++
        return reportingAttempt === 1 ? json(504, {}) : json(201, { graph_revision: '10' })
      }
      throw new Error(`unexpected request ${method} ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF }, attachTo: document.body })
    await selectAndPreview(page)
    expect(page.text()).toContain('已校验 2 行')
    expect(page.text()).toContain('合成员工')
    expect(page.text()).toContain('Synthetic Employee')
    expect(page.text()).toContain('employee@example.test')
    expect(page.text()).toContain('+86 21 5555 0100')
    expect(page.text()).toContain('跨团队交付')
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()

    const creates = requests.filter(request => request.path === `/api/v1/orgs/${ORG}/employees`)
    expect(creates).toHaveLength(2)
    expect(creates.map(request => request.body)).toEqual([
      { profile: { local_name: '合成主管' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'MGR-001', expected_catalog_revision: '4', expected_graph_revision: '9' },
      { profile: { local_name: '合成员工', english_name: 'Synthetic Employee', work_contact: { email: 'employee@example.test', phone: '+86 21 5555 0100' }, profile_summary: '跨团队交付' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'EMP-001', expected_catalog_revision: '4', expected_graph_revision: '9' },
    ])
    const reporting = requests.find(request => request.path.endsWith('/workforce-changes'))!
    expect(reporting.body).toEqual({
      expected_catalog_revision: '4', expected_graph_revision: '9', expected_employee_revisions: { [EMPLOYEE]: '2' }, reason: 'Personnel XLSX import',
      changes: [{ action: 'add', kind: 'reporting', employee_id: EMPLOYEE, manager_employee_id: MANAGER, reporting_kind: 'administrative', valid_from: AS_OF, valid_to: null }],
    })
    expect(page.text()).toContain('主管关系提交结果不确定')
    await page.findAll('button').find(button => button.text() === '确认原提交并继续')!.trigger('click')
    await flushPromises()
    const reportingRequests = requests.filter(request => request.path.endsWith('/workforce-changes'))
    expect(reportingRequests).toHaveLength(2)
    expect(reportingRequests[0]!.body).toEqual(reportingRequests[1]!.body)
    expect(reportingRequests[0]!.headers.get('Idempotency-Key')).toBe(reportingRequests[1]!.headers.get('Idempotency-Key'))
    expect(requests.filter(request => request.path === '/api/v1/session')).toHaveLength(3)
    expect(page.text()).toContain('批量处理完成：已创建 2')
    const completed = page.findAll('button').find(button => button.text() === '批量处理已完成')!
    expect(completed.attributes('disabled')).toBeDefined()
    expect(page.emitted('session-updated')).toEqual([[{ session: { ...SESSION, auth_epoch: '2' }, catalogRevision: '4', graphRevision: '10' }]])
    page.unmount()
  })

  it('replays a 502 employee result with its original revision despite an unrelated failed row and newer graph', async () => {
    const creates: { key: string | null; body: string }[] = []
    let uncertainAttempt = 0
    let catalogRead = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, { row_count: 2, errors: [], rows: [
        { row_number: 2, staff_code: 'DUP-001', local_name: '合成冲突员工', hire_date: AS_OF, departure_date: null },
        { row_number: 3, staff_code: 'EMP-002', local_name: '合成重试员工', manager_staff_code: 'OLD-MGR', hire_date: AS_OF, departure_date: null },
      ] })
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/workforce-catalogs')) {
        catalogRead++
        return json(200, { catalog_revision: '4', graph_revision: catalogRead === 1 ? '9' : '10' })
      }
      if (path.endsWith('/employees/query')) {
        const query = JSON.parse(String(init.body))
        if (catalogRead === 1 && !query.cursor) return json(200, { graph_revision: '9', items: [], next_cursor: 'synthetic-page-2', search_incomplete: true })
        if (catalogRead === 1 && query.cursor === 'synthetic-page-2') return json(200, {
          graph_revision: '9', next_cursor: null, search_incomplete: false,
          items: [{ id: MANAGER, lifecycle: { valid_from: AS_OF, valid_to: null }, identifiers: [{ kind: 'staff_code', staff_code: 'OLD-MGR' }] }],
        })
        return json(200, { graph_revision: '10', items: [], next_cursor: null, search_incomplete: false })
      }
      if (path === `/api/v1/orgs/${ORG}/employees`) {
        creates.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: String(init.body) })
        const body = JSON.parse(String(init.body))
        if (body.staff_code === 'DUP-001') return json(409, {})
        uncertainAttempt++
        return uncertainAttempt === 1 ? json(502, {}) : json(201, { id: EMPLOYEE, profile_revision: '1', workforce_revision: '2', graph_revision: '9' })
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('结果不确定')
    expect(page.text()).toContain('Staff Code 已存在或组织版本已变化')
    expect(page.get('input[type=file]').attributes('disabled')).toBeDefined()
    expect(page.findAll('button').find(button => button.text() === '校验并预览')!.attributes('disabled')).toBeDefined()
    await page.findAll('button').find(button => button.text() === '确认原提交并继续')!.trigger('click')
    await flushPromises()
    expect(creates).toHaveLength(3)
    expect(creates[1]).toEqual(creates[2])
    expect(JSON.parse(creates[2]!.body).expected_graph_revision).toBe('9')
    expect(page.text()).toContain('批量处理完成：已创建 0，主管待维护 1，失败 1')
    page.unmount()
  })
})
