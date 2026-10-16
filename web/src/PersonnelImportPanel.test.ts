import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import PersonnelImportPanel from './PersonnelImportPanel.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const SUBJECT = '10000000-0000-4000-8000-000000000002'
const MANAGER = '10000000-0000-4000-8000-000000000010'
const EMPLOYEE = '10000000-0000-4000-8000-000000000011'
const AS_OF = '2026-10-16'
const SESSION = { subject_id: SUBJECT, org_id: ORG, auth_epoch: '1', capabilities: ['organization.read', 'organization.write', 'pii.read', 'pii.write'], csrf_token: 'csrf' }
const BRANCH = '10000000-0000-4000-8000-000000000020'
const BUSINESS_GROUP = '10000000-0000-4000-8000-000000000021'
const DIVISION = '10000000-0000-4000-8000-000000000022'
const DEPARTMENT = '10000000-0000-4000-8000-000000000023'
const JOB_FAMILY = '10000000-0000-4000-8000-000000000024'
const CAREER_LEVEL = '10000000-0000-4000-8000-000000000025'
const workforce = {
  location: 'Shanghai', branch_code: 'BRANCH-A', business_group_code: 'BG-A', division_code: 'DIV-A', department_code: 'DEP-A',
  education_level: 'Master', position: '合成顾问', job_family_code: 'JF-A', career_level_code: 'P1',
  branch_id: BRANCH, business_group_id: BUSINESS_GROUP, division_id: DIVISION, department_id: DEPARTMENT, job_family_id: JOB_FAMILY, career_level_id: CAREER_LEVEL,
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
function previewBody(body: Record<string, unknown>) {
  return { warnings: [], education_levels: [{ code: 'Master', rank: 3 }, { code: 'Bachelor', rank: 2 }, { code: 'Diploma', rank: 1 }], ...body }
}
function workbookFile() {
  return new File(['synthetic workbook'], 'people.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
}
async function selectAndPreview(page: ReturnType<typeof mount>) {
  const input = page.get('input[type=file]')
  Object.defineProperty(input.element, 'files', { value: [workbookFile()] })
  await input.trigger('change')
  await flushPromises()
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  document.body.replaceChildren()
})

describe('personnel batch import panel', () => {
  it('uploads and previews the selected workbook without a second button click', async () => {
    const requests: { path: string; method: string; headers: Headers; body: unknown }[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      requests.push({ path, method: init.method ?? 'GET', headers: new Headers(init.headers), body: init.body })
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 1, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 2, staff_code: 'AUTO-001', local_name: '自动预览员工', hire_date: AS_OF, departure_date: null },
      ] }))
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    const input = page.get('input[type=file]')
    Object.defineProperty(input.element, 'files', { value: [workbookFile()] })
    await input.trigger('change')
    await flushPromises()

    expect(requests).toHaveLength(1)
    expect(requests[0]!.path).toBe(`/api/v1/orgs/${ORG}/employees/import-preview`)
    expect(requests[0]!.method).toBe('POST')
    expect(requests[0]!.headers.get('Content-Type')).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    expect(requests[0]!.body).toBeInstanceOf(File)
    expect(page.text()).toContain('people.xlsx 已校验 1 行')
    expect((page.findAll('.edit-input')[1]!.element as HTMLInputElement).value).toBe('自动预览员工')
    expect(page.findAll('button').find(button => button.text() === '从文件重新校验')).toBeDefined()
    page.unmount()
  })

  it('shows safe sheet/cell diagnostics from both workbook rejection and row preview', async () => {
    let attempt = 0
    vi.stubGlobal('fetch', async () => {
      attempt++
      if (attempt === 1) return json(422, {
        code: 'INVALID_INPUT', request_id: ORG,
        workbook_error: { sheet: 'Employees', cell: 'A1', code: 'header_mismatch' },
      })
      return json(200, previewBody({
        row_count: 1,
        errors: [{ row_number: 2, sheet: 'Employees', cell: 'J2', field: 'hire_date', code: 'invalid_date' }],
        rows: [{ ...workforce, row_number: 2, staff_code: 'AUTO-001', local_name: '自动预览员工', hire_date: '31/12/2026', departure_date: null }],
      }))
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    expect(page.get('[role=alert]').text()).toContain('Employees!A1：表头与最新模板不一致')
    expect(page.get('[role=alert]').text()).toContain(`请求 ID：${ORG}`)

    await page.findAll('button').find(button => button.text() === '校验并预览')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('Employees!J2 · hire_date：日期格式无法识别')
    expect(page.text()).toContain('可直接编辑预览表')
    expect(page.text()).not.toContain('服务端暂时无法完成预览')
    page.unmount()
  })

  it('keeps edited rows blocked until the server revalidates every editable field', async () => {
    const requests: { path: string; body: unknown }[] = []
    const invalidRow = { ...workforce, row_number: 2, staff_code: '7107', local_name: '可编辑员工', hire_date: '31/12/2026', departure_date: null }
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
      requests.push({ path, body })
      if (path.endsWith('/import-preview')) return json(200, previewBody({
        row_count: 1, catalog_revision: '4', graph_revision: '9',
        errors: [{ row_number: 2, sheet: 'Employees', cell: 'J2', field: 'hire_date', code: 'invalid_date' }],
        warnings: [{ row_number: 2, sheet: 'Employees', cell: 'A2', field: 'staff_code', code: 'numeric_staff_code_coerced' }],
        rows: [invalidRow],
      }))
      if (path.endsWith('/import-review')) return json(200, previewBody({
        row_count: 1, catalog_revision: '4', graph_revision: '9', errors: [],
        rows: [{ ...invalidRow, hire_date: AS_OF }],
      }))
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    expect(page.text()).toContain('数字 Staff Code 已按原始十进制整数转为文本')
    const create = page.findAll('button').find(button => button.text().includes('确认并批量创建'))!
    expect(create.attributes('disabled')).toBeDefined()
    await page.findAll('.edit-input')[9]!.setValue(AS_OF)
    expect(page.text()).toContain('编辑待校验')
    expect(create.attributes('disabled')).toBeDefined()
    await page.findAll('button').find(button => button.text() === '校验编辑内容')!.trigger('click')
    await flushPromises()
    const review = requests.find(request => request.path.endsWith('/import-review'))!
    expect(review.body).toEqual({ rows: [{
      row_number: 2, staff_code: '7107', local_name: '可编辑员工', english_name: '', location: 'Shanghai',
      branch_code: 'BRANCH-A', business_group_code: 'BG-A', division_code: 'DIV-A', department_code: 'DEP-A',
      education_level: 'Master', hire_date: AS_OF, position: '合成顾问', job_family_code: 'JF-A',
      career_level_code: 'P1', manager_staff_code: '', departure_date: null, email: '', phone: '', profile_summary: '',
    }] })
    expect(page.text()).not.toContain('编辑待校验')
    expect(page.findAll('button').find(button => button.text() === '确认并批量创建')!.attributes('disabled')).toBeUndefined()
    page.unmount()
  })

  it('appends an unknown education level explicitly and then revalidates rows', async () => {
    const requests: { path: string; body: unknown }[] = []
    const row = { ...workforce, education_level: 'Doctor', row_number: 2, staff_code: 'EDU-001', local_name: '学历员工', hire_date: AS_OF, departure_date: null }
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
      requests.push({ path, body })
      if (path.endsWith('/import-preview')) return json(200, previewBody({
        row_count: 1, catalog_revision: '4', graph_revision: '9',
        errors: [{ row_number: 2, sheet: 'Employees', cell: 'I2', field: 'education_level', code: 'unknown_education_level' }],
        rows: [row],
      }))
      if (path.endsWith('/workforce-catalog-changes')) return json(201, { catalog_revision: '5', graph_revision: '9' })
      if (path.endsWith('/import-review')) return json(200, previewBody({
        row_count: 1, catalog_revision: '5', graph_revision: '9', errors: [],
        education_levels: [{ code: 'Doctor', rank: 4 }, { code: 'Master', rank: 3 }, { code: 'Bachelor', rank: 2 }, { code: 'Diploma', rank: 1 }],
        rows: [row],
      }))
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    expect(page.text()).toContain('追加新学历目录')
    await page.findAll('button').find(button => button.text() === '确认追加并重新校验')!.trigger('click')
    await flushPromises()
    const catalog = requests.find(request => request.path.endsWith('/workforce-catalog-changes'))!
    expect(catalog.body).toEqual({
      expected_catalog_revision: '4', expected_graph_revision: '9',
      changes: [{ action: 'create', kind: 'education_level', code: 'Doctor', rank: 4 }],
    })
    expect(requests.some(request => request.path.endsWith('/import-review'))).toBe(true)
    expect(page.text()).not.toContain('追加新学历目录')
    expect(page.findAll('button').find(button => button.text() === '确认并批量创建')!.attributes('disabled')).toBeUndefined()
    page.unmount()
  })

  it('keeps a request ID visible when the server cannot produce a cell diagnostic', async () => {
    vi.stubGlobal('fetch', async () => json(503, { code: 'INTERNAL', request_id: ORG }))
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    expect(page.get('[role=alert]').text()).toContain('服务端暂时无法完成预览')
    expect(page.get('[role=alert]').text()).toContain(`请求 ID：${ORG}`)
    page.unmount()
  })

  it('replays an uncertain reporting command once, then keeps the completed batch terminal', async () => {
    const requests: { path: string; method: string; headers: Headers; body: unknown }[] = []
    let createCount = 0
    let reportingAttempt = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const method = init.method ?? 'GET'
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
      requests.push({ path, method, headers: new Headers(init.headers), body })
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 2, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 2, staff_code: 'MGR-001', local_name: '合成主管', hire_date: AS_OF, departure_date: null },
        { ...workforce, row_number: 3, staff_code: 'EMP-001', local_name: '合成员工', english_name: 'Synthetic Employee', email: 'employee@example.test', phone: '+86 21 5555 0100', profile_summary: '跨团队交付', manager_staff_code: 'MGR-001', hire_date: AS_OF, departure_date: null },
      ] }))
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
    const values = page.findAll('.edit-input').map(field => (field.element as HTMLInputElement).value)
    expect(values).toContain('合成员工')
    expect(values).toContain('Synthetic Employee')
    expect(values).toContain('employee@example.test')
    expect(values).toContain('+86 21 5555 0100')
    expect(values).toContain('跨团队交付')
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()

    const creates = requests.filter(request => request.path === `/api/v1/orgs/${ORG}/employees`)
    expect(creates).toHaveLength(2)
    expect(creates.map(request => request.body)).toEqual([
      { profile: { local_name: '合成主管' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'MGR-001', employment: { legal_entity_id: BRANCH, location_code: 'Shanghai' }, education: { level: 'Master' }, job_assignment: { department_id: DEPARTMENT, job_family_id: JOB_FAMILY, career_level_id: CAREER_LEVEL, position: { title: '合成顾问' } }, expected_catalog_revision: '4', expected_graph_revision: '9' },
      { profile: { local_name: '合成员工', english_name: 'Synthetic Employee', work_contact: { email: 'employee@example.test', phone: '+86 21 5555 0100' }, profile_summary: '跨团队交付' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'EMP-001', employment: { legal_entity_id: BRANCH, location_code: 'Shanghai' }, education: { level: 'Master' }, job_assignment: { department_id: DEPARTMENT, job_family_id: JOB_FAMILY, career_level_id: CAREER_LEVEL, position: { title: '合成顾问' } }, expected_catalog_revision: '4', expected_graph_revision: '9' },
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

  it('replays a 502 employee result with its frozen preview revision despite an unrelated failed row', async () => {
    const creates: { key: string | null; body: string }[] = []
    let uncertainAttempt = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 2, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 2, staff_code: 'DUP-001', local_name: '合成冲突员工', hire_date: AS_OF, departure_date: null },
        { ...workforce, row_number: 3, staff_code: 'EMP-002', local_name: '合成重试员工', manager_staff_code: 'OLD-MGR', hire_date: AS_OF, departure_date: null },
      ] }))
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/employees/query')) {
        const query = JSON.parse(String(init.body))
        if (!query.cursor) return json(200, { graph_revision: '9', items: [], next_cursor: 'synthetic-page-2', search_incomplete: true })
        if (query.cursor === 'synthetic-page-2') return json(200, {
          graph_revision: '9', next_cursor: null, search_incomplete: false,
          items: [{ id: MANAGER, lifecycle: { valid_from: AS_OF, valid_to: null }, identifiers: [{ kind: 'staff_code', staff_code: 'OLD-MGR' }] }],
        })
        throw new Error('unexpected directory cursor')
      }
      if (path === `/api/v1/orgs/${ORG}/employees`) {
        creates.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: String(init.body) })
        const body = JSON.parse(String(init.body))
        if (body.staff_code === 'DUP-001') return json(409, {})
        uncertainAttempt++
        return uncertainAttempt === 1 ? json(502, {}) : json(201, { id: EMPLOYEE, profile_revision: '1', workforce_revision: '2', graph_revision: '9' })
      }
      if (path.endsWith('/workforce-changes')) return json(409, {})
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('结果不确定')
    expect(page.text()).toContain('Staff Code 已存在或组织版本已变化')
    expect(page.get('input[type=file]').attributes('disabled')).toBeDefined()
    expect(page.get('.import-controls button.secondary').attributes('disabled')).toBeDefined()
    await page.findAll('button').find(button => button.text() === '确认原提交并继续')!.trigger('click')
    await flushPromises()
    expect(creates).toHaveLength(3)
    expect(creates[1]).toEqual(creates[2])
    expect(JSON.parse(creates[2]!.body).expected_graph_revision).toBe('9')
    expect(page.text()).toContain('批量处理完成：已创建 0，主管待维护 1，失败 1')
    page.unmount()
  })
})
