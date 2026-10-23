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
  return {
    warnings: [],
    education_levels: [{ code: 'Master', rank: 3 }, { code: 'Bachelor', rank: 2 }, { code: 'Diploma', rank: 1 }],
    legal_entities: [{ id: BRANCH, code: 'BRANCH-A', label: 'Branch A' }],
    business_groups: [{ id: BUSINESS_GROUP, code: 'BG-A', label: 'Group A' }],
    divisions: [{ id: DIVISION, code: 'DIV-A', label: 'Division A' }],
    departments: [{ id: DEPARTMENT, code: 'DEP-A', label: 'Department A' }],
    job_families: [{ id: JOB_FAMILY, code: 'JF-A', label: 'Job Family A' }],
    career_levels: [{ id: CAREER_LEVEL, code: 'P1', label: 'P1', rank: 1 }],
    ...body,
  }
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

  it('creates explicitly confirmed missing catalogs and inferred organization links before revalidation', async () => {
    const requests: { path: string; body: Record<string, unknown> }[] = []
    let catalogCall = 0
    let reviewCall = 0
    const rawRow = {
      ...workforce,
      row_number: 2,
      staff_code: 'LEGACY-001',
      local_name: '旧表员工',
      branch_code: 'Legacy Branch',
      business_group_code: 'Legacy Group',
      division_code: 'Legacy Division',
      department_code: 'Legacy Department',
      job_family_code: 'Legacy Family',
      career_level_code: 'L1',
      branch_id: '',
      business_group_id: '',
      division_id: '',
      department_id: '',
      job_family_id: '',
      career_level_id: '',
      hire_date: AS_OF,
      departure_date: null,
    }
    const unknown = ['branch_code', 'business_group_code', 'division_code', 'department_code', 'job_family_code', 'career_level_code'].map((field, index) => ({
      row_number: 2,
      sheet: 'Employees',
      cell: `${String.fromCharCode(69 + index)}2`,
      field,
      code: 'unknown_catalog_code',
    }))
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const body = typeof init.body === 'string' ? JSON.parse(init.body) as Record<string, unknown> : {}
      requests.push({ path, body })
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 1, catalog_revision: '4', graph_revision: '9', errors: unknown, rows: [rawRow] }))
      if (path.endsWith('/workforce-catalog-changes')) {
        catalogCall++
        return catalogCall === 1
          ? json(201, { catalog_revision: '5', graph_revision: '10', items: [
            { kind: 'legal_entity', id: BRANCH }, { kind: 'business_group', id: BUSINESS_GROUP },
            { kind: 'division', id: DIVISION }, { kind: 'department', id: DEPARTMENT },
            { kind: 'job_family', id: JOB_FAMILY }, { kind: 'career_level', id: CAREER_LEVEL },
          ] })
          : json(201, { catalog_revision: '6', graph_revision: '11', items: [{ kind: 'org_unit_parent', id: ORG }, { kind: 'org_unit_parent', id: SUBJECT }] })
      }
      if (path.endsWith('/import-review')) {
        reviewCall++
        const resolved = { ...rawRow, branch_id: BRANCH, business_group_id: BUSINESS_GROUP, division_id: DIVISION, department_id: DEPARTMENT, job_family_id: JOB_FAMILY, career_level_id: CAREER_LEVEL }
        return json(200, previewBody({
          row_count: 1,
          catalog_revision: reviewCall === 1 ? '5' : '6',
          graph_revision: reviewCall === 1 ? '10' : '11',
          errors: reviewCall === 1 ? [
            { row_number: 2, sheet: 'Employees', cell: 'H2', field: 'department_code', code: 'organization_hierarchy_mismatch' },
          ] : [],
          rows: [resolved],
        }))
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    expect(page.text()).toContain('适配缺失目录')
    expect(page.findAll('.catalog-draft')).toHaveLength(7)
    await page.findAll('button').find(button => button.text() === '确认新增目录并重新校验')!.trigger('click')
    await flushPromises()
    const catalogRequests = requests.filter(request => request.path.endsWith('/workforce-catalog-changes'))
    expect(catalogRequests).toHaveLength(2)
    expect(catalogRequests[0]!.body).toMatchObject({
      expected_catalog_revision: '4',
      expected_graph_revision: '9',
      changes: [
        { action: 'create', kind: 'legal_entity', code: 'Legacy Branch', label: 'Legacy Branch', valid_from: AS_OF },
        { action: 'create', kind: 'business_group', code: 'Legacy Group', label: 'Legacy Group', valid_from: AS_OF },
        { action: 'create', kind: 'division', code: 'Legacy Division', label: 'Legacy Division', valid_from: AS_OF },
        { action: 'create', kind: 'department', code: 'Legacy Department', label: 'Legacy Department', valid_from: AS_OF },
        { action: 'create', kind: 'job_family', code: 'Legacy Family', label: 'Legacy Family', valid_from: AS_OF },
        { action: 'create', kind: 'career_level', code: 'L1', label: 'L1', valid_from: AS_OF, rank: 2 },
      ],
    })
    expect(catalogRequests[1]!.body).toMatchObject({
      expected_catalog_revision: '5',
      expected_graph_revision: '10',
      changes: [
        { action: 'create', kind: 'org_unit_parent', ref: DIVISION, parent_ref: BUSINESS_GROUP, valid_from: AS_OF },
        { action: 'create', kind: 'org_unit_parent', ref: DEPARTMENT, parent_ref: DIVISION, valid_from: AS_OF },
      ],
    })
    expect(page.text()).not.toContain('适配缺失目录')
    expect(page.findAll('button').find(button => button.text() === '确认并批量创建')!.attributes('disabled')).toBeUndefined()
    page.unmount()
  })

  it('preserves blank optional fields in the atomic batch command', async () => {
    const commits: Record<string, any>[] = []
    const row = { ...workforce, row_number: 2, staff_code: 'OPTIONAL001', local_name: '合成可选员工', education_level: '', position: '', job_family_code: '', career_level_code: '', hire_date: AS_OF, departure_date: null }
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 1, catalog_revision: '4', graph_revision: '9', errors: [], rows: [row] }))
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/import-commit')) {
        commits.push(JSON.parse(String(init.body)))
        return json(201, { catalog_revision: '4', graph_revision: '9', items: [{ kind: 'employee', id: EMPLOYEE }] })
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(commits).toHaveLength(1)
    expect(commits[0]!.rows[0]).toMatchObject({ education_level: '', position: '', job_family_code: '', career_level_code: '', manager_staff_code: '' })
    expect(page.text()).toContain('批量处理完成：已创建 1')
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

  it.each([502, 504])('replays an uncertain %s batch with its original key and body', async status => {
    const commits: { key: string | null; body: string }[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 2, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 5, staff_code: 'SUB001', local_name: '合成下属', manager_staff_code: '002046-San Zhang', hire_date: AS_OF, departure_date: null },
        { ...workforce, row_number: 80, staff_code: '002046', local_name: '合成主管', hire_date: AS_OF, departure_date: null },
      ] }))
      if (path === '/api/v1/session') return json(200, { ...SESSION, auth_epoch: commits.length > 1 ? '2' : '1' })
      if (path.endsWith('/import-commit')) {
        commits.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: String(init.body) })
        if (commits.length === 1) return json(status, {})
        return json(201, { catalog_revision: '4', graph_revision: '10', items: [{ kind: 'employee', id: EMPLOYEE }, { kind: 'employee', id: MANAGER }] })
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    const values = page.findAll('.edit-input').map(field => (field.element as HTMLInputElement).value)
    expect(values).toContain('002046')
    expect(values).not.toContain('002046-San Zhang')
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('整批提交结果不确定')
    expect(page.get('input[type=file]').attributes('disabled')).toBeDefined()
    expect(page.findAll('.edit-input').every(field => field.attributes('disabled') !== undefined)).toBe(true)
    await page.findAll('button').find(button => button.text() === '确认原提交并继续')!.trigger('click')
    await flushPromises()
    expect(commits).toHaveLength(2)
    expect(commits[0]).toEqual(commits[1])
    const payload = JSON.parse(commits[0]!.body)
    expect(payload.expected_graph_revision).toBe('9')
    expect(payload.rows.map((row: any) => [row.row_number, row.staff_code, row.manager_staff_code])).toEqual([[5, 'SUB001', '002046'], [80, '002046', '']])
    expect(page.text()).toContain('批量处理完成：已创建 2，失败 0')
    expect(page.findAll('button').find(button => button.text() === '批量处理已完成')!.attributes('disabled')).toBeDefined()
    expect(page.emitted('session-updated')).toEqual([[{ session: { ...SESSION, auth_epoch: '2' }, catalogRevision: '4', graphRevision: '10' }]])
    page.unmount()
  })

  it('shows the whole batch as failed on a definitive conflict', async () => {
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 2, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 2, staff_code: 'FRESH001', local_name: '合成员工', hire_date: AS_OF, departure_date: null },
        { ...workforce, row_number: 3, staff_code: 'DUP001', local_name: '合成冲突', hire_date: AS_OF, departure_date: null },
      ] }))
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/import-commit')) return json(409, {})
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('批量处理完成：已创建 0，失败 2')
    expect(page.text()).toContain('整批未创建')
    expect(page.emitted('session-updated')).toBeUndefined()
    page.unmount()
  })

  it('sends an external composite HOD as a normalized code for server resolution', async () => {
    const commits: any[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, previewBody({ row_count: 1, catalog_revision: '4', graph_revision: '9', errors: [], rows: [
        { ...workforce, row_number: 2, staff_code: 'SUB001', local_name: '合成下属', manager_staff_code: '002046 - San Zhang', hire_date: AS_OF, departure_date: null },
      ] }))
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/import-commit')) {
        commits.push(JSON.parse(String(init.body)))
        return json(201, { catalog_revision: '4', graph_revision: '10', items: [{ kind: 'employee', id: EMPLOYEE }] })
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(commits[0].rows[0].manager_staff_code).toBe('002046')
    expect(page.text()).toContain('批量处理完成：已创建 1')
    page.unmount()
  })
})
