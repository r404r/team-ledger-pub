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
  it('previews rows, creates profiles without managers, then writes all confirmed reporting lines once', async () => {
    const requests: { path: string; method: string; headers: Headers; body: unknown }[] = []
    let createCount = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      const method = init.method ?? 'GET'
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
      requests.push({ path, method, headers: new Headers(init.headers), body })
      if (path.endsWith('/import-preview')) return json(200, { row_count: 2, errors: [], rows: [
        { row_number: 2, staff_code: 'MGR-001', local_name: '合成主管', hire_date: AS_OF, departure_date: null },
        { row_number: 3, staff_code: 'EMP-001', local_name: '合成员工', manager_staff_code: 'MGR-001', hire_date: AS_OF, departure_date: null },
      ] })
      if (path === '/api/v1/session') return json(200, { ...SESSION, auth_epoch: requests.some(request => request.path.endsWith('/workforce-changes')) ? '2' : '1' })
      if (path.endsWith('/workforce-catalogs')) return json(200, { catalog_revision: '4', graph_revision: '9' })
      if (path === `/api/v1/orgs/${ORG}/employees`) {
        createCount++
        return json(201, { id: createCount === 1 ? MANAGER : EMPLOYEE, profile_revision: '1', workforce_revision: '2', graph_revision: '9' })
      }
      if (path.endsWith('/workforce-changes')) return json(201, { graph_revision: '10' })
      throw new Error(`unexpected request ${method} ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF }, attachTo: document.body })
    await selectAndPreview(page)
    expect(page.text()).toContain('已校验 2 行')
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()

    const creates = requests.filter(request => request.path === `/api/v1/orgs/${ORG}/employees`)
    expect(creates).toHaveLength(2)
    expect(creates.map(request => request.body)).toEqual([
      { profile: { local_name: '合成主管' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'MGR-001', expected_catalog_revision: '4', expected_graph_revision: '9' },
      { profile: { local_name: '合成员工' }, lifecycle: { valid_from: AS_OF, valid_to: null }, staff_code: 'EMP-001', expected_catalog_revision: '4', expected_graph_revision: '9' },
    ])
    const reporting = requests.find(request => request.path.endsWith('/workforce-changes'))!
    expect(reporting.body).toEqual({
      expected_catalog_revision: '4', expected_graph_revision: '9', expected_employee_revisions: { [EMPLOYEE]: '2' }, reason: 'Personnel XLSX import',
      changes: [{ action: 'add', kind: 'reporting', employee_id: EMPLOYEE, manager_employee_id: MANAGER, reporting_kind: 'administrative', valid_from: AS_OF, valid_to: null }],
    })
    expect(page.text()).toContain('批量处理完成：已创建 2')
    expect(page.emitted('session-updated')).toEqual([[{ session: { ...SESSION, auth_epoch: '2' }, catalogRevision: '4', graphRevision: '10' }]])
    page.unmount()
  })

  it('replays an uncertain employee create with the original body and idempotency key', async () => {
    const creates: { key: string | null; body: string }[] = []
    let attempt = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), location.href).pathname
      if (path.endsWith('/import-preview')) return json(200, { row_count: 1, errors: [], rows: [{ row_number: 2, staff_code: 'EMP-002', local_name: '合成重试员工', hire_date: AS_OF, departure_date: null }] })
      if (path === '/api/v1/session') return json(200, SESSION)
      if (path.endsWith('/workforce-catalogs')) return json(200, { catalog_revision: '4', graph_revision: '9' })
      if (path === `/api/v1/orgs/${ORG}/employees`) {
        creates.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: String(init.body) })
        attempt++
        return attempt === 1 ? json(503, {}) : json(201, { id: EMPLOYEE, profile_revision: '1', workforce_revision: '2', graph_revision: '9' })
      }
      throw new Error(`unexpected request ${path}`)
    })
    const page = mount(PersonnelImportPanel, { props: { session: SESSION, asOf: AS_OF } })
    await selectAndPreview(page)
    await page.findAll('button').find(button => button.text() === '确认并批量创建')!.trigger('click')
    await flushPromises()
    expect(page.text()).toContain('结果不确定')
    await page.findAll('button').find(button => button.text() === '确认原提交并继续')!.trigger('click')
    await flushPromises()
    expect(creates).toHaveLength(2)
    expect(creates[0]).toEqual(creates[1])
    expect(page.text()).toContain('批量处理完成：已创建 1')
    page.unmount()
  })
})
