import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import CompensationBatchPage from './CompensationBatchPage.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const BATCH = '10000000-0000-4000-8000-000000000002'
const CANDIDATE = '10000000-0000-4000-8000-000000000003'
const EMPLOYEE = '10000000-0000-4000-8000-000000000004'
const BRANCH = '10000000-0000-4000-8000-000000000005'
const GROUP = '10000000-0000-4000-8000-000000000006'
const DIVISION = '10000000-0000-4000-8000-000000000007'
const DEPARTMENT = '10000000-0000-4000-8000-000000000008'
const FAMILY = '10000000-0000-4000-8000-000000000009'
const LEVEL = '10000000-0000-4000-8000-000000000010'
const session = { org_id: ORG, csrf_token: 'csrf', mfa_recent: true, mfa_valid_until: '2099-01-01T00:00:00Z', capabilities: ['organization.read', 'pii.read'], compensation_permissions: [{ capability: 'compensation.propose', category: 'financial' }, { capability: 'compensation.read', category: 'financial' }] }
const catalogs = {
  legal_entities: [{ id: BRANCH, code: 'BR', display_name: '合成法分公司', valid_from: '2020-01-01', valid_to: null, active: true }],
  org_units: [
    { id: GROUP, code: 'BG', label: '合成业务单元', kind: 'business_group', valid_from: '2020-01-01' },
    { id: DIVISION, code: 'DIV', label: '合成事业部', kind: 'division', valid_from: '2020-01-01' },
    { id: DEPARTMENT, code: 'DEP', label: '合成部门', kind: 'department', valid_from: '2020-01-01' },
  ],
  org_unit_parents: [{ child_unit_id: DIVISION, parent_unit_id: GROUP, valid_from: '2020-01-01', active: true }, { child_unit_id: DEPARTMENT, parent_unit_id: DIVISION, valid_from: '2020-01-01', active: true }],
  job_families: [{ id: FAMILY, code: 'CONSULT', label: '咨询', valid_from: '2020-01-01' }],
  career_levels: [{ id: LEVEL, code: 'P2', label: 'P2', valid_from: '2020-01-01' }],
}
const employee = { id: EMPLOYEE, profile: { local_name: '合成员工', english_name: 'Synthetic Employee' }, identifiers: [{ kind: 'staff_code', staff_code: 'S001', valid_from: '2020-01-01', valid_to: null }], employment: [{ legal_entity_id: BRANCH, location_code: 'Shanghai', valid_from: '2020-01-01', valid_to: null }], job_assignments: [{ department_id: DEPARTMENT, job_family_id: FAMILY, career_level_id: LEVEL, position: { title: 'Consultant' }, valid_from: '2020-01-01', valid_to: null }] }
const created = { id: BATCH, business_code: 'N-2026-0001', name: '2026 Normal 调薪', cycle_year: 2026, adjustment_type: 'normal', legal_entity_id: BRANCH, default_effective_date: '2026-10-01', budget_currency: 'CNY', budget_amount: '1000000', state: 'draft', revision: '1', lines: [], increase_totals_by_currency: [] }
const stagedLine = { employee_id: EMPLOYEE, staff_code: 'S001', currency: 'CNY', salary_before: '11000', increase_amount: '500', salary_after: '11500', performance_grade: 'A', effective_date: '2026-10-01' }
const frozen = { ...created, revision: '2', manifest_digest: 'frozen-digest', lines: [{ ...stagedLine, correct_salary_before: true, result: 'changed', adjustment_counts: { current_year: 0, previous_year: 0, count_as_of_date: '2026-10-01' } }], increase_totals_by_currency: [{ currency: 'CNY', amount: '500' }] }
const baselineCreated = { id: BATCH, business_code: 'B-2026-0001', name: '2026-06 工资基线', cycle_year: 2026, adjustment_type: 'baseline', legal_entity_id: BRANCH, default_effective_date: '2026-06-30', state: 'draft', revision: '1', lines: [], increase_totals_by_currency: [] }
const baselineLine = { employee_id: EMPLOYEE, staff_code: 'S001', currency: 'CNY', salary_before: '10000', increase_amount: '', salary_after: '9000', result: 'changed' }
const baselineFrozen = { ...baselineCreated, revision: '2', manifest_digest: 'baseline-digest', lines: [baselineLine], increase_totals_by_currency: [] }

type Seen = { url: URL; init: RequestInit; body?: unknown }
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
async function settle() { await flushPromises(); await flushPromises() }
function button(page: VueWrapper, text: string) { const found = page.findAll('button').find(item => item.text() === text); if (!found) throw new Error(`missing button ${text}`); return found }
function installAPI() {
  const seen: Seen[] = []
  let baselineMode = false
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), location.href), method = init.method ?? 'GET'
    let body: unknown
    if (typeof init.body === 'string') body = JSON.parse(init.body)
    seen.push({ url, init, body })
    if (url.pathname === '/api/v1/session') return response(session)
    if (url.pathname.endsWith('/workforce-catalogs')) return response(catalogs)
    if (url.pathname.endsWith('/salary-ranges')) return response([])
    if (url.pathname.endsWith('/compensation-adjustment-batches/options')) return response({ special_reasons: [{ code: 'market_adjustment', label: '市场调整' }] })
    if (url.pathname.endsWith('/compensation-adjustment-batches') && method === 'GET') return response({ batches: [] })
    if (url.pathname.endsWith('/compensation-adjustment-batches') && method === 'POST') {
      baselineMode = (body as { adjustment_type?: string })?.adjustment_type === 'baseline'
      return response(baselineMode ? baselineCreated : created, 201)
    }
    if (url.pathname.endsWith('/compensation-adjustment-batches/import-template')) return new Response(new Uint8Array([80, 75, 3, 4]), { status: 200, headers: { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' } })
    if (url.pathname.endsWith('/employees/query')) return response({ items: [employee] })
    if (url.pathname.endsWith(`/employees/${EMPLOYEE}/compensation`)) return response({ current_term: { terms: { currency: 'CNY', scale: 0, amount_minor: '10000', unit: 'month', payment_frequency: 'monthly', tax_basis: 'gross' } } })
    if (url.pathname.endsWith(`/compensation-adjustment-batches/${BATCH}/previews`)) return response(baselineMode
      ? { id: CANDIDATE, batch_id: BATCH, base_revision: '1', state: 'valid', line_count: 1, lines: [baselineLine], warnings: [], adjustment_counts_by_employee: {}, errors: [], expires_at: '2099-01-01T00:00:00Z' }
      : { id: CANDIDATE, batch_id: BATCH, base_revision: '1', state: 'valid', line_count: 1, lines: [stagedLine], warnings: [{ code: 'SALARY_BEFORE_MISMATCH', employee_id: EMPLOYEE, staff_code: 'S001', effective_date: '2026-10-01', entered_salary_before: '11000', current_salary_before: '10000' }], adjustment_counts_by_employee: {}, errors: [], expires_at: '2099-01-01T00:00:00Z' }, 201)
    if (url.pathname.endsWith(`/compensation-adjustment-batches/${BATCH}/imports`)) return response({ id: CANDIDATE, batch_id: BATCH, base_revision: '1', state: 'valid', line_count: 1, lines: [stagedLine], warnings: [], adjustment_counts_by_employee: {}, errors: [], expires_at: '2099-01-01T00:00:00Z' }, 201)
    if (url.pathname.endsWith(`/compensation-adjustment-batches/${BATCH}/draft`)) return response(baselineMode ? baselineFrozen : frozen)
    if (url.pathname.endsWith(`/compensation-adjustment-batches/${BATCH}/transitions`)) return response({ ...(baselineMode ? baselineFrozen : frozen), state: 'activated', revision: '3' })
    throw new Error(`unexpected ${method} ${url.pathname}`)
  }))
  return seen
}
async function createNormal(page: VueWrapper) {
  const form = page.get('form[aria-label="创建薪资调整批次"]')
  await form.get('input[placeholder*="2026-07-08"]').setValue('2026 Normal 调薪')
  const selects = form.findAll('select')
  await selects[1]!.setValue(BRANCH)
  await form.get('input[type="date"]').setValue('2026-10-01')
  const numeric = form.findAll('input[inputmode="numeric"]')
  await numeric[1]!.setValue('1000000')
  await form.trigger('submit'); await settle()
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); document.body.replaceChildren() })

describe('salary adjustment batch workbench', () => {
  it('creates business metadata, starts with three rows, autofills staff, previews warnings, and activates only after both confirmations', async () => {
    history.replaceState({}, '', `/orgs/${ORG}/compensation-adjustments`)
    const seen = installAPI()
    const page = mount(CompensationBatchPage, { attachTo: document.body }); await settle()
    await createNormal(page)

    const createRequest = seen.find(item => item.url.pathname.endsWith('/compensation-adjustment-batches') && item.init.method === 'POST')!
    expect(createRequest.body).toEqual({ name: '2026 Normal 调薪', cycle_year: 2026, adjustment_type: 'normal', legal_entity_id: BRANCH, default_effective_date: '2026-10-01', budget_currency: 'CNY', budget_amount: '1000000' })
    expect(page.findAll('input[id^="staff-"]')).toHaveLength(3)

    const staff = page.findAll('input[id^="staff-"]')[0]!
    await staff.setValue('S001'); await staff.trigger('blur'); await settle()
    expect(page.text()).toContain('合成员工')
    expect(page.text()).toContain('合成业务单元 / 合成事业部 / 合成部门')
    expect(page.get('input[aria-label="第1行调整前工资"]').element).toHaveProperty('value', '10000')

    await page.get('input[aria-label="第1行调整前工资"]').setValue('11000')
    await page.get('input[aria-label="第1行增加额"]').setValue('500')
    await page.get('input[aria-label="第1行绩效等级"]').setValue('A')
    expect(page.get('input[aria-label="第1行调整后工资"]').element).toHaveProperty('value', '11500')
    await button(page, '生成确认预览').trigger('click'); await settle()

    const preview = seen.find(item => item.url.pathname.endsWith('/previews'))!
    expect(preview.body).toMatchObject({ revision: '1', lines: [{ employee_id: '', staff_code: 'S001', currency: 'CNY', salary_before: '11000', increase_amount: '500', salary_after: '11500', performance_grade: 'A' }, { staff_code: '', currency: '' }, { staff_code: '', currency: '' }] })
    expect(new Headers(preview.init.headers).get('X-Access-Purpose')).toBe('compensation_management')
    const directory = seen.find(item => item.url.pathname.endsWith('/employees/query'))!
    expect(new Headers(directory.init.headers).get('X-Access-Purpose')).toBe('organization_management')
    expect(page.text()).toContain('调整前工资不一致')
    expect(button(page, '确认并应用为草稿').attributes('disabled')).toBeDefined()

    await page.get('.warning-list input[type="checkbox"]').setValue(true)
    expect(button(page, '确认并应用为草稿').attributes('disabled')).toBeUndefined()
    await button(page, '确认并应用为草稿').trigger('click'); await settle()
    const apply = seen.find(item => item.url.pathname.endsWith('/draft'))!
    expect(apply.body).toEqual({ revision: '1', candidate_id: CANDIDATE, confirm_salary_corrections: [EMPLOYEE] })
    expect(page.text()).toContain('生效时先追加纠正')
    expect(seen.some(item => item.url.pathname.endsWith('/transitions'))).toBe(false)

    await page.get('.activation-check input[type="checkbox"]').setValue(true)
    await button(page, '确认整批生效').trigger('click'); await settle()
    expect(seen.find(item => item.url.pathname.endsWith('/transitions'))!.body).toEqual({ action: 'submit', revision: '2', manifest_digest: 'frozen-digest' })
    expect(page.text()).toContain('整批已原子生效')
    page.unmount()
  })

  it('keeps XLSX secondary, collapsed, byte-exact, and routed through the same preview panel', async () => {
    history.replaceState({}, '', `/orgs/${ORG}/compensation-adjustments`)
    const seen = installAPI()
    const page = mount(CompensationBatchPage, { attachTo: document.body }); await settle(); await createNormal(page)
    const panel = page.get('details.xlsx-panel')
    expect(panel.attributes('open')).toBeUndefined()
    await panel.get('summary').trigger('click')
    const workbook = new File(['synthetic-xlsx'], 'normal.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
    const fileInput = panel.get('input[type="file"]')
    Object.defineProperty(fileInput.element, 'files', { value: [workbook] }); await fileInput.trigger('change')
    await button(page, '解析 XLSX').trigger('click'); await settle()
    expect(seen.find(item => item.url.pathname.endsWith('/imports'))!.init.body).toBe(workbook)
    expect(page.get('[aria-label="调薪预览确认"]').text()).toContain('1 名员工')
    page.unmount()
  })
  it('submits the controlled Special header with a manual default date and reference budget', async () => {
    history.replaceState({}, '', `/orgs/${ORG}/compensation-adjustments`)
    const seen = installAPI()
    const page = mount(CompensationBatchPage, { attachTo: document.body }); await settle()
    const form = page.get('form[aria-label="创建薪资调整批次"]')
    await form.get('input[placeholder*="2026-07-08"]').setValue('2026-07-08 特调')
    await form.findAll('select')[0]!.setValue('special')
    await form.findAll('select')[1]!.setValue(BRANCH)
    await form.get('input[type="date"]').setValue('2026-10-01')
    await form.findAll('input[inputmode="numeric"]')[1]!.setValue('1000000')
    await form.findAll('select').at(-1)!.setValue('market_adjustment')
    await form.get('input[placeholder*="业务背景"]').setValue('关键岗位市场调整')
    await form.trigger('submit'); await settle()
    expect(seen.find(item => item.url.pathname.endsWith('/compensation-adjustment-batches') && item.init.method === 'POST')!.body).toEqual({
      name: '2026-07-08 特调', cycle_year: 2026, adjustment_type: 'special', legal_entity_id: BRANCH,
      default_effective_date: '2026-10-01', budget_currency: 'CNY', budget_amount: '1000000',
      special_reason_code: 'market_adjustment', special_reason_text: '关键岗位市场调整',
    })
    page.unmount()
  })

  it('creates a salary-at-date baseline without a budget, keeps target salary editable, and uses the controlled template and confirmation flow', async () => {
    history.replaceState({}, '', `/orgs/${ORG}/compensation-adjustments`)
    const createObjectURL = vi.fn(() => 'blob:baseline-template')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const seen = installAPI()
    const page = mount(CompensationBatchPage, { attachTo: document.body }); await settle()
    const form = page.get('form[aria-label="创建薪资调整批次"]')
    await form.get('input[placeholder*="2026-07-08"]').setValue('2026-06 工资基线')
    await form.findAll('select')[0]!.setValue('baseline')
    await form.findAll('select')[1]!.setValue(BRANCH)
    await form.get('input[type="date"]').setValue('2026-06-30')
    await form.trigger('submit'); await settle()

    expect(seen.find(item => item.url.pathname.endsWith('/compensation-adjustment-batches') && item.init.method === 'POST')!.body).toEqual({
      name: '2026-06 工资基线', cycle_year: 2026, adjustment_type: 'baseline', legal_entity_id: BRANCH, default_effective_date: '2026-06-30',
    })
    expect(page.find('input[aria-label="第1行调整前工资"]').exists()).toBe(false)
    const staff = page.findAll('input[id^="staff-"]')[0]!
    await staff.setValue('S001'); await staff.trigger('blur'); await settle()
    expect(page.get('input[aria-label="第1行指定日工资"]').element).toHaveProperty('value', '')
    await page.get('input[aria-label="第1行指定日工资"]').setValue('9000')
    await button(page, '生成确认预览').trigger('click'); await settle()
    expect(seen.find(item => item.url.pathname.endsWith('/previews'))!.body).toMatchObject({ lines: [{ staff_code: 'S001', currency: 'CNY', salary_before: '', increase_amount: '', salary_after: '9000' }, { staff_code: '', currency: '', salary_after: '' }, { staff_code: '', currency: '', salary_after: '' }] })
    expect(page.get('[aria-label="调薪预览确认"]').text()).toContain('系统指定日前工资')
    expect(page.get('[aria-label="调薪预览确认"]').text()).toContain('10000')
    expect(page.get('[aria-label="调薪预览确认"]').text()).toContain('9000')

    await page.get('details.xlsx-panel').get('summary').trigger('click')
    await button(page, '下载工资基线模板').trigger('click'); await settle()
    expect(seen.some(item => item.url.pathname.endsWith('/import-template') && item.url.searchParams.get('adjustment_type') === 'baseline')).toBe(true)
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(click).toHaveBeenCalledOnce()
    await button(page, '确认并应用为草稿').trigger('click'); await settle()
    expect(page.text()).toContain('不会计入 Normal / Special 调薪次数')
    await page.get('.activation-check input[type="checkbox"]').setValue(true)
    await button(page, '确认整批生效').trigger('click'); await settle()
    expect(seen.find(item => item.url.pathname.endsWith('/transitions'))!.body).toEqual({ action: 'submit', revision: '2', manifest_digest: 'baseline-digest' })

    page.unmount()
  })
})
