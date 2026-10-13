import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import CompensationBatchPage from './CompensationBatchPage.vue'

const ORG = '10000000-0000-4000-8000-000000000001'
const BATCH = '10000000-0000-4000-8000-000000000002'
const CANDIDATE = '10000000-0000-4000-8000-000000000003'
const session = { org_id: ORG, csrf_token: 'csrf', mfa_recent: true, mfa_valid_until: '2099-01-01T00:00:00Z', compensation_permissions: [{ capability: 'compensation.propose', category: 'financial' }] }
const draft = { id: BATCH, business_code: 'N-2026-0001', cycle_year: 2026, adjustment_type: 'normal', legal_entity_id: 'branch', default_effective_date: '2026-04-01', state: 'draft', revision: '2', manifest_digest: 'digest', lines: [{ employee_id: 'employee', staff_code: 'S001', currency: 'CNY', salary_before: '10000', increase_amount: '500', salary_after: '10500', effective_date: '2026-04-01', result: 'changed', adjustment_counts: { current_year: 0, previous_year: 1 } }], increase_totals_by_currency: [{ currency: 'CNY', amount: '500' }] }
const salaryRange = { id: 'range', legal_entity_id: 'branch', location: 'Shanghai', job_family_id: 'family', career_level_id: 'level', currency: 'CNY', valid_from: '2026-01-01', revision: '1', amounts: { minimum: '10000', midpoint: '15000', maximum: '20000' } }
function json(body: unknown) { return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }) }
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); document.body.replaceChildren() })
describe('salary adjustment batch workbench', () => {
  it('uses compensation purpose, imports exact XLSX bytes and activates only after explicit frozen confirmation', async () => {
    history.replaceState({}, '', `/orgs/${ORG}/compensation-adjustments`)
    const requests: { url: URL; init: RequestInit }[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const request = { url: new URL(String(input), location.href), init }; requests.push(request)
      if (request.url.pathname.endsWith('/session')) return json(session)
      if (request.url.pathname.endsWith('/salary-ranges')) return json([salaryRange])
      if (request.url.pathname.endsWith('/salary-range-changes')) return json([{ ...salaryRange, valid_to: '2026-07-01' }, { ...salaryRange, id: 'replacement', valid_from: '2026-07-01', revision: '1', amounts: { minimum: '11000', midpoint: '16000', maximum: '21000' } }])
      if (request.url.pathname.endsWith('/compensation-adjustment-batches') && !init.method) return json({ batches: [draft] })
      if (request.url.pathname.endsWith(`/compensation-adjustment-batches/${BATCH}`)) return json(draft)
      if (request.url.pathname.endsWith('/imports')) return json({ id: CANDIDATE, batch_id: BATCH, base_revision: '2', state: 'valid', line_count: 1, lines: draft.lines, errors: [], expires_at: '2099-01-01T00:00:00Z' })
      if (request.url.pathname.endsWith('/draft') && init.method === 'PATCH') return json(draft)
      if (request.url.pathname.endsWith('/transitions')) return json({ ...draft, state: 'activated', revision: '3', lines: draft.lines.map(line => ({ ...line, original_adjustment_event_id: 'event', correction_members: [{ member_key: 'batch_1', action: 'replace', original_event_id: 'event', effective_date: '2026-04-01', before_ref: null, after: { currency: 'CNY', scale: 0, amount_minor: '10500', unit: 'month', payment_frequency: 'monthly', tax_basis: 'gross', components: [] } }] })) })
      if (request.url.pathname.endsWith('/corrections')) return json({ business_code: 'NC-2026-0001' })
      throw new Error(`unexpected ${request.url}`)
    })
    const page = mount(CompensationBatchPage, { attachTo: document.body }); await flushPromises()
    await page.findAll('button').find(button => button.text() === '结束/替换')!.trigger('click')
    const rangeForm = page.get('form[aria-label="结束或替换 Salary Range"]')
    await rangeForm.get('select').setValue('replace')
    await rangeForm.get('input[type=date]').setValue('2026-07-01')
    const amounts = rangeForm.findAll('input:not([type=date])')
    await amounts[0].setValue('11000'); await amounts[1].setValue('16000'); await amounts[2].setValue('21000')
    await rangeForm.trigger('submit'); await flushPromises()
    const rangeRequest = requests.find(r => r.url.pathname.endsWith('/salary-range-changes'))!
    expect(JSON.parse(String(rangeRequest.init.body))).toMatchObject({ changes: [{ action: 'replace', id: 'range', expected_revision: '1', effective_to: '2026-07-01', valid_from: '2026-07-01', amounts: { minimum: '11000', midpoint: '16000', maximum: '21000' } }] })
    await page.findAll('button').find(button => button.text().includes('N-2026-0001'))!.trigger('click'); await flushPromises()
    const workbook = new File(['synthetic-xlsx'], 'normal.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
    Object.defineProperty(page.get('input[type=file]').element, 'files', { value: [workbook] }); await page.get('input[type=file]').trigger('change')
    await page.findAll('button').find(button => button.text() === '解析 XLSX 候选')!.trigger('click'); await flushPromises()
    expect(requests.find(r => r.url.pathname.endsWith('/imports'))!.init.body).toBe(workbook)
    expect(requests.every(r => new Headers(r.init.headers).get('X-Access-Purpose') === 'compensation_management')).toBe(true)
    expect(requests.some(r => r.url.pathname.endsWith('/transitions'))).toBe(false)
    expect(page.text()).toContain('1 行')
    expect(page.text()).toContain('应用前候选预览')
    expect(page.text()).toContain('10500')
    await page.findAll('button').find(button => button.text() === '应用候选并替换草稿')!.trigger('click'); await flushPromises()
    const apply = requests.find(r => r.url.pathname.endsWith('/draft'))!
    expect(JSON.parse(String(apply.init.body))).toEqual({ revision: '2', candidate_id: CANDIDATE })
    await page.get('input[type=checkbox]').setValue(true); await page.findAll('button').find(button => button.text() === '整批生效')!.trigger('click'); await flushPromises()
    const activation = requests.find(r => r.url.pathname.endsWith('/transitions'))!
    expect(JSON.parse(String(activation.init.body))).toEqual({ action: 'submit', revision: '2', manifest_digest: 'digest' })
    expect(page.text()).toContain('整批已原子生效')
    const correctionForm = page.get('form[aria-label="更正已生效批次"]')
    await correctionForm.get('input').setValue('更正错误金额')
    await correctionForm.findAll('button').find(button => button.text() === '生成更正模板')!.trigger('click')
    const generated = JSON.parse(String((correctionForm.get('textarea').element as HTMLTextAreaElement).value))
    generated[0].members[0].after.amount_minor = '10400'
    await correctionForm.get('textarea').setValue(JSON.stringify(generated))
    await correctionForm.trigger('submit'); await flushPromises()
    const correction = requests.find(r => r.url.pathname.endsWith('/corrections'))!
    expect(JSON.parse(String(correction.init.body))).toMatchObject({ reason: '更正错误金额', lines: [{ employee_id: 'employee' }] })
    expect(page.text()).toContain('更正 NC-2026-0001 已原子生效')
    page.unmount()
  })
})
