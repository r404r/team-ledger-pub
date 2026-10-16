<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()

type Permission = { capability: string; category: string }
type Session = { org_id: string; csrf_token: string; mfa_recent: boolean; mfa_valid_until: string; capabilities?: string[]; compensation_permissions: Permission[] }
type Lifecycle = { valid_from: string; valid_to?: string | null }
type CatalogEntry = Lifecycle & { id: string; code: string; kind?: string; label?: string; display_name?: string; active?: boolean }
type Catalogs = { legal_entities: CatalogEntry[]; org_units: CatalogEntry[]; org_unit_parents: (Lifecycle & { child_unit_id: string; parent_unit_id: string; active?: boolean })[]; job_families: CatalogEntry[]; career_levels: CatalogEntry[] }
type Employee = {
  id: string
  profile?: { local_name?: string; english_name?: string }
  identifiers: (Lifecycle & { kind: string; staff_code?: string })[]
  employment: (Lifecycle & { legal_entity_id: string; location_code: string })[]
  job_assignments: (Lifecycle & { department_id: string; job_family_id?: string; career_level_id?: string; position?: { title?: string } })[]
}
type Directory = { items: Employee[] }
type CurrentCompensation = { current_term: null | { terms: { currency: string; scale: number; amount_minor: string | null; unit: string; payment_frequency: string; tax_basis: string } } }
type AdjustmentCounts = { current_year: number; previous_year: number; count_as_of_date?: string }
type Line = {
  employee_id: string; staff_code: string; currency: string; salary_before: string; increase_amount: string; salary_after: string
  performance_grade?: string; average_merit_increase?: string; department_suggested_increase?: string
  effective_date?: string; effective_month?: string; reason_code?: string; reason_text?: string; correct_salary_before?: boolean
  original_adjustment_event_id?: string; correction_members?: unknown[]; result?: string; adjustment_counts?: AdjustmentCounts
}
type Batch = {
  id: string; business_code: string; name: string; cycle_year: number; adjustment_type: 'normal' | 'special' | 'baseline'; legal_entity_id: string
  default_effective_date: string; special_reason_code?: string; special_reason_text?: string; budget_currency?: string; budget_amount?: string
  budget_legacy_unspecified?: boolean; state: string; revision: string; manifest_digest?: string; lines: Line[]
  increase_totals_by_currency: { currency: string; amount: string }[]
}
type PreviewWarning = { code: string; employee_id: string; staff_code: string; effective_date: string; entered_salary_before: string; current_salary_before: string }
type ImportCandidate = { id: string; batch_id: string; base_revision: string; state: string; line_count: number; lines: Line[]; warnings: PreviewWarning[]; adjustment_counts_by_employee: Record<string, AdjustmentCounts>; errors: string[]; expires_at: string }
type SalaryRange = { id: string; legal_entity_id: string; location: string; job_family_id: string; career_level_id: string; currency: 'CNY' | 'JPY'; valid_from: string; valid_to?: string; revision: string; amounts: { minimum: string; midpoint: string; maximum: string } }
type EmployeeDisplay = { employeeID: string; name: string; englishName: string; location: string; branch: string; businessGroup: string; division: string; department: string; position: string; jobFamily: string; careerLevel: string; currentSalary: string; currency: string }
type EditorRow = Line & { key: number; lookupState: 'idle' | 'loading' | 'ready' | 'limited' | 'error'; lookupMessage: string; display?: EmployeeDisplay }
type BatchOptions = { special_reasons: { code: string; label: string }[] }

class ApiFailure extends Error { constructor(readonly status: number) { super(String(status)) } }
const batches = shallowRef<Batch[]>([])
const salaryRanges = shallowRef<SalaryRange[]>([])
const catalogs = shallowRef<Catalogs | null>(null)
const options = shallowRef<BatchOptions>({ special_reasons: [] })
const selected = shallowRef<Batch | null>(null)
const candidate = shallowRef<ImportCandidate | null>(null)
const session = shallowRef<Session | null>(null)
const rows = ref<EditorRow[]>([])
const confirmedCorrections = ref<string[]>([])
const busy = ref(false)
const error = ref('')
const notice = ref('')
const confirmed = ref(false)
const file = shallowRef<File | null>(null)
const create = reactive({ name: '', cycle_year: String(new Date().getUTCFullYear()), adjustment_type: 'normal' as 'normal' | 'special' | 'baseline', legal_entity_id: '', default_effective_date: '', special_reason_code: '', special_reason_text: '', budget_currency: 'CNY', budget_amount: '' })
const range = reactive({ legal_entity_id: '', location: 'Shanghai', job_family_id: '', career_level_id: '', currency: 'CNY', valid_from: '', minimum: '', midpoint: '', maximum: '' })
const rangeChange = reactive({ action: 'end', id: '', revision: '', legal_entity_id: '', location: '', job_family_id: '', career_level_id: '', currency: 'CNY', effective_to: '', minimum: '', midpoint: '', maximum: '' })
const correction = reactive({ reason: '', lines: '' })
let controller: AbortController | null = null
let rowKey = 0

const canPropose = computed(() => session.value?.compensation_permissions.some(permission => permission.category === 'financial' && permission.capability === 'compensation.propose') === true)
const draftOpen = computed(() => selected.value && ['draft', 'activation_conflict'].includes(selected.value.state))
const legalEntities = computed(() => catalogs.value?.legal_entities.filter(item => item.active !== false) ?? [])
const budgetSummary = computed(() => {
  const batch = selected.value, staged = candidate.value
  if (!batch || !staged || staged.state !== 'valid' || batch.adjustment_type === 'baseline') return [] as { currency: string; amount: string; budgetDelta?: string }[]
  const totals = new Map<string, bigint>()
  for (const line of staged.lines) totals.set(line.currency, (totals.get(line.currency) ?? 0n) + BigInt(line.increase_amount))
  return [...totals].map(([currency, amount]) => ({ currency, amount: String(amount), budgetDelta: currency === batch.budget_currency && batch.budget_amount ? String(BigInt(batch.budget_amount) - amount) : undefined }))
})

function orgID() { return /^\/orgs\/([0-9a-f-]+)\/compensation-adjustments\/?$/.exec(location.pathname)?.[1] ?? '' }
function today() { return new Date().toISOString().slice(0, 10) }
function label(entry?: CatalogEntry) { return entry?.display_name || entry?.label || entry?.code || '—' }
function catalogLabel(id?: string) {
  if (!id || !catalogs.value) return '—'
  return label([...catalogs.value.legal_entities, ...catalogs.value.org_units, ...catalogs.value.job_families, ...catalogs.value.career_levels].find(item => item.id === id))
}
function batchTypeLabel(type: Batch['adjustment_type']) {
  if (type === 'baseline') return '工资基线'
  return type === 'normal' ? 'Normal 年度调薪' : 'Special 特殊调薪'
}
function orgUnit(id?: string) { return catalogs.value?.org_units.find(item => item.id === id) }
function parentUnit(id?: string) {
  const parent = catalogs.value?.org_unit_parents.find(edge => edge.child_unit_id === id && edge.active !== false)?.parent_unit_id
  return orgUnit(parent)
}
function newRow(line: Partial<Line> = {}): EditorRow {
  return { key: ++rowKey, employee_id: '', staff_code: '', currency: '', salary_before: '', increase_amount: '', salary_after: '', performance_grade: '', average_merit_increase: '', department_suggested_increase: '', effective_date: '', effective_month: '', reason_code: '', reason_text: '', lookupState: 'idle', lookupMessage: '', ...line }
}
function resetRows(lines: Line[] = []) { rows.value = lines.length ? lines.map(line => newRow(line)) : [newRow(), newRow(), newRow()] }
function clearCandidate() { candidate.value = null; confirmedCorrections.value = []; confirmed.value = false }
function clearSensitive() { selected.value = null; rows.value = []; clearCandidate(); file.value = null; correction.reason = ''; correction.lines = '' }
function headers(purpose: 'compensation_management' | 'organization_management', body?: BodyInit | null, extra: HeadersInit = {}) {
  return { Accept: 'application/json', 'X-Access-Purpose': purpose, ...(body && !(body instanceof Blob) ? { 'Content-Type': 'application/json' } : {}), ...(session.value ? { 'X-CSRF-Token': session.value.csrf_token } : {}), ...Object.fromEntries(new Headers(extra)) }
}
async function request<T>(path: string, init: RequestInit = {}, purpose: 'compensation_management' | 'organization_management' = 'compensation_management'): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { ...init, signal: controller?.signal, credentials: 'same-origin', cache: 'no-store', headers: headers(purpose, init.body, init.headers) })
  if (response.status === 401) emit('session-expired')
  if (!response.ok) throw new ApiFailure(response.status)
  return response.json()
}
function message(cause: unknown) { return cause instanceof ApiFailure ? String(cause.status) : '503' }

async function load() {
  controller?.abort(); controller = new AbortController(); busy.value = true; error.value = ''; notice.value = ''; clearSensitive()
  try {
    session.value = await request<Session>('/session')
    if (!session.value.mfa_recent || session.value.org_id !== orgID() || !canPropose.value) throw new ApiFailure(403)
    const queryDate = today()
    const [reply, ranges, catalogReply, optionReply] = await Promise.all([
      request<{ batches: Batch[] }>(`/compensation-adjustment-batches?cycle_year=${encodeURIComponent(create.cycle_year)}`),
      request<SalaryRange[]>(`/orgs/${orgID()}/salary-ranges`),
      request<Catalogs>(`/orgs/${orgID()}/workforce-catalogs?as_of=${queryDate}&limit=100`, {}, 'organization_management'),
      request<BatchOptions>('/compensation-adjustment-batches/options'),
    ])
    batches.value = reply.batches; salaryRanges.value = ranges; catalogs.value = catalogReply; options.value = optionReply
    if (!create.special_reason_code) create.special_reason_code = optionReply.special_reasons[0]?.code ?? ''
    if (!create.legal_entity_id) create.legal_entity_id = catalogReply.legal_entities[0]?.id ?? ''
  } catch (cause) {
    batches.value = []; salaryRanges.value = []; catalogs.value = null; error.value = `批次工作台未就绪（${message(cause)}）。请确认财务权限、近期 MFA 与组织目录权限。`
  } finally { busy.value = false }
}
async function refreshBatches() {
  if (busy.value || !/^\d{4}$/.test(create.cycle_year)) return
  busy.value = true; error.value = ''
  try { batches.value = (await request<{ batches: Batch[] }>(`/compensation-adjustment-batches?cycle_year=${encodeURIComponent(create.cycle_year)}`)).batches } catch (cause) { error.value = `批次列表刷新失败（${message(cause)}）。` } finally { busy.value = false }
}
async function createBatch() {
  const baseline = create.adjustment_type === 'baseline'
  const cycleYear = baseline ? create.default_effective_date.slice(0, 4) : create.cycle_year
  const valid = create.name.trim() && /^\d{4}$/.test(cycleYear) && create.legal_entity_id && /^\d{4}-\d{2}-\d{2}$/.test(create.default_effective_date) && (baseline || /^(0|[1-9]\d*)$/.test(create.budget_amount)) && (create.adjustment_type !== 'special' || create.special_reason_code && create.special_reason_text.trim())
  if (busy.value || !canPropose.value || !valid) { error.value = baseline ? '请完整填写批次名、法分公司和工资时点。' : '请完整填写批次名、年度、法分公司、生效日和参考预算；Special 还需理由目录与说明。'; return }
  busy.value = true; error.value = ''; clearSensitive()
  try {
    if (baseline) create.cycle_year = cycleYear
    const body: Record<string, unknown> = { name: create.name.trim(), cycle_year: Number(cycleYear), adjustment_type: create.adjustment_type, legal_entity_id: create.legal_entity_id, default_effective_date: create.default_effective_date }
    if (!baseline) Object.assign(body, { budget_currency: create.budget_currency, budget_amount: create.budget_amount })
    if (create.adjustment_type === 'special') Object.assign(body, { special_reason_code: create.special_reason_code, special_reason_text: create.special_reason_text.trim() })
    const batch = await request<Batch>('/compensation-adjustment-batches', { method: 'POST', body: JSON.stringify(body), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    batches.value = [batch, ...batches.value.filter(item => item.id !== batch.id)]; selected.value = batch; resetRows(); notice.value = `已创建 ${batch.name}（${batch.business_code}），请录入员工。`
  } catch (cause) { error.value = `创建失败（${message(cause)}）。` } finally { busy.value = false }
}
async function openBatch(id: string) {
  if (busy.value) return
  busy.value = true; error.value = ''; clearCandidate()
  try { const batch = await request<Batch>(`/compensation-adjustment-batches/${id}`); selected.value = batch; resetRows(batch.lines) } catch (cause) { error.value = `批次读取失败（${message(cause)}）。` } finally { busy.value = false }
}
function effectiveDate(row: EditorRow) {
  const batch = selected.value
  if (!batch) return ''
  if (batch.adjustment_type === 'normal') return row.effective_date || batch.default_effective_date
  if (batch.adjustment_type === 'baseline') return batch.default_effective_date
  const month = row.effective_month || batch.default_effective_date.slice(0, 7)
  return /^\d{4}-\d{2}$/.test(month) ? `${month}-01` : ''
}
function exactStaffCode(employee: Employee, code: string) { return employee.identifiers.some(item => item.kind === 'staff_code' && item.staff_code === code) }
async function resolveRow(row: EditorRow) {
  const code = row.staff_code.trim(), date = effectiveDate(row)
  row.display = undefined; row.employee_id = ''; row.lookupMessage = ''
  if (!code || !date || !session.value) { row.lookupState = 'idle'; return }
  row.lookupState = 'loading'
  try {
    const directory = await request<Directory>(`/orgs/${orgID()}/employees/query`, { method: 'POST', body: JSON.stringify({ as_of: date, lifecycle: 'all', limit: 100, include_profile: true, q: code }) }, 'organization_management')
    const matches = directory.items.filter(employee => exactStaffCode(employee, code))
    if (matches.length !== 1) throw new ApiFailure(matches.length ? 409 : 404)
    const employee = matches[0]!, employment = employee.employment[0], assignment = employee.job_assignments[0]
    const department = orgUnit(assignment?.department_id), division = parentUnit(department?.id), businessGroup = parentUnit(division?.id)
    const display: EmployeeDisplay = { employeeID: employee.id, name: employee.profile?.local_name || '—', englishName: employee.profile?.english_name || '—', location: employment?.location_code || '—', branch: catalogLabel(employment?.legal_entity_id), businessGroup: label(businessGroup), division: label(division), department: label(department), position: assignment?.position?.title || '—', jobFamily: catalogLabel(assignment?.job_family_id), careerLevel: catalogLabel(assignment?.career_level_id), currentSalary: '', currency: '' }
    row.employee_id = employee.id; row.display = display
    try {
      const current = await request<CurrentCompensation>(`/employees/${employee.id}/compensation?${new URLSearchParams({ as_of: date, future_limit: '1' })}`)
      const terms = current.current_term?.terms
      if (terms?.amount_minor !== null && terms?.amount_minor !== undefined && terms.scale === 0 && terms.unit === 'month' && terms.payment_frequency === 'monthly' && terms.tax_basis === 'gross') {
        display.currentSalary = terms.amount_minor; display.currency = terms.currency
        if (!row.currency) row.currency = terms.currency
        if (selected.value?.adjustment_type !== 'baseline') {
          if (!row.salary_before) row.salary_before = terms.amount_minor
          recalculate(row)
        }
      }
      row.lookupState = 'ready'; row.lookupMessage = display.currentSalary ? '员工与当前月基本工资已读取。' : '员工已读取；系统当前没有可用月基本工资。'
    } catch (cause) {
      row.lookupState = 'limited'; row.lookupMessage = `员工资料已读取；当前工资未释放（${message(cause)}），可继续录入并由预览核验。`
    }
  } catch (cause) { row.lookupState = 'error'; row.lookupMessage = `未找到唯一有效员工（${message(cause)}）。` }
}
function recalculate(row: EditorRow) {
  if (/^(0|[1-9]\d*)$/.test(row.salary_before) && /^(0|[1-9]\d*)$/.test(row.increase_amount)) row.salary_after = String(BigInt(row.salary_before) + BigInt(row.increase_amount))
}
function addRow() { if (rows.value.length < 500) rows.value.push(newRow()) }
function removeRow(index: number) { rows.value.splice(index, 1); if (!rows.value.length) rows.value.push(newRow()) }
function linePayload(row: EditorRow): Line {
  const batch = selected.value!
  if (batch.adjustment_type === 'baseline') return { employee_id: '', staff_code: row.staff_code.trim(), currency: row.currency, salary_before: '', increase_amount: '', salary_after: row.salary_after.trim() }
  const line: Line = { employee_id: '', staff_code: row.staff_code.trim(), currency: row.currency, salary_before: row.salary_before.trim(), increase_amount: row.increase_amount.trim(), salary_after: row.salary_after.trim() }
  if (batch.adjustment_type === 'normal') Object.assign(line, { performance_grade: row.performance_grade?.trim() || '', average_merit_increase: row.average_merit_increase?.trim() || '', department_suggested_increase: row.department_suggested_increase?.trim() || '', effective_date: row.effective_date || '' })
  else Object.assign(line, { effective_month: row.effective_month || '', reason_code: row.reason_code?.trim() || '', reason_text: row.reason_text?.trim() || '' })
  return line
}
async function previewRows() {
  const batch = selected.value
  if (!batch || busy.value || !draftOpen.value) return
  busy.value = true; error.value = ''; clearCandidate()
  try {
    candidate.value = await request<ImportCandidate>(`/compensation-adjustment-batches/${batch.id}/previews`, { method: 'POST', body: JSON.stringify({ revision: batch.revision, lines: rows.value.map(linePayload) }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = candidate.value.state === 'valid' ? '预览已生成；尚未修改草稿或工资。' : '预览发现错误；尚未修改草稿或工资。'
  } catch (cause) { error.value = `预览失败（${message(cause)}）。` } finally { busy.value = false }
}
function chooseFile(event: Event) { file.value = (event.target as HTMLInputElement).files?.[0] ?? null }
async function importWorkbook() {
  const batch = selected.value, workbook = file.value
  if (!batch || !workbook || busy.value || workbook.size > 10 * 1024 * 1024) { error.value = '请选择不超过 10 MiB 的 XLSX。'; return }
  busy.value = true; error.value = ''; clearCandidate()
  try {
    candidate.value = await request<ImportCandidate>(`/compensation-adjustment-batches/${batch.id}/imports?revision=${encodeURIComponent(batch.revision)}`, { method: 'POST', body: workbook, headers: { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = 'XLSX 已进入同一预览校验；尚未修改草稿或工资。'
  } catch (cause) { error.value = `导入失败（${message(cause)}）。` } finally { busy.value = false }
}
async function downloadBaselineTemplate() {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    const response = await fetch('/api/v1/compensation-adjustment-batches/import-template?adjustment_type=baseline', { credentials: 'same-origin', cache: 'no-store', headers: headers('compensation_management') })
    if (response.status === 401) emit('session-expired')
    if (!response.ok) throw new ApiFailure(response.status)
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url; link.download = 'teamledger-salary-baseline.xlsx'; link.click()
    URL.revokeObjectURL(url)
  } catch (cause) { error.value = `模板下载失败（${message(cause)}）。` } finally { busy.value = false }
}
function warningConfirmed(warning: PreviewWarning) { return confirmedCorrections.value.includes(warning.employee_id) }
async function applyCandidate() {
  const batch = selected.value, staged = candidate.value
  if (!batch || !staged || busy.value || staged.state !== 'valid' || staged.base_revision !== batch.revision || staged.warnings.some(warning => !warningConfirmed(warning))) { error.value = '请先处理全部预览错误，并逐人确认所有调整前工资不一致警告。'; return }
  busy.value = true; error.value = ''
  try {
    selected.value = await request<Batch>(`/compensation-adjustment-batches/${batch.id}/draft`, { method: 'PATCH', body: JSON.stringify({ revision: batch.revision, candidate_id: staged.id, confirm_salary_corrections: confirmedCorrections.value }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    const updated = selected.value; clearCandidate(); file.value = null; resetRows(updated.lines); batches.value = batches.value.map(item => item.id === updated.id ? updated : item); notice.value = '草稿已冻结；工资仍未生效。请核对汇总后再确认整批生效。'
  } catch (cause) { error.value = `应用预览失败（${message(cause)}）。` } finally { busy.value = false }
}
async function activate() {
  const batch = selected.value
  if (!batch || !confirmed.value || !['draft', 'activation_blocked'].includes(batch.state) || !batch.manifest_digest || busy.value) { error.value = '必须先核对非空冻结清单并明确确认。'; return }
  busy.value = true; error.value = ''; const frozen = { id: batch.id, revision: batch.revision, manifest_digest: batch.manifest_digest }; confirmed.value = false
  try {
    selected.value = await request<Batch>(`/compensation-adjustment-batches/${frozen.id}/transitions`, { method: 'POST', body: JSON.stringify({ action: 'submit', revision: frozen.revision, manifest_digest: frozen.manifest_digest }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    batches.value = batches.value.map(item => item.id === frozen.id ? selected.value! : item); notice.value = '整批已原子生效。'
  } catch (cause) { error.value = `整批未生效（${message(cause)}）；系统不会自动重试。` } finally { busy.value = false }
}

async function addSalaryRange() {
  if (busy.value || !range.legal_entity_id || !range.job_family_id || !range.career_level_id || !/^\d{4}-\d{2}-\d{2}$/.test(range.valid_from) || ![range.minimum, range.midpoint, range.maximum].every(value => /^(0|[1-9]\d*)$/.test(value))) { error.value = '请完整填写 Salary Range，金额必须为非负整数。'; return }
  busy.value = true
  try { salaryRanges.value = await request<SalaryRange[]>(`/orgs/${orgID()}/salary-range-changes`, { method: 'POST', body: JSON.stringify({ changes: [{ action: 'add', expected_revision: '0', legal_entity_id: range.legal_entity_id, location: range.location, job_family_id: range.job_family_id, career_level_id: range.career_level_id, currency: range.currency, valid_from: range.valid_from, amounts: { minimum: range.minimum, midpoint: range.midpoint, maximum: range.maximum } }] }), headers: { 'Idempotency-Key': crypto.randomUUID() } }); notice.value = 'Salary Range 已新增。' } catch (cause) { error.value = `Salary Range 新增失败（${message(cause)}）。` } finally { busy.value = false }
}
function selectSalaryRange(item: SalaryRange) { Object.assign(rangeChange, { action: 'end', id: item.id, revision: item.revision, legal_entity_id: item.legal_entity_id, location: item.location, job_family_id: item.job_family_id, career_level_id: item.career_level_id, currency: item.currency, effective_to: '', minimum: item.amounts.minimum, midpoint: item.amounts.midpoint, maximum: item.amounts.maximum }) }
async function changeSalaryRange() {
  if (busy.value || !rangeChange.id || !/^\d{4}-\d{2}-\d{2}$/.test(rangeChange.effective_to)) { error.value = '请选择 Range 并填写结束/替换生效日。'; return }
  if (rangeChange.action === 'replace' && ![rangeChange.minimum, rangeChange.midpoint, rangeChange.maximum].every(value => /^(0|[1-9]\d*)$/.test(value))) { error.value = '替换金额必须为非负整数。'; return }
  const change: Record<string, unknown> = { action: rangeChange.action, id: rangeChange.id, expected_revision: rangeChange.revision, effective_to: rangeChange.effective_to }
  if (rangeChange.action === 'replace') Object.assign(change, { legal_entity_id: rangeChange.legal_entity_id, location: rangeChange.location, job_family_id: rangeChange.job_family_id, career_level_id: rangeChange.career_level_id, currency: rangeChange.currency, valid_from: rangeChange.effective_to, amounts: { minimum: rangeChange.minimum, midpoint: rangeChange.midpoint, maximum: rangeChange.maximum } })
  busy.value = true
  try { salaryRanges.value = await request<SalaryRange[]>(`/orgs/${orgID()}/salary-range-changes`, { method: 'POST', body: JSON.stringify({ changes: [change] }), headers: { 'Idempotency-Key': crypto.randomUUID() } }); notice.value = rangeChange.action === 'replace' ? 'Salary Range 已替换。' : 'Salary Range 已结束。'; rangeChange.id = '' } catch (cause) { error.value = `Salary Range 维护失败（${message(cause)}）。` } finally { busy.value = false }
}
function generateCorrectionTemplate() {
  correction.lines = JSON.stringify(selected.value?.lines.filter(line => line.result === 'changed' && line.original_adjustment_event_id && line.correction_members?.length).map(line => ({ employee_id: line.employee_id, members: JSON.parse(JSON.stringify(line.correction_members)) })) ?? [], null, 2)
}
async function correctBatch() {
  const batch = selected.value
  if (!batch || batch.state !== 'activated' || busy.value || !correction.reason.trim() || !correction.lines.trim()) { error.value = '请输入更正原因和更正成员 JSON。'; return }
  let lines: unknown
  try { lines = JSON.parse(correction.lines) } catch { error.value = '更正成员必须是合法 JSON。'; return }
  if (!Array.isArray(lines) || !lines.length) { error.value = '更正成员必须是非空数组。'; return }
  busy.value = true
  try { const result = await request<{ business_code: string }>(`/compensation-adjustment-batches/${batch.id}/corrections`, { method: 'POST', body: JSON.stringify({ reason: correction.reason.trim(), lines }), headers: { 'Idempotency-Key': crypto.randomUUID() } }); notice.value = `更正 ${result.business_code} 已原子生效。`; correction.reason = ''; correction.lines = '' } catch (cause) { error.value = `更正未生效（${message(cause)}）。` } finally { busy.value = false }
}

onMounted(load)
onBeforeUnmount(() => { controller?.abort(); clearSensitive(); batches.value = []; salaryRanges.value = []; catalogs.value = null; session.value = null })
</script>

<template>
  <main class="batch-page">
    <header class="page-intro">
      <p class="eyebrow">Compensation operations</p>
      <h1>薪资调整批次</h1>
      <p>按 Staff Code 批量录入某个日期的工资基线、Normal 年度调薪或 Special 特殊调薪。预览、草稿确认和整批生效相互独立。</p>
    </header>

    <p v-if="error" class="message danger" role="alert">{{ error }}</p>
    <p v-if="notice" class="message success" role="status">{{ notice }}</p>

    <section class="create-card" aria-labelledby="create-batch-heading">
      <div class="section-heading"><div><p class="step-label">01 · Batch setup</p><h2 id="create-batch-heading">建立批次</h2></div><p>服务器自动生成唯一业务编号。</p></div>
      <form class="batch-create-form" aria-label="创建薪资调整批次" @submit.prevent="createBatch">
        <label class="span-2">批次名<input v-model="create.name" maxlength="200" placeholder="例如：2026-07-08 特调" required /></label>
        <label>年度<input v-model="create.cycle_year" inputmode="numeric" maxlength="4" :disabled="create.adjustment_type === 'baseline'" required /></label>
        <label>类型<select v-model="create.adjustment_type"><option value="baseline">工资基线（指定日期工资）</option><option value="normal">Normal 年度调薪</option><option value="special">Special 特殊调薪</option></select></label>
        <label class="span-2">法分公司<select v-model="create.legal_entity_id" required><option value="" disabled>请选择</option><option v-for="entity in legalEntities" :key="entity.id" :value="entity.id">{{ label(entity) }}</option></select></label>
        <label>{{ create.adjustment_type === 'baseline' ? '工资时点' : '默认生效日' }}<input v-model="create.default_effective_date" type="date" required /></label>
        <template v-if="create.adjustment_type !== 'baseline'"><label>预算币种<select v-model="create.budget_currency"><option>CNY</option><option>JPY</option></select></label>
        <label>整体参考预算<input v-model="create.budget_amount" inputmode="numeric" placeholder="非负整数" required /></label></template>
        <template v-if="create.adjustment_type === 'special'">
          <label>Special 理由<select v-model="create.special_reason_code" required><option value="" disabled>请选择</option><option v-for="reason in options.special_reasons" :key="reason.code" :value="reason.code">{{ reason.label }}</option></select></label>
          <label class="span-2">理由说明<input v-model="create.special_reason_text" maxlength="1000" placeholder="说明本批次的业务背景" required /></label>
        </template>
        <div class="form-actions span-all"><button :disabled="busy || !canPropose">创建并开始录入</button><button type="button" class="secondary" :disabled="busy" @click="refreshBatches">刷新批次列表</button></div>
      </form>
    </section>

    <section class="batch-list" aria-labelledby="batch-list-heading">
      <div class="section-heading"><div><p class="step-label">Existing batches</p><h2 id="batch-list-heading">{{ create.cycle_year }} 年批次</h2></div><p>{{ batches.length }} 个可见批次</p></div>
      <div v-if="batches.length" class="batch-grid">
        <button v-for="batch in batches" :key="batch.id" type="button" class="batch-tile" :class="{ active: selected?.id === batch.id }" :disabled="busy" @click="openBatch(batch.id)">
          <span class="batch-type">{{ batch.adjustment_type.toUpperCase() }}</span><strong>{{ batch.name || batch.business_code }}</strong><small>{{ batch.business_code }} · {{ catalogLabel(batch.legal_entity_id) }}</small><span><span class="state-dot"></span>{{ batch.state }} · R{{ batch.revision }}</span>
        </button>
      </div>
      <div v-else class="empty-state">本年度还没有批次。</div>
    </section>

    <section v-if="selected" class="workbench" aria-label="调薪批次录入工作台">
      <header class="batch-summary">
        <div><p class="step-label">02 · Entry workbench</p><h2>{{ selected.name }}</h2><p>{{ selected.business_code }} · {{ batchTypeLabel(selected.adjustment_type) }} · R{{ selected.revision }}</p></div>
        <dl><div><dt>法分公司</dt><dd>{{ catalogLabel(selected.legal_entity_id) }}</dd></div><div><dt>{{ selected.adjustment_type === 'baseline' ? '工资时点' : '默认生效' }}</dt><dd>{{ selected.default_effective_date }}</dd></div><div v-if="selected.adjustment_type !== 'baseline'"><dt>参考预算</dt><dd>{{ selected.budget_legacy_unspecified ? '历史批次未指定' : `${selected.budget_currency} ${selected.budget_amount}` }}</dd></div><div><dt>状态</dt><dd><span class="status-pill">{{ selected.state }}</span></dd></div></dl>
      </header>

      <div v-if="selected.state === 'activation_conflict'" class="message danger" role="alert">冻结依据已经变化。请重新解析员工、生成预览并应用草稿。</div>

      <template v-if="draftOpen">
        <div class="entry-toolbar"><div><h3>逐人录入</h3><p v-if="selected.adjustment_type === 'baseline'">默认 3 行；输入指定日期的税前固定月基本工资，全空行在预览时忽略。</p><p v-else>默认 3 行；全空行在预览时忽略。调整后工资由调整前工资＋增加额计算。</p></div><button type="button" class="secondary" :disabled="busy || rows.length >= 500" @click="addRow">＋ 追加一行</button></div>
        <div class="line-table-wrap">
          <table class="line-table">
            <caption class="sr-only">调薪批次逐人录入</caption>
            <thead><tr><th>#</th><th>员工 / Staff Code</th><th>员工资料</th><th>币种</th><th v-if="selected.adjustment_type !== 'baseline'">调整前工资</th><th v-if="selected.adjustment_type !== 'baseline'">增加额</th><th>{{ selected.adjustment_type === 'baseline' ? '指定日工资' : '调整后工资' }}</th><th v-if="selected.adjustment_type === 'normal'">绩效等级</th><th v-if="selected.adjustment_type === 'normal'">参考幅度</th><th v-if="selected.adjustment_type === 'normal'">生效日</th><th v-if="selected.adjustment_type === 'special'">生效月份</th><th v-if="selected.adjustment_type === 'special'">逐行理由覆盖</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="(row, index) in rows" :key="row.key">
                <td class="row-number">{{ index + 1 }}</td>
                <td class="staff-cell"><label :for="`staff-${row.key}`">Staff Code</label><input :id="`staff-${row.key}`" v-model="row.staff_code" autocomplete="off" placeholder="输入后离开以查询" @blur="resolveRow(row)" /><small :class="`lookup-${row.lookupState}`">{{ row.lookupState === 'loading' ? '查询中…' : row.lookupMessage }}</small></td>
                <td class="employee-cell"><template v-if="row.display"><strong>{{ row.display.name }}</strong><span>{{ row.display.englishName }}</span><small>{{ row.display.location }} · {{ row.display.branch }}</small><small>{{ row.display.businessGroup }} / {{ row.display.division }} / {{ row.display.department }}</small><small>{{ row.display.position }} · {{ row.display.jobFamily }} · {{ row.display.careerLevel }}</small><small v-if="row.display.currentSalary">系统当前：{{ row.display.currency }} {{ row.display.currentSalary }}</small></template><span v-else class="muted">输入 Staff Code 后回填</span></td>
                <td><select v-model="row.currency" :aria-label="`第${index + 1}行币种`"><option value="">—</option><option>CNY</option><option>JPY</option></select></td>
                <td v-if="selected.adjustment_type !== 'baseline'"><input v-model="row.salary_before" :aria-label="`第${index + 1}行调整前工资`" inputmode="numeric" @input="recalculate(row)" /></td>
                <td v-if="selected.adjustment_type !== 'baseline'"><input v-model="row.increase_amount" :aria-label="`第${index + 1}行增加额`" inputmode="numeric" @input="recalculate(row)" /></td>
                <td><input v-model="row.salary_after" :aria-label="selected.adjustment_type === 'baseline' ? `第${index + 1}行指定日工资` : `第${index + 1}行调整后工资`" inputmode="numeric" :readonly="selected.adjustment_type !== 'baseline'" /></td>
                <td v-if="selected.adjustment_type === 'normal'"><input v-model="row.performance_grade" :aria-label="`第${index + 1}行绩效等级`" placeholder="手工输入" /></td>
                <td v-if="selected.adjustment_type === 'normal'" class="reference-cell"><input v-model="row.average_merit_increase" :aria-label="`第${index + 1}行平均调薪幅度`" placeholder="平均，如 6%" /><input v-model="row.department_suggested_increase" :aria-label="`第${index + 1}行部门建议幅度`" placeholder="部门建议" /></td>
                <td v-if="selected.adjustment_type === 'normal'"><input v-model="row.effective_date" :aria-label="`第${index + 1}行生效日`" type="date" @change="resolveRow(row)" /><small>空值继承 {{ selected.default_effective_date }}</small></td>
                <td v-if="selected.adjustment_type === 'special'"><input v-model="row.effective_month" :aria-label="`第${index + 1}行生效月份`" type="month" @change="resolveRow(row)" /><small>空值继承 {{ selected.default_effective_date.slice(0, 7) }}</small></td>
                <td v-if="selected.adjustment_type === 'special'" class="reason-cell"><select v-model="row.reason_code" :aria-label="`第${index + 1}行理由目录`"><option value="">继承批次理由</option><option v-for="reason in options.special_reasons" :key="reason.code" :value="reason.code">{{ reason.label }}</option></select><input v-model="row.reason_text" :aria-label="`第${index + 1}行理由说明`" placeholder="与目录同时覆盖" /></td>
                <td><button type="button" class="icon-button" :aria-label="`删除第${index + 1}行`" :disabled="busy" @click="removeRow(index)">删除</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="entry-actions"><p>{{ rows.length }} 行录入区 · 最多 500 名唯一员工</p><button type="button" :disabled="busy" @click="previewRows">生成确认预览</button></div>

        <details class="xlsx-panel"><summary>从 XLSX 导入（使用同一预览规则）</summary><div><button v-if="selected.adjustment_type === 'baseline'" type="button" class="secondary" :disabled="busy" @click="downloadBaselineTemplate">下载工资基线模板</button><label>XLSX 文件<input type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" @change="chooseFile" /></label><button type="button" class="secondary" :disabled="busy || !file" @click="importWorkbook">解析 XLSX</button><p>文件不会直接修改草稿或工资；解析后仍需完成下方确认。</p></div></details>

        <section v-if="candidate" class="preview-panel" aria-label="调薪预览确认">
          <div class="section-heading"><div><p class="step-label">03 · Review</p><h3>预览与确认</h3></div><p>{{ candidate.line_count }} 名员工 · 有效期至 {{ candidate.expires_at }}</p></div>
          <div v-if="candidate.errors.length" class="message danger"><strong>预览未通过</strong><ul><li v-for="messageText in candidate.errors" :key="messageText">{{ messageText }}</li></ul></div>
          <div v-if="candidate.warnings.length" class="warning-list"><h4>调整前工资不一致</h4><p>仅勾选后才能继续；最终生效时先追加历史纠正，再追加本次调薪，原历史不会覆盖。</p><label v-for="warning in candidate.warnings" :key="warning.employee_id"><input v-model="confirmedCorrections" type="checkbox" :value="warning.employee_id" /><span><strong>{{ warning.staff_code }}</strong> · {{ warning.effective_date }}：录入 {{ warning.entered_salary_before }}，系统 {{ warning.current_salary_before }}。确认先纠正系统当前工资。</span></label></div>
          <div v-if="candidate.lines.length" class="preview-table-wrap"><table><thead><tr><th>工号</th><th>姓名</th><th>币种</th><th>{{ selected.adjustment_type === 'baseline' ? '系统指定日前工资' : '调整前' }}</th><th v-if="selected.adjustment_type !== 'baseline'">增加</th><th>{{ selected.adjustment_type === 'baseline' ? '指定日工资' : '调整后' }}</th><th>生效日/月</th><th v-if="selected.adjustment_type === 'special'">本年/上年次数</th><th v-if="selected.adjustment_type !== 'baseline'">理由</th></tr></thead><tbody><tr v-for="(line, index) in candidate.lines" :key="`${line.employee_id}-${index}`"><td><strong>{{ line.staff_code }}</strong></td><td>{{ rows.find(row => row.staff_code === line.staff_code)?.display?.name || '受限' }}</td><td>{{ line.currency }}</td><td>{{ line.salary_before || '未登记' }}</td><td v-if="selected.adjustment_type !== 'baseline'">{{ line.increase_amount }}</td><td>{{ line.salary_after }}</td><td>{{ line.effective_date || line.effective_month || selected.default_effective_date }}</td><td v-if="selected.adjustment_type === 'special'">{{ candidate.adjustment_counts_by_employee[line.employee_id]?.current_year ?? 0 }} / {{ candidate.adjustment_counts_by_employee[line.employee_id]?.previous_year ?? 0 }}</td><td v-if="selected.adjustment_type !== 'baseline'">{{ [line.reason_code, line.reason_text].filter(Boolean).join(' · ') || '—' }}</td></tr></tbody></table></div>
          <div v-if="budgetSummary.length" class="budget-review"><article v-for="total in budgetSummary" :key="total.currency"><span>{{ total.currency }} 增加额合计</span><strong>{{ total.amount }}</strong><small v-if="total.budgetDelta !== undefined">参考预算差额 {{ total.budgetDelta }}（不阻断）</small><small v-else>与 {{ selected.budget_currency }} 预算不可合并；不进行 FX 换算</small></article></div>
          <div class="preview-actions"><button type="button" class="secondary" :disabled="busy" @click="clearCandidate">返回修改</button><button type="button" :disabled="busy || candidate.state !== 'valid' || candidate.warnings.some(warning => !warningConfirmed(warning))" @click="applyCandidate">确认并应用为草稿</button></div>
        </section>
      </template>

      <section v-if="selected.lines.length" class="frozen-panel" aria-label="已冻结调薪清单">
        <div class="section-heading"><div><p class="step-label">Frozen draft</p><h3>已冻结清单</h3></div><p>{{ selected.lines.length }} 名员工</p></div>
        <div class="preview-table-wrap"><table><thead><tr><th>工号</th><th>币种</th><th>{{ selected.adjustment_type === 'baseline' ? '指定日前工资' : '调整前' }}</th><th v-if="selected.adjustment_type !== 'baseline'">增加</th><th>{{ selected.adjustment_type === 'baseline' ? '指定日工资' : '调整后' }}</th><th>结果</th><th v-if="selected.adjustment_type !== 'baseline'">工资纠正</th><th v-if="selected.adjustment_type !== 'baseline'">本年/上年次数</th></tr></thead><tbody><tr v-for="line in selected.lines" :key="line.employee_id"><td><strong>{{ line.staff_code }}</strong></td><td>{{ line.currency }}</td><td>{{ line.salary_before || '未登记' }}</td><td v-if="selected.adjustment_type !== 'baseline'">{{ line.increase_amount }}</td><td>{{ line.salary_after }}</td><td>{{ line.result }}</td><td v-if="selected.adjustment_type !== 'baseline'">{{ line.correct_salary_before ? '生效时先追加纠正' : '不需要' }}</td><td v-if="selected.adjustment_type !== 'baseline'">{{ line.adjustment_counts?.current_year ?? 0 }} / {{ line.adjustment_counts?.previous_year ?? 0 }}</td></tr></tbody></table></div>
        <div class="frozen-footer"><p v-if="selected.adjustment_type !== 'baseline'">增加额合计：<strong v-for="total in selected.increase_totals_by_currency" :key="total.currency">{{ total.currency }} {{ total.amount }}　</strong></p><p v-else>工资基线生效时按指定日期追加不可变工资历史；不会计入 Normal / Special 调薪次数。</p><template v-if="['draft', 'activation_blocked'].includes(selected.state)"><label class="activation-check"><input v-model="confirmed" type="checkbox" /> {{ selected.adjustment_type === 'baseline' ? '已核对 Staff Code、币种、指定日前工资及指定日工资' : '已核对逐人结果、工资纠正标记、币种合计及参考预算' }}</label><button type="button" class="danger-button" :disabled="busy || !confirmed" @click="activate">{{ selected.state === 'activation_blocked' ? '重试整批生效' : '确认整批生效' }}</button></template></div>
      </section>

      <details v-if="selected.state === 'activated' && selected.adjustment_type !== 'baseline'" class="correction-panel"><summary>已生效批次的高级更正</summary><form aria-label="更正已生效批次" @submit.prevent="correctBatch"><p>仅用于 append-only 反转/替换，不修改原始事件。</p><label>更正原因<input v-model="correction.reason" /></label><button type="button" class="secondary" :disabled="busy || !selected.lines.some(line => line.original_adjustment_event_id)" @click="generateCorrectionTemplate">生成受控 JSON 模板</button><label class="span-all">更正成员 JSON<textarea v-model="correction.lines" rows="8" spellcheck="false"></textarea></label><button :disabled="busy || !correction.reason || !correction.lines">原子生效更正</button></form></details>
    </section>

    <details class="range-panel">
      <summary><span><strong>Salary Range 维护</strong><small>管理员工具 · 非日常调薪录入</small></span><span>{{ salaryRanges.length }} 条</span></summary>
      <div class="range-body">
        <form @submit.prevent="addSalaryRange"><label>法分公司<select v-model="range.legal_entity_id"><option value="">请选择</option><option v-for="entity in legalEntities" :key="entity.id" :value="entity.id">{{ label(entity) }}</option></select></label><label>地点<select v-model="range.location"><option>Shanghai</option><option>Wuxi</option><option>Tokyo</option></select></label><label>Job Family ID<input v-model="range.job_family_id" /></label><label>Career Level ID<input v-model="range.career_level_id" /></label><label>币种<select v-model="range.currency"><option>CNY</option><option>JPY</option></select></label><label>生效日<input v-model="range.valid_from" type="date" /></label><label>Minimum<input v-model="range.minimum" /></label><label>Midpoint<input v-model="range.midpoint" /></label><label>Maximum<input v-model="range.maximum" /></label><button :disabled="busy">新增 Range</button></form>
        <div class="preview-table-wrap"><table><thead><tr><th>法分公司</th><th>地点</th><th>Job Family</th><th>Career Level</th><th>币种</th><th>Min / Mid / Max</th><th>有效期</th><th>维护</th></tr></thead><tbody><tr v-for="item in salaryRanges" :key="item.id"><td>{{ catalogLabel(item.legal_entity_id) }}</td><td>{{ item.location }}</td><td>{{ catalogLabel(item.job_family_id) }}</td><td>{{ catalogLabel(item.career_level_id) }}</td><td>{{ item.currency }}</td><td>{{ item.amounts.minimum }} / {{ item.amounts.midpoint }} / {{ item.amounts.maximum }}</td><td>{{ item.valid_from }} – {{ item.valid_to || '∞' }}</td><td><button v-if="!item.valid_to" type="button" class="secondary" :disabled="busy" @click="selectSalaryRange(item)">结束/替换</button></td></tr></tbody></table></div>
        <form v-if="rangeChange.id" aria-label="结束或替换 Salary Range" @submit.prevent="changeSalaryRange"><label>动作<select v-model="rangeChange.action"><option value="end">结束</option><option value="replace">结束并替换</option></select></label><label>生效日<input v-model="rangeChange.effective_to" type="date" /></label><template v-if="rangeChange.action === 'replace'"><label>Minimum<input v-model="rangeChange.minimum" /></label><label>Midpoint<input v-model="rangeChange.midpoint" /></label><label>Maximum<input v-model="rangeChange.maximum" /></label></template><button :disabled="busy">确认维护</button></form>
      </div>
    </details>
  </main>
</template>

<style scoped>
.batch-page { --table-min: 88rem; }
.page-intro { max-width: 72rem; margin-bottom: 1.5rem; }
.eyebrow, .step-label { margin: 0 0 .35rem; color: var(--brand-700); font-size: .72rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.page-intro > p:last-child { max-width: 65rem; color: var(--ink-600); font-size: 1rem; }
.message { border: 1px solid; border-radius: var(--radius-md); padding: .85rem 1rem; }
.message.danger { border-color: var(--danger-100); background: var(--danger-50); color: var(--danger-700); }
.message.success { border-color: var(--success-100); background: var(--success-50); color: var(--success-700); }
.section-heading, .entry-toolbar, .entry-actions, .preview-actions, .frozen-footer { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.section-heading > p, .entry-toolbar p, .entry-actions p { margin: 0; color: var(--ink-600); }
.batch-create-form { grid-template-columns: repeat(5, minmax(0, 1fr)) !important; }
.span-2 { grid-column: span 2; }.span-all { grid-column: 1 / -1; }
.form-actions { display: flex; justify-content: flex-end; gap: .65rem; }
.batch-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 17rem), 1fr)); gap: .75rem; }
.batch-tile { display: grid; min-height: 9rem; align-content: start; gap: .32rem; border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--surface-muted); color: var(--ink-700); padding: 1rem; text-align: left; }
.batch-tile:hover, .batch-tile.active { border-color: var(--brand-500); background: var(--brand-50); box-shadow: var(--shadow-sm); transform: translateY(-1px); }
.batch-tile strong { font-size: 1.05rem; }.batch-type { color: var(--brand-700); font-size: .68rem; font-weight: 850; letter-spacing: .1em; }.state-dot { display: inline-block; width: .45rem; height: .45rem; margin-right: .38rem; border-radius: 50%; background: var(--brand-500); }
.empty-state { border: 1px dashed var(--line-strong); border-radius: var(--radius-md); color: var(--ink-600); padding: 2rem; text-align: center; }
.workbench { padding: 0 !important; overflow: hidden; }
.batch-summary { display: grid; grid-template-columns: minmax(16rem, .8fr) minmax(30rem, 1.5fr); gap: 2rem; border-bottom: 1px solid var(--line); background: linear-gradient(135deg, var(--brand-50), white 62%); padding: 1.5rem; }
.batch-summary dl { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 0; gap: .75rem; }.batch-summary dl div { border-left: 1px solid var(--line); padding-left: .8rem; }.batch-summary dt { color: var(--ink-600); font-size: .72rem; font-weight: 700; }.batch-summary dd { margin: .2rem 0 0; color: var(--ink-950); font-weight: 700; overflow-wrap: anywhere; }.status-pill { display: inline-flex; border-radius: 999px; background: var(--brand-100); color: var(--brand-900); padding: .15rem .55rem; font-size: .76rem; }
.workbench > .message, .entry-toolbar, .entry-actions, .xlsx-panel, .preview-panel, .frozen-panel, .correction-panel { margin: 1rem 1.5rem; }
.entry-toolbar { align-items: end; }.entry-toolbar h3 { margin-bottom: .2rem; }
.line-table-wrap, .preview-table-wrap { max-width: 100%; overflow-x: auto; border-block: 1px solid var(--line); background: white; }
.line-table { min-width: var(--table-min); margin: 0; }.line-table th { position: sticky; top: 0; z-index: 1; background: var(--ink-900); color: white; font-size: .72rem; letter-spacing: .02em; }.line-table td { min-width: 7.5rem; vertical-align: top; }.line-table td:first-child { min-width: 3rem; }.line-table input, .line-table select { min-width: 7.2rem; }.line-table small { display: block; max-width: 13rem; margin-top: .3rem; line-height: 1.35; }.staff-cell { min-width: 12rem !important; }.employee-cell { min-width: 17rem !important; }.employee-cell strong, .employee-cell span, .employee-cell small { display: block; }.reference-cell, .reason-cell { display: grid; gap: .4rem; min-width: 11rem !important; }.row-number { color: var(--ink-500); font-weight: 800; }.muted { color: var(--ink-500); }.lookup-error { color: var(--danger-700); }.lookup-ready { color: var(--success-700); }.lookup-limited { color: var(--accent-700); }
.icon-button { min-height: 2.25rem !important; border-color: var(--line) !important; background: white !important; color: var(--danger-700) !important; padding: .35rem .55rem !important; }
.entry-actions { padding: 1rem 1.5rem; }.entry-actions button { min-width: 11rem; }
.xlsx-panel, .correction-panel, .range-panel { border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--surface-muted); }.xlsx-panel summary, .correction-panel summary, .range-panel > summary { cursor: pointer; color: var(--ink-800); font-weight: 750; padding: 1rem; }.xlsx-panel > div { display: flex; align-items: end; gap: 1rem; border-top: 1px solid var(--line); padding: 1rem; }.xlsx-panel p { margin: 0; color: var(--ink-600); }
.preview-panel, .frozen-panel { border-color: var(--brand-100) !important; background: var(--surface) !important; }.preview-panel .section-heading, .frozen-panel .section-heading { padding: 0 0 .8rem; }.warning-list { border: 1px solid var(--accent-100); border-radius: var(--radius-md); background: #fffaf0; padding: 1rem; }.warning-list label { display: flex; align-items: flex-start; gap: .7rem; margin-top: .6rem; }.warning-list input { width: auto; margin-top: .25rem; }.budget-review { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; margin-top: 1rem; }.budget-review article { display: grid; margin: 0 !important; gap: .2rem; }.budget-review strong { font-size: 1.2rem; }.preview-actions { justify-content: flex-end; margin-top: 1rem; }
.frozen-footer { align-items: end; margin-top: 1rem; }.activation-check { display: flex !important; grid-template-columns: auto 1fr !important; align-items: center; max-width: 30rem; }.activation-check input { width: auto !important; }.danger-button { background: var(--danger-700) !important; }.correction-panel form { border-top: 1px solid var(--line); margin: 0 !important; }
.range-panel { width: min(100%, var(--content)); margin: 1.25rem 0; background: white; }.range-panel > summary { display: flex; justify-content: space-between; list-style-position: inside; }.range-panel > summary span:first-child { display: inline-grid; margin-left: .35rem; }.range-panel > summary small { font-weight: 500; }.range-body { border-top: 1px solid var(--line); padding: 0 1rem 1rem; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; overflow: hidden; }
@media (max-width: 62rem) { .batch-create-form { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }.batch-summary { grid-template-columns: 1fr; }.batch-summary dl { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 42rem) { .batch-page { --table-min: 78rem; }.batch-create-form { grid-template-columns: 1fr !important; }.span-2 { grid-column: auto; }.section-heading, .entry-toolbar, .entry-actions, .preview-actions, .frozen-footer, .xlsx-panel > div { align-items: stretch; flex-direction: column; }.form-actions { justify-content: stretch; }.form-actions button, .entry-actions button, .preview-actions button { width: 100%; }.batch-summary dl { grid-template-columns: 1fr; }.batch-summary dl div { border-left: 0; border-top: 1px solid var(--line); padding: .55rem 0 0; }.workbench > .message, .entry-toolbar, .entry-actions, .xlsx-panel, .preview-panel, .frozen-panel, .correction-panel { margin-inline: .8rem; } }
</style>
