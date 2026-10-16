<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef } from 'vue'

type Session = {
  subject_id: string
  org_id: string
  auth_epoch: string
  capabilities: string[]
  csrf_token: string
}
type ImportRow = {
  row_number: number
  staff_code: string
  local_name?: string
  english_name?: string
  location: string
  branch_code: string
  business_group_code: string
  division_code: string
  department_code: string
  education_level: string
  hire_date: string
  position: string
  job_family_code: string
  career_level_code: string
  manager_staff_code?: string
  departure_date: string | null
  email?: string
  phone?: string
  profile_summary?: string
  branch_id: string
  business_group_id: string
  division_id: string
  department_id: string
  job_family_id: string
  career_level_id: string
}
type ImportIssue = { row_number: number; sheet: string; cell?: string; field: string; code: string }
type Preview = { rows: ImportRow[]; errors: ImportIssue[]; row_count: number; catalog_revision: string; graph_revision: string }
type WorkbookDiagnostic = { sheet?: string; cell?: string; code: string }
type WorkbookFailure = { status: number; requestID?: string; diagnostic?: WorkbookDiagnostic }
type Employee = {
  id: string
  lifecycle: { valid_from: string; valid_to: string | null }
  identifiers: { kind: string; staff_code?: string }[]
}
type Directory = { items: Employee[]; graph_revision: string; next_cursor?: string | null; search_incomplete?: boolean }
type Catalog = { catalog_revision: string; graph_revision: string }
type CreateResult = { id: string; profile_revision: string; workforce_revision: string; graph_revision: string }
type WorkforceResult = { graph_revision: string }
type RowStatus = 'pending' | 'created' | 'manager_pending' | 'failed' | 'uncertain'
type RowExecution = ImportRow & {
  status: RowStatus
  message: string
  employeeId?: string
  workforceRevision?: string
  command?: { key: string; body: string; graphRevision: string }
}
type ReportingCommand = { key: string; body: string; rowNumbers: number[] }

const props = defineProps<{ session: Session; asOf: string }>()
const emit = defineEmits<{
  'session-expired': []
  'session-updated': [payload: { session: Session; catalogRevision: string; graphRevision: string }]
}>()

const workbook = shallowRef<File | null>(null)
const preview = shallowRef<Preview | null>(null)
const executions = ref<RowExecution[]>([])
const phase = ref<'idle' | 'previewing' | 'applying' | 'downloading'>('idle')
const errorMessage = ref('')
const notice = ref('')
const reportingCommand = shallowRef<ReportingCommand | null>(null)
const reportingUncertain = ref(false)
const reportingComplete = ref(false)
const fileGeneration = ref(0)
let controller: AbortController | null = null

const busy = computed(() => phase.value !== 'idle')
const hasPreviewErrors = computed(() => Boolean(preview.value?.errors.length))
const batchComplete = computed(() => reportingComplete.value && executions.value.length > 0 && executions.value.every(row => row.status === 'created' || row.status === 'manager_pending' || row.status === 'failed'))
const executionLocked = computed(() => reportingComplete.value || reportingCommand.value !== null || executions.value.some(row => row.command !== undefined))
const summary = computed(() => executions.value.reduce((result, row) => {
  result[row.status] = (result[row.status] ?? 0) + 1
  return result
}, {} as Record<RowStatus, number>))
const issueMessages: Record<string, string> = {
  text_required: '必须使用文本单元格',
  invalid_staff_code: 'Staff Code 格式不正确',
  invalid_profile: '姓名或资料字段不符合规则',
  invalid_employment_dates: '入职日/退职日必须为 YYYY-MM-DD，且退职日晚于入职日',
  field_too_large: '字段超过允许长度，预览未回传其内容',
  manager_cycle: '同一文件内的直属主管关系形成自引用或闭环',
  unexpected_column: '存在模板以外的非空列',
  invalid_location: 'Location必须为Shanghai、Wuxi或Tokyo',
  invalid_education_level: '学历必须为Master、Bachelor或Diploma',
  invalid_position: '职位不能为空或超过允许长度',
  invalid_catalog_code: '目录Code不能为空或格式不正确',
  unknown_catalog_code: '该入职日没有唯一有效的目录Code',
  organization_hierarchy_mismatch: 'Business Group、Division与Department层级不一致',
}
const workbookErrorMessages: Record<string, string> = {
  invalid_package: '文件不是有效的 XLSX 工作簿，或压缩包结构已损坏',
  unsafe_package_entry: '工作簿包含不安全的压缩包路径',
  expanded_size_limit: '工作簿解压后超过 20 MiB 安全上限',
  macros_not_allowed: '不接受包含宏的工作簿',
  invalid_relationships: '工作簿关系定义损坏',
  external_relationship_not_allowed: '工作簿包含外部链接；请删除外部数据连接后重试',
  worksheet_count: '工作簿必须且只能包含一个工作表',
  worksheet_manifest: '工作簿的工作表清单损坏',
  invalid_worksheet_relationship: '工作表引用关系损坏',
  invalid_shared_strings: '工作簿的共享文本表损坏',
  worksheet_missing: '工作簿声明的工作表不存在',
  invalid_worksheet_xml: '工作表结构损坏或超过行、单元格/XML安全上限',
  unordered_rows: '工作表行号顺序不合法',
  invalid_cell_reference: '单元格坐标不合法或与所在行不一致',
  formula_not_allowed: '不允许公式；请将该单元格转换为纯文本',
  duplicate_cell_reference: '同一坐标出现了重复单元格',
  invalid_shared_string: '单元格引用了不存在的共享文本',
  unsupported_cell_type: '单元格类型不受支持；请转换为纯文本',
  empty_worksheet: 'Employees 工作表没有可导入的员工行',
  header_row_missing: '第 1 行必须是模板表头',
  header_missing: '缺少模板表头',
  header_text_required: '模板表头必须是文本单元格',
  header_mismatch: '表头与最新模板不一致；请勿修改中英文标题',
  unexpected_column: '模板范围外存在非空列',
  row_limit: '单次最多导入 100 名员工',
}
function workbookFailure(error: unknown): string {
  const failure = error as WorkbookFailure
  const diagnostic = failure.diagnostic
  if (diagnostic && workbookErrorMessages[diagnostic.code]) {
    const sheet = diagnostic.sheet === 'Employees' ? diagnostic.sheet : ''
    const cell = typeof diagnostic.cell === 'string' && /^[A-Z]{1,3}[1-9]\d{0,6}$/.test(diagnostic.cell) ? diagnostic.cell : ''
    const location = sheet && cell ? `${sheet}!${cell}` : sheet || cell
    const request = typeof failure.requestID === 'string' && /^[0-9a-f-]{36}$/.test(failure.requestID) ? `（请求 ID：${failure.requestID}）` : ''
    return `${location ? `${location}：` : ''}${workbookErrorMessages[diagnostic.code]}${request}`
  }
  if (failure.status === 401) return '会话已失效，请重新登录后再上传。'
  if (failure.status === 403) return '当前账号没有批量创建人员的权限。'
  if (failure.status === 413) return '工作簿超过 5 MiB 上传上限。'
  if (failure.status === 409) return '组织目录版本已变化，请重新上传并校验。'
  if (failure.status >= 500) return '服务暂时不可用；文件仍保留，可稍后点击“重新校验”。'
  return '工作簿无法校验。请下载最新模板；错误仍存在时请提供请求 ID 给管理员。'
}
const statusLabels: Record<RowStatus, string> = {
  pending: '未处理',
  created: '已创建',
  manager_pending: '已创建，主管待维护',
  failed: '失败',
  uncertain: '结果不确定',
}

function headers(json = false) {
  const value: Record<string, string> = { 'X-Access-Purpose': 'organization_management' }
  if (json) value['Content-Type'] = 'application/json'
  return value
}
function csrfHeaders(json = false, key = '') {
  const value = headers(json)
  value['X-CSRF-Token'] = props.session.csrf_token
  if (key) value['Idempotency-Key'] = key
  return value
}
async function api(path: string, init: RequestInit = {}) {
  const response = await fetch(`/api/v1${path}`, { credentials: 'same-origin', cache: 'no-store', signal: controller?.signal, ...init })
  if (response.status === 401) emit('session-expired')
  return response
}
function resetResults() {
  preview.value = null
  executions.value = []
  reportingCommand.value = null
  reportingUncertain.value = false
  reportingComplete.value = false
  errorMessage.value = ''
  notice.value = ''
}
async function chooseWorkbook(event: Event) {
  if (busy.value || executionLocked.value) return
  const input = event.target as HTMLInputElement
  workbook.value = input.files?.[0] ?? null
  resetResults()
  if (workbook.value) await previewWorkbook()
}
function startNewBatch() {
  if (busy.value || !batchComplete.value) return
  workbook.value = null
  fileGeneration.value += 1
  resetResults()
}
function stopOperation() {
  controller?.abort()
  controller = null
  phase.value = 'idle'
}
async function downloadTemplate() {
  if (busy.value) return
  phase.value = 'downloading'
  errorMessage.value = ''
  controller = new AbortController()
  try {
    const response = await api(`/orgs/${props.session.org_id}/employees/import-template`, { headers: headers() })
    if (!response.ok) throw new Error(String(response.status))
    const blob = await response.blob()
    const href = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = href
    link.download = 'teamledger-personnel-import.xlsx'
    link.click()
    URL.revokeObjectURL(href)
    notice.value = '上传模板已下载。'
  } catch (error) {
    if ((error as Error).name !== 'AbortError') errorMessage.value = '模板下载失败，请重新核对会话后重试。'
  } finally {
    if (phase.value === 'downloading') stopOperation()
  }
}
async function previewWorkbook() {
  const file = workbook.value
  if (!file || busy.value) return
  if (file.size === 0 || file.size > 5 * 1024 * 1024) {
    errorMessage.value = '请选择不超过 5 MiB 的 XLSX 文件。'
    return
  }
  phase.value = 'previewing'
  errorMessage.value = ''
  notice.value = `${file.name} 正在上传并校验…`
  controller = new AbortController()
  try {
    const response = await api(`/orgs/${props.session.org_id}/employees/import-preview`, {
      method: 'POST',
      headers: { ...csrfHeaders(), 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
      body: file,
    })
    if (!response.ok) {
      let requestID: string | undefined
      let diagnostic: WorkbookDiagnostic | undefined
      try {
        const failure = await response.json() as { request_id?: unknown; workbook_error?: unknown }
        if (typeof failure.request_id === 'string') requestID = failure.request_id
        if (failure.workbook_error && typeof failure.workbook_error === 'object') {
          const candidate = failure.workbook_error as Record<string, unknown>
          if (typeof candidate.code === 'string') {
            diagnostic = {
              code: candidate.code,
              sheet: typeof candidate.sheet === 'string' ? candidate.sheet : undefined,
              cell: typeof candidate.cell === 'string' ? candidate.cell : undefined,
            }
          }
        }
      } catch {
        // Non-JSON proxy failures remain status-specific and never become success.
      }
      throw { status: response.status, requestID, diagnostic } satisfies WorkbookFailure
    }
    const parsed = await response.json() as Preview
    if (!parsed || !Array.isArray(parsed.rows) || !Array.isArray(parsed.errors) || parsed.row_count !== parsed.rows.length || parsed.row_count < 1 || parsed.row_count > 100 || !/^[1-9]\d*$/.test(parsed.catalog_revision) || !/^[1-9]\d*$/.test(parsed.graph_revision)) throw { status: 503 } satisfies WorkbookFailure
    preview.value = parsed
    executions.value = parsed.rows.map(row => ({ ...row, status: 'pending', message: '' }))
    notice.value = parsed.errors.length ? `${file.name} 预览发现错误；请按工作表和单元格定位修正后重新上传。` : `${file.name} 已校验 ${parsed.row_count} 行，尚未创建人员。`
  } catch (error) {
    if ((error as Error).name !== 'AbortError') {
      notice.value = ''
      errorMessage.value = workbookFailure(error)
    }
  } finally {
    if (phase.value === 'previewing') stopOperation()
  }
}
function exactStaffCode(employee: Employee, code: string) {
  return employee.identifiers?.some(identifier => identifier.kind === 'staff_code' && identifier.staff_code === code)
}
async function readJSON<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await api(path, init)
  if (!response.ok) throw Object.assign(new Error(String(response.status)), { status: response.status })
  return await response.json() as T
}
async function resolveExistingManager(current: Session, catalog: Catalog, code: string, effectiveDate: string) {
  const seen = new Set<string>()
  let cursor = ''
  for (let page = 0; page < 100; page++) {
    const body: Record<string, unknown> = { as_of: effectiveDate, lifecycle: 'active', q: code, include_profile: true, limit: 100 }
    if (cursor) body.cursor = cursor
    const directory = await readJSON<Directory>(`/orgs/${current.org_id}/employees/query`, {
      method: 'POST',
      headers: csrfHeaders(true),
      body: JSON.stringify(body),
    })
    if (directory.graph_revision !== catalog.graph_revision) throw Object.assign(new Error('409'), { status: 409 })
    const matches = directory.items.filter(employee => exactStaffCode(employee, code))
    if (matches.length > 1) return { matches: [] as Employee[], ambiguous: true }
    if (matches.length === 1) return { matches, ambiguous: false }
    if (directory.next_cursor === null || directory.next_cursor === undefined) {
      if (directory.search_incomplete) throw Object.assign(new Error('503'), { status: 503 })
      return { matches: [] as Employee[], ambiguous: false }
    }
    if (typeof directory.next_cursor !== 'string' || directory.next_cursor === '' || seen.has(directory.next_cursor)) throw Object.assign(new Error('503'), { status: 503 })
    seen.add(directory.next_cursor)
    cursor = directory.next_cursor
  }
  throw Object.assign(new Error('503'), { status: 503 })
}

async function verifyCurrentSession() {
  const current = await readJSON<Session>('/session', { headers: headers() })
  if (current.subject_id !== props.session.subject_id || current.org_id !== props.session.org_id || !['organization.read', 'organization.write', 'pii.read', 'pii.write'].every(capability => current.capabilities.includes(capability))) {
    throw Object.assign(new Error('403'), { status: 403 })
  }
  return current
}
async function preflight() {
  const current = await verifyCurrentSession()
  if (!preview.value) throw Object.assign(new Error('preview'), { status: 422 })
  const catalog = { catalog_revision: preview.value.catalog_revision, graph_revision: preview.value.graph_revision }
  const batchCodes = new Set(executions.value.map(row => row.staff_code))
  const externalPairs = new Map<string, { code: string; effectiveDate: string }>()
  for (const row of executions.value.filter(item => item.status !== 'failed' && item.status !== 'manager_pending' && item.manager_staff_code && !batchCodes.has(item.manager_staff_code))) {
    externalPairs.set(`${row.manager_staff_code}\u0000${row.hire_date}`, { code: row.manager_staff_code!, effectiveDate: row.hire_date })
  }
  const managers = new Map<string, string>()
  let managerError = false
  for (const [key, pair] of externalPairs) {
    const resolved = await resolveExistingManager(current, catalog, pair.code, pair.effectiveDate)
    const matches = resolved.matches
    if (resolved.ambiguous || matches.length !== 1) {
      for (const row of executions.value.filter(item => item.status !== 'failed' && item.status !== 'manager_pending' && item.manager_staff_code === pair.code && item.hire_date === pair.effectiveDate)) {
        if (row.employeeId) {
          row.status = 'manager_pending'
          row.message = '人员已创建；直属主管在该入职日已退职、不可读或不再唯一，主管待维护'
        } else {
          row.status = 'failed'
          row.message = resolved.ambiguous ? '直属主管 Staff Code 匹配不唯一' : '直属主管在该入职日不存在、已退职或当前不可读'
          managerError = true
        }
      }
    } else {
      managers.set(key, matches[0]!.id)
    }
  }
  if (managerError) throw Object.assign(new Error('manager'), { status: 422 })
  return { current, catalog, managers }
}
function createBody(row: RowExecution, catalog: Catalog) {
  const profile: Record<string, unknown> = {}
  if (row.local_name) profile.local_name = row.local_name
  if (row.english_name) profile.english_name = row.english_name
  if (row.email || row.phone) profile.work_contact = { ...(row.email ? { email: row.email } : {}), ...(row.phone ? { phone: row.phone } : {}) }
  if (row.profile_summary) profile.profile_summary = row.profile_summary
  return JSON.stringify({
    profile,
    lifecycle: { valid_from: row.hire_date, valid_to: row.departure_date },
    staff_code: row.staff_code,
    employment: { legal_entity_id: row.branch_id, location_code: row.location },
    education: { level: row.education_level },
    job_assignment: {
      department_id: row.department_id,
      job_family_id: row.job_family_id,
      career_level_id: row.career_level_id,
      position: { title: row.position },
    },
    expected_catalog_revision: catalog.catalog_revision,
    expected_graph_revision: catalog.graph_revision,
  })
}
async function submitEmployee(row: RowExecution, catalog: Catalog) {
  row.command ??= { key: crypto.randomUUID(), body: createBody(row, catalog), graphRevision: catalog.graph_revision }
  try {
    const response = await api(`/orgs/${props.session.org_id}/employees`, {
      method: 'POST', headers: csrfHeaders(true, row.command.key), body: row.command.body,
    })
    if (!response.ok) {
      if (response.status === 401) throw Object.assign(new Error('401'), { status: 401 })
      if (response.status >= 500 || response.status === 408) throw Object.assign(new Error(String(response.status)), { status: response.status })
      row.status = 'failed'
      row.message = response.status === 409 ? 'Staff Code 已存在或组织版本已变化，未创建；请重新预览后核对' : '资料未被接受，未创建'
      return true
    }
    const result = await response.json() as CreateResult
    if (!result.id || !result.workforce_revision || result.graph_revision !== row.command.graphRevision) throw Object.assign(new Error('503'), { status: 503 })
    row.employeeId = result.id
    row.workforceRevision = result.workforce_revision
    row.status = 'created'
    row.message = '基本资料与 Staff Code 已创建'
    return true
  } catch (error) {
    const status = (error as { status?: number }).status
    if (status === 401) throw error
    row.status = 'uncertain'
    row.message = '创建结果不确定；必须以原命令确认'
    return false
  }
}
function freezeReportingCommand(catalog: Catalog, managers: Map<string, string>) {
  const byCode = new Map(executions.value.filter(row => row.employeeId).map(row => [row.staff_code, row.employeeId!]))
  const rowNumbers: number[] = []
  const expected: Record<string, string> = {}
  const changes: Record<string, unknown>[] = []
  for (const row of executions.value) {
    if (row.status !== 'created' || !row.manager_staff_code || !row.employeeId || !row.workforceRevision) continue
    const manager = byCode.get(row.manager_staff_code) ?? managers.get(`${row.manager_staff_code}\u0000${row.hire_date}`)
    if (!manager) {
      row.status = 'manager_pending'
      row.message = '人员已创建；同批主管未成功创建，主管待维护'
      continue
    }
    expected[row.employeeId] = row.workforceRevision
    rowNumbers.push(row.row_number)
    changes.push({ action: 'add', kind: 'reporting', employee_id: row.employeeId, manager_employee_id: manager, reporting_kind: 'administrative', valid_from: row.hire_date, valid_to: row.departure_date })
  }
  if (!changes.length) return null
  return {
    key: crypto.randomUUID(),
    rowNumbers,
    body: JSON.stringify({ expected_catalog_revision: catalog.catalog_revision, expected_graph_revision: catalog.graph_revision, expected_employee_revisions: expected, reason: 'Personnel XLSX import', changes }),
  }
}
async function submitReporting(command: ReportingCommand, catalog: Catalog) {
  try {
    const response = await api(`/orgs/${props.session.org_id}/workforce-changes`, { method: 'POST', headers: csrfHeaders(true, command.key), body: command.body })
    if (!response.ok) {
      if (response.status === 401) throw Object.assign(new Error('401'), { status: 401 })
      if (response.status >= 500 || response.status === 408) throw Object.assign(new Error(String(response.status)), { status: response.status })
      for (const row of executions.value.filter(item => command.rowNumbers.includes(item.row_number))) {
        row.status = 'manager_pending'
        row.message = '人员已创建；主管关系因版本或业务冲突未写入'
      }
      reportingCommand.value = null
      reportingComplete.value = true
      return true
    }
    const result = await response.json() as WorkforceResult
    for (const row of executions.value.filter(item => command.rowNumbers.includes(item.row_number))) {
      row.status = 'created'
      row.message = '人员、Staff Code 与直属主管已创建'
    }
    reportingUncertain.value = false
    reportingCommand.value = null
    reportingComplete.value = true
    try {
      const next = await readJSON<Session>('/session', { headers: headers() })
      if (next.subject_id === props.session.subject_id && next.org_id === props.session.org_id) emit('session-updated', { session: next, catalogRevision: catalog.catalog_revision, graphRevision: result.graph_revision })
    } catch { /* committed result remains visible; outer shell will recheck on next operation */ }
    return true
  } catch (error) {
    if ((error as { status?: number }).status === 401) throw error
    reportingUncertain.value = true
    for (const row of executions.value.filter(item => command.rowNumbers.includes(item.row_number))) {
      row.status = 'uncertain'
      row.message = '主管关系提交结果不确定；必须以原命令确认'
    }
    return false
  }
}
function setCompletionNotice() {
  const created = executions.value.filter(row => row.status === 'created').length
  const pending = executions.value.filter(row => row.status === 'manager_pending').length
  const failed = executions.value.filter(row => row.status === 'failed').length
  notice.value = `批量处理完成：已创建 ${created}，主管待维护 ${pending}，失败 ${failed}。`
}

async function applyBatch() {
  if (busy.value || !preview.value || hasPreviewErrors.value || batchComplete.value) return
  phase.value = 'applying'
  errorMessage.value = ''
  notice.value = ''
  controller = new AbortController()
  try {
    if (reportingUncertain.value && reportingCommand.value) {
      await verifyCurrentSession()
      const catalog = await readJSON<Catalog>(`/orgs/${props.session.org_id}/workforce-catalogs?${new URLSearchParams({ as_of: props.asOf, limit: '100' })}`, { headers: headers() })
      if (await submitReporting(reportingCommand.value, catalog)) setCompletionNotice()
      return
    }
    const uncertainCreates = executions.value.filter(row => row.status === 'uncertain' && row.command && !row.employeeId)
    if (uncertainCreates.length) {
      await verifyCurrentSession()
      for (const row of uncertainCreates) {
        if (!await submitEmployee(row, { catalog_revision: '', graph_revision: row.command!.graphRevision })) {
          notice.value = '批量创建仍无法确认；请继续使用原提交确认。'
          return
        }
      }
    }
    const { catalog, managers } = await preflight()
    for (const row of executions.value) {
      if (row.status === 'created' || row.status === 'manager_pending' || row.status === 'failed') continue
      if (!await submitEmployee(row, catalog)) {
        notice.value = '批量创建已暂停；请确认结果不确定的原提交后继续。'
        return
      }
    }
    reportingCommand.value ??= freezeReportingCommand(catalog, managers)
    if (!reportingCommand.value) reportingComplete.value = true
    if (reportingCommand.value && !await submitReporting(reportingCommand.value, catalog)) {
      notice.value = '主管关系提交结果不确定；请使用原命令确认。'
      return
    }
    setCompletionNotice()
  } catch (error) {
    const status = (error as { status?: number }).status
    if (status === 401) emit('session-expired')
    errorMessage.value = status === 403 ? '当前权限不足，批量处理已停止；此前已确认结果保持不变。' : status === 422 ? '主管预检未通过，未开始新的创建；此前已确认结果保持不变。' : '批量处理前置核对失败，未开始新的创建；此前已确认结果保持不变。'
  } finally {
    if (phase.value === 'applying') stopOperation()
  }
}

onBeforeUnmount(() => stopOperation())
</script>

<template>
  <details class="personnel-import">
    <summary>
      <span><strong>批量上传人员</strong><small>下载模板、校验预览后再明确创建</small></span>
      <span class="summary-action">展开</span>
    </summary>
    <div class="import-body">
      <div class="import-intro">
        <div>
          <h2>批量创建人员</h2>
          <p>最多 100 人。一次校验并创建完整员工主数据：身份、雇佣关系、组织任职、学历及直属主管；薪资不在此功能导入。</p>
        </div>
        <button type="button" class="secondary" :disabled="busy" @click="downloadTemplate">下载 XLSX 模板</button>
      </div>
      <ol class="import-steps" aria-label="批量上传步骤">
        <li><strong>1</strong><span>下载并填写模板</span></li>
        <li><strong>2</strong><span>上传后校验预览</span></li>
        <li><strong>3</strong><span>确认后批量创建</span></li>
      </ol>
      <div class="import-controls">
        <label>选择 XLSX<input :key="fileGeneration" type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" :disabled="busy || executionLocked" @change="chooseWorkbook"></label>
        <button type="button" class="secondary" :disabled="busy || !workbook || executionLocked" @click="previewWorkbook">{{ phase === 'previewing' ? '正在上传并校验…' : preview ? '重新校验' : '校验并预览' }}</button>
        <button type="button" :disabled="busy || !preview || hasPreviewErrors || batchComplete" @click="applyBatch">{{ batchComplete ? '批量处理已完成' : executions.some(row => row.status === 'uncertain') ? '确认原提交并继续' : '确认并批量创建' }}</button>
        <button v-if="batchComplete" type="button" class="secondary" :disabled="busy" @click="startNewBatch">开始下一批</button>
      </div>
      <p v-if="errorMessage" class="error" role="alert">{{ errorMessage }}</p>
      <p v-if="notice" class="notice" role="status">{{ notice }}</p>
      <div v-if="preview" class="import-preview">
        <div class="import-summary">
          <strong>{{ preview.row_count }} 行</strong>
          <span v-if="preview.errors.length">{{ preview.errors.length }} 个错误</span>
          <template v-if="executions.length">
            <span>已创建 {{ summary.created ?? 0 }}</span>
            <span>主管待维护 {{ summary.manager_pending ?? 0 }}</span>
            <span>失败 {{ summary.failed ?? 0 }}</span>
            <span>结果不确定 {{ summary.uncertain ?? 0 }}</span>
          </template>
        </div>
        <ul v-if="preview.errors.length" class="import-errors">
          <li v-for="issue in preview.errors" :key="`${issue.row_number}-${issue.cell ?? issue.field}-${issue.code}`">{{ issue.sheet }}<template v-if="issue.cell">!{{ issue.cell }}</template> · {{ issue.field }}：{{ issueMessages[issue.code] ?? issue.code }}</li>
        </ul>
        <div class="import-table-wrap">
          <table>
            <thead><tr><th>行</th><th>Staff Code</th><th>姓名</th><th>Location</th><th>Branch</th><th>Business Group</th><th>Division</th><th>Department</th><th>学历</th><th>入职日</th><th>职位</th><th>职系</th><th>职级</th><th>HOD Staff Code</th><th>退职日</th><th>联系与摘要</th><th>结果</th></tr></thead>
            <tbody>
              <tr v-for="row in executions" :key="row.row_number">
                <td>{{ row.row_number }}</td><td>{{ row.staff_code }}</td>
                <td><span>{{ row.local_name || '—' }}</span><small>英文：{{ row.english_name || '—' }}</small></td>
                <td>{{ row.location }}</td><td>{{ row.branch_code }}</td><td>{{ row.business_group_code }}</td><td>{{ row.division_code }}</td><td>{{ row.department_code }}</td>
                <td>{{ row.education_level }}</td><td>{{ row.hire_date }}</td><td>{{ row.position }}</td><td>{{ row.job_family_code }}</td><td>{{ row.career_level_code }}</td>
                <td>{{ row.manager_staff_code || '—' }}</td><td>{{ row.departure_date || '未退职' }}</td>
                <td class="profile-summary"><span>{{ row.email || '—' }}</span><small>电话：{{ row.phone || '—' }}</small><small>摘要：{{ row.profile_summary || '—' }}</small></td>
                <td><span :class="['row-status', `is-${row.status}`]">{{ statusLabels[row.status] }}</span><small v-if="row.message">{{ row.message }}</small></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </details>
</template>

<style scoped>
.personnel-import { margin-bottom: 1.25rem; border: 1px solid var(--line); border-radius: var(--radius-lg); background: var(--surface); box-shadow: var(--shadow-sm); overflow: hidden; }
.personnel-import > summary { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 1rem 1.25rem; cursor: pointer; list-style: none; }
.personnel-import > summary::-webkit-details-marker { display: none; }
.personnel-import > summary span:first-child { display: grid; gap: .2rem; }
.personnel-import > summary strong { color: var(--ink-900); }
.personnel-import > summary small { color: var(--ink-600); font-size: .76rem; }
.summary-action { color: var(--brand-700); font-size: .78rem; font-weight: 750; }
details[open] .summary-action { font-size: 0; }
details[open] .summary-action::after { content: '收起'; font-size: .78rem; }
.import-body { padding: 1.25rem; border-top: 1px solid var(--line-soft); }
.import-intro { display: flex; align-items: start; justify-content: space-between; gap: 1.5rem; }
.import-intro h2 { margin: 0 0 .35rem; font-size: 1rem; }
.import-intro p { max-width: 52rem; margin: 0; color: var(--ink-600); font-size: .82rem; line-height: 1.55; }
.import-steps { display: grid; grid-template-columns: repeat(3, 1fr); gap: .75rem; margin: 1rem 0; padding: 0; list-style: none; }
.import-steps li { display: flex; align-items: center; gap: .55rem; padding: .7rem; border-radius: var(--radius-md); background: var(--surface-muted); color: var(--ink-700); font-size: .78rem; }
.import-steps strong { display: grid; width: 1.45rem; height: 1.45rem; place-items: center; border-radius: 50%; background: var(--brand-100); color: var(--brand-800); }
.import-controls { display: flex; align-items: end; gap: .75rem; flex-wrap: wrap; }
.import-controls label { display: grid; gap: .35rem; min-width: min(100%, 22rem); color: var(--ink-800); font-size: .78rem; font-weight: 700; }
.import-controls input { min-height: 2.65rem; padding: .55rem; }
.import-summary { display: flex; flex-wrap: wrap; gap: .55rem 1rem; margin: 1rem 0 .65rem; color: var(--ink-600); font-size: .78rem; }
.import-errors { margin: .5rem 0 1rem; padding: .75rem 1rem .75rem 2rem; border: 1px solid var(--danger-100); border-radius: var(--radius-md); background: var(--danger-50); color: var(--danger-700); font-size: .78rem; }
.import-table-wrap { overflow-x: auto; border: 1px solid var(--line-soft); border-radius: var(--radius-md); }
table { width: 100%; min-width: 110rem; border-collapse: collapse; }
th, td { padding: .7rem .8rem; border-bottom: 1px solid var(--line-soft); text-align: left; vertical-align: top; font-size: .75rem; }
th { background: var(--surface-muted); color: var(--ink-700); }
td small { display: block; max-width: 16rem; margin-top: .25rem; color: var(--ink-600); }
.profile-summary { max-width: 18rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.row-status { display: inline-flex; padding: .15rem .45rem; border-radius: 999px; background: var(--surface-muted); font-weight: 720; }
.is-created { background: var(--success-50); color: var(--success-700); }
.is-manager_pending, .is-uncertain { background: var(--accent-100); color: var(--accent-700); }
.is-failed { background: var(--danger-50); color: var(--danger-700); }
.notice { color: var(--brand-800); }
.error { color: var(--danger-700); }
@media (max-width: 760px) {
  .import-intro { display: grid; }
  .import-intro button, .import-controls button, .import-controls label { width: 100%; }
  .import-steps { grid-template-columns: 1fr; }
  .import-body, .personnel-import > summary { padding-inline: 1rem; }
}
</style>
