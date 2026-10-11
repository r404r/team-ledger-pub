<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()
type Lifecycle = { valid_from: string; valid_to: string | null }
type Session = { subject_id: string; org_id: string; auth_epoch: string; csrf_token: string; capabilities: string[] }
type Profile = { display_name: string }
type Relation = Lifecycle & { id: string; employee_id?: string; team_id?: string; parent_team_id?: string; manager_employee_id?: string; kind?: string; is_primary?: boolean; position?: { title: string; position_code?: string; description?: string } }
type Employee = { id: string; org_id: string; lifecycle: Lifecycle; as_of: string; authorization_date: string; graph_revision?: string; profile_revision?: string; profile?: Profile; memberships?: Relation[]; positions?: Relation[]; reporting_lines?: Relation[] }
type Snapshot = { as_of?: string; authorization_date: string; graph_revision: string; auth_epoch: string }
type Tree = Snapshot & { org_id: string; as_of: string; nodes: { id: string; code: string; lifecycle: Lifecycle; label?: string }[]; edges: (Lifecycle & { id: string; child_team_id: string; parent_team_id: string })[]; employees: { id: string; team_id: string; profile?: Profile }[] }
type Directory = Snapshot & { as_of: string; consistency: 'current'; items: Employee[]; next_cursor: string | null; search_incomplete: boolean }
type HistoryRelation = Partial<Relation> & { id: string; action: string; kind: string; reporting_kind?: string; effective_to?: string | null; end_date?: string; supersedes_id?: string; superseded?: boolean }
type History = Snapshot & { from?: string; to?: string; consistency: 'current'; next_cursor: string | null; items: { id: string; actor_subject_id: string; recorded_at: string; graph_before: string; graph_after: string; items: HistoryRelation[]; reason?: string }[] }
type Receipt = { id: string; graph_revision: string; auth_epoch: string; items?: { kind: string; id: string }[] }
type Operation = { generation: number; controller: AbortController }
type Row = { key: number; action: string; kind: string; ref: string; employee: string; team: string; parent: string; manager: string; reportingKind: string; from: string; to: string; end: string; title: string; positionCode: string; description: string }
type Command = { path: string; body: string; key: string; context: Session; kind: 'team' | 'structure' }
type Preview = Omit<Command, 'key'> & { summary: string[] }
type DirectoryQuery = { as_of: string; lifecycle: string; limit: number; include_profile: boolean; team_id?: string; employee_id?: string; q?: string; cursor?: string }
type StructureAction = 'add' | 'end' | 'replace' | 'lifecycle'
type StructureKind = 'team_parent' | 'membership' | 'position' | 'reporting_line' | 'team_lifecycle' | 'employee_lifecycle'
type StructureItem = {
  action: StructureAction; kind: StructureKind; ref?: string; employee_id?: string; team_id?: string
  parent_team_id?: string; manager_employee_id?: string; reporting_kind?: 'administrative' | 'dotted'
  is_primary?: true; lifecycle?: Lifecycle; end_date?: string; position?: { title: string; position_code?: string; description?: string }
}
type StructureCommand = { expected_graph_revision: string; reason?: string; changes: StructureItem[] }
type CreateTeamCommand = { code: string; lifecycle: Lifecycle; label?: string }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revision = /^[1-9][0-9]*$/
const session = shallowRef<Session | null>(null)
const tree = shallowRef<Tree | null>(null)
const directory = shallowRef<Directory | null>(null)
const history = shallowRef<History | null>(null)
const confirmed = shallowRef<Receipt | null>(null)
const mode = ref<'tree' | 'directory' | 'history' | 'away'>('away')
const orgID = ref('')
const employeeID = ref('')
const phase = ref<'idle' | 'loading' | 'submitting' | 'verifying'>('idle')
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const uncertain = ref(false)
const preview = shallowRef<Preview | null>(null)
const filters = reactive({ asOf: '', root: '', depth: '3', limit: '50', labels: false, team: '', employee: '', lifecycle: 'active', q: '', profile: false, from: '', to: '' })
const teamForm = reactive({ code: '', from: '', to: '', labelEnabled: false, label: '' })
const reasonEnabled = ref(false)
const reason = ref('')
const rows = ref<Row[]>([])
let rowKey = 0
let generation = 0
let controller: AbortController | null = null
let alive = false
let lastCommand: Command | null = null
let appliedDirectory: DirectoryQuery | null = null
let appliedHistory = ''

const busy = computed(() => phase.value !== 'idle')
const graphRevision = computed(() => tree.value?.graph_revision ?? directory.value?.graph_revision ?? history.value?.graph_revision ?? '')
const canWrite = computed(() => has('organization.read') && has('organization.write'))
const canPIIWrite = computed(() => has('pii.read') && has('pii.write'))
const heading = computed(() => mode.value === 'tree' ? '组织树与原子结构变更' : mode.value === 'directory' ? '员工目录' : '员工组织历史')
const treeOutline = computed(() => {
  const snapshot = tree.value
  if (!snapshot) return []
  const children = new Map<string, typeof snapshot.nodes>()
  const parentIDs = new Set<string>()
  for (const edge of snapshot.edges) {
    const child = snapshot.nodes.find((node) => node.id === edge.child_team_id)
    if (!child) continue
    const siblings = children.get(edge.parent_team_id) ?? []
    siblings.push(child); children.set(edge.parent_team_id, siblings); parentIDs.add(child.id)
  }
  const ordered: { node: Tree['nodes'][number]; depth: number }[] = []
  const seen = new Set<string>()
  const append = (node: Tree['nodes'][number], depth: number) => {
    if (seen.has(node.id)) return
    seen.add(node.id); ordered.push({ node, depth })
    for (const child of children.get(node.id) ?? []) append(child, depth + 1)
  }
  for (const node of snapshot.nodes) if (!parentIDs.has(node.id)) append(node, 0)
  for (const node of snapshot.nodes) if (!seen.has(node.id)) append(node, 0)
  return ordered
})

class ApiFailure extends Error { constructor(readonly status: number) { super('Organization request failed') } }
function has(capability: string) { return Boolean(session.value?.capabilities.includes(capability)) }
function validRevision(value: unknown): value is string { return typeof value === 'string' && revision.test(value) && value.length <= 19 && BigInt(value) <= 9223372036854775807n }
function validDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}
function validLifecycle(value: Lifecycle) { return Boolean(value && validDate(value.valid_from) && (value.valid_to === null || validDate(value.valid_to) && value.valid_to > value.valid_from)) }
function bytes(value: string) { return new TextEncoder().encode(value).length }
function sameIdentity(left: Session, right: Session) { return left.subject_id === right.subject_id && left.org_id === right.org_id }
function clearViews() { tree.value = null; directory.value = null; history.value = null; confirmed.value = null }
function clearForms() {
  rows.value = []; teamForm.code = ''; teamForm.from = ''; teamForm.to = ''; teamForm.label = ''; teamForm.labelEnabled = false
  reason.value = ''; reasonEnabled.value = false; preview.value = null; lastCommand = null; uncertain.value = false
}
function clearSensitive() { clearViews(); clearForms(); filters.q = ''; appliedDirectory = null; notice.value = null }
function cancelOperation() { generation += 1; controller?.abort(); controller = null; phase.value = 'idle' }
function beginOperation(next: 'loading' | 'submitting') {
  cancelOperation(); controller = new AbortController(); phase.value = next; error.value = null; notice.value = null
  return { generation, controller }
}
function isCurrent(operation: Operation) { return alive && generation === operation.generation && !operation.controller.signal.aborted }
async function request<T>(path: string, operation: Operation, options?: { body: string; key?: string }): Promise<T> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'organization_management' }
  if (options) { headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = session.value!.csrf_token; if (options.key) headers['Idempotency-Key'] = options.key }
  const response = await fetch(`/api/v1${path}`, { method: options ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal, headers, body: options?.body })
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  const result: T = await response.json()
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  return result
}
function sessionContext() {
  const employee = mode.value === 'history' ? employeeID.value : mode.value === 'directory' ? filters.employee : ''
  const team = mode.value === 'tree' ? filters.root : mode.value === 'directory' ? filters.team : ''
  return employee && uuid.test(employee) ? `?${new URLSearchParams({ employee_id: employee })}` : team && uuid.test(team) ? `?${new URLSearchParams({ team_id: team })}` : ''
}
async function readSession(operation: Operation, expected?: Session, replay = false) {
  const next = await request<Session>(`/session${sessionContext()}`, operation)
  if (!next || !uuid.test(next.subject_id) || !uuid.test(next.org_id) || !validRevision(next.auth_epoch) || typeof next.csrf_token !== 'string' || !next.csrf_token || !Array.isArray(next.capabilities) || !next.capabilities.every((value) => typeof value === 'string')) {
    clearSensitive(); session.value = null
    throw new ApiFailure(503)
  }
  if ((orgID.value && next.org_id !== orgID.value) || expected && (!sameIdentity(expected, next) || !replay && expected.auth_epoch !== next.auth_epoch)) throw new ApiFailure(403)
  if (session.value && (!sameIdentity(session.value, next) || session.value.auth_epoch !== next.auth_epoch)) clearSensitive()
  session.value = next
  if (!has('organization.read')) throw new ApiFailure(403)
  if (mode.value === 'history') orgID.value = next.org_id
  return next
}
function validSnapshot(value: Snapshot) { return Boolean(value && validDate(value.authorization_date) && validRevision(value.graph_revision) && value.auth_epoch === session.value?.auth_epoch) }
function validRelation(value: Relation) {
  return Boolean(value && uuid.test(value.id) && validLifecycle(value) &&
    (!value.employee_id || uuid.test(value.employee_id)) && (!value.team_id || uuid.test(value.team_id)) &&
    (!value.manager_employee_id || uuid.test(value.manager_employee_id)) &&
    (!value.position || typeof value.position.title === 'string' && (value.position.position_code === undefined || typeof value.position.position_code === 'string') && (value.position.description === undefined || typeof value.position.description === 'string')))
}
function validEmployee(value: Employee, include: boolean) {
  if (!value || !uuid.test(value.id) || value.org_id !== session.value?.org_id || value.as_of !== filters.asOf || !validDate(value.authorization_date) || !validLifecycle(value.lifecycle)) return false
  if (value.profile && (!include || !has('pii.read') || typeof value.profile.display_name !== 'string' || !validRevision(value.profile_revision))) return false
  if (!value.profile) delete value.profile_revision
  for (const relations of [value.memberships, value.positions, value.reporting_lines]) if (relations !== undefined && (!Array.isArray(relations) || !relations.every(validRelation))) return false
  return !value.positions?.some((value) => value.position && (!include || !has('pii.read')))
}
async function loadTree(operation: Operation) {
  const query = new URLSearchParams({ as_of: filters.asOf, depth: filters.depth, limit: filters.limit, include_labels: String(filters.labels) })
  if (filters.root) query.set('root_team_id', filters.root)
  const next = await request<Tree>(`/orgs/${orgID.value}/tree?${query}`, operation)
  if (!validSnapshot(next) || next.org_id !== orgID.value || next.as_of !== filters.asOf || !Array.isArray(next.nodes) || !Array.isArray(next.edges) || !Array.isArray(next.employees) ||
      !next.nodes.every((node) => uuid.test(node.id) && typeof node.code === 'string' && validLifecycle(node.lifecycle) && (node.label === undefined || filters.labels && has('pii.read') && typeof node.label === 'string')) ||
      !next.edges.every((edge) => uuid.test(edge.id) && uuid.test(edge.child_team_id) && uuid.test(edge.parent_team_id) && validLifecycle(edge) && next.nodes.some((node) => node.id === edge.child_team_id) && next.nodes.some((node) => node.id === edge.parent_team_id)) ||
      !next.employees.every((item) => uuid.test(item.id) && uuid.test(item.team_id) && (!item.profile || filters.labels && has('pii.read') && typeof item.profile.display_name === 'string'))) throw new ApiFailure(503)
  tree.value = next
}
function directoryQuery(): DirectoryQuery {
  const query: DirectoryQuery = { as_of: filters.asOf, lifecycle: filters.lifecycle, limit: Number(filters.limit), include_profile: filters.profile }
  if (filters.team) query.team_id = filters.team
  if (filters.employee) query.employee_id = filters.employee
  if (filters.q) query.q = filters.q
  return query
}
async function loadDirectory(operation: Operation, query: DirectoryQuery) {
  const next = await request<Directory>(`/orgs/${orgID.value}/employees/query`, operation, { body: JSON.stringify(query) })
  if (!validSnapshot(next) || next.as_of !== query.as_of || next.consistency !== 'current' || !Array.isArray(next.items) || next.items.length > query.limit || !next.items.every((item) => validEmployee(item, query.include_profile)) || typeof next.search_incomplete !== 'boolean' || (next.next_cursor !== null && (typeof next.next_cursor !== 'string' || !next.next_cursor))) throw new ApiFailure(503)
  directory.value = next; appliedDirectory = { ...query }; delete appliedDirectory.cursor
}
function historyQuery() {
  const query = new URLSearchParams({ limit: filters.limit })
  if (filters.from) { query.set('from', filters.from); query.set('to', filters.to) }
  return query.toString()
}
async function loadHistory(operation: Operation, query: string) {
  const next = await request<History>(`/employees/${employeeID.value}/organization-history?${query}`, operation)
  if (!validSnapshot(next) || next.consistency !== 'current' || !Array.isArray(next.items) || next.items.length > Number(filters.limit) ||
      (next.next_cursor !== null && (typeof next.next_cursor !== 'string' || !next.next_cursor)) ||
      !next.items.every((item) => uuid.test(item.id) && uuid.test(item.actor_subject_id) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(item.recorded_at) && validRevision(item.graph_before) && validRevision(item.graph_after) && Array.isArray(item.items) &&
        item.items.every((relation) => uuid.test(relation.id) && ['add', 'end', 'replace', 'lifecycle'].includes(relation.action) && ['team_parent', 'membership', 'position', 'reporting_line', 'team_lifecycle', 'employee_lifecycle'].includes(relation.kind) &&
          (!relation.position || has('pii.read') && typeof relation.position.title === 'string' && (relation.position.position_code === undefined || typeof relation.position.position_code === 'string') && (relation.position.description === undefined || typeof relation.position.description === 'string'))) &&
        (item.reason === undefined || has('pii.read') && typeof item.reason === 'string'))) throw new ApiFailure(503)
  history.value = next
}
function validFilters() {
  if (!/^[1-9][0-9]*$/.test(filters.limit) || Number(filters.limit) > 100 || [filters.root, filters.team, filters.employee].some((id) => id && !uuid.test(id))) return false
  if (mode.value === 'history') return !filters.from && !filters.to || validDate(filters.from) && validDate(filters.to) && filters.from < filters.to
  return validDate(filters.asOf) && (mode.value !== 'tree' || /^[1-9]\d*$/.test(filters.depth) && Number(filters.depth) <= 10) &&
    ['active', 'inactive', 'all'].includes(filters.lifecycle) && bytes(filters.q) <= 256 && (!filters.q || filters.profile)
}
function showFailure(cause: unknown, operation: Operation) {
  if (!isCurrent(operation)) return
  const status = cause instanceof ApiFailure ? cause.status : 503
  if ([401, 403, 404].includes(status)) { cancelOperation(); clearSensitive(); session.value = null; if (status === 401) emit('session-expired') }
  else if ([400, 409, 422].includes(status)) { preview.value = null; lastCommand = null; uncertain.value = false; if (status === 409) clearViews() }
  error.value = status === 401 ? '会话已失效，内容与表单已清空。' : [403, 404].includes(status) ? '当前范围不可访问，内容与表单已清空。身份、团队或经理关系不是自动授权。' : status === 409 ? '图版本或游标上下文已改变。请刷新实际当前版本，再以新命令重新预览；未自动重试。' : [400, 422].includes(status) ? '输入未被接受，请核对明确日期、范围、原关系与当前授权。' : status === 413 ? '快照超过安全范围；请收窄根团队、深度或筛选后重试。没有截断拓扑。' : '服务或网络不可用，结果尚未确认。未显示成功。'
  notice.value = null
}
function updateAddress() {
  const path = mode.value === 'history' ? `/employees/${employeeID.value}/organization-history` : `/orgs/${orgID.value}/${mode.value === 'tree' ? 'tree' : 'employees'}`
  const query = new URLSearchParams()
  if (mode.value === 'history') {
    if (validDate(filters.from) && validDate(filters.to) && filters.from < filters.to) { query.set('from', filters.from); query.set('to', filters.to) }
  } else if (validDate(filters.asOf)) query.set('as_of', filters.asOf)
  window.history.replaceState({}, '', `${path}${query.size ? `?${query}` : ''}`)
}
async function loadCurrent(operation: Operation) {
  if (mode.value === 'tree') await loadTree(operation)
  else if (mode.value === 'directory') await loadDirectory(operation, directoryQuery())
  else if (mode.value === 'history') { appliedHistory = historyQuery(); await loadHistory(operation, appliedHistory) }
}
async function refresh(updateURL = true) {
  if (mode.value === 'away' || busy.value) return
  if (!validFilters()) { error.value = '查询需要明确有效日期、规范 UUID、页大小 1..100；姓名查询限 256 UTF-8 字节且必须勾选个人资料。历史范围须成对且起日早于止日。'; return }
  const operation = beginOperation('loading'); clearViews(); clearForms(); appliedDirectory = null
  try { await readSession(operation); if (updateURL) updateAddress(); await loadCurrent(operation) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
async function nextPage() {
  const cursor = directory.value?.next_cursor ?? history.value?.next_cursor
  if (busy.value || uncertain.value || !cursor || !session.value) return
  if (mode.value === 'directory' && JSON.stringify(directoryQuery()) !== JSON.stringify(appliedDirectory) ||
      mode.value === 'history' && historyQuery() !== appliedHistory) {
    error.value = '筛选草稿已改变，请刷新后再使用新的游标；不会把新姓名或日期绑定到旧游标。'
    return
  }
  const context = session.value; const query = appliedDirectory && { ...appliedDirectory, cursor }
  const historyParams = new URLSearchParams(appliedHistory); historyParams.set('cursor', cursor)
  const operation = beginOperation('loading'); clearViews(); clearForms()
  try { await readSession(operation, context); if (mode.value === 'directory' && query) await loadDirectory(operation, query); else await loadHistory(operation, historyParams.toString()) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function addRow(kind = 'membership', action = 'add', relation?: Relation) {
  if (busy.value || uncertain.value || preview.value || !canWrite.value || rows.value.length >= 100) return
  rows.value.push({ key: ++rowKey, action, kind, ref: relation?.id ?? '', employee: relation?.employee_id ?? employeeID.value, team: relation?.team_id ?? '', parent: relation?.parent_team_id ?? '', manager: relation?.manager_employee_id ?? '', reportingKind: relation?.kind === 'dotted' ? 'dotted' : 'administrative', from: '', to: '', end: '', title: '', positionCode: '', description: '' })
}
function resetRow(row: Row) { row.ref = ''; row.employee = ''; row.team = ''; row.parent = ''; row.manager = ''; row.title = ''; row.positionCode = ''; row.description = ''; row.from = ''; row.to = ''; row.end = '' }
function serializeRow(row: Row): StructureItem {
  if (!['add', 'end', 'replace', 'lifecycle'].includes(row.action) ||
      !['membership', 'position', 'reporting_line', 'team_parent', 'team_lifecycle', 'employee_lifecycle'].includes(row.kind)) {
    throw new Error('请选择已实现的操作与关系类型。')
  }
  const lifecycleKind = ['team_lifecycle', 'employee_lifecycle'].includes(row.kind)
  if (lifecycleKind !== (row.action === 'lifecycle')) throw new Error('生命周期须选择 lifecycle；任职须选择 add/end/replace。')
  const item: StructureItem = { action: row.action as StructureAction, kind: row.kind as StructureKind }
  if (row.action === 'end' || row.action === 'replace') { if (!uuid.test(row.ref)) throw new Error('结束或更正须原稳定任职 UUID。'); item.ref = row.ref }
  if (row.action === 'end') { if (!validDate(row.end)) throw new Error('结束须明确日期。'); item.end_date = row.end; return item }
  const lifecycle = { valid_from: row.from, valid_to: row.to || null }
  if (!validLifecycle(lifecycle)) throw new Error('每项须明确生效日期；结束日期须晚于生效日期。')
  item.lifecycle = lifecycle
  const requireID = (field: 'employee_id' | 'team_id' | 'parent_team_id' | 'manager_employee_id', value: string) => {
    if (!uuid.test(value)) throw new Error(`${field} 须规范 UUID。`)
    item[field] = value
  }
  if (row.kind === 'team_parent') { requireID('team_id', row.team); requireID('parent_team_id', row.parent) }
  else if (row.kind === 'team_lifecycle') requireID('team_id', row.team)
  else {
    requireID('employee_id', row.employee)
    if (row.kind === 'membership') { requireID('team_id', row.team); item.is_primary = true }
    else if (row.kind === 'position') {
      if (!canPIIWrite.value || !row.title.trim() || bytes(row.title) > 256 || row.positionCode !== '' && (!row.positionCode.trim() || bytes(row.positionCode) > 64) || bytes(row.description) > 4096) throw new Error('职位正文须独立员工 PII 读写授权，标题 1..256、可选代号 1..64、描述最多4096 UTF-8 字节。')
      if (row.team) requireID('team_id', row.team)
      item.is_primary = true; item.position = { title: row.title, ...(row.positionCode ? { position_code: row.positionCode } : {}), ...(row.description ? { description: row.description } : {}) }
    } else if (row.kind === 'reporting_line') {
      requireID('manager_employee_id', row.manager)
      if (!['administrative', 'dotted'].includes(row.reportingKind)) throw new Error('经理类别须 administrative 或 dotted。')
      item.reporting_kind = row.reportingKind as 'administrative' | 'dotted'
    }
  }
  return item
}
function previewTeam() {
  if (busy.value || uncertain.value || !session.value || !canWrite.value) return
  const lifecycle = { valid_from: teamForm.from, valid_to: teamForm.to || null }
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(teamForm.code) || !validLifecycle(lifecycle) || teamForm.labelEnabled && (!canPIIWrite.value || bytes(teamForm.label) > 256)) { error.value = '团队 code 须1..64 ASCII字节，生命周期须明确；加密名称须独立组织 PII 读写授权且最多256 UTF-8字节。'; return }
  const body: CreateTeamCommand = { code: teamForm.code, lifecycle, ...(teamForm.labelEnabled ? { label: teamForm.label } : {}) }
  preview.value = { kind: 'team', path: `/orgs/${orgID.value}/teams`, body: JSON.stringify(body), context: session.value, summary: [`创建稳定团队 ${teamForm.code} · [${teamForm.from}, ${teamForm.to || '∞'})`, teamForm.labelEnabled ? '包含加密团队名称；服务器另核对组织 PII 权限。' : '仅元数据；不创建父团队、任职或权限。'] }
}
function previewStructure() {
  if (busy.value || uncertain.value || !session.value || !canWrite.value || !validRevision(graphRevision.value)) return
  try {
    if (!rows.value.length || rows.value.length > 100) throw new Error('原子命令须1..100项。')
    if (reasonEnabled.value && (!canPIIWrite.value || bytes(reason.value) > 4096)) throw new Error('加密全局理由须独立组织 PII 读写授权且最多4096 UTF-8字节。')
    const changes = rows.value.map(serializeRow)
    const body: StructureCommand = { expected_graph_revision: graphRevision.value, ...(reasonEnabled.value ? { reason: reason.value } : {}), changes }
    preview.value = { kind: 'structure', path: `/orgs/${orgID.value}/structure-changes`, context: session.value,
      body: JSON.stringify(body),
      summary: [`expected_graph_revision ${graphRevision.value} · 全部${changes.length}项同一次提交`, ...rows.value.map((row) => `${row.action} ${row.kind} · ${row.ref || row.employee || row.team} · ${row.action === 'end' ? row.end : `[${row.from}, ${row.to || '∞'})`}`), reasonEnabled.value ? '包含独立组织授权的加密理由。' : '不包含自由文本理由。'] }
    error.value = null
  } catch (cause) { preview.value = null; error.value = cause instanceof Error ? cause.message : '请核对变更项。' }
}
function confirmCommand() {
  if (!preview.value || busy.value || uncertain.value) return
  const command: Command = { path: preview.value.path, body: preview.value.body, context: preview.value.context, kind: preview.value.kind, key: crypto.randomUUID() }
  lastCommand = command; void execute(command)
}
async function execute(command: Command, replay = false) {
  if (busy.value) return
  const operation = beginOperation('submitting'); let sent = false; let committed = false
  uncertain.value = false
  try {
    await readSession(operation, command.context, replay)
    if (!canWrite.value) throw new ApiFailure(403)
    sent = true
    const result = await request<Receipt>(command.path, operation, command)
    if (!result || !uuid.test(result.id) || !validRevision(result.graph_revision) || !validRevision(result.auth_epoch) || result.items !== undefined && (!Array.isArray(result.items) || !result.items.every((item) => uuid.test(item.id) && typeof item.kind === 'string'))) throw new ApiFailure(503)
    committed = true; clearSensitive(); phase.value = 'verifying'
    // A receipt is immutable historical confirmation, never a replacement for current authority.
    const current = await readSession(operation)
    if (!sameIdentity(command.context, current) || BigInt(current.auth_epoch) < BigInt(result.auth_epoch)) throw new ApiFailure(403)
    await loadCurrent(operation)
    confirmed.value = result; notice.value = '服务端已确认原命令；已重新读取实际当前会话及当前获准投影。后续变更可能已推进版本。'
  } catch (cause) {
    if (!isCurrent(operation)) return
    const status = cause instanceof ApiFailure ? cause.status : 503
    if ((sent || replay) && !committed && ![400, 401, 403, 404, 409, 422].includes(status)) {
      clearSensitive(); lastCommand = command; uncertain.value = true
      if (!sent) session.value = null
    }
    else if (!sent) { clearSensitive(); session.value = null }
    showFailure(cause, operation)
  } finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function retryCommand() { if (!busy.value && uncertain.value && lastCommand) void execute(lastCommand, true) }
function navigate(event: MouseEvent, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault(); window.history.pushState({}, '', path); window.dispatchEvent(new PopStateEvent('popstate'))
}
function dated(path: string) { return validDate(filters.asOf) ? `${path}?${new URLSearchParams({ as_of: filters.asOf })}` : path }
function readRoute() {
  cancelOperation(); clearSensitive(); session.value = null; error.value = null
  const url = new URL(window.location.href)
  const org = /^\/orgs\/([^/]+)\/(tree|employees)\/?$/.exec(url.pathname)
  const employee = /^\/employees\/([^/]+)\/organization-history\/?$/.exec(url.pathname)
  filters.asOf = url.searchParams.get('as_of') ?? ''; filters.from = url.searchParams.get('from') ?? ''; filters.to = url.searchParams.get('to') ?? ''
  filters.root = ''; filters.team = ''; filters.employee = ''; filters.labels = false; filters.profile = false
  if (org && uuid.test(org[1]!)) { mode.value = org[2] === 'tree' ? 'tree' : 'directory'; orgID.value = org[1]!; employeeID.value = '' }
  else if (employee && uuid.test(employee[1]!)) { mode.value = 'history'; employeeID.value = employee[1]!; orgID.value = '' }
  else { mode.value = 'away'; return }
  // Canonical safe routes never carry names, opaque cursors, or arbitrary input.
  updateAddress()
  void refresh(false)
}
onMounted(() => { alive = true; window.addEventListener('popstate', readRoute); readRoute() })
onBeforeUnmount(() => { alive = false; window.removeEventListener('popstate', readRoute); cancelOperation(); clearSensitive(); session.value = null })
</script>

<template>
  <main v-if="mode !== 'away'" :aria-busy="busy">
    <h1>{{ heading }}</h1>
    <nav v-if="orgID" aria-label="组织页面导航">
      <a :href="dated(`/orgs/${orgID}/tree`)" @click="navigate($event, dated(`/orgs/${orgID}/tree`))">组织树</a>
      <a :href="dated(`/orgs/${orgID}/employees`)" @click="navigate($event, dated(`/orgs/${orgID}/employees`))">员工目录</a>
      <a v-if="employeeID" :href="dated(`/employees/${employeeID}`)" @click="navigate($event, dated(`/employees/${employeeID}`))">员工资料</a>
      <a v-if="employeeID && history" :href="`/employees/${employeeID}/interviews`" @click="navigate($event, `/employees/${employeeID}/interviews`)">员工面谈（独立授权）</a>
    </nav>
    <p>查询日期只决定业务投影；授权始终按组织当前业务日重新判断。团队层级、任职、经理和身份映射不自动授予权限。</p>
    <form aria-label="组织查询" @submit.prevent="refresh()">
      <fieldset :disabled="busy || uncertain || Boolean(preview)">
        <template v-if="mode !== 'history'"><label for="org-as-of">业务查询日（as_of）</label><input id="org-as-of" v-model="filters.asOf" type="date" required /></template>
        <template v-if="mode === 'tree'">
          <label for="org-root">根团队 ID（可留空）</label><input id="org-root" v-model="filters.root" autocomplete="off" />
          <label for="org-depth">树深度（1..10）</label><input id="org-depth" v-model="filters.depth" type="number" min="1" max="10" />
          <label><input v-model="filters.labels" type="checkbox" />请求获准的加密团队名称</label>
        </template>
        <template v-if="mode === 'directory'">
          <label for="directory-team">筛选团队 ID</label><input id="directory-team" v-model="filters.team" autocomplete="off" />
          <label for="directory-employee">筛选员工 ID</label><input id="directory-employee" v-model="filters.employee" autocomplete="off" />
          <label for="directory-lifecycle">员工生命周期</label><select id="directory-lifecycle" v-model="filters.lifecycle"><option value="active">active</option><option value="inactive">inactive</option><option value="all">all</option></select>
          <label><input id="directory-profile" v-model="filters.profile" type="checkbox" />请求获准的个人资料与职位正文</label>
          <label for="directory-q">姓名查询（仅请求正文内，最多256 UTF-8字节）</label><input id="directory-q" v-model="filters.q" autocomplete="off" :disabled="!filters.profile" />
          <p>姓名不进入 URL、浏览器持久存储或游标；换页重发同一查询，仅扫描获准候选。不显示隐藏总数。</p>
        </template>
        <template v-if="mode === 'history'">
          <label for="history-from">UTC录入起日（含，可留空须成对）</label><input id="history-from" v-model="filters.from" type="date" />
          <label for="history-to">UTC录入止日（不含，可留空）</label><input id="history-to" v-model="filters.to" type="date" />
        </template>
        <label for="org-limit">{{ mode === 'tree' ? '快照节点上限' : '每页条数' }}（1..100）</label><input id="org-limit" v-model="filters.limit" type="number" min="1" max="100" required />
        <button type="submit">刷新当前投影（放弃草稿）</button>
      </fieldset>
    </form>
    <p v-if="error" role="alert">{{ error }}</p>
    <p v-if="busy" role="status">{{ phase === 'submitting' ? '正在提交原子命令……' : phase === 'verifying' ? '正在重新读取当前授权和投影……' : '正在核对会话并读取……' }}</p>
    <p v-if="notice" role="status">{{ notice }}</p>
    <p v-if="tree || directory || history">当前获准 graph_revision {{ graphRevision }} · 当前授权日 {{ (tree || directory || history)?.authorization_date }} · epoch {{ session?.auth_epoch }}</p>
    <section v-if="tree" aria-label="当前获准组织树">
      <h2>{{ tree.as_of }} 组织投影</h2>
      <p v-if="!tree.nodes.length">当前范围无可见团队；不推测隐藏团队。</p>
      <ul aria-label="可见团队层级"><li v-for="{ node, depth } in treeOutline" :key="node.id" :style="{ marginInlineStart: `${depth * 1.5}rem` }"><strong>{{ node.code }}</strong> · {{ node.id }} <span v-if="node.label !== undefined">· {{ node.label }}</span> · [{{ node.lifecycle.valid_from }}, {{ node.lifecycle.valid_to ?? '∞' }})
        <ul><li v-for="edge in tree.edges.filter(edge => edge.child_team_id === node.id)" :key="edge.id">父团队 {{ edge.parent_team_id }} · 原关系 {{ edge.id }} · [{{ edge.valid_from }}, {{ edge.valid_to ?? '∞' }}) <button v-if="canWrite" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow('team_parent', 'end', { ...edge, team_id: edge.child_team_id })">结束父团队关系</button><button v-if="canWrite" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow('team_parent', 'replace', { ...edge, team_id: edge.child_team_id })">更正父团队关系</button></li></ul>
        <ul><li v-for="item in tree.employees.filter(item => item.team_id === node.id)" :key="item.id"><a :href="dated(`/employees/${item.id}`)" @click="navigate($event, dated(`/employees/${item.id}`))">员工 {{ item.id }}</a><span v-if="item.profile"> · {{ item.profile.display_name }}</span></li></ul>
      </li></ul>
      <p>以上只含独立获准节点与边。子团队不继承父团队权限；超出边界须收窄后重新查询，不静默截断。</p>
    </section>
    <section v-if="directory" aria-label="当前获准员工目录">
      <h2>{{ directory.as_of }} 员工目录</h2>
      <p v-if="directory.search_incomplete" role="status">有界候选扫描尚未完成；本页不是完整姓名结果。可继续扫描或收窄筛选，即使本页无命中仍可能有下一页。</p>
      <p v-if="!directory.items.length">本页无获准匹配员工；不代表没有后续匹配或隐藏员工。</p>
      <article v-for="employee in directory.items" :key="employee.id">
        <h3>{{ employee.profile?.display_name ?? employee.id }}</h3>
        <p>员工 {{ employee.id }} · [{{ employee.lifecycle.valid_from }}, {{ employee.lifecycle.valid_to ?? '∞' }})</p>
        <a :href="dated(`/employees/${employee.id}`)" @click="navigate($event, dated(`/employees/${employee.id}`))">资料与任职</a>
        <a :href="`/employees/${employee.id}/organization-history`" @click="navigate($event, `/employees/${employee.id}/organization-history`)">组织历史</a>
        <a :href="`/employees/${employee.id}/interviews`" @click="navigate($event, `/employees/${employee.id}/interviews`)">员工面谈（独立授权）</a>
        <template v-for="group in [{ kind: 'membership', label: '团队任职', items: employee.memberships }, { kind: 'position', label: '职位任职', items: employee.positions }, { kind: 'reporting_line', label: '经理关系', items: employee.reporting_lines }]" :key="group.kind">
          <h4>{{ group.label }}</h4><p v-if="!group.items?.length">查询日无获准{{ group.label }}；不推测当前团队或经理。</p>
          <ul><li v-for="relation in group.items" :key="relation.id">原关系 {{ relation.id }} · {{ relation.team_id ?? relation.manager_employee_id ?? '' }} {{ relation.kind ?? '' }} · [{{ relation.valid_from }}, {{ relation.valid_to ?? '∞' }})<span v-if="relation.position"> · {{ relation.position.title }} {{ relation.position.position_code }} {{ relation.position.description }}</span>
            <button v-if="canWrite" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow(group.kind, 'end', relation)">结束此任职</button><button v-if="canWrite && (group.kind !== 'position' || canPIIWrite)" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow(group.kind, 'replace', relation)">更正此任职</button>
          </li></ul>
        </template>
      </article>
      <button v-if="directory.next_cursor" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="nextPage">继续扫描下一页</button>
    </section>
    <section v-if="history" aria-label="获准组织历史">
      <h2>员工 {{ employeeID }} 的不可变变更历史</h2><p>范围 {{ history.from ?? history.as_of ?? '全部获准历史' }} {{ history.to ?? '' }} · consistency {{ history.consistency }}</p>
      <p v-if="!history.items.length">本页无获准历史记录。</p>
      <article v-for="change in history.items" :key="change.id"><h3>变更 {{ change.id }}</h3><p>操作者 {{ change.actor_subject_id }} · UTC {{ change.recorded_at }} · 图 {{ change.graph_before }} → {{ change.graph_after }}</p><p v-if="change.reason !== undefined">获准加密全局理由：{{ change.reason }}</p>
        <ul><li v-for="(relation, index) in change.items" :key="`${relation.id}:${index}`">{{ relation.action }} {{ relation.kind }} · 原稳定关系 {{ relation.id }} · 员工 {{ relation.employee_id ?? '—' }} · 团队 {{ relation.team_id ?? relation.parent_team_id ?? '—' }} · 经理 {{ relation.manager_employee_id ?? '—' }} {{ relation.reporting_kind ?? '' }} · 原区间 [{{ relation.valid_from ?? '—' }}, {{ relation.valid_to ?? '∞' }}) · 有效结束 {{ relation.effective_to ?? relation.end_date ?? '未结束' }} <span v-if="relation.superseded">· 已永久被更正</span><span v-if="relation.supersedes_id">· 更正自 {{ relation.supersedes_id }}</span>
          <span v-if="relation.position"> · 获准职位正文 {{ relation.position.title }} {{ relation.position.position_code }} {{ relation.position.description }}</span>
          <button v-if="canWrite && ['membership', 'position', 'reporting_line', 'team_parent'].includes(relation.kind) && !relation.superseded" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow(relation.kind, 'end', { ...relation, valid_from: relation.valid_from ?? '', valid_to: relation.valid_to ?? null })">按原 ID 结束任职</button>
          <button v-if="canWrite && ['membership', 'reporting_line', 'team_parent', 'position'].includes(relation.kind) && !relation.superseded && (relation.kind !== 'position' || canPIIWrite)" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="addRow(relation.kind, 'replace', { ...relation, kind: relation.reporting_kind, valid_from: relation.valid_from ?? '', valid_to: relation.valid_to ?? null })">按原 ID 更正任职</button>
        </li></ul>
      </article>
      <button v-if="history.next_cursor" type="button" :disabled="busy || uncertain || Boolean(preview)" @click="nextPage">下一页历史</button>
    </section>
    <template v-if="session && canWrite && graphRevision">
      <form aria-label="创建稳定团队" @submit.prevent="previewTeam">
        <h2>创建团队（不创建任职或权限）</h2><fieldset :disabled="busy || uncertain || Boolean(preview)">
          <label for="team-code">团队 code（非个人名称）</label><input id="team-code" v-model="teamForm.code" required autocomplete="off" />
          <label for="team-from">团队生命周期生效日</label><input id="team-from" v-model="teamForm.from" type="date" required />
          <label for="team-to">团队生命周期结束日（可留空）</label><input id="team-to" v-model="teamForm.to" type="date" />
          <label v-if="canPIIWrite"><input v-model="teamForm.labelEnabled" type="checkbox" />包含加密团队名称（另需组织 PII 读写授权）</label>
          <template v-if="teamForm.labelEnabled && canPIIWrite"><label for="team-label">加密团队名称</label><input id="team-label" v-model="teamForm.label" autocomplete="off" /></template>
          <button type="submit">预览团队创建</button>
        </fieldset>
      </form>
      <form aria-label="原子组织结构变更" @submit.prevent="previewStructure">
        <h2>原子结构变更</h2><p>expected_graph_revision {{ graphRevision }}。普通调动：同一命令结束旧任职 + 新增新任职，边界使用同一明确日期。replace 是事实更正，会永久使原绑定失效，不是普通调动。所有项一起提交或一起拒绝。</p>
        <fieldset :disabled="busy || uncertain || Boolean(preview)">
          <button type="button" :disabled="rows.length >= 100" @click="addRow()">添加变更项</button>
          <section v-for="(row, index) in rows" :key="row.key" :aria-label="`变更项 ${index + 1}`">
            <h3>变更项 {{ index + 1 }}</h3>
            <label :for="`row-${row.key}-kind`">关系或生命周期类型</label><select :id="`row-${row.key}-kind`" v-model="row.kind" @change="resetRow(row); row.action = row.kind.endsWith('_lifecycle') ? 'lifecycle' : 'add'"><option value="membership">团队任职 membership</option><option value="position" :disabled="!canPIIWrite">职位 position（加密正文）</option><option value="reporting_line">经理 reporting_line</option><option value="team_parent">父团队 team_parent</option><option value="team_lifecycle">团队生命周期</option><option value="employee_lifecycle">员工生命周期</option></select>
            <label :for="`row-${row.key}-action`">操作</label><select :id="`row-${row.key}-action`" v-model="row.action" :disabled="row.kind.endsWith('_lifecycle')"><option value="add">新增原任职 add</option><option value="end">结束原任职 end</option><option value="replace">明确更正 replace</option><option v-if="row.kind.endsWith('_lifecycle')" value="lifecycle">生命周期 lifecycle</option></select>
            <template v-if="row.action === 'end' || row.action === 'replace'"><label :for="`row-${row.key}-ref`">原稳定关系 ID</label><input :id="`row-${row.key}-ref`" v-model="row.ref" required autocomplete="off" /></template>
            <template v-if="row.action === 'end'"><label :for="`row-${row.key}-end`">任职有效结束日（半开）</label><input :id="`row-${row.key}-end`" v-model="row.end" type="date" required /></template>
            <template v-else>
              <template v-if="!['team_parent', 'team_lifecycle'].includes(row.kind)"><label :for="`row-${row.key}-employee`">员工 ID</label><input :id="`row-${row.key}-employee`" v-model="row.employee" required autocomplete="off" /></template>
              <template v-if="['membership', 'position', 'team_parent', 'team_lifecycle'].includes(row.kind)"><label :for="`row-${row.key}-team`">{{ row.kind === 'position' ? '团队 ID（职位可留空）' : '团队 ID' }}</label><input :id="`row-${row.key}-team`" v-model="row.team" :required="row.kind !== 'position'" autocomplete="off" /></template>
              <template v-if="row.kind === 'team_parent'"><label :for="`row-${row.key}-parent`">父团队 ID</label><input :id="`row-${row.key}-parent`" v-model="row.parent" required autocomplete="off" /></template>
              <template v-if="row.kind === 'reporting_line'"><label :for="`row-${row.key}-manager`">经理员工 ID（不自动授权）</label><input :id="`row-${row.key}-manager`" v-model="row.manager" required autocomplete="off" /><label :for="`row-${row.key}-reporting`">经理关系类别</label><select :id="`row-${row.key}-reporting`" v-model="row.reportingKind"><option value="administrative">行政 administrative</option><option value="dotted">虚线 dotted</option></select></template>
              <template v-if="row.kind === 'position'"><label :for="`row-${row.key}-title`">加密职位标题</label><input :id="`row-${row.key}-title`" v-model="row.title" required autocomplete="off" /><label :for="`row-${row.key}-position-code`">加密职位代号（可留空）</label><input :id="`row-${row.key}-position-code`" v-model="row.positionCode" autocomplete="off" /><label :for="`row-${row.key}-description`">加密职位描述（可留空）</label><textarea :id="`row-${row.key}-description`" v-model="row.description" autocomplete="off"></textarea></template>
              <label :for="`row-${row.key}-from`">明确生效日</label><input :id="`row-${row.key}-from`" v-model="row.from" type="date" required />
              <label :for="`row-${row.key}-to`">明确结束日（可留空，无穷半开）</label><input :id="`row-${row.key}-to`" v-model="row.to" type="date" />
              <p v-if="row.kind === 'membership' || row.kind === 'position'">primary=true；不启用次要任职政策。</p>
            </template>
            <button type="button" @click="rows.splice(index, 1)">移除此变更项</button>
          </section>
          <label v-if="canPIIWrite"><input v-model="reasonEnabled" type="checkbox" />包含加密全局理由（另需组织 PII 读写授权）</label>
          <template v-if="reasonEnabled && canPIIWrite"><label for="structure-reason">加密全局理由</label><textarea id="structure-reason" v-model="reason" autocomplete="off"></textarea></template>
          <button type="submit" :disabled="!rows.length">预览全部原子变更</button>
        </fieldset>
      </form>
    </template>
    <section v-if="preview" aria-label="未提交组织命令预览"><h2>未提交预览</h2><ul><li v-for="(summary, index) in preview.summary" :key="index">{{ summary }}</li></ul><p>尚未成功，尚未写入。服务器重新检查当前范围、MFA、所有有效区间与版本；不会自动授予关系权限。</p><button type="button" :disabled="busy" @click="confirmCommand">确认提交原命令</button><button type="button" :disabled="busy" @click="preview = null">返回修改草稿</button></section>
    <section v-if="uncertain" aria-label="组织命令结果未知"><p>原命令可能已提交。只能用完全相同的 UUID 和不可变正文重试，不把表单变化或新版本塞入旧键。重新核对同一主体、组织和当前权限；历史 receipt 的 epoch 不是当前授权。</p><button type="button" :disabled="busy" @click="retryCommand">重试原命令</button><button type="button" :disabled="busy" @click="refresh()">放弃重试并刷新实际当前投影</button></section>
    <section v-if="confirmed" aria-label="已确认原命令安全回执"><h2>已确认原命令</h2><p>ID {{ confirmed.id }} · 原 graph_revision {{ confirmed.graph_revision }} · 原 auth_epoch {{ confirmed.auth_epoch }}（不作为当前权限）</p><ul><li v-for="(item, index) in confirmed.items" :key="`${item.id}:${index}`">{{ item.kind }} · 新稳定关系 ID {{ item.id }}</li></ul><p>关系引用仅供明确后续操作，不授予权限。</p></section>
  </main>
</template>

<style scoped>
main { max-width: 72rem; margin: 1.5rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; }
nav, article, section, form { margin-block: 1rem; }
fieldset, section[aria-label^="变更项"] { display: grid; gap: .5rem; padding: 1rem; border: 1px solid #9ba4ae; }
input, select, textarea { font: inherit; padding: .4rem; max-width: 48rem; }
button, a { margin-right: .8rem; } li, p { overflow-wrap: anywhere; }
[role="alert"] { color: #8a1717; } textarea { min-height: 5rem; }
</style>
