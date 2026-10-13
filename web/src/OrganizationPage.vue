<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()
type Session = { subject_id: string; org_id: string; auth_epoch: string; csrf_token: string; capabilities: string[] }
type Profile = { local_name?: string; english_name?: string }
type Lifecycle = { valid_from: string; valid_to: string | null }
type Identifier = Lifecycle & { id: string; kind: string; staff_code?: string }
type Employment = Lifecycle & { id: string; legal_entity_id: string; location_code: string; kind: string }
type Education = Lifecycle & { id: string; level: string; institution?: string; field?: string; award_date?: string }
type Assignment = Lifecycle & { id: string; department_id: string; job_family_id?: string; career_level_id?: string; position?: { title: string; position_code?: string; description?: string } }
type Reporting = Lifecycle & { id: string; employee_id: string; manager_employee_id: string; kind: string }
type Employee = { id: string; org_id: string; profile_revision?: string; lifecycle: Lifecycle; as_of: string; authorization_date: string; graph_revision: string; profile?: Profile; identifiers: Identifier[]; employment: Employment[]; education: Education[]; job_assignments: Assignment[]; reporting_lines: Reporting[]; direct_manager?: Reporting; hod?: Reporting }
type Tree = { org_id: string; as_of: string; authorization_date: string; graph_revision: string; auth_epoch: string; nodes: (Lifecycle & { id: string; code: string; kind: string; label?: string })[]; edges: (Lifecycle & { id: string; child_unit_id: string; parent_unit_id: string })[]; employees: { id: string; department_id: string; profile?: Profile }[] }
type Directory = { items: Employee[]; next_cursor: string | null; as_of: string; consistency: 'current'; authorization_date: string; graph_revision: string; auth_epoch: string; search_incomplete: boolean }
type History = { items: { id: string; actor_subject_id: string; recorded_at: string; graph_before: string; graph_after: string; reason?: string; items: { action: string; kind: string; id?: string; employee_id?: string; valid_from?: string; valid_to?: string | null; effective_to?: string | null; supersedes_id?: string }[] }[]; next_cursor: string | null; consistency: 'current'; authorization_date: string; graph_revision: string; auth_epoch: string }
type Catalogs = { as_of: string; catalog_revision: string; graph_revision: string; legal_entities: unknown[]; locations: string[]; org_units: unknown[]; org_unit_parents: unknown[]; education_levels: unknown[]; job_families: unknown[]; career_levels: unknown[] }
type Operation = { generation: number; controller: AbortController }
type Preview = { endpoint: string; body: Record<string, unknown>; summary: string }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revision = /^[1-9][0-9]*$/
const session = shallowRef<Session | null>(null)
const tree = shallowRef<Tree | null>(null)
const directory = shallowRef<Directory | null>(null)
const history = shallowRef<History | null>(null)
const catalogs = shallowRef<Catalogs | null>(null)
const mode = ref<'tree' | 'directory' | 'history' | 'away'>('away')
const orgID = ref('')
const employeeID = ref('')
const phase = ref<'idle' | 'loading' | 'submitting'>('idle')
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const preview = shallowRef<Preview | null>(null)
const filters = reactive({ asOf: '', rootDepartment: '', depth: '3', limit: '50', labels: false, department: '', employee: '', lifecycle: 'active', q: '', profile: false, from: '', to: '' })
const catalogChanges = ref('[]')
const workforceChanges = ref('[]')
const employeeRevisions = ref('{}')
let generation = 0
let controller: AbortController | null = null
let alive = false

const busy = computed(() => phase.value !== 'idle')
const canWrite = computed(() => Boolean(session.value?.capabilities.includes('organization.write')))
const heading = computed(() => mode.value === 'tree' ? '组织树与主数据维护' : mode.value === 'directory' ? '员工目录' : '员工组织历史')
const treeOutline = computed(() => {
  if (!tree.value) return []
  const children = new Map<string, Tree['nodes']>()
  const childIDs = new Set<string>()
  for (const edge of tree.value.edges) {
    const child = tree.value.nodes.find((node) => node.id === edge.child_unit_id)
    if (!child) continue
    children.set(edge.parent_unit_id, [...(children.get(edge.parent_unit_id) ?? []), child]); childIDs.add(child.id)
  }
  const result: { node: Tree['nodes'][number]; depth: number }[] = []
  const visit = (node: Tree['nodes'][number], depth: number) => { result.push({ node, depth }); for (const child of children.get(node.id) ?? []) visit(child, depth + 1) }
  for (const node of tree.value.nodes) if (!childIDs.has(node.id)) visit(node, 0)
  return result
})

class ApiFailure extends Error { constructor(readonly status: number) { super('request failed') } }
function validDate(value: string) { if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false; return new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value }
function cancel() { generation += 1; controller?.abort(); controller = null; phase.value = 'idle' }
function begin(next: 'loading' | 'submitting'): Operation { cancel(); controller = new AbortController(); phase.value = next; error.value = null; notice.value = null; return { generation, controller } }
function current(op: Operation) { return alive && op.generation === generation && !op.controller.signal.aborted }
async function request<T>(path: string, op: Operation, body?: Record<string, unknown>): Promise<T> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'organization_management' }
  if (body) { headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = session.value!.csrf_token; headers['Idempotency-Key'] = crypto.randomUUID() }
  const response = await fetch(`/api/v1${path}`, { method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers, body: body ? JSON.stringify(body) : undefined, signal: op.controller.signal })
  if (!current(op)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  return response.status === 204 ? undefined as T : await response.json() as T
}
async function readSession(op: Operation) {
  const suffix = mode.value === 'history' && uuid.test(employeeID.value) ? `?employee_id=${employeeID.value}` : mode.value === 'directory' && uuid.test(filters.employee) ? `?employee_id=${filters.employee}` : ''
  const next = await request<Session>(`/session${suffix}`, op)
  if (!next || !uuid.test(next.subject_id) || !uuid.test(next.org_id) || !revision.test(next.auth_epoch) || !next.csrf_token || !Array.isArray(next.capabilities)) throw new ApiFailure(503)
  session.value = next
  return next
}
function fail(cause: unknown) {
  if (cause instanceof DOMException && cause.name === 'AbortError') return
  if (cause instanceof ApiFailure && [401, 403, 404].includes(cause.status)) { session.value = null; tree.value = null; directory.value = null; history.value = null; emit('session-expired') }
  error.value = cause instanceof ApiFailure && cause.status === 422 ? '输入不符合契约。' : '服务或网络不可用，未确认任何变更。'
}
function route() {
  cancel(); preview.value = null; tree.value = null; directory.value = null; history.value = null; catalogs.value = null
  const parts = location.pathname.split('/').filter(Boolean)
  const query = new URLSearchParams(location.search)
  filters.asOf = query.get('as_of') ?? new Date().toISOString().slice(0, 10)
  if (parts.length === 3 && parts[0] === 'orgs' && parts[2] === 'tree' && uuid.test(parts[1]!)) { mode.value = 'tree'; orgID.value = parts[1]! }
  else if (parts.length === 3 && parts[0] === 'orgs' && parts[2] === 'employees' && uuid.test(parts[1]!)) { mode.value = 'directory'; orgID.value = parts[1]! }
  else if (parts.length === 3 && parts[0] === 'employees' && parts[2] === 'organization-history' && uuid.test(parts[1]!)) { mode.value = 'history'; employeeID.value = parts[1]! }
  else { mode.value = 'away'; return }
  void refresh()
}
async function refresh(cursor = '') {
  if (mode.value === 'away' || !validDate(filters.asOf)) { error.value = '请填写有效业务查询日。'; return }
  const op = begin('loading')
  try {
    const currentSession = await readSession(op)
    if (mode.value !== 'history' && currentSession.org_id !== orgID.value) throw new ApiFailure(403)
    if (mode.value === 'tree') {
      const params = new URLSearchParams({ as_of: filters.asOf, depth: filters.depth, limit: filters.limit, include_labels: String(filters.labels) })
      if (filters.rootDepartment) params.set('root_department_id', filters.rootDepartment)
      const catalogParams = new URLSearchParams({ as_of: filters.asOf, limit: '100' })
      ;[catalogs.value, tree.value] = await Promise.all([request<Catalogs>(`/orgs/${orgID.value}/workforce-catalogs?${catalogParams}`, op), request<Tree>(`/orgs/${orgID.value}/tree?${params}`, op)])
    } else if (mode.value === 'directory') {
      const body: Record<string, unknown> = { as_of: filters.asOf, lifecycle: filters.lifecycle, limit: Number(filters.limit), include_profile: filters.profile }
      if (filters.department) body.department_id = filters.department
      if (filters.employee) body.employee_id = filters.employee
      if (filters.q) body.q = filters.q
      if (cursor) body.cursor = cursor
      directory.value = await request<Directory>(`/orgs/${orgID.value}/employees/query`, op, body)
      catalogs.value = await request<Catalogs>(`/orgs/${orgID.value}/workforce-catalogs?as_of=${filters.asOf}&limit=100`, op)
    } else {
      const params = new URLSearchParams({ from: filters.from || filters.asOf, to: filters.to || new Date(new Date(`${filters.asOf}T00:00:00Z`).getTime() + 86400000).toISOString().slice(0, 10), limit: filters.limit })
      if (cursor) params.set('cursor', cursor)
      history.value = await request<History>(`/employees/${employeeID.value}/organization-history?${params}`, op)
    }
  } catch (cause) { fail(cause) } finally { if (current(op)) { phase.value = 'idle'; controller = null } }
}
function parseArray(text: string) { const value: unknown = JSON.parse(text); if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw new ApiFailure(422); return value }
function prepare(kind: 'catalog' | 'workforce') {
  try {
    if (!catalogs.value || !tree.value && mode.value === 'tree') throw new ApiFailure(503)
    const changes = parseArray(kind === 'catalog' ? catalogChanges.value : workforceChanges.value)
    const graph = tree.value?.graph_revision ?? directory.value?.graph_revision ?? catalogs.value.graph_revision
    const body: Record<string, unknown> = { expected_catalog_revision: catalogs.value.catalog_revision, expected_graph_revision: graph, changes }
    if (kind === 'workforce') { const revisions: unknown = JSON.parse(employeeRevisions.value); if (!revisions || typeof revisions !== 'object' || Array.isArray(revisions)) throw new ApiFailure(422); body.expected_employee_revisions = revisions }
    preview.value = { endpoint: kind === 'catalog' ? `/orgs/${orgID.value}/workforce-catalog-changes` : `/orgs/${orgID.value}/workforce-changes`, body, summary: `${changes.length} 项原子变更；任一失败整单回滚。` }
  } catch (cause) { fail(cause) }
}
async function submit() {
  if (!preview.value || !session.value) return
  const op = begin('submitting')
  try {
    const before = session.value
    const now = await readSession(op)
    if (before.subject_id !== now.subject_id || before.org_id !== now.org_id || before.auth_epoch !== now.auth_epoch || !now.capabilities.includes('organization.write')) throw new ApiFailure(403)
    await request(preview.value.endpoint, op, preview.value.body)
    preview.value = null; notice.value = '服务端已提交；正在重新读取权威投影。'; phase.value = 'idle'; controller = null
    await refresh()
  } catch (cause) { fail(cause) } finally { if (current(op)) { phase.value = 'idle'; controller = null } }
}
function navigate(event: MouseEvent, href: string) { if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return; event.preventDefault(); window.history.pushState({}, '', href); route() }
onMounted(() => { alive = true; window.addEventListener('popstate', route); route() })
onBeforeUnmount(() => { alive = false; window.removeEventListener('popstate', route); cancel(); session.value = null; tree.value = null; directory.value = null; history.value = null })
</script>

<template>
  <main v-if="mode !== 'away'">
    <h1>{{ heading }}</h1>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <form aria-label="组织查询条件" @submit.prevent="refresh()">
      <label>业务查询日（as_of）<input v-model="filters.asOf" type="date" required /></label>
      <label>每页/节点上限<input v-model="filters.limit" type="number" min="1" max="100" /></label>
      <template v-if="mode === 'tree'"><label>根Department ID<input v-model="filters.rootDepartment" /></label><label>层级深度<input v-model="filters.depth" type="number" min="1" max="3" /></label><label><input v-model="filters.labels" type="checkbox" />显示名称和员工姓名（需要PII权限）</label></template>
      <template v-if="mode === 'directory'"><label>Department ID<input v-model="filters.department" /></label><label>员工ID<input v-model="filters.employee" /></label><label>状态<select v-model="filters.lifecycle"><option>active</option><option>inactive</option><option>all</option></select></label><label>姓名或Staff Code<input v-model="filters.q" /></label><label><input v-model="filters.profile" type="checkbox" />请求PII资料</label></template>
      <template v-if="mode === 'history'"><label>开始日<input v-model="filters.from" type="date" /></label><label>结束日（不含）<input v-model="filters.to" type="date" /></label></template>
      <button type="submit" :disabled="busy">刷新权威投影</button>
    </form>

    <section v-if="tree" aria-label="组织树">
      <p>图版本 {{ tree.graph_revision }} · 授权版本 {{ tree.auth_epoch }}</p>
      <ul><li v-for="entry in treeOutline" :key="entry.node.id" :style="{ marginInlineStart: `${entry.depth * 1.5}rem` }"><strong>{{ entry.node.kind }} · {{ entry.node.code }}</strong><span v-if="entry.node.label"> · {{ entry.node.label }}</span> · {{ entry.node.id }}</li></ul>
      <h2>Department员工</h2><ul><li v-for="item in tree.employees" :key="item.id"><a :href="`/employees/${item.id}?as_of=${tree.as_of}`" @click="navigate($event, `/employees/${item.id}?as_of=${tree.as_of}`)">{{ item.profile?.local_name || item.profile?.english_name || item.id }}</a> · Department {{ item.department_id }}</li></ul>
    </section>

    <section v-if="directory" aria-label="员工目录">
      <p>图版本 {{ directory.graph_revision }} · <span v-if="directory.search_incomplete">本页仅是受权候选扫描结果，搜索尚未完成。</span></p>
      <article v-for="employee in directory.items" :key="employee.id"><h2>{{ employee.profile?.local_name || employee.profile?.english_name || employee.id }}</h2><p>员工 {{ employee.id }}</p><p v-for="identifier in employee.identifiers" :key="identifier.id">{{ identifier.kind }}：{{ identifier.staff_code }}</p><p v-for="spell in employee.employment" :key="spell.id">{{ spell.kind }} · {{ spell.location_code }} · 法分公司 {{ spell.legal_entity_id }}</p><p v-for="assignment in employee.job_assignments" :key="assignment.id">Department {{ assignment.department_id }}<span v-if="assignment.position"> · {{ assignment.position.title }}</span></p><p v-if="employee.direct_manager">直属主管/HOD：{{ employee.direct_manager.manager_employee_id }}</p><a :href="`/employees/${employee.id}?as_of=${directory.as_of}`" @click="navigate($event, `/employees/${employee.id}?as_of=${directory.as_of}`)">查看完整员工资料</a></article>
      <button v-if="directory.next_cursor" :disabled="busy" @click="refresh(directory.next_cursor)">继续下一页</button>
    </section>

    <section v-if="history" aria-label="员工组织历史"><article v-for="change in history.items" :key="change.id"><h2>{{ change.recorded_at }} · {{ change.id }}</h2><p>图版本 {{ change.graph_before }} → {{ change.graph_after }}</p><p v-if="change.reason">原因：{{ change.reason }}</p><ul><li v-for="(item, index) in change.items" :key="`${change.id}-${index}`">{{ item.action }} {{ item.kind }} {{ item.id }} · [{{ item.valid_from || '—' }}, {{ item.valid_to || item.effective_to || '∞' }})</li></ul></article><button v-if="history.next_cursor" :disabled="busy" @click="refresh(history.next_cursor)">继续下一页</button></section>

    <section v-if="canWrite && mode !== 'history'" aria-label="原子主数据维护">
      <h2>目录与组织层级变更</h2><p>输入1..100项changes数组。系统自动带入当前catalog/graph revision；先预览，再提交。</p><textarea v-model="catalogChanges" rows="8" spellcheck="false"></textarea><button :disabled="busy" @click="prepare('catalog')">预览目录变更</button>
      <h2>员工主数据变更</h2><label>expected_employee_revisions对象<textarea v-model="employeeRevisions" rows="3" spellcheck="false"></textarea></label><label>changes数组<textarea v-model="workforceChanges" rows="10" spellcheck="false"></textarea></label><button :disabled="busy" @click="prepare('workforce')">预览员工变更</button>
      <aside v-if="preview" aria-label="提交预览"><p>{{ preview.summary }}</p><pre>{{ JSON.stringify(preview.body, null, 2) }}</pre><button :disabled="busy" @click="submit">确认原子提交</button><button :disabled="busy" @click="preview = null">取消</button></aside>
    </section>
  </main>
</template>
