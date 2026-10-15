<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'

const props = defineProps<{ queryDate?: string }>()
const emit = defineEmits<{ 'session-expired': [] }>()

type Session = {
  subject_id: string
  org_id: string
  auth_epoch: string
  capabilities: string[]
  csrf_token: string
}

type Profile = {
  local_name?: string
  english_name?: string
  work_contact?: { email?: string; phone?: string }
  profile_summary?: string
}

type Fact = { id: string; valid_from: string; valid_to: string | null }
type Identifier = Fact & { kind: string; staff_code?: string }
type Employment = Fact & { legal_entity_id: string; location_code: string; kind: string }
type Education = Fact & { level: string; institution?: string; field?: string; award_date?: string }
type Assignment = Fact & { department_id: string; job_family_id?: string; career_level_id?: string; position?: { title: string; position_code?: string; description?: string } }
type Reporting = Fact & { employee_id: string; manager_employee_id: string; kind: 'administrative' | 'dotted' }
type Employee = {
  id: string
  org_id: string
  profile_revision?: string
  lifecycle: { valid_from: string; valid_to: string | null }
  as_of: string
  authorization_date: string
  profile?: Profile
  graph_revision?: string
  identifiers: Identifier[]
  employment: Employment[]
  education: Education[]
  job_assignments: Assignment[]
  reporting_lines: Reporting[]
  direct_manager?: Reporting
  hod?: Reporting
}
type CatalogState = { catalog_revision: string; graph_revision: string }
type ManagerDirectory = { items: Employee[]; graph_revision: string }

type Operation = { generation: number; controller: AbortController }
type Command = { method: 'POST' | 'PATCH'; path: string; body: string; key: string }
type RouteKind = 'create' | 'employee' | 'away'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revisionPattern = /^[1-9][0-9]*$/
const failureMessages: Record<number, string> = {
  401: '会话已失效，敏感资料和表单已清空。',
  403: '当前无权访问，敏感资料和表单已清空。',
  404: '资料不可访问，敏感资料和表单已清空。',
  409: '资料版本冲突，未覆盖服务端资料。请先刷新，再以新版本手动更正。',
  422: '提交的资料未被接受，请检查输入后再提交。',
  503: '服务暂时不可用，尚未确认保存后的资料，请手动刷新或重试。',
}

class ApiFailure extends Error {
  constructor(readonly status: number) {
    super('API request failed')
    this.name = 'ApiFailure'
  }
}

const session = shallowRef<Session | null>(null)
const details = shallowRef<Employee | null>(null)
const routeKind = ref<RouteKind>('away')
const employeeId = ref<string | null>(null)
const queuedViewDate = ref('')
const asOf = ref('')
const editing = ref(false)
const phase = ref<'idle' | 'loading' | 'saving' | 'verifying'>('idle')
const errorMessage = ref<string | null>(null)
const notice = ref<string | null>(null)
const form = reactive({
  localName: '',
  englishName: '',
  email: '',
  phone: '',
  summary: '',
  staffCode: '',
  managerEmployeeId: '',
  managerSearch: '',
  validFrom: '',
  validTo: '',
  editReason: '',
})
const managerOptions = shallowRef<Employee[]>([])
const catalogRevision = ref('')
const graphRevision = ref('')
const commandUncertain = ref(false)

let generation = 0
let controller: AbortController | null = null
let alive = false
let lastCommand: Command | null = null

const busy = computed(() => phase.value !== 'idle')
const canCreate = computed(() => hasCapabilities(session.value, [
  'organization.read', 'organization.write', 'pii.read', 'pii.write',
]))
const canEdit = computed(() => Boolean(details.value?.profile) && hasCapabilities(session.value, [
  'organization.read', 'pii.read', 'pii.write',
]))

function hasCapabilities(value: Session | null, capabilities: string[]) {
  return value !== null && capabilities.every((capability) => value.capabilities.includes(capability))
}

function sameSession(left: Session, right: Session) {
  return left.subject_id === right.subject_id &&
    left.org_id === right.org_id &&
    left.auth_epoch === right.auth_epoch
}
function sameIdentity(left: Session, right: Session) {
  return left.subject_id === right.subject_id && left.org_id === right.org_id
}

function validDate(value: string) {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}

function clearSensitive() {
  details.value = null
  editing.value = false
  form.localName = ''
  form.englishName = ''
  form.email = ''
  form.phone = ''
  form.summary = ''
  form.validFrom = ''
  form.staffCode = ''
  form.managerEmployeeId = ''
  form.managerSearch = ''
  managerOptions.value = []
  catalogRevision.value = ''
  graphRevision.value = ''
  form.validTo = ''
  form.editReason = ''
  lastCommand = null
  commandUncertain.value = false
  notice.value = null
}

function cancelOperation() {
  generation += 1
  controller?.abort()
  controller = null
  phase.value = 'idle'
}

function beginOperation(nextPhase: 'loading' | 'saving') {
  cancelOperation()
  controller = new AbortController()
  phase.value = nextPhase
  errorMessage.value = null
  notice.value = null
  return { generation, controller }
}

function isCurrent(operation: Operation) {
  return alive && generation === operation.generation && !operation.controller.signal.aborted
}

async function request<T>(path: string, operation: Operation, command?: Command): Promise<T> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'organization_management' }
  if (command) {
    headers['Content-Type'] = 'application/json'
    headers['X-CSRF-Token'] = session.value!.csrf_token
    headers['Idempotency-Key'] = command.key
  }
  const response = await fetch(`/api/v1${path}`, {
    method: command?.method ?? 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    signal: operation.controller.signal,
    headers,
    body: command?.body,
  })
  if (!isCurrent(operation)) throw new DOMException('Request cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  const result: T = await response.json()
  if (!isCurrent(operation)) throw new DOMException('Request cancelled', 'AbortError')
  return result
}
async function postQuery<T>(path: string, operation: Operation, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    signal: operation.controller.signal,
    headers: {
      'Content-Type': 'application/json',
      'X-Access-Purpose': 'organization_management',
      'X-CSRF-Token': session.value!.csrf_token,
    },
    body: JSON.stringify(body),
  })
  if (!isCurrent(operation)) throw new DOMException('Request cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  const result = await response.json() as T
  if (!isCurrent(operation)) throw new DOMException('Request cancelled', 'AbortError')
  return result
}

async function readSession(operation: Operation, allowEpochAdvance = false) {
  const context = routeKind.value === 'employee' && employeeId.value
    ? `?${new URLSearchParams({ employee_id: employeeId.value })}` : ''
  const next = await request<Session>(`/session${context}`, operation)
  if (!next || !uuidPattern.test(next.subject_id) || !uuidPattern.test(next.org_id) ||
      typeof next.auth_epoch !== 'string' || !revisionPattern.test(next.auth_epoch) ||
      typeof next.csrf_token !== 'string' || next.csrf_token === '' ||
      !Array.isArray(next.capabilities) || !next.capabilities.every((value) => typeof value === 'string')) {
    throw new ApiFailure(503)
  }
  if ((session.value && (!sameIdentity(session.value, next) || !allowEpochAdvance && session.value.auth_epoch !== next.auth_epoch)) ||
      !hasCapabilities(next, ['organization.read', 'pii.read'])) {
    clearSensitive()
  }
  session.value = next
  return next
}

async function readCreationContext(operation: Operation, search = '') {
  const org = session.value!.org_id
  const queryBody: Record<string, unknown> = { as_of: asOf.value, lifecycle: 'active', limit: 100, include_profile: true }
  if (search) queryBody.q = search
  const [catalogs, directory] = await Promise.all([
    request<CatalogState>(`/orgs/${org}/workforce-catalogs?${new URLSearchParams({ as_of: asOf.value, limit: '100' })}`, operation),
    postQuery<ManagerDirectory>(`/orgs/${org}/employees/query`, operation, queryBody),
  ])
  if (!catalogs || !revisionPattern.test(catalogs.catalog_revision) || !revisionPattern.test(catalogs.graph_revision) ||
      !directory || !revisionPattern.test(directory.graph_revision) || catalogs.graph_revision !== directory.graph_revision ||
      !Array.isArray(directory.items) || directory.items.some(item => !uuidPattern.test(item.id) || !item.profile)) {
    throw new ApiFailure(503)
  }
  catalogRevision.value = catalogs.catalog_revision
  graphRevision.value = catalogs.graph_revision
  if (form.managerEmployeeId && !directory.items.some(item => item.id === form.managerEmployeeId)) form.managerEmployeeId = ''
  managerOptions.value = directory.items
}

function managerLabel(manager: Employee) {
  const name = manager.profile?.local_name || manager.profile?.english_name || manager.id
  const code = manager.identifiers?.find(identifier => identifier.kind === 'staff_code')?.staff_code
  return code ? `${name} · ${code}` : name
}

async function readEmployee(id: string, operation: Operation) {
  const query = new URLSearchParams({ as_of: asOf.value, include_profile: 'true' })
  const next = await request<Employee>(`/employees/${id}?${query}`, operation)
  if (!next || next.id !== id || next.org_id !== session.value?.org_id ||
      !next.lifecycle || !validDate(next.lifecycle.valid_from) ||
      (next.lifecycle.valid_to !== null && !validDate(next.lifecycle.valid_to)) ||
      next.as_of !== asOf.value || !validDate(next.authorization_date) ||
      (next.graph_revision !== undefined && (typeof next.graph_revision !== 'string' || !revisionPattern.test(next.graph_revision)))) {
    throw new ApiFailure(503)
  }
  if (next.profile !== undefined) {
    if (typeof next.profile_revision !== 'string' || !revisionPattern.test(next.profile_revision)) throw new ApiFailure(503)
    const profile = next.profile
    if (!hasCapabilities(session.value, ['pii.read']) || !profile ||
        (profile.local_name !== undefined && typeof profile.local_name !== 'string') ||
        (profile.english_name !== undefined && typeof profile.english_name !== 'string') ||
        (!profile.local_name && !profile.english_name) ||
        (profile.profile_summary !== undefined && typeof profile.profile_summary !== 'string') ||
        (profile.work_contact !== undefined && (!profile.work_contact ||
          (profile.work_contact.email !== undefined && typeof profile.work_contact.email !== 'string') ||
          (profile.work_contact.phone !== undefined && typeof profile.work_contact.phone !== 'string')))) {
      throw new ApiFailure(503)
    }
  } else {
    clearSensitive()
    delete next.profile_revision
  }
  const factValid = (fact: Fact) => uuidPattern.test(fact.id) && validDate(fact.valid_from) && (fact.valid_to === null || validDate(fact.valid_to) && fact.valid_to > fact.valid_from)
  if (![next.identifiers, next.employment, next.education, next.job_assignments, next.reporting_lines].every(Array.isArray) ||
      !next.identifiers.every((fact) => factValid(fact) && typeof fact.kind === 'string' && (fact.staff_code === undefined || hasCapabilities(session.value, ['pii.read']) && typeof fact.staff_code === 'string')) ||
      !next.employment.every((fact) => factValid(fact) && uuidPattern.test(fact.legal_entity_id) && typeof fact.location_code === 'string' && typeof fact.kind === 'string') ||
      !next.education.every((fact) => factValid(fact) && hasCapabilities(session.value, ['pii.read']) && typeof fact.level === 'string') ||
      !next.job_assignments.every((fact) => factValid(fact) && uuidPattern.test(fact.department_id) && (!fact.position || hasCapabilities(session.value, ['pii.read']) && typeof fact.position.title === 'string')) ||
      !next.reporting_lines.every((fact) => factValid(fact) && fact.employee_id === id && uuidPattern.test(fact.manager_employee_id)) ||
      Boolean(next.direct_manager) !== Boolean(next.hod) || next.direct_manager && (!next.hod || next.direct_manager.id !== next.hod.id)) {
    details.value = null
    throw new ApiFailure(503)
  }
  details.value = next
}

function showFailure(cause: unknown, operation: Operation) {
  if (!isCurrent(operation)) return
  const status = cause instanceof ApiFailure ? cause.status : 503
  if (status === 401 || status === 403 || status === 404) {
    cancelOperation()
    clearSensitive()
    session.value = null
    if (status === 401) emit('session-expired')
  }
  errorMessage.value = failureMessages[status] ?? failureMessages[503]!
  notice.value = null
}
async function searchManagers() {
  if (busy.value || commandUncertain.value || routeKind.value !== 'create' || !session.value) return
  const original = session.value
  const operation = beginOperation('loading')
  try {
    const current = await readSession(operation)
    if (!sameSession(original, current) || !canCreate.value) throw new ApiFailure(403)
    await readCreationContext(operation, form.managerSearch.trim())
  } catch (cause) {
    showFailure(cause, operation)
  } finally {
    if (isCurrent(operation)) {
      phase.value = 'idle'
      controller = null
    }
  }
}

function updateAddress() {
  const path = routeKind.value === 'employee' ? `/employees/${employeeId.value}` : '/'
  if (validDate(props.queryDate ?? '')) window.history.replaceState({}, '', path)
  else window.history.replaceState({}, '', `${path}?${new URLSearchParams({ as_of: asOf.value })}`)
}

async function refresh(updateUrl = true) {
  if (routeKind.value === 'away') return
  const operation = beginOperation('loading')
  clearSensitive()
  try {
    const current = await readSession(operation)
    if (!hasCapabilities(current, ['organization.read'])) throw new ApiFailure(403)
    if (!validDate(asOf.value)) {
      errorMessage.value = '请明确填写业务查询日（as_of）；系统不会推测业务时区或查询日期。'
      return
    }
    if (updateUrl) updateAddress()
    if (routeKind.value === 'employee' && employeeId.value) {
      await readEmployee(employeeId.value, operation)
    } else {
      if (!canCreate.value) throw new ApiFailure(403)
      await readCreationContext(operation)
    }
  } catch (cause) {
    showFailure(cause, operation)
  } finally {
    if (isCurrent(operation)) {
      phase.value = 'idle'
      controller = null
    }
  }
}

function beginEdit() {
  if (busy.value || !canEdit.value || !details.value?.profile) return
  const profile = details.value.profile
  form.localName = profile.local_name ?? ''
  form.englishName = profile.english_name ?? ''
  form.email = profile.work_contact?.email ?? ''
  form.phone = profile.work_contact?.phone ?? ''
  form.summary = profile.profile_summary ?? ''
  form.editReason = ''
  editing.value = true
  lastCommand = null
  notice.value = null
  errorMessage.value = null
}

function adoptQueuedViewDate() {
  if (!queuedViewDate.value) return
  asOf.value = queuedViewDate.value
  queuedViewDate.value = ''
  void refresh(false)
}

async function save() {
  if (busy.value || !session.value || routeKind.value === 'away') return
  const creating = routeKind.value === 'create'
  if ((creating && !canCreate.value) || (!creating && (!editing.value || !canEdit.value))) return
  if (!validDate(asOf.value) || (!form.localName.trim() && !form.englishName.trim()) ||
      (creating && (!form.staffCode || form.staffCode.trim() !== form.staffCode ||
        !catalogRevision.value || !graphRevision.value ||
        form.managerEmployeeId !== '' && !uuidPattern.test(form.managerEmployeeId) ||
        !validDate(form.validFrom) ||
        (form.validTo !== '' && (!validDate(form.validTo) || form.validTo <= form.validFrom)))) ||
      (!creating && !form.editReason.trim())) {
    errorMessage.value = failureMessages[422]!
    return
  }

  const originalSession = session.value
  const targetId = employeeId.value
  const operation = beginOperation('saving')
  let commandFinal = false
  const confirmingUncertainCreate = creating && lastCommand !== null
  try {
    const current = await readSession(operation, confirmingUncertainCreate)
    if ((confirmingUncertainCreate ? !sameIdentity(originalSession, current) : !sameSession(originalSession, current)) ||
        (creating ? !canCreate.value : !canEdit.value)) throw new ApiFailure(403)

    const profile: Profile = {}
    if (form.localName !== '') profile.local_name = form.localName
    if (form.englishName !== '') profile.english_name = form.englishName
    if (form.email !== '' || form.phone !== '') {
      profile.work_contact = {}
      if (form.email !== '') profile.work_contact.email = form.email
      if (form.phone !== '') profile.work_contact.phone = form.phone
    }
    if (form.summary !== '') profile.profile_summary = form.summary
    const method = creating ? 'POST' : 'PATCH'
    const path = creating ? `/orgs/${current.org_id}/employees` : `/employees/${targetId}/profile`
    const body = JSON.stringify(creating
      ? {
          profile,
          lifecycle: { valid_from: form.validFrom, valid_to: form.validTo || null },
          staff_code: form.staffCode,
          ...(form.managerEmployeeId ? { manager_employee_id: form.managerEmployeeId } : {}),
          expected_catalog_revision: catalogRevision.value,
          expected_graph_revision: graphRevision.value,
        }
      : { expected_profile_revision: details.value!.profile_revision, profile, edit_reason: form.editReason })
    if (!lastCommand || lastCommand.method !== method || lastCommand.path !== path || lastCommand.body !== body) {
      lastCommand = { method, path, body, key: crypto.randomUUID() }
    }
    const receipt = await request<{ id: string; profile_revision: string; workforce_revision?: string; graph_revision?: string }>(path, operation, lastCommand)
    if (!receipt || !uuidPattern.test(receipt.id) ||
        (!creating && receipt.id !== targetId) ||
        typeof receipt.profile_revision !== 'string' || !revisionPattern.test(receipt.profile_revision) ||
        creating && (typeof receipt.workforce_revision !== 'string' || !revisionPattern.test(receipt.workforce_revision) ||
          typeof receipt.graph_revision !== 'string' || !revisionPattern.test(receipt.graph_revision))) {
      throw new ApiFailure(503)
    }
    commandFinal = true

    if (creating) {
      employeeId.value = receipt.id
      routeKind.value = 'employee'
      updateAddress()
    }
    // The receipt contains metadata, not saved profile data. Never promote the form to details.
    clearSensitive()
    phase.value = 'verifying'
    const verifiedSession = await readSession(operation, creating)
    if (creating ? !sameIdentity(originalSession, verifiedSession) : !sameSession(originalSession, verifiedSession)) throw new ApiFailure(403)
    await readEmployee(receipt.id, operation)
    notice.value = '已提交，并重新读取服务端当前获准的资料。'
  } catch (cause) {
    if (!isCurrent(operation)) return
    const failedBeforeReceipt = !commandFinal
    const status = cause instanceof ApiFailure ? cause.status : 503
    if ([400, 401, 403, 404, 409, 422].includes(status)) commandFinal = true
    const preserveUncertain = creating && lastCommand !== null && !commandFinal &&
      (!(cause instanceof ApiFailure) || status >= 500)
    if (!preserveUncertain && cause instanceof ApiFailure) commandUncertain.value = false
    if (preserveUncertain) {
      commandUncertain.value = true
      errorMessage.value = '提交结果尚未确认。表单已锁定，请再次点击“确认原提交”；系统将使用相同命令核对，不会创建第二条记录。'
      notice.value = null
    } else if (creating && failedBeforeReceipt && status === 404) {
      form.managerEmployeeId = ''
      errorMessage.value = '所选直属主管不存在或已无权引用；未创建任何人员，请重新选择。'
      notice.value = null
    } else if (cause instanceof ApiFailure && cause.status === 409) {
      try {
        const current = await readSession(operation)
        if (!sameSession(originalSession, current) ||
            (creating ? !canCreate.value : !canEdit.value)) throw new ApiFailure(403)
        if (creating) {
          errorMessage.value = 'Staff Code 已被占用，或组织资料已更新；未创建任何人员，请刷新后重试。'
          notice.value = null
        } else {
          showFailure(cause, operation)
        }
      } catch (authorizationFailure) {
        showFailure(authorizationFailure, operation)
      }
    } else {
      showFailure(cause, operation)
    }
  } finally {
    if (isCurrent(operation)) {
      phase.value = 'idle'
      controller = null
      if (commandFinal) adoptQueuedViewDate()
    }
  }
}
function navigate(event: MouseEvent, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault()
  window.history.pushState({}, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
}


function readRoute() {
  cancelOperation()
  clearSensitive()
  queuedViewDate.value = ''
  errorMessage.value = null
  const url = new URL(window.location.href)
  asOf.value = validDate(props.queryDate ?? '') ? props.queryDate! : url.searchParams.get('as_of') ?? ''
  const employeeRoute = /^\/employees\/([^/]+)(?:\/profile)?\/?$/.exec(url.pathname)
  if (employeeRoute && uuidPattern.test(employeeRoute[1]!)) {
    routeKind.value = 'employee'
    employeeId.value = employeeRoute[1]!
  } else if (url.pathname === '/') {
    routeKind.value = 'create'
    employeeId.value = null
  } else {
    routeKind.value = 'away'
    employeeId.value = null
    session.value = null
    return
  }
  void refresh(false)
}

watch(() => props.queryDate, (next) => {
  if (!alive || !validDate(next ?? '') || routeKind.value === 'away') return
  if (next === asOf.value) {
    queuedViewDate.value = ''
    return
  }
  if (phase.value === 'saving' || phase.value === 'verifying') {
    queuedViewDate.value = next!
    return
  }
  if (phase.value === 'loading') cancelOperation()
  queuedViewDate.value = ''
  asOf.value = next!
  void refresh(false)
})

onMounted(() => {
  alive = true
  window.addEventListener('popstate', readRoute)
  readRoute()
})

onBeforeUnmount(() => {
  alive = false
  window.removeEventListener('popstate', readRoute)
  cancelOperation()
  clearSensitive()
  session.value = null
})
</script>

<template>
  <main class="profile-page" :aria-busy="busy">
    <template v-if="routeKind !== 'away'">
      <header class="profile-page-heading">
        <p class="eyebrow">人员主数据</p>
        <h1>人员资料</h1>
        <p>建立并维护员工身份资料；创建时同时登记Staff Code与初始直属主管，后续任职、组织关系和学历在组织模块维护。</p>
      </header>

      <form v-if="!validDate(props.queryDate ?? '')" class="profile-query" aria-label="人员资料查询条件" @submit.prevent="refresh()">
        <label for="profile-as-of">
          <span>查看日期</span>
          <input id="profile-as-of" v-model="asOf" type="date" required :disabled="busy" />
        </label>
        <button type="submit" :disabled="busy">刷新资料</button>
        <p>刷新将放弃当前尚未保存的更改。</p>
      </form>

      <p v-if="errorMessage" role="alert">{{ errorMessage }}</p>
      <p v-if="busy" role="status">
        {{ phase === 'saving' ? '正在提交资料……' : phase === 'verifying' ? '正在重新读取服务端资料……' : '正在验证会话并读取资料……' }}
      </p>
      <p v-if="queuedViewDate" role="status">查看日期已改变；将在当前人员资料命令结果明确后加载，新旧日期不会混合显示。</p>
      <p v-if="notice" role="status">{{ notice }}</p>

      <section v-if="details && !queuedViewDate" aria-label="当前获准的人员资料">
        <dl>
          <dt>员工 ID</dt>
          <dd>{{ details.id }}</dd>
          <template v-if="details.profile_revision !== undefined">
            <dt>资料版本（profile_revision）</dt>
            <dd>{{ details.profile_revision }}</dd>
          </template>
          <dt>业务查询日（as_of）</dt>
          <dd>{{ details.as_of }}</dd>
          <dt>当前授权判断日</dt>
          <dd>{{ details.authorization_date }}</dd>
          <dt>生命周期生效日</dt>
          <dd>{{ details.lifecycle.valid_from }}</dd>
          <dt>生命周期结束日</dt>
          <dd>{{ details.lifecycle.valid_to ?? '未结束' }}</dd>
        </dl>
        <dl v-if="details.profile">
          <dt>本地姓名</dt>
          <dd>{{ details.profile.local_name || '未填写' }}</dd>
          <dt>英文姓名</dt>
          <dd>{{ details.profile.english_name || '未填写' }}</dd>
          <template v-if="details.profile.work_contact?.email">
            <dt>业务邮箱</dt>
            <dd>{{ details.profile.work_contact.email }}</dd>
          </template>
          <template v-if="details.profile.work_contact?.phone">
            <dt>业务电话</dt>
            <dd>{{ details.profile.work_contact.phone }}</dd>
          </template>
          <template v-if="details.profile.profile_summary">
            <dt>资料摘要</dt>
            <dd class="profile-summary">{{ details.profile.profile_summary }}</dd>
          </template>
        </dl>
        <p v-else>当前只获准查看元数据，未提供个人资料。</p>
        <nav aria-label="员工组织导航">
          <a :href="`/employees/${details.id}/organization-history`" @click="navigate($event, `/employees/${details.id}/organization-history`)">组织历史</a>
          <a :href="`/employees/${details.id}/interviews`" @click="navigate($event, `/employees/${details.id}/interviews`)">员工面谈（独立授权）</a>
          <a :href="`/employees/${details.id}/followup`" @click="navigate($event, `/employees/${details.id}/followup`)">面谈跟进周期与状态（独立授权）</a>
          <a :href="`/employees/${details.id}/compensation`" @click="navigate($event, `/employees/${details.id}/compensation`)">员工薪酬（独立财务授权）</a>
          <a :href="`/employees/${details.id}/bonuses`" @click="navigate($event, `/employees/${details.id}/bonuses`)">员工奖金（独立财务授权）</a>
          <a :href="`/orgs/${details.org_id}/tree?as_of=${details.as_of}`" @click="navigate($event, `/orgs/${details.org_id}/tree?as_of=${details.as_of}`)">组织树</a>
          <a :href="`/orgs/${details.org_id}/employees?as_of=${details.as_of}`" @click="navigate($event, `/orgs/${details.org_id}/employees?as_of=${details.as_of}`)">员工目录</a>
        </nav>
        <section aria-label="查询日员工主数据">
          <h2>{{ details.as_of }} 员工主数据</h2>
          <p v-if="details.graph_revision">图版本 {{ details.graph_revision }}（独立于个人资料版本）</p>
          <h3>工号</h3><p v-if="!details.identifiers.length">无获准工号资料。</p><ul><li v-for="fact in details.identifiers" :key="fact.id">{{ fact.kind }} · {{ fact.staff_code || '正文未授权' }} · [{{ fact.valid_from }}, {{ fact.valid_to ?? '∞' }})</li></ul>
          <h3>雇佣</h3><p v-if="!details.employment.length">查询日无雇佣事实。</p><ul><li v-for="fact in details.employment" :key="fact.id">事实 {{ fact.id }} · {{ fact.kind }} · {{ fact.location_code }} · 法分公司 {{ fact.legal_entity_id }} · [{{ fact.valid_from }}, {{ fact.valid_to ?? '∞' }})</li></ul>
          <h3>学历</h3><p v-if="!details.education.length">无获准学历资料。</p><ul><li v-for="fact in details.education" :key="fact.id">{{ fact.level }}<span v-if="fact.institution"> · {{ fact.institution }}</span><span v-if="fact.field"> · {{ fact.field }}</span><span v-if="fact.award_date"> · {{ fact.award_date }}</span></li></ul>
          <h3>单一任职</h3><p v-if="!details.job_assignments.length">查询日无任职事实。</p><ul><li v-for="fact in details.job_assignments" :key="fact.id">Department {{ fact.department_id }}<span v-if="fact.job_family_id"> · Job Family {{ fact.job_family_id }}</span><span v-if="fact.career_level_id"> · Career Level {{ fact.career_level_id }}</span><span v-if="fact.position"> · {{ fact.position.title }}</span></li></ul>
          <h3>直属主管 / HOD</h3><p v-if="details.direct_manager">同一administrative事实 {{ details.direct_manager.id }} · {{ details.direct_manager.manager_employee_id }}</p><p v-else>查询日无直属主管。</p>
          <h3>Dotted reporting</h3><ul><li v-for="fact in details.reporting_lines.filter((fact) => fact.kind === 'dotted')" :key="fact.id">{{ fact.manager_employee_id }}</li></ul>
        </section>
        <button v-if="canEdit && !editing" type="button" :disabled="busy" @click="beginEdit">更正资料</button>
      </section>

      <form v-if="session && ((routeKind === 'create' && canCreate) || editing)" class="profile-editor" @submit.prevent="save">
        <fieldset :disabled="busy">
          <legend>{{ routeKind === 'create' ? '创建人员' : '完整更正个人资料' }}</legend>
          <p class="profile-form-lead">{{ routeKind === 'create' ? '一次提交基本资料、全集团 Staff Code 与直属主管；任一项失败都不会留下半成品员工。' : '本次保存将完整替换个人资料；未填写的可选字段不会继续保留。' }}</p>

          <div class="profile-form-section">
            <div class="profile-section-heading">
              <h2>基本资料</h2>
              <p>姓名用于人员识别；至少填写一种适合当前业务的姓名。</p>
            </div>
            <div class="profile-form-grid">
              <label class="profile-field" for="profile-local-name">
                <span>本地姓名 <small>local_name</small></span>
                <input id="profile-local-name" v-model="form.localName" name="local_name" :readonly="commandUncertain" autocomplete="off" />
              </label>
              <label class="profile-field" for="profile-english-name">
                <span>英文姓名 <small>english_name</small></span>
                <input id="profile-english-name" v-model="form.englishName" name="english_name" :readonly="commandUncertain" autocomplete="off" />
              </label>
            </div>
          </div>

          <div v-if="routeKind === 'create'" class="profile-form-section">
            <div class="profile-section-heading">
              <h2>员工识别与汇报关系</h2>
              <p>Staff Code 在全集团保持唯一；直属主管与 HOD 使用同一汇报关系。</p>
            </div>
            <div class="profile-form-grid">
              <label class="profile-field" for="profile-staff-code">
                <span>Staff Code <small>工号 · 必填</small></span>
                <input id="profile-staff-code" v-model="form.staffCode" name="staff_code" maxlength="64" required :readonly="commandUncertain" autocomplete="off" />
              </label>
              <div class="profile-manager-search">
                <label class="profile-field" for="profile-manager-search">
                  <span>查找主管 <small>姓名或 Staff Code</small></span>
                  <input id="profile-manager-search" v-model="form.managerSearch" :readonly="commandUncertain" autocomplete="off" />
                </label>
                <button type="button" class="secondary" :disabled="commandUncertain" @click="searchManagers">查找</button>
              </div>
              <label class="profile-field profile-field-wide" for="profile-manager">
                <span>直属主管 / HOD <small>可留空</small></span>
                <select id="profile-manager" v-model="form.managerEmployeeId" name="manager_employee_id" :disabled="commandUncertain">
                  <option value="">无直属主管</option>
                  <option v-for="manager in managerOptions" :key="manager.id" :value="manager.id">{{ managerLabel(manager) }}</option>
                </select>
              </label>
            </div>
          </div>

          <div class="profile-form-section">
            <div class="profile-section-heading">
              <h2>工作联系方式</h2>
              <p>仅记录业务联系方式；两个字段均可留空。</p>
            </div>
            <div class="profile-form-grid">
              <label class="profile-field" for="profile-email">
                <span>业务邮箱 <small>email · 可清空</small></span>
                <input id="profile-email" v-model="form.email" name="email" type="email" :readonly="commandUncertain" autocomplete="off" />
              </label>
              <label class="profile-field" for="profile-phone">
                <span>业务电话 <small>phone · 可清空</small></span>
                <input id="profile-phone" v-model="form.phone" name="phone" type="tel" :readonly="commandUncertain" autocomplete="off" />
              </label>
              <label class="profile-field profile-field-wide" for="profile-summary">
                <span>资料摘要 <small>profile_summary · 可清空</small></span>
                <textarea id="profile-summary" v-model="form.summary" name="profile_summary" :readonly="commandUncertain" autocomplete="off"></textarea>
              </label>
            </div>
          </div>

          <div v-if="routeKind === 'create'" class="profile-form-section">
            <div class="profile-section-heading">
              <h2>生命周期</h2>
              <p>明确人员记录的业务有效期；结束日可在创建后再维护。</p>
            </div>
            <div class="profile-form-grid">
              <label class="profile-field" for="profile-valid-from">
                <span>生效日 <small>valid_from</small></span>
                <input id="profile-valid-from" v-model="form.validFrom" name="valid_from" type="date" required :readonly="commandUncertain" />
              </label>
              <label class="profile-field" for="profile-valid-to">
                <span>结束日 <small>valid_to · 可留空</small></span>
                <input id="profile-valid-to" v-model="form.validTo" name="valid_to" type="date" :readonly="commandUncertain" />
              </label>
            </div>
          </div>
          <div v-else class="profile-form-section">
            <div class="profile-section-heading">
              <h2>更正依据</h2>
              <p>说明本次完整更正的业务原因；不会修改任职或组织结构。</p>
            </div>
            <label class="profile-field" for="profile-edit-reason">
              <span>更正理由 <small>edit_reason</small></span>
              <textarea id="profile-edit-reason" v-model="form.editReason" name="edit_reason" required autocomplete="off"></textarea>
            </label>
          </div>

          <div class="profile-form-actions">
            <p>{{ commandUncertain ? '保留原命令与幂等键，确认前不可修改表单。' : routeKind === 'create' ? '提交后将重新读取新建人员资料。' : '保存后将重新读取已更正资料。' }}</p>
            <button type="submit" :disabled="!validDate(asOf)">
              {{ commandUncertain ? '确认原提交' : routeKind === 'create' ? '创建人员' : '保存完整更正' }}
            </button>
          </div>
        </fieldset>
      </form>
    </template>
  </main>
</template>

<style>
#app .profile-page-heading {
  max-width: 52rem;
}

#app .profile-query {
  grid-template-columns: minmax(16rem, 28rem) auto;
  justify-content: start;
}

#app .profile-query label,
#app .profile-field {
  display: grid;
  gap: .5rem;
}

#app .profile-query label > span,
#app .profile-field > span {
  color: var(--ink-800);
  font-size: .82rem;
  font-weight: 720;
}

#app .profile-query small,
#app .profile-field small {
  margin-left: .35rem;
  color: var(--ink-500);
  font-family: var(--font-mono);
  font-size: .72rem;
  font-weight: 560;
}

#app .profile-query > p {
  grid-column: 1 / -1;
  margin: -.2rem 0 0;
  color: var(--ink-600);
  font-size: .78rem;
}

#app .profile-editor {
  padding: 0;
  overflow: hidden;
}

#app .profile-editor fieldset {
  display: block;
  padding: 0;
  border: 0;
}

#app .profile-editor legend {
  width: 100%;
  padding: 1.25rem 1.5rem .35rem;
  color: var(--ink-950);
  font-family: var(--font-display);
  font-size: 1.18rem;
  font-weight: 780;
}

#app .profile-form-lead {
  margin: 0;
  padding: 0 1.5rem 1.25rem;
  border-bottom: 1px solid var(--line-soft);
  color: var(--ink-600);
  font-size: .86rem;
}

#app .profile-form-section {
  display: grid;
  grid-template-columns: minmax(11rem, .34fr) minmax(0, 1fr);
  gap: 1.5rem;
  margin: 0;
  padding: 1.45rem 1.5rem;
  border: 0;
  border-bottom: 1px solid var(--line-soft);
  background: var(--surface);
}

#app .profile-section-heading h2 {
  margin: 0 0 .35rem;
  font-size: .95rem;
}

#app .profile-section-heading p {
  margin: 0;
  color: var(--ink-600);
  font-size: .78rem;
  line-height: 1.55;
}

#app .profile-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1rem 1.25rem;
  min-width: 0;
}

#app .profile-field {
  align-content: start;
  min-width: 0;
}

#app .profile-field-wide {
  grid-column: 1 / -1;
}

#app .profile-manager-search {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: .65rem;
}

#app .profile-manager-search button {
  min-height: 2.7rem;
}

#app .profile-field textarea {
  min-height: 7rem;
  resize: vertical;
}

#app .profile-form-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 1rem;
  padding: 1.15rem 1.5rem;
  background: var(--surface-muted);
}

#app .profile-form-actions p {
  margin: 0 auto 0 0;
  color: var(--ink-600);
  font-size: .78rem;
}

#app .profile-page dt {
  margin-top: .75rem;
  font-weight: 700;
}

#app .profile-page dd {
  margin-left: 0;
  overflow-wrap: anywhere;
}

#app .profile-summary {
  white-space: pre-wrap;
}

@media (max-width: 760px) {
  #app .profile-query {
    grid-template-columns: 1fr;
  }

  #app .profile-query button {
    width: 100%;
  }

  #app .profile-form-section {
    grid-template-columns: 1fr;
    gap: 1rem;
    padding: 1.2rem 1rem;
  }

  #app .profile-editor legend {
    padding-inline: 1rem;
  }

  #app .profile-form-lead {
    padding-inline: 1rem;
  }

  #app .profile-form-grid {
    grid-template-columns: 1fr;
  }

  #app .profile-field-wide {
    grid-column: auto;
  }

  #app .profile-form-actions {
    align-items: stretch;
    flex-direction: column;
    padding: 1rem;
  }

  #app .profile-form-actions button {
    width: 100%;
  }
}
</style>
