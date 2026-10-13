<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

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

type Relation = {
  id: string; employee_id: string; team_id?: string; manager_employee_id?: string; kind?: 'administrative' | 'dotted'
  is_primary?: boolean; valid_from: string; valid_to: string | null
  position?: { title: string; position_code?: string; description?: string }
}
type Employee = {
  id: string
  org_id: string
  profile_revision?: string
  lifecycle: { valid_from: string; valid_to: string | null }
  as_of: string
  authorization_date: string
  profile?: Profile
  graph_revision?: string
  memberships?: Relation[]
  positions?: Relation[]
  reporting_lines?: Relation[]
}

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
  validFrom: '',
  validTo: '',
  editReason: '',
})

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
  form.validTo = ''
  form.editReason = ''
  lastCommand = null
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

async function readSession(operation: Operation) {
  const context = routeKind.value === 'employee' && employeeId.value
    ? `?${new URLSearchParams({ employee_id: employeeId.value })}` : ''
  const next = await request<Session>(`/session${context}`, operation)
  if (!next || !uuidPattern.test(next.subject_id) || !uuidPattern.test(next.org_id) ||
      typeof next.auth_epoch !== 'string' || !revisionPattern.test(next.auth_epoch) ||
      typeof next.csrf_token !== 'string' || next.csrf_token === '' ||
      !Array.isArray(next.capabilities) || !next.capabilities.every((value) => typeof value === 'string')) {
    throw new ApiFailure(503)
  }
  if ((session.value && !sameSession(session.value, next)) ||
      !hasCapabilities(next, ['organization.read', 'pii.read'])) {
    clearSensitive()
  }
  session.value = next
  return next
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
  details.value = next
  for (const relations of [next.memberships, next.positions, next.reporting_lines]) {
    if (relations !== undefined && (!Array.isArray(relations) || !relations.every((relation) =>
      relation && uuidPattern.test(relation.id) && relation.employee_id === id && validDate(relation.valid_from) &&
      (relation.valid_to === null || validDate(relation.valid_to) && relation.valid_to > relation.valid_from) &&
      (!relation.team_id || uuidPattern.test(relation.team_id)) &&
      (!relation.manager_employee_id || uuidPattern.test(relation.manager_employee_id)) &&
      (!relation.position || hasCapabilities(session.value, ['pii.read']) && typeof relation.position.title === 'string' &&
        (relation.position.position_code === undefined || typeof relation.position.position_code === 'string') &&
        (relation.position.description === undefined || typeof relation.position.description === 'string'))))) {
      details.value = null
      throw new ApiFailure(503)
    }
  }
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

function updateAddress() {
  const path = routeKind.value === 'employee' ? `/employees/${employeeId.value}` : '/'
  const query = new URLSearchParams({ as_of: asOf.value })
  window.history.replaceState({}, '', `${path}?${query}`)
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
    } else if (!canCreate.value) {
      throw new ApiFailure(403)
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

async function save() {
  if (busy.value || !session.value || routeKind.value === 'away') return
  const creating = routeKind.value === 'create'
  if ((creating && !canCreate.value) || (!creating && (!editing.value || !canEdit.value))) return
  if (!validDate(asOf.value) || (!form.localName.trim() && !form.englishName.trim()) ||
      (creating && (!validDate(form.validFrom) ||
        (form.validTo !== '' && (!validDate(form.validTo) || form.validTo <= form.validFrom)))) ||
      (!creating && !form.editReason.trim())) {
    errorMessage.value = failureMessages[422]!
    return
  }

  const originalSession = session.value
  const targetId = employeeId.value
  const operation = beginOperation('saving')
  try {
    const current = await readSession(operation)
    if (!sameSession(originalSession, current) ||
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
      ? { profile, lifecycle: { valid_from: form.validFrom, valid_to: form.validTo || null } }
      : { expected_profile_revision: details.value!.profile_revision, profile, edit_reason: form.editReason })
    if (!lastCommand || lastCommand.method !== method || lastCommand.path !== path || lastCommand.body !== body) {
      lastCommand = { method, path, body, key: crypto.randomUUID() }
    }
    const receipt = await request<{ id: string; profile_revision: string }>(path, operation, lastCommand)
    if (!receipt || !uuidPattern.test(receipt.id) ||
        (!creating && receipt.id !== targetId) ||
        typeof receipt.profile_revision !== 'string' || !revisionPattern.test(receipt.profile_revision)) {
      throw new ApiFailure(503)
    }

    if (creating) {
      employeeId.value = receipt.id
      routeKind.value = 'employee'
      updateAddress()
    }
    // The receipt contains metadata, not saved profile data. Never promote the form to details.
    clearSensitive()
    phase.value = 'verifying'
    const verifiedSession = await readSession(operation)
    if (!sameSession(originalSession, verifiedSession)) throw new ApiFailure(403)
    await readEmployee(receipt.id, operation)
    notice.value = '已提交，并重新读取服务端当前获准的资料。'
  } catch (cause) {
    if (!isCurrent(operation)) return
    if (cause instanceof ApiFailure && cause.status === 409) {
      try {
        const current = await readSession(operation)
        if (!sameSession(originalSession, current) ||
            (creating ? !canCreate.value : !canEdit.value)) throw new ApiFailure(403)
        showFailure(cause, operation)
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
  errorMessage.value = null
  const url = new URL(window.location.href)
  asOf.value = url.searchParams.get('as_of') ?? ''
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
  <main :aria-busy="busy">
    <template v-if="routeKind !== 'away'">
      <h1>人员资料</h1>

      <form @submit.prevent="refresh()">
        <label for="profile-as-of">业务查询日（as_of）</label>
        <input id="profile-as-of" v-model="asOf" type="date" required :disabled="busy" />
        <button type="submit" :disabled="busy">刷新（放弃未保存更改）</button>
      </form>

      <p v-if="errorMessage" role="alert">{{ errorMessage }}</p>
      <p v-if="busy" role="status">
        {{ phase === 'saving' ? '正在提交资料……' : phase === 'verifying' ? '正在重新读取服务端资料……' : '正在验证会话并读取资料……' }}
      </p>
      <p v-if="notice" role="status">{{ notice }}</p>

      <section v-if="details" aria-label="当前获准的人员资料">
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
        <section aria-label="查询日任职与经理">
          <h2>{{ details.as_of }} 任职与经理</h2>
          <p v-if="details.graph_revision">图版本 {{ details.graph_revision }}（独立于个人资料版本）</p>
          <template v-for="group in [{ label: '团队任职', items: details.memberships }, { label: '职位任职', items: details.positions }, { label: '经理关系', items: details.reporting_lines }]" :key="group.label">
            <h3>{{ group.label }}</h3>
            <p v-if="!group.items?.length">查询日无获准{{ group.label }}；不推测当前团队或经理。</p>
            <ul><li v-for="relation in group.items" :key="relation.id">
              原稳定关系 {{ relation.id }} · {{ relation.team_id ?? relation.manager_employee_id ?? '未指定团队' }} {{ relation.kind ?? '' }}
              · [{{ relation.valid_from }}, {{ relation.valid_to ?? '∞' }})
              <template v-if="relation.position"> · {{ relation.position.title }} <span v-if="relation.position.position_code">（{{ relation.position.position_code }}）</span> <span v-if="relation.position.description">{{ relation.position.description }}</span></template>
            </li></ul>
          </template>
        </section>
        <button v-if="canEdit && !editing" type="button" :disabled="busy" @click="beginEdit">更正资料</button>
      </section>

      <form v-if="session && ((routeKind === 'create' && canCreate) || editing)" @submit.prevent="save">
        <fieldset :disabled="busy">
          <legend>{{ routeKind === 'create' ? '创建人员' : '完整更正个人资料' }}</legend>
          <label for="profile-local-name">本地姓名（local_name）</label>
          <input id="profile-local-name" v-model="form.localName" name="local_name" autocomplete="off" />

          <label for="profile-english-name">英文姓名（english_name）</label>
          <input id="profile-english-name" v-model="form.englishName" name="english_name" autocomplete="off" />

          <label for="profile-email">业务邮箱（email，可清空）</label>
          <input id="profile-email" v-model="form.email" name="email" type="email" autocomplete="off" />

          <label for="profile-phone">业务电话（phone，可清空）</label>
          <input id="profile-phone" v-model="form.phone" name="phone" type="tel" autocomplete="off" />

          <label for="profile-summary">资料摘要（profile_summary，可清空）</label>
          <textarea id="profile-summary" v-model="form.summary" name="profile_summary" autocomplete="off"></textarea>

          <template v-if="routeKind === 'create'">
            <label for="profile-valid-from">生命周期生效日（valid_from）</label>
            <input id="profile-valid-from" v-model="form.validFrom" name="valid_from" type="date" required />
            <label for="profile-valid-to">生命周期结束日（valid_to，可留空）</label>
            <input id="profile-valid-to" v-model="form.validTo" name="valid_to" type="date" />
          </template>
          <template v-else>
            <label for="profile-edit-reason">更正理由（edit_reason）</label>
            <textarea id="profile-edit-reason" v-model="form.editReason" name="edit_reason" required autocomplete="off"></textarea>
            <p>更正将完整替换资料；清空的可选字段不会继续保留。不更改任职或组织结构。</p>
          </template>

          <button type="submit" :disabled="!validDate(asOf)">
            {{ routeKind === 'create' ? '创建并重新读取' : '保存更正并重新读取' }}
          </button>
        </fieldset>
      </form>
    </template>
  </main>
</template>

<style scoped>
main {
  max-width: 48rem;
  margin: 2rem auto;
  padding: 0 1rem;
}

form, section {
  margin-block: 1.5rem;
}

fieldset {
  display: grid;
  gap: 0.5rem;
}

input, textarea, button {
  font: inherit;
}

textarea {
  min-height: 5rem;
}

dt {
  margin-top: 0.75rem;
  font-weight: bold;
}

dd {
  margin-left: 0;
  overflow-wrap: anywhere;
}

.profile-summary {
  white-space: pre-wrap;
}

[role='alert'] {
  border-left: 0.25rem solid #a12a2a;
  padding-left: 0.75rem;
}
</style>
