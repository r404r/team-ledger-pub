<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'
import { grantCapabilities as capabilities, grantObjectKinds, validGrantPair, validGrantObject, validSourceApproval, type ObjectReference } from './grantPairs'

const emit = defineEmits<{ 'session-expired': []; 'grant-result': [kind: 'issue' | 'revoke'] }>()

type Scope = { kind: 'org' | 'team' | 'employee'; id: string }
type RelationReference = { kind: 'reporting_line' | 'team_membership'; id: string }
type Authority = {
  id: string; capability: string; category: string; scope: Scope; purpose: string
  valid_from: string; expires_at: string; mfa_required: boolean
  approved_by: string; approved_at: string; policy_version: string
  delegable_scopes: Scope[]
}
type Session = {
  subject_id: string; org_id: string; auth_epoch: string; capabilities: string[]; csrf_token: string
  grant_authorities: Authority[]; mfa_recent: boolean; mfa_valid_until: string; sensitivity_valid_until?: string
}
type Grant = {
  id: string; org_id: string; subject_id: string; capability: string; category: string; scope: Scope; purpose: string
  valid_from: string; expires_at: string; mfa_required: boolean; relation_bound: boolean
  relation_ref: RelationReference | null; object_ref: ObjectReference | null; approved_source_refs?: ObjectReference[] | null; revision: string; status: 'current' | 'future' | 'expired' | 'revoked'
  authority_id: string | null; policy_version: string | null; approved_by: string | null; approved_at: string | null
  issued_by: string | null; issued_at: string | null; revoked_by: string | null; revoked_at: string | null; revoke_reason: string | null
}
type GrantList = { items: Grant[]; next_cursor: string | null; as_of: string; consistency: 'current'; auth_epoch: string; authorities: Authority[] }
type Receipt = { id: string; revision: string; status: Grant['status']; auth_epoch: string }
type Operation = { generation: number; controller: AbortController }
type Command = { path: string; body: string; key: string; context: Session; kind: 'issue' | 'revoke'; authorityID?: string }
type Preview = { body: string; context: Session; authority: Authority }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revision = /^[1-9][0-9]*$/
const session = shallowRef<Session | null>(null)
const currentList = shallowRef<GrantList | null>(null)
const details = shallowRef<Grant | null>(null)
const preview = shallowRef<Preview | null>(null)
const editing = ref(false)
const revokeConfirm = ref(false)
const revokeReason = ref('access_no_longer_required')
const uncertain = ref(false)
const phase = ref<'idle' | 'loading' | 'submitting' | 'verifying'>('idle')
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const filters = reactive({ subject: '', scopeKind: '', scopeID: '', category: '', purpose: '', state: '', grantID: '', capability: '', objectKind: '', objectID: '', limit: '20' })
const form = reactive({ authorityID: '', subject: '', scopeKind: 'employee', scopeID: '', validFrom: '', expiresAt: '', mfa: true,
  relationKind: '', relationID: '', objectKind: '', objectID: '', sourceIDs: '' })
let appliedFilters = ''
let generation = 0
let controller: AbortController | null = null
let alive = false
let lastCommand: Command | null = null
let expiryTimer: ReturnType<typeof setInterval> | null = null

const busy = computed(() => phase.value !== 'idle')
const manageable = computed(() => Boolean(session.value?.capabilities.includes('access_grant.manage') &&
  session.value.mfa_recent && session.value.grant_authorities.length && currentList.value?.authorities.length))
const selectedAuthority = computed(() => currentList.value?.authorities.find((item) => item.id === form.authorityID))
const canUseOrg = computed(() => Boolean(selectedAuthority.value?.delegable_scopes.some((scope) => scope.kind === 'org' && scope.id === session.value?.org_id)))

class ApiFailure extends Error {
  constructor(readonly status: number) { super('Grant request failed') }
}
function validRevision(value: unknown): value is string {
  return typeof value === 'string' && revision.test(value) && value.length <= 19 && BigInt(value) <= 9223372036854775807n
}
function timestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/.exec(value)
  if (!match) return null
  const parsed = new Date(`${match[1]}Z`)
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 19) !== match[1]) return null
  // Lexically compare normalized microseconds, never round them through Date's milliseconds.
  return `${match[1]}.${(match[2] ?? '').padEnd(6, '0')}Z`
}
function validScope(value: Scope): boolean {
  return Boolean(value && ['org', 'team', 'employee'].includes(value.kind) && typeof value.id === 'string' && uuid.test(value.id))
}
function scopeCovers(allowed: Scope, kind: string, id: string): boolean {
  return allowed.kind === 'org' ? (kind === 'employee' || kind === 'team' || kind === 'org' && id === allowed.id)
    : allowed.kind === kind && id === allowed.id
}
function validRelation(bound: boolean, ref: RelationReference | null, scope: Scope): boolean {
  if (!bound) return ref === null
  return Boolean(ref && uuid.test(ref.id) &&
    (ref.kind === 'reporting_line' && scope.kind === 'employee' || ref.kind === 'team_membership' && scope.kind === 'team'))
}
function validAuthority(value: Authority): boolean {
  return Boolean(value && uuid.test(value.id) && capabilities.includes(value.capability) &&
    validGrantPair(value.capability, value.category, value.purpose) && validScope(value.scope) &&
    timestamp(value.valid_from) && timestamp(value.expires_at) &&
    timestamp(value.valid_from)! < timestamp(value.expires_at)! && typeof value.mfa_required === 'boolean' &&
    uuid.test(value.approved_by) && timestamp(value.approved_at) && typeof value.policy_version === 'string' && value.policy_version.length > 0 &&
    Array.isArray(value.delegable_scopes) && value.delegable_scopes.length > 0 && value.delegable_scopes.length <= 1000 &&
    value.delegable_scopes.every((scope) => validScope(scope) &&
      (scopeCovers(value.scope, scope.kind, scope.id) || value.scope.kind === 'team' && scope.kind === 'employee')))
}
function sameContext(left: Session, right: Session): boolean {
  return left.subject_id === right.subject_id && left.org_id === right.org_id && left.auth_epoch === right.auth_epoch &&
    JSON.stringify(left.grant_authorities) === JSON.stringify(right.grant_authorities) &&
    right.capabilities.includes('access_grant.manage') && right.mfa_recent
}
function clearData() {
  currentList.value = null
  details.value = null
  editing.value = false
  preview.value = null
  revokeConfirm.value = false
  revokeReason.value = 'access_no_longer_required'
  form.authorityID = ''; form.subject = ''; form.scopeKind = 'employee'; form.scopeID = ''
  form.validFrom = ''; form.expiresAt = ''; form.mfa = true; form.relationKind = ''; form.relationID = ''
  form.objectKind = ''; form.objectID = ''; form.sourceIDs = ''
  lastCommand = null; uncertain.value = false; notice.value = null
}
function cancelOperation() {
  generation += 1; controller?.abort(); controller = null; phase.value = 'idle'
}
function beginOperation(next: 'loading' | 'submitting') {
  cancelOperation(); controller = new AbortController(); phase.value = next; error.value = null; notice.value = null
  return { generation, controller }
}
function isCurrent(operation: Operation): boolean {
  return alive && generation === operation.generation && !operation.controller.signal.aborted
}
async function request<T>(path: string, operation: Operation, command?: Command): Promise<T> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'security_administration' }
  if (command) {
    headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = session.value!.csrf_token
    headers['Idempotency-Key'] = command.key
  }
  const response = await fetch(`/api/v1${path}`, {
    method: command ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
    signal: operation.controller.signal, headers, body: command?.body,
  })
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  const result: T = await response.json()
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  return result
}
async function readSession(operation: Operation, expected?: Session, replay = false) {
  const next = await request<Session>('/session', operation)
  if (!next || !uuid.test(next.subject_id) || !uuid.test(next.org_id) || !validRevision(next.auth_epoch) ||
      typeof next.csrf_token !== 'string' || !next.csrf_token || !Array.isArray(next.capabilities) ||
      !next.capabilities.every((cap) => typeof cap === 'string') || !Array.isArray(next.grant_authorities) ||
      !next.grant_authorities.every(validAuthority) || typeof next.mfa_recent !== 'boolean' || !timestamp(next.mfa_valid_until)) {
    clearData(); session.value = null
    throw new ApiFailure(503)
  }
  if (next.sensitivity_valid_until !== undefined && !timestamp(next.sensitivity_valid_until)) throw new ApiFailure(503)
  if (next.sensitivity_valid_until && timestamp(next.sensitivity_valid_until)! <= timestamp(new Date().toISOString())!) throw new ApiFailure(403)
  const wrongContext = expected && (replay
    ? expected.subject_id !== next.subject_id || expected.org_id !== next.org_id
    : !sameContext(expected, next))
  if (wrongContext || !next.capabilities.includes('access_grant.manage') ||
      !next.mfa_recent || next.grant_authorities.length === 0) throw new ApiFailure(403)
  if (session.value && !sameContext(session.value, next)) clearData()
  session.value = next
  return next
}
function validGrant(value: Grant): boolean {
  if (!value || !uuid.test(value.id) || value.org_id !== session.value?.org_id || !uuid.test(value.subject_id) ||
      !validGrantPair(value.capability, value.category, value.purpose) ||
      !validScope(value.scope) || !timestamp(value.valid_from) || !timestamp(value.expires_at) ||
      timestamp(value.valid_from)! >= timestamp(value.expires_at)! || typeof value.mfa_required !== 'boolean' ||
      typeof value.relation_bound !== 'boolean' || !validRelation(value.relation_bound, value.relation_ref, value.scope) ||
      !validGrantObject(value.object_ref, value.capability, value.category, value.purpose) ||
      !validSourceApproval(value.approved_source_refs ?? [], value.capability, value.category) || !validRevision(value.revision) ||
      !['current', 'future', 'expired', 'revoked'].includes(value.status)) return false
  for (const field of ['authority_id', 'approved_by', 'issued_by', 'revoked_by'] as const) {
    if (value[field] !== null && (typeof value[field] !== 'string' || !uuid.test(value[field]!))) return false
  }
  for (const field of ['approved_at', 'issued_at', 'revoked_at'] as const) {
    if (value[field] !== null && !timestamp(value[field])) return false
  }
  return (value.policy_version === null || typeof value.policy_version === 'string') &&
    (value.revoke_reason === null || ['access_no_longer_required', 'policy_change', 'incorrect_grant'].includes(value.revoke_reason))
}
async function readList(operation: Operation, query = appliedFilters, detailID?: string) {
  const next = await request<GrantList>(`/access-grants${query ? `?${query}` : ''}`, operation)
  if (!next || !validRevision(next.auth_epoch)) throw new ApiFailure(503)
  if (next.auth_epoch !== session.value?.auth_epoch) throw new ApiFailure(403)
  if (!Array.isArray(next.authorities) || !next.authorities.every(validAuthority)) throw new ApiFailure(503)
  if (!next.authorities.length) throw new ApiFailure(403)
  if (!Array.isArray(next.items) || next.items.length > 100 || !next.items.every(validGrant) ||
      next.consistency !== 'current' || !/^\d{4}-\d{2}-\d{2}$/.test(next.as_of) ||
      (next.next_cursor !== null && (typeof next.next_cursor !== 'string' || !next.next_cursor))) throw new ApiFailure(503)
  if (detailID) {
    if (next.items.length !== 1 || next.items[0]!.id !== detailID) throw new ApiFailure(404)
    details.value = next.items[0]!
    if (currentList.value) currentList.value = { ...currentList.value, authorities: next.authorities, as_of: next.as_of }
  } else currentList.value = next
}
function showFailure(cause: unknown, operation: Operation) {
  if (!isCurrent(operation)) return
  const status = cause instanceof ApiFailure ? cause.status : 503
  if ([401, 403, 404].includes(status)) {
    cancelOperation(); clearData(); session.value = null
    error.value = status === 401 ? '会话已失效，授权内容和表单已清空。' : '当前授权不可访问或管理条件已改变，内容和表单已清空。请手动刷新；MFA 只能由可信身份设施验证。'
    if (status === 401) emit('session-expired')
  } else if (status === 409) {
    clearData(); error.value = '授权版本或上下文冲突。未自动重试；请手动刷新，再重新预览与确认。'
  } else if (status === 422 || status === 400) {
    lastCommand = null; uncertain.value = false; preview.value = null; revokeConfirm.value = false
    error.value = '输入未被接受，请核对已批准范围和期限后重新预览。'
  } else error.value = '服务或网络不可用，结果尚未确认。不会显示成功；请手动刷新，或仅在上下文未变时显式重试原命令。'
  notice.value = null
}
async function refresh() {
  const operation = beginOperation('loading'); clearData()
  try { await readSession(operation); await readList(operation) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
async function applyFilters() {
  if (busy.value || uncertain.value) return
  if ((filters.subject && !uuid.test(filters.subject)) || (filters.grantID && !uuid.test(filters.grantID)) ||
      Boolean(filters.scopeKind) !== Boolean(filters.scopeID) || (filters.scopeID && !uuid.test(filters.scopeID)) ||
      filters.scopeKind && !['org', 'team', 'employee'].includes(filters.scopeKind) ||
      filters.category && !['metadata', 'pii', 'audit', 'shared', 'manager_private', 'hr_confidential', 'financial'].includes(filters.category) ||
      filters.purpose && !['organization_management', 'security_administration', 'interview_followup', 'compensation_management'].includes(filters.purpose) ||
      filters.capability && !capabilities.includes(filters.capability) ||
      filters.state && !['current', 'future', 'expired', 'revoked'].includes(filters.state) ||
      Boolean(filters.objectKind) !== Boolean(filters.objectID) ||
      filters.objectKind && (!grantObjectKinds.includes(filters.objectKind as ObjectReference['kind']) || !uuid.test(filters.objectID)) ||
      !/^[1-9][0-9]*$/.test(filters.limit) || Number(filters.limit) > 100) {
    error.value = '筛选 ID 须为规范 UUID，scope 须成对，页大小须为 1..100。'; return
  }
  const query = new URLSearchParams({ limit: filters.limit })
  for (const [key, value] of Object.entries({ subject_id: filters.subject, scope_kind: filters.scopeKind, scope_id: filters.scopeID,
    category: filters.category, purpose: filters.purpose, state: filters.state, grant_id: filters.grantID, capability: filters.capability, object_kind: filters.objectKind, object_id: filters.objectID })) if (value) query.set(key, value)
  appliedFilters = query.toString(); await refresh()
}
async function nextPage() {
  if (busy.value || uncertain.value || !currentList.value?.next_cursor || !session.value) return
  const query = new URLSearchParams(appliedFilters); query.set('cursor', currentList.value.next_cursor)
  const context = session.value; const operation = beginOperation('loading'); clearData()
  try { await readSession(operation, context); await readList(operation, query.toString()) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
async function selectGrant(id: string) {
  if (busy.value || uncertain.value || !session.value) return
  const context = session.value; const operation = beginOperation('loading')
  details.value = null; preview.value = null; editing.value = false; revokeConfirm.value = false; lastCommand = null
  try { await readSession(operation, context); await readList(operation, new URLSearchParams({ grant_id: id }).toString(), id) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function chooseAuthority() {
  const selected = selectedAuthority.value
  if (!selected) return
  const scope = selected.delegable_scopes[0]!
  form.scopeKind = scope.kind; form.scopeID = scope.id
  form.mfa = selected.mfa_required || selected.category === 'financial' || ['note.publish', 'sensitive.export'].includes(selected.capability)
}
function newGrant() {
  if (busy.value || uncertain.value || !manageable.value) return
  details.value = null; editing.value = true; preview.value = null; revokeConfirm.value = false; error.value = null; notice.value = null
  form.authorityID = currentList.value!.authorities[0]!.id; form.subject = ''; form.validFrom = ''; form.expiresAt = ''
  form.relationKind = ''; form.relationID = ''
  form.objectKind = ''; form.objectID = ''; form.sourceIDs = ''
  chooseAuthority()
}
function previewGrant() {
  if (busy.value || uncertain.value || !session.value || !manageable.value) return
  const authority = selectedAuthority.value
  const start = timestamp(form.validFrom); const end = timestamp(form.expiresAt)
  const relation = form.relationKind
    ? { kind: form.relationKind, id: form.relationID } as RelationReference : null
  if ((!form.relationKind && form.relationID) ||
      !validRelation(Boolean(form.relationKind), relation, { kind: form.scopeKind as Scope['kind'], id: form.scopeID })) {
    preview.value = null; error.value = '关系绑定须明确填写原任职 ID：reporting_line 仅 employee 范围，team_membership 仅 team 范围。'; return
  }
  if (!authority || !uuid.test(form.subject) || form.subject === session.value.subject_id || !uuid.test(form.scopeID) ||
      !['org', 'team', 'employee'].includes(form.scopeKind) || (form.scopeKind === 'org' && form.scopeID !== session.value.org_id) ||
      !authority.delegable_scopes.some((scope) => scopeCovers(scope, form.scopeKind, form.scopeID)) ||
      !start || !end || start >= end || start < timestamp(authority.valid_from)! || end > timestamp(authority.expires_at)! ||
      (authority.mfa_required && !form.mfa)) {
    preview.value = null; error.value = '请使用已批准的范围、非自身主体、RFC3339 UTC 时间（最多六位小数）及批准期限；不得降低 MFA 要求。'; return
  }
  const object = form.objectKind ? { kind: form.objectKind, id: form.objectID } as ObjectReference : null
  const sources: ObjectReference[] = form.sourceIDs.trim() ? form.sourceIDs.trim().split(/\s+/).map(id => ({ kind: 'note_version', id })) : []
  if ((!form.objectKind && form.objectID) || !validGrantObject(object, authority.capability, authority.category, authority.purpose) ||
      !validSourceApproval(sources, authority.capability, authority.category) ||
      sources.length > 0 && form.scopeKind !== 'employee' ||
      (['note.publish', 'sensitive.export'].includes(authority.capability) || authority.category === 'financial') && !form.mfa) {
    preview.value = null; error.value = '对象须为当前类别允许的明确类型与 UUID，并仍满足已批准范围；来源批准须为最多十个唯一 note_version，仅用于 note.publish 或 shared action.write。发布、导出与财务必须 MFA。'; return
  }
  preview.value = { context: session.value, authority, body: JSON.stringify({
    subject_id: form.subject, capability: authority.capability, category: authority.category,
    scope: { kind: form.scopeKind, id: form.scopeID }, purpose: authority.purpose,
    valid_from: form.validFrom, expires_at: form.expiresAt, mfa_required: form.mfa,
    relation_bound: relation !== null, relation_ref: relation, object_ref: object, approved_source_refs: sources, authority_id: authority.id, expected_revision: session.value.auth_epoch,
  }) }
  error.value = null; editing.value = false
}
function confirmIssue() {
  if (!preview.value || busy.value || uncertain.value) return
  const pending = preview.value
  lastCommand = { path: '/access-grants', body: pending.body, context: pending.context, authorityID: pending.authority.id, key: crypto.randomUUID(), kind: 'issue' }
  void execute(lastCommand)
}
function confirmRevoke() {
  if (!details.value || !session.value || !revokeConfirm.value || busy.value || uncertain.value ||
      !['access_no_longer_required', 'policy_change', 'incorrect_grant'].includes(revokeReason.value)) return
  lastCommand = { path: `/access-grants/${details.value.id}/revoke`, key: crypto.randomUUID(), context: session.value, kind: 'revoke',
    body: JSON.stringify({ expected_revision: details.value.revision, expected_auth_epoch: session.value.auth_epoch, reason: revokeReason.value }) }
  void execute(lastCommand)
}
async function execute(command: Command, replay = false) {
  if (busy.value) return
  const operation = beginOperation('submitting')
  let sent = false; let committed = false
  uncertain.value = false
  try {
    await readSession(operation, command.context, replay)
    if (command.authorityID && !session.value!.grant_authorities.some((authority) => authority.id === command.authorityID)) throw new ApiFailure(403)
    sent = true
    const result = await request<Receipt>(command.path, operation, command)
    if (!result || !uuid.test(result.id) || !validRevision(result.revision) || !validRevision(result.auth_epoch) ||
        !['current', 'future', 'expired', 'revoked'].includes(result.status) ||
        (command.kind === 'revoke' && (command.path !== `/access-grants/${result.id}/revoke` || result.status !== 'revoked'))) throw new ApiFailure(503)
    committed = true
    emit('grant-result', command.kind)
    clearData(); phase.value = 'verifying'
    // The immutable receipt confirms this command, not the current epoch or status.
    // Fresh authorized reads may include later writes; never recreate the command.
    const next = await readSession(operation)
    if (next.subject_id !== command.context.subject_id || next.org_id !== command.context.org_id ||
        BigInt(next.auth_epoch) < BigInt(result.auth_epoch)) throw new ApiFailure(403)
    await readList(operation)
    notice.value = command.kind === 'issue' ? '授予成功，已重新读取当前获准的授权列表。' : '撤销成功，已重新读取当前获准的授权列表。'
  } catch (cause) {
    if (!isCurrent(operation)) return
    const status = cause instanceof ApiFailure ? cause.status : 503
    if ((sent || replay) && !committed && ![400, 401, 403, 404, 409, 422].includes(status)) {
      lastCommand = command; uncertain.value = true; preview.value = null; revokeConfirm.value = false; editing.value = false
    }
    showFailure(cause, operation)
  } finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function retryCommand() {
  if (!busy.value && uncertain.value && lastCommand) void execute(lastCommand, true)
}
function routeChanged() {
  if (/^\/security\/grants\/?$/.test(location.pathname)) void refresh()
  else { cancelOperation(); clearData(); session.value = null }
}
function clearExpiredContext() {
  if (!session.value) return
  const now = timestamp(new Date().toISOString())!
  if (timestamp(session.value.mfa_valid_until)! > now && (!session.value.sensitivity_valid_until || timestamp(session.value.sensitivity_valid_until)! > now)) return
  cancelOperation(); clearData(); session.value = null
  error.value = '当前敏感显示期限或 MFA 已到期，授权内容、表单与原命令已清空。请重新核对可信会话。'
}
function suspend() { cancelOperation(); clearData(); session.value = null }
onMounted(() => {
  alive = true; window.addEventListener('popstate', routeChanged); window.addEventListener('pagehide', suspend)
  expiryTimer = setInterval(clearExpiredContext, 1000); void refresh()
})
onBeforeUnmount(() => {
  alive = false; window.removeEventListener('popstate', routeChanged); window.removeEventListener('pagehide', suspend)
  if (expiryTimer) clearInterval(expiryTimer)
  cancelOperation(); clearData(); session.value = null
})
</script>

<template>
  <main :aria-busy="busy">
    <h1>明确授权管理</h1>
    <p>仅管理明确批准的 org / team / employee 授权。团队、经理或身份映射不自动授予权限；关系绑定须填写原任职引用。管理权不授予员工 PII、业务正文或全库审计读取权。</p>
    <button type="button" @click="refresh">刷新授权</button>
    <p v-if="error" role="alert">{{ error }}</p>
    <p v-if="busy" role="status">{{ phase === 'submitting' ? '正在提交命令……' : phase === 'verifying' ? '正在重新验证并读取当前授权……' : '正在验证会话并读取授权……' }}</p>
    <p v-if="notice" role="status">{{ notice }}</p>
    <template v-if="session && currentList">
      <section aria-label="当前委派批准范围">
        <h2>当前批准的委派范围</h2>
        <p>主体 {{ session.subject_id }} · 组织 {{ session.org_id }} · 当前授权 epoch {{ session.auth_epoch }}</p>
        <p>可信会话 MFA：{{ session.mfa_recent ? '当前已验证' : '未满足' }}，有效至 {{ session.mfa_valid_until }}。摘要仅作提示，每个操作仍由服务器重新授权。</p>
        <ul><li v-for="authority in currentList.authorities" :key="authority.id">
          批准依据 {{ authority.id }} · {{ authority.capability }} / {{ authority.category }} / {{ authority.purpose }}
          · 原批准 {{ authority.scope.kind }} {{ authority.scope.id }} · [{{ authority.valid_from }}, {{ authority.expires_at }})
          · MFA {{ authority.mfa_required ? '必须' : '按会话策略' }} · 批准者 {{ authority.approved_by }}
          · 批准时间 {{ authority.approved_at }} · policy {{ authority.policy_version }}
          <ul><li v-for="scope in authority.delegable_scopes" :key="`${scope.kind}:${scope.id}`">当前可委派交集：{{ scope.kind }} {{ scope.id }}</li></ul>
        </li></ul>
      </section>
      <form aria-label="授权筛选" @submit.prevent="applyFilters">
        <h2>筛选当前可管理授权</h2>
        <fieldset :disabled="busy || uncertain">
          <label for="grant-filter-subject">筛选主体 ID</label><input id="grant-filter-subject" v-model="filters.subject" />
          <label for="grant-filter-scope-kind">筛选 scope 类型</label><select id="grant-filter-scope-kind" v-model="filters.scopeKind"><option value="">全部</option><option value="org">org</option><option value="team">team</option><option value="employee">employee</option></select>
          <label for="grant-filter-scope-id">筛选 scope ID</label><input id="grant-filter-scope-id" v-model="filters.scopeID" />
          <label for="grant-filter-category">筛选类别</label><select id="grant-filter-category" v-model="filters.category"><option value="">全部</option><option v-for="category in ['metadata', 'pii', 'shared', 'manager_private', 'hr_confidential', 'financial']" :key="category" :value="category">{{ category }}</option></select>
          <label for="grant-filter-purpose">筛选目的</label><select id="grant-filter-purpose" v-model="filters.purpose"><option value="">全部</option><option value="organization_management">organization_management</option><option value="interview_followup">interview_followup</option><option value="compensation_management">compensation_management</option></select>
          <label for="grant-filter-state">筛选状态</label><select id="grant-filter-state" v-model="filters.state"><option value="">全部</option><option value="current">current</option><option value="future">future</option><option value="expired">expired</option><option value="revoked">revoked</option></select>
          <label for="grant-filter-id">筛选授权 ID</label><input id="grant-filter-id" v-model="filters.grantID" />
          <label for="grant-filter-capability">筛选能力</label><select id="grant-filter-capability" v-model="filters.capability"><option value="">全部</option><option v-for="capability in capabilities" :key="capability" :value="capability">{{ capability }}</option></select>
          <label for="grant-filter-object-kind">筛选对象类型（须与 ID 成对）</label><select id="grant-filter-object-kind" v-model="filters.objectKind"><option value="">全部</option><option v-for="kind in grantObjectKinds" :key="kind" :value="kind">{{ kind }}</option></select>
          <label for="grant-filter-object-id">筛选具体对象 ID</label><input id="grant-filter-object-id" v-model="filters.objectID" />
          <label for="grant-filter-limit">每页条数</label><input id="grant-filter-limit" v-model="filters.limit" type="number" min="1" max="100" />
          <button type="submit">应用筛选</button>
        </fieldset>
      </form>
      <section aria-label="授权列表">
        <h2>当前可管理的授权</h2>
        <p>当前业务日 {{ currentList.as_of }} · consistency {{ currentList.consistency }} · 不展示隐藏数量</p>
        <p v-if="!currentList.items.length">当前条件下无可管理授权。</p>
        <ul><li v-for="grant in currentList.items" :key="grant.id">
          {{ grant.id }} · 主体 {{ grant.subject_id }} · {{ grant.capability }} / {{ grant.category }}
          · {{ grant.scope.kind }} {{ grant.scope.id }} · {{ grant.purpose }}
          · revision {{ grant.revision }} · 状态 {{ grant.status }}
          <button type="button" :aria-label="`查看授权 ${grant.id}`" :disabled="busy || uncertain" @click="selectGrant(grant.id)">查看详情</button>
        </li></ul>
        <button v-if="currentList.next_cursor" type="button" :disabled="busy || uncertain" @click="nextPage">下一页</button>
      </section>
      <button v-if="manageable && !editing && !preview" type="button" :disabled="busy || uncertain" @click="newGrant">新建授权</button>
    </template>
    <section v-if="details" aria-label="授权详情">
      <h2>授权详情</h2>
      <dl>
        <dt>授权 ID</dt><dd>{{ details.id }}</dd><dt>主体 ID</dt><dd>{{ details.subject_id }}</dd>
        <dt>组织 ID</dt><dd>{{ details.org_id }}</dd><dt>能力 / 类别 / 目的</dt><dd>{{ details.capability }} / {{ details.category }} / {{ details.purpose }}</dd>
        <dt>范围</dt><dd>{{ details.scope.kind }} {{ details.scope.id }}</dd><dt>期限（半开）</dt><dd>[{{ details.valid_from }}, {{ details.expires_at }})</dd>
        <dt>revision</dt><dd>{{ details.revision }}</dd><dt>状态</dt><dd>{{ details.status }}</dd>
        <dt>MFA</dt><dd>{{ details.mfa_required ? '必须' : '按会话策略' }}</dd>
        <dt>绑定</dt><dd>{{ details.relation_bound ? `${details.relation_ref?.kind} ${details.relation_ref?.id}` : '独立授权；无关系引用' }}；{{ details.object_ref ? `${details.object_ref.kind} ${details.object_ref.id}（仅此对象的合法谱系，不授全部历史）` : '无对象限制' }}</dd>
        <dt>独立批准的最小来源版本</dt><dd>{{ details.approved_source_refs?.map(ref => ref.id).join(' · ') || '无' }}；仅追溯与人工最小化，不向目标读者授予源正文权。</dd>
        <dt>原批准依据</dt><dd>{{ details.authority_id ?? '历史未知' }}</dd><dt>policy version</dt><dd>{{ details.policy_version ?? '历史未知' }}</dd>
        <dt>批准者 / 时间</dt><dd>{{ details.approved_by ?? '历史未知' }} / {{ details.approved_at ?? '历史未知' }}</dd>
        <dt>签发者 / 时间</dt><dd>{{ details.issued_by ?? '历史未知' }} / {{ details.issued_at ?? '历史未知' }}</dd>
        <dt>撤销者 / 时间 / 原因</dt><dd>{{ details.revoked_by ?? '未记录' }} / {{ details.revoked_at ?? '未记录' }} / {{ details.revoke_reason ?? '未记录' }}</dd>
      </dl>
      <button v-if="details.status !== 'revoked' && !revokeConfirm" type="button" :disabled="busy || uncertain" @click="revokeConfirm = true; notice = null">撤销此授权</button>
    </section>
    <form v-if="editing" aria-label="新建明确授权" @submit.prevent="previewGrant">
      <h2>新建明确授权</h2>
      <fieldset :disabled="busy || uncertain">
        <label for="grant-authority">批准依据（authority）</label><select id="grant-authority" v-model="form.authorityID" @change="chooseAuthority"><option v-for="authority in currentList?.authorities" :key="authority.id" :value="authority.id">{{ authority.id }} · {{ authority.capability }} · 原批准 {{ authority.scope.kind }} {{ authority.scope.id }}</option></select>
        <p v-if="selectedAuthority">能力 {{ selectedAuthority.capability }} · 类别 {{ selectedAuthority.category }} · 目的 {{ selectedAuthority.purpose }} · policy {{ selectedAuthority.policy_version }}</p>
        <label for="grant-subject">受授权主体 ID（已有资格，非自身）</label><input id="grant-subject" v-model="form.subject" required autocomplete="off" />
        <label for="grant-scope-kind">授权 scope 类型</label><select id="grant-scope-kind" v-model="form.scopeKind"><option value="org" :disabled="!canUseOrg">org</option><option value="team">team</option><option value="employee">employee</option></select>
        <label for="grant-scope-id">授权 scope ID</label><input id="grant-scope-id" v-model="form.scopeID" required autocomplete="off" />
        <label for="grant-start">生效时间（RFC3339 UTC，最多六位小数）</label><input id="grant-start" v-model="form.validFrom" placeholder="YYYY-MM-DDTHH:mm:ss.ffffffZ" required autocomplete="off" />
        <label for="grant-end">到期时间（RFC3339 UTC，最多六位小数）</label><input id="grant-end" v-model="form.expiresAt" placeholder="YYYY-MM-DDTHH:mm:ss.ffffffZ" required autocomplete="off" />
        <label for="grant-mfa"><input id="grant-mfa" v-model="form.mfa" type="checkbox" :disabled="selectedAuthority?.mfa_required || selectedAuthority?.category === 'financial' || ['note.publish', 'sensitive.export'].includes(selectedAuthority?.capability ?? '')" />被授予人使用此授权须 MFA（发布、导出与财务不可降低）</label>
        <label for="grant-relation-kind">关系绑定类型（可留空）</label>
        <select id="grant-relation-kind" v-model="form.relationKind" @change="form.relationID = ''"><option value="">独立授权</option><option value="reporting_line">reporting_line（经理任职）</option><option value="team_membership">team_membership（团队任职）</option></select>
        <label v-if="form.relationKind" for="grant-relation-id">原任职关系 ID（不可猜测或自动填入）</label>
        <input v-if="form.relationKind" id="grant-relation-id" v-model="form.relationID" required autocomplete="off" />
        <label for="grant-object-kind">对象类型（可留空；具体历史版本只批准该版本）</label><select id="grant-object-kind" v-model="form.objectKind" @change="form.objectID = ''"><option value="">无对象限制</option><option v-for="kind in grantObjectKinds" :key="kind" :value="kind">{{ kind }}</option></select>
        <label v-if="form.objectKind" for="grant-object-id">明确对象 ID</label><input v-if="form.objectKind" id="grant-object-id" v-model="form.objectID" required autocomplete="off" />
        <label for="grant-source-ids">独立批准的最小来源版本 ID（note_version，空白分隔，最多十个；不填源正文）</label><textarea id="grant-source-ids" v-model="form.sourceIDs" autocomplete="off" />
        <p>源批准者仍须当前源读取权与目标委派权。这里只独立授予权限，不发布笔记；授予成功后发布失败是不同结果，不自动复制私有文字。</p>
        <p>financial / compensation_management 与提出、审批、导出能力独立；明确 compensation_event 或 compensation_term 只授该不可变对象，不授整名员工的现状或其他历史。金融授权不得降低 MFA。</p>
        <p>服务器核对目标主体的已批准员工映射、当前原任职与范围。换任职、结束或更正不使旧引用复活；不自动授经理或团队权限。</p>
        <button type="submit">预览授权</button>
        <button type="button" @click="editing = false; form.subject = ''; form.validFrom = ''; form.expiresAt = ''">取消新建</button>
      </fieldset>
    </form>
    <section v-if="preview" aria-label="授权预览">
      <h2>确认已批准的授权</h2>
      <p>受授权主体 {{ form.subject }} · {{ preview.authority.capability }} / {{ preview.authority.category }} / {{ preview.authority.purpose }}</p>
      <p>{{ form.scopeKind }} {{ form.scopeID }} · [{{ form.validFrom }}, {{ form.expiresAt }}) · MFA {{ form.mfa ? '必须' : '按会话策略' }}</p>
      <p>{{ form.relationKind ? `${form.relationKind} ${form.relationID}` : '独立授权' }} · 批准依据 {{ preview.authority.id }} · 批准者 {{ preview.authority.approved_by }} · {{ preview.authority.approved_at }} · policy {{ preview.authority.policy_version }} · expected epoch {{ preview.context.auth_epoch }}</p>
      <p>对象 {{ form.objectKind ? `${form.objectKind} ${form.objectID}` : '无对象限制' }} · 最小来源版本 {{ form.sourceIDs || '无' }}。批准特定历史版本不批准其余历史。</p>
      <p>这会向已有资格的主体开放上述范围；不授角色。请逐项确认真实批准范围。</p>
      <button type="button" :disabled="busy || uncertain" @click="confirmIssue">确认授予</button>
      <button type="button" :disabled="busy || uncertain" @click="preview = null; editing = true">返回修改</button>
    </section>
    <section v-if="revokeConfirm && details" aria-label="撤销影响">
      <h2>确认撤销影响</h2>
      <p>主体 {{ details.subject_id }} 的 {{ details.capability }} / {{ details.category }} / {{ details.purpose }} · {{ details.scope.kind }} {{ details.scope.id }} · revision {{ details.revision }} 将被撤销。</p>
      <p>后续读取重新检查当前权限，在途敏感释放仍由服务器重验。已经披露、已下载的内容无法收回；不宣称回收副本或未实现的派生数据。</p>
      <label for="grant-revoke-reason">撤销原因</label><select id="grant-revoke-reason" v-model="revokeReason" :disabled="busy || uncertain"><option value="access_no_longer_required">access_no_longer_required</option><option value="policy_change">policy_change</option><option value="incorrect_grant">incorrect_grant</option></select>
      <button type="button" :disabled="busy || uncertain" @click="confirmRevoke">确认撤销</button>
      <button type="button" :disabled="busy || uncertain" @click="revokeConfirm = false">取消撤销</button>
    </section>
    <section v-if="uncertain" aria-label="命令结果尚未确认">
      <p>原命令结果尚未确认。只显式重放同一幂等键及原命令；epoch 可能已因该提交或后续写入推进。先重验同一主体/组织、当前管理权、MFA与所需批准，仍由服务器授权并查 receipt；不是重新批准或用新 epoch 创建命令。</p>
      <button type="button" :disabled="busy" @click="retryCommand">重试原命令</button>
    </section>
  </main>
</template>

<style scoped>
main { max-width: 72rem; margin: 1.5rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; }
section, form { margin: 1.5rem 0; padding: 1rem; border: 1px solid #9ba4ae; border-radius: .25rem; }
fieldset { display: grid; gap: .5rem; border: 0; padding: 0; }
input, select { padding: .45rem; max-width: 46rem; }
button { padding: .5rem .8rem; margin: .4rem .5rem .4rem 0; cursor: pointer; }
button:disabled { cursor: not-allowed; }
li { margin-bottom: .8rem; overflow-wrap: anywhere; }
dt { font-weight: 600; margin-top: .7rem; } dd { margin-left: 0; overflow-wrap: anywhere; }
[role="alert"] { color: #8a1717; } [role="status"] { color: #165129; }
</style>
