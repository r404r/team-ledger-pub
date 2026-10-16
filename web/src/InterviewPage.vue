<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'
import GrantPage from './GrantPage.vue'
import { sections, uuid, validRevision, validDate, timestamp, validParty, validInterview, validInterviewEvent, validNote, validAction, type Category, type Party, type SourceRef, type Note, type Detail, type List, type Permission, type Result, type ExportObject, type ExportEvent, type ActionItem } from './interviewDTO'

const emit = defineEmits<{ 'session-expired': [] }>()
type Session = { subject_id: string; org_id: string; auth_epoch: string; csrf_token: string; capabilities: string[]; mfa_recent: boolean; mfa_valid_until: string; sensitivity_valid_until?: string; interview_permissions?: Permission[] }
type Operation = { generation: number; controller: AbortController }
type Command = { path: string; body: string; key: string; context: Session; capability: string; category: string; export: boolean }
class ApiFailure extends Error { constructor(readonly status: number) { super('Interview request failed') } }
const session = shallowRef<Session | null>(null)
const list = shallowRef<List | null>(null)
const detail = shallowRef<Detail | null>(null)
const historical = shallowRef<Note | null>(null)
const mode = ref<'selector' | 'list' | 'detail' | 'away'>('away')
const employeeID = ref(''), interviewID = ref(''), selector = ref('')
const phase = ref<'idle' | 'loading' | 'submitting' | 'verifying'>('idle')
const error = ref(''), notice = ref(''), approvalNotice = ref('')
const uncertain = ref(false), grantOpen = ref(false)
const historyScope = ref('')
const filters = reactive({ from: '', to: '', status: '', limit: '20' })
const schedule = reactive({ at: '', backfilled: false, start: '', end: '', participants: '' })
const state = reactive({ start: '', end: '', reason: '', backfilledConfirmed: false })
const note = reactive({ category: '' as Category | '', text: '', reason: '', supersedes: '', sourceIDs: [] as string[], minimized: false, publishConfirmed: false })
const action = reactive({ text: '', ownerKind: 'subject', ownerID: '', due: '', sourceIDs: [] as string[], minimized: false })
const blocker = ref(''), actionStatus = ref(''), actionDue = ref('')
const exportSelection = ref<string[]>([]), exportOutput = ref(''), exportStatus = ref('')
let generation = 0, alive = false
let controller: AbortController | null = null
let lastCommand: Command | null = null
let appliedList = ''
let appliedCategory = ''
let timer: ReturnType<typeof setInterval> | null = null
const busy = computed(() => phase.value !== 'idle')
const terminal = computed(() => detail.value && ['completed', 'cancelled'].includes(detail.value.interview.status))
const permissions = computed(() => mode.value === 'detail' ? detail.value?.permissions ?? [] : mode.value === 'list' ? list.value?.permissions ?? [] : session.value?.interview_permissions ?? [])
const editableCategories = computed(() => sections.filter(category => permits('note.read', category) && permits('note.write', category)))
const selectedSection = computed(() => detail.value?.sections.find(section => section.category === note.category))
const sources = computed(() => detail.value?.sections.flatMap(section => section.versions.filter(version => version.status === 'published')) ?? [])
const visibleActions = computed(() => detail.value?.action_items.filter(item => (!actionStatus.value || item.status === actionStatus.value) && (!actionDue.value || item.due_date === actionDue.value)) ?? [])
const exportObjects = computed<ExportObject[]>(() => {
  if (!detail.value) return []
  const objects: ExportObject[] = []
  if (permits('sensitive.export', 'metadata')) objects.push({ kind: 'interview', id: detail.value.interview.id, expected_revision: detail.value.interview.revision })
  for (const section of detail.value.sections) if (permits('sensitive.export', section.category)) for (const version of section.versions) objects.push({ kind: 'note_version', id: version.id, expected_revision: version.version_no })
  if (permits('sensitive.export', 'shared')) for (const item of detail.value.action_items) objects.push({ kind: 'action_item', id: item.id, expected_revision: item.revision })
  return objects
})
function permits(capability: string, category: string): boolean { return permissions.value.some(permission => permission.capability === capability && permission.category === category) }
function clearForms() {
  schedule.at = ''; schedule.backfilled = false; schedule.start = ''; schedule.end = ''; schedule.participants = ''
  state.start = ''; state.end = ''; state.reason = ''; state.backfilledConfirmed = false
  note.category = ''; note.text = ''; note.reason = ''; note.supersedes = ''; note.sourceIDs = []; note.minimized = false; note.publishConfirmed = false
  action.text = ''; action.ownerKind = 'subject'; action.ownerID = ''; action.due = ''; action.sourceIDs = []; action.minimized = false
  blocker.value = ''; historical.value = null; exportSelection.value = []; exportOutput.value = ''; exportStatus.value = ''
}
function clearSensitive() { list.value = null; detail.value = null; clearForms(); lastCommand = null; uncertain.value = false; notice.value = '' }
function cancelOperation() { generation += 1; controller?.abort(); controller = null; phase.value = 'idle' }
function beginOperation(next: 'loading' | 'submitting'): Operation { cancelOperation(); controller = new AbortController(); phase.value = next; error.value = ''; notice.value = ''; return { generation, controller } }
function isCurrent(operation: Operation): boolean { return alive && generation === operation.generation && !operation.controller.signal.aborted }
function sameIdentity(left: Session, right: Session): boolean { return left.subject_id === right.subject_id && left.org_id === right.org_id }
async function request<T>(path: string, operation: Operation, command?: Command): Promise<T> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'interview_followup' }
  if (command) { headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = session.value!.csrf_token; headers['Idempotency-Key'] = command.key }
  const response = await fetch(`/api/v1${path}`, { method: command ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal, headers, body: command?.body })
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  const result: T = await response.json()
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  return result
}
async function readSession(operation: Operation, expected?: Session, replay = false) {
  // Interview authorization is independent of employee-directory visibility.
  // Object/list responses supply current operation hints, never session hints.
  const next = await request<Session>('/session', operation)
  if (!next || !uuid.test(next.subject_id) || !uuid.test(next.org_id) || !validRevision(next.auth_epoch) || typeof next.csrf_token !== 'string' || !next.csrf_token || !Array.isArray(next.capabilities) || !next.capabilities.every(cap => typeof cap === 'string') || typeof next.mfa_recent !== 'boolean' || !timestamp(next.mfa_valid_until)) throw new ApiFailure(503)
  if (next.interview_permissions !== undefined && !validPermissions(next.interview_permissions)) throw new ApiFailure(503)
  if (next.sensitivity_valid_until !== undefined && !timestamp(next.sensitivity_valid_until)) throw new ApiFailure(503)
  if (next.sensitivity_valid_until && timestamp(next.sensitivity_valid_until)! <= timestamp(new Date().toISOString())!) throw new ApiFailure(403)
  if (expected && (!sameIdentity(expected, next) || !replay && expected.auth_epoch !== next.auth_epoch)) throw new ApiFailure(403)
  if (session.value && (!sameIdentity(session.value, next) || session.value.auth_epoch !== next.auth_epoch)) clearSensitive()
  session.value = next
  return next
}
function validPermissions(value: Permission[]) {
  return Array.isArray(value) && value.length <= 30 && value.every(permission => permission && (['interview.read', 'interview.write', 'interview.create'].includes(permission.capability) && permission.category === 'metadata' || ['note.read', 'note.write', 'note.publish'].includes(permission.capability) && sections.includes(permission.category as Category) || ['action.read', 'action.write'].includes(permission.capability) && permission.category === 'shared' || permission.capability === 'sensitive.export' && ['metadata', ...sections, 'shared'].includes(permission.category)))
}
async function readDetail(operation: Operation, category = appliedCategory, cursor = '') {
  const query = new URLSearchParams({ include_sections: sections.join(','), include_actions: 'true', limit: '100' })
  if (category) query.set('category', category)
  if (cursor) query.set('cursor', cursor)
  const next = await request<Detail>(`/interviews/${interviewID.value}?${query}`, operation)
  if (!next || !validInterview(next.interview) || next.interview.id !== interviewID.value || employeeID.value && next.interview.employee_id !== employeeID.value || !validPermissions(next.permissions) || !Array.isArray(next.sections) || next.sections.length > 3 || !Array.isArray(next.action_items) || next.action_items.length > 100 || (next.next_cursor !== null && (typeof next.next_cursor !== 'string' || !next.next_cursor))) throw new ApiFailure(503)
  if (!Array.isArray(next.interview_events) || next.interview_events.length > 3 || !next.interview_events.every(validInterviewEvent)) throw new ApiFailure(503)
  const can = (capability: string, category: string) => next.permissions.some(permission => permission.capability === capability && permission.category === category)
  if (!next.sections.every(section => sections.includes(section.category) && (section.head_id === undefined || uuid.test(section.head_id)) && (section.head_revision == null || validRevision(section.head_revision)) && (section.head_id !== undefined || section.head_revision == null && section.draft_version_id == null && section.published_version_id == null) && can('note.read', section.category) && Array.isArray(section.versions) && section.versions.length <= 100 && section.versions.every(version => validNote(version, next.interview) && version.category === section.category && version.head_id === section.head_id) && [section.draft_version_id, section.published_version_id].every(id => id == null || uuid.test(id))) || !next.action_items.every(item => can('action.read', 'shared') && validAction(item, next.interview))) throw new ApiFailure(503)
  detail.value = next; employeeID.value = next.interview.employee_id
}
async function readList(operation: Operation, query = appliedList) {
  const next = await request<List>(`/employees/${employeeID.value}/interviews${query ? `?${query}` : ''}`, operation)
  if (!next || !Array.isArray(next.items) || next.items.length > 100 || !next.items.every(item => validInterview(item) && item.employee_id === employeeID.value) || !validDate(next.as_of) || next.consistency !== 'current' || !validPermissions(next.permissions) || !next.permissions.some(permission => permission.capability === 'interview.read' && permission.category === 'metadata') || next.permissions.some(permission => !['interview.read', 'interview.write', 'interview.create'].includes(permission.capability) || permission.category !== 'metadata') || next.next_cursor !== null && (typeof next.next_cursor !== 'string' || !next.next_cursor)) throw new ApiFailure(503)
  list.value = next
}
function showFailure(cause: unknown, operation: Operation) {
  if (!isCurrent(operation)) return
  const status = cause instanceof ApiFailure ? cause.status : 503
  if ([401, 403, 404].includes(status)) { cancelOperation(); clearSensitive(); session.value = null; grantOpen.value = false; if (status === 401) emit('session-expired') }
  else if ([400, 409, 422].includes(status)) { clearSensitive() }
  error.value = status === 401 ? '会话已失效，面谈正文与表单已清空。' : [403, 404].includes(status) ? '当前对象不可访问或许可已改变，面谈正文与表单已清空。' : status === 409 ? '真实版本冲突：未覆盖任何历史。请刷新当前版本后手动重新编辑；未自动重试。' : [400, 422].includes(status) ? '输入未被接受，请核对时间、责任人、理由与当前许可。' : '服务或网络不可用，命令结果尚未确认。不会显示成功；可重放原键及原正文或刷新当前获准事实。'
  notice.value = ''
}
async function refresh() {
  const operation = beginOperation('loading'); clearSensitive()
  try { await readSession(operation); if (mode.value === 'detail') await readDetail(operation); else if (mode.value === 'list') await readList(operation) }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function navigate(event: MouseEvent, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault(); window.history.pushState({}, '', path); window.dispatchEvent(new PopStateEvent('popstate'))
}
function selectEmployee() {
  if (!uuid.test(selector.value)) { error.value = '请明确选择规范员工 UUID；不猜测员工或隐式授权。'; return }
  window.history.pushState({}, '', `/employees/${selector.value}/interviews`); window.dispatchEvent(new PopStateEvent('popstate'))
}
async function applyFilters() {
  if (busy.value || uncertain.value) return
  if (Boolean(filters.from) !== Boolean(filters.to) || filters.from && (!validDate(filters.from) || !validDate(filters.to) || filters.from >= filters.to) || !/^[1-9][0-9]*$/.test(filters.limit) || Number(filters.limit) > 100) { error.value = '日期须成对且 from < to，窗口为 [from,to)；每页 1..100 条。'; return }
  const query = new URLSearchParams({ limit: filters.limit })
  if (filters.from) { query.set('from', filters.from); query.set('to', filters.to) }
  if (filters.status) query.set('status', filters.status)
  appliedList = query.toString(); await refresh()
}
async function changeHistoryScope() {
  if (historyScope.value && historyScope.value !== 'actions' && !sections.includes(historyScope.value as Category)) return
  appliedCategory = historyScope.value; await refresh()
}
async function nextPage() {
  const cursor = mode.value === 'detail' ? detail.value?.next_cursor : list.value?.next_cursor
  if (!cursor || busy.value || uncertain.value || !session.value) return
  const context = session.value, operation = beginOperation('loading'); clearSensitive()
  try { await readSession(operation, context); if (mode.value === 'detail') await readDetail(operation, appliedCategory, cursor); else { const query = new URLSearchParams(appliedList); query.set('cursor', cursor); await readList(operation, query.toString()) } }
  catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function queue(path: string, body: unknown, capability: string, category: string, exporting = false) {
  if (busy.value || uncertain.value || !session.value || !permits(capability, category)) return
  lastCommand = { path, body: JSON.stringify(body), key: crypto.randomUUID(), context: session.value, capability, category, export: exporting }
  void execute(lastCommand)
}
async function execute(command: Command, replay = false) {
  if (busy.value) return
  const operation = beginOperation('submitting'); let sent = false, committed = false
  uncertain.value = false
  try {
    await readSession(operation, command.context, replay)
    if (['note.publish', 'sensitive.export'].includes(command.capability) && (!session.value!.mfa_recent || timestamp(session.value!.mfa_valid_until)! <= timestamp(new Date().toISOString())!)) throw new ApiFailure(403)
    if (mode.value === 'detail') await readDetail(operation)
    else if (mode.value === 'list') await readList(operation)
    if (!permits(command.capability, command.category)) throw new ApiFailure(403)
    sent = true
    if (command.export) { await streamExport(command, operation); lastCommand = null; return }
    const result = await request<Result>(command.path, operation, command)
    if (!result || !uuid.test(result.id) || !validRevision(result.revision) || !['scheduled', 'in_progress', 'completed', 'cancelled', 'draft', 'published', 'todo', 'done'].includes(result.status)) throw new ApiFailure(503)
    committed = true; clearSensitive(); phase.value = 'verifying'
    const next = await readSession(operation)
    if (!sameIdentity(command.context, next)) throw new ApiFailure(403)
    if (mode.value === 'detail') await readDetail(operation); else await readList(operation)
    notice.value = '此面谈命令已保存；已重新读取当前获准事实。授权请求是独立操作，不宣称组合成功。'
  } catch (cause) {
    if (!isCurrent(operation)) return
    const status = cause instanceof ApiFailure ? cause.status : 503
    if (!sent) { clearSensitive(); session.value = null }
    if ((sent || replay) && !committed && ![400, 401, 403, 404, 409, 422].includes(status)) {
      if (!command.export) clearSensitive()
      else {
        const partialOutput = exportOutput.value
        clearForms(); exportOutput.value = partialOutput
        exportStatus.value = '导出中断：未确认完整结果，不是成功导出。可重试同一所选对象命令，服务器重新核对当前许可。'
      }
      lastCommand = command; uncertain.value = true
    }
    showFailure(cause, operation)
    if (committed) {
      notice.value = '此面谈命令已保存，但当前授权回读未成功；不表示已提交事实回滚，也不宣称后续操作成功。'
      error.value = '当前获准事实尚未重新核对。请刷新后再操作。'
    }
  } finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function createInterview() {
  const start = timestamp(schedule.start), end = timestamp(schedule.end)
  const participants: Party[] = schedule.participants.trim() ? schedule.participants.trim().split(/\s+/).map(value => { const [kind, id] = value.split(':'); return { kind, id } as Party }) : []
  if (!timestamp(schedule.at) || participants.length > 20 || !participants.every(validParty) || new Set(participants.map(party => `${party.kind}:${party.id}`)).size !== participants.length || schedule.backfilled && (!start || !end || end < start || end > timestamp(new Date().toISOString())!)) { error.value = '计划须为真实 UTC 时间；补录实际起止须有效、顺序正确且不在未来；参与者须为最多二十个唯一 subject:UUID 或 employee:UUID。'; return }
  queue(`/employees/${employeeID.value}/interviews`, { scheduled_at: schedule.at, participants, backfilled: schedule.backfilled, actual_started_at: schedule.backfilled ? schedule.start : null, actual_ended_at: schedule.backfilled ? schedule.end : null }, permits('interview.create', 'metadata') ? 'interview.create' : 'interview.write', 'metadata')
}
function transitionInterview(kind: string) {
  if (!detail.value || terminal.value) return
  const backfilled = kind === 'complete' && detail.value.interview.status === 'scheduled'
  const start = timestamp(backfilled || kind === 'start' ? state.start : detail.value.interview.actual_started_at)
  const end = timestamp(state.end), now = timestamp(new Date().toISOString())!
  if (new TextEncoder().encode(state.reason).length > 4096 ||
      kind === 'start' && (!start || start > now) ||
      kind === 'complete' && (!start || !end || end < start || end > now || backfilled && !state.backfilledConfirmed) ||
      kind === 'cancel' && !state.reason.trim()) { error.value = '须真实且非未来的实际时间；完成须起止顺序正确，计划面谈补录须人工明确确认；取消须安全原因。'; return }
  queue(`/interviews/${interviewID.value}/transitions`, { action: kind, expected_revision: detail.value.interview.revision, actual_started_at: kind === 'start' || backfilled ? state.start : null, actual_ended_at: kind === 'complete' ? state.end : null, backfilled, reason: state.reason }, 'interview.write', 'metadata')
}
function chooseCategory() { cancelOperation(); note.text = ''; note.reason = ''; note.supersedes = ''; note.sourceIDs = []; note.minimized = false; note.publishConfirmed = false; historical.value = null; lastCommand = null; uncertain.value = false; exportOutput.value = ''; exportStatus.value = '' }
function selectedSources(ids: string[]): SourceRef[] | null {
  if (ids.length > 10 || new Set(ids).size !== ids.length) { error.value = '须明确选择最多十个唯一发布来源版本。'; return null }
  const result: SourceRef[] = []
  for (const id of ids) {
    const source = sources.value.find(value => value.id === id)
    if (!source) { error.value = '所选来源不再是当前获准读取的发布版本，请重新读取。'; return null }
    result.push({ kind: 'note_version', id, expected_version: source.version_no })
  }
  return result
}
function saveNote(kind: 'save_draft' | 'publish') {
  if (!detail.value || !note.category || detail.value.interview.status === 'cancelled') return
  const section = selectedSection.value
  if (section && !section.head_revision) { error.value = '仅获准历史版本，不具备当前 head 的修改许可。'; return }
  if (section && !note.supersedes) { error.value = '已有分区须明确选择当前获准被替代版本，并提供修订理由；不会创建脱离历史的新版本。'; return }
  const needsReason = Boolean(section || note.supersedes || detail.value.interview.status === 'completed')
  const crossCategory = note.sourceIDs.some(id => sources.value.find(source => source.id === id)?.category !== note.category)
  if (!note.text.trim() || new TextEncoder().encode(note.text).length > 12288 || new TextEncoder().encode(note.reason).length > 4096 || needsReason && !note.reason.trim() || crossCategory && !note.minimized || kind === 'publish' && !note.publishConfirmed) { error.value = '手工正文须 1..12288 UTF-8 字节；纠正或完成后的更正须理由；跨分区须确认人工最小化；发布须独立确认。'; return }
  const refs = selectedSources(note.sourceIDs)
  if (refs === null) return
  queue(`/interviews/${interviewID.value}/note-versions`, { head_id: section?.head_id ?? null, category: note.category, expected_head_revision: section?.head_revision ?? '0', text: note.text, edit_reason: note.reason, action: kind, supersedes_version_id: note.supersedes || null, source_refs: refs, confirm_minimized: note.minimized }, kind === 'publish' ? 'note.publish' : 'note.write', note.category)
}
async function readVersion(version: Note) {
  if (uncertain.value || !session.value || !detail.value) return
  const context = session.value, interview = detail.value.interview, operation = beginOperation('loading'); clearForms(); lastCommand = null
  try {
    await readSession(operation, context)
    const next = await request<Note>(`/note-versions/${version.id}`, operation)
    if (!validNote(next, interview) || next.id !== version.id || next.head_id !== version.head_id || next.category !== version.category) throw new ApiFailure(503)
    historical.value = next
  } catch (cause) { showFailure(cause, operation) }
  finally { if (isCurrent(operation)) { phase.value = 'idle'; controller = null } }
}
function createAction() {
  if (!detail.value || terminal.value) return
  if (!action.text.trim() || new TextEncoder().encode(action.text).length > 12288 || !validParty({ kind: action.ownerKind, id: action.ownerID } as Party) || action.due && !validDate(action.due) || action.sourceIDs.some(id => sources.value.find(source => source.id === id)?.category !== 'shared') && !action.minimized) { error.value = '共享行动须手工最小文字、同组织现有责任人、合法截止日或明确未设；私有来源须独立批准并确认人工最小化。'; return }
  const refs = selectedSources(action.sourceIDs)
  if (refs === null) return
  queue(`/interviews/${interviewID.value}/action-items`, { expected_revision: detail.value.interview.revision, minimal_shared_text: action.text, owner: { kind: action.ownerKind, id: action.ownerID }, due_date: action.due || null, source_refs: refs, confirm_minimized: action.minimized }, 'action.write', 'shared')
}
function transitionAction(item: ActionItem, kind: string) {
  if (['done', 'cancelled'].includes(item.status)) return
  if (new TextEncoder().encode(blocker.value).length > 4096) { error.value = '安全阻碍文字最多 4096 UTF-8 字节。'; return }
  queue(`/action-items/${item.id}/transitions`, { action: kind, expected_revision: item.revision, safe_blocker_text: blocker.value }, 'action.write', 'shared')
}
function exportSelected() {
  const objects = exportObjects.value.filter(object => exportSelection.value.includes(`${object.kind}:${object.id}`))
  if (!objects.length || objects.length > 100) { error.value = '须显式选择 1..100 个当前获准对象，不导出未选或隐蔽分区。'; return }
  queue('/sensitive-exports', { objects, format: 'ndjson' }, 'sensitive.export', objects[0]!.kind === 'interview' ? 'metadata' : objects[0]!.kind === 'action_item' ? 'shared' : detail.value!.sections.find(section => section.versions.some(version => version.id === objects[0]!.id))!.category, true)
}
async function streamExport(command: Command, operation: Operation) {
  exportOutput.value = ''; exportStatus.value = '导出进行中；尚未完成。'
  const response = await fetch('/api/v1/sensitive-exports', { method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal, headers: { 'Content-Type': 'application/json', 'X-Access-Purpose': 'interview_followup', 'X-CSRF-Token': session.value!.csrf_token, 'Idempotency-Key': command.key }, body: command.body })
  if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw new ApiFailure(response.status)
  if (!response.body || !response.headers.get('Content-Type')?.includes('application/x-ndjson')) throw new ApiFailure(503)
  const requested = (JSON.parse(command.body) as { objects: ExportObject[] }).objects
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
  let bytes = 0, pending = '', exportID = '', ended = false, count = 0
  const released = new Set<string>()
  try {
    while (true) {
      const chunk = await reader.read()
      if (!isCurrent(operation)) throw new DOMException('Cancelled', 'AbortError')
      if (chunk.done) break
      bytes += chunk.value.byteLength
      if (bytes > 8 * 1024 * 1024) throw new ApiFailure(413)
      pending += decoder.decode(chunk.value, { stream: true })
      let newline = pending.indexOf('\n')
      while (newline >= 0) {
        const line = pending.slice(0, newline); pending = pending.slice(newline + 1)
        const event = JSON.parse(line) as ExportEvent
        if (!event || ended || !uuid.test(event.export_id) || !['header', 'object', 'complete', 'partial'].includes(event.kind)) throw new ApiFailure(503)
        if (!exportID) { if (event.kind !== 'header') throw new ApiFailure(503); exportID = event.export_id }
        else if (event.export_id !== exportID || event.kind === 'header') throw new ApiFailure(503)
        if (event.kind === 'object') {
          const actual = event.note_version ? { kind: 'note_version', id: event.note_version.id } : event.action_item ? { kind: 'action_item', id: event.action_item.id } : event.interview ? { kind: 'interview', id: event.interview.id } : null
          const expected = actual && requested.find(object => object.kind === actual.kind && object.id === actual.id)
          const key = actual && `${actual.kind}:${actual.id}`
          const actualRevision = event.note_version?.version_no ?? event.action_item?.revision ?? event.interview?.revision
          if (!expected || !key || released.has(key) || expected.expected_revision !== actualRevision || ++count > requested.length) throw new ApiFailure(503)
          released.add(key)
          if (event.note_version && !validNote(event.note_version, detail.value!.interview) || event.action_item && !validAction(event.action_item, detail.value!.interview) || event.interview && (!validInterview(event.interview) || event.interview.id !== interviewID.value)) throw new ApiFailure(503)
        }
        if (event.kind === 'complete') { if (count !== requested.length) throw new ApiFailure(503); ended = true; exportStatus.value = '所选对象导出完成。内容仅在当前页面内存；离页即清空。' }
        if (event.kind === 'partial') {
          if (!event.reason || !['ACCESS_LOST', 'REVISION_STALE', 'AUDIT_UNAVAILABLE', 'DEPENDENCY_UNAVAILABLE', 'WRITE_FAILED'].includes(event.reason)) throw new ApiFailure(503)
          ended = true
          if (event.reason === 'ACCESS_LOST') {
            cancelOperation(); clearSensitive(); session.value = null; grantOpen.value = false
            error.value = '导出部分完成：当前访问已失效，之前的敏感显示与命令已清空；不是完整导出。'
            return
          }
          exportStatus.value = '导出部分完成：输出或服务已改变；不是成功的完整导出。请重新读取当前许可。'
        }
        exportOutput.value += `${line}\n`
        newline = pending.indexOf('\n')
      }
    }
    pending += decoder.decode()
    if (pending || !ended) { exportStatus.value = '导出中断：仅部分输出，未确认完成。'; throw new ApiFailure(503) }
  } finally { await reader.cancel(); reader.releaseLock() }
}
function grantResult(kind: 'issue' | 'revoke') { cancelOperation(); clearSensitive(); session.value = null; approvalNotice.value = kind === 'issue' ? '独立授权请求已成功；笔记尚未发布。请刷新面谈后另行人工编辑与发布。' : '独立撤销请求已成功；旧面谈内容已清空。'; error.value = '' }
function expire() { cancelOperation(); clearSensitive(); session.value = null; emit('session-expired') }
function readRoute() {
  cancelOperation(); clearSensitive(); session.value = null; approvalNotice.value = ''; grantOpen.value = false; error.value = ''; appliedList = ''; employeeID.value = ''; interviewID.value = ''; selector.value = ''
  historyScope.value = ''; appliedCategory = ''
  const employee = /^\/employees\/([^/]+)\/interviews\/?$/.exec(location.pathname), interview = /^\/interviews\/([^/]+)\/?$/.exec(location.pathname)
  if (employee && uuid.test(employee[1]!)) { employeeID.value = employee[1]!; mode.value = 'list' }
  else if (interview && uuid.test(interview[1]!)) { interviewID.value = interview[1]!; mode.value = 'detail' }
  else mode.value = /^\/interviews\/?$/.test(location.pathname) ? 'selector' : 'away'
  if (mode.value !== 'away') void refresh()
}
function checkClock() {
  const now = timestamp(new Date().toISOString())!
  if (session.value && (session.value.sensitivity_valid_until && timestamp(session.value.sensitivity_valid_until)! <= now || session.value.mfa_recent && timestamp(session.value.mfa_valid_until)! <= now)) {
    cancelOperation(); clearSensitive(); session.value = null; grantOpen.value = false
    error.value = '当前敏感显示期限或近期 MFA 已到期，正文、命令与导出已清空。请重新核对会话。'
  }
}
onMounted(() => { alive = true; window.addEventListener('popstate', readRoute); window.addEventListener('focus', readRoute); window.addEventListener('pagehide', expire); timer = setInterval(checkClock, 1000); readRoute() })
onBeforeUnmount(() => { alive = false; window.removeEventListener('popstate', readRoute); window.removeEventListener('focus', readRoute); window.removeEventListener('pagehide', expire); if (timer) clearInterval(timer); cancelOperation(); clearSensitive(); session.value = null })
</script>

<template>
  <main :aria-busy="busy">
    <h1>面谈与明确最小交接</h1>
    <p>共享也须明确授权。作者、参与者、经理或 HR 身份不自动授予权限；只显示当前允许的对象与历史版本，不显示隐藏数量。</p>
    <button type="button" @click="refresh">刷新面谈</button>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p><p v-if="approvalNotice" role="status" aria-label="独立授权结果">{{ approvalNotice }}</p>
    <p v-if="busy" role="status">{{ phase === 'submitting' ? '正在提交显式命令……' : '正在核对当前会话与获准事实……' }}</p>
    <form v-if="mode === 'selector'" aria-label="选择面谈员工" @submit.prevent="selectEmployee"><label for="interview-employee">明确员工 ID</label><input id="interview-employee" v-model="selector" autocomplete="off" required /><button type="submit">读取员工面谈</button></form>
    <template v-if="mode === 'list' && session && list">
      <h2>员工 {{ employeeID }} 的当前获准面谈</h2>
      <form aria-label="面谈筛选" @submit.prevent="applyFilters"><fieldset :disabled="busy || uncertain"><label for="interview-from">发生日期 from（含）</label><input id="interview-from" v-model="filters.from" type="date" /><label for="interview-to">发生日期 to（不含）</label><input id="interview-to" v-model="filters.to" type="date" /><label for="interview-status">面谈状态</label><select id="interview-status" v-model="filters.status"><option value="">全部获准</option><option v-for="status in ['scheduled', 'in_progress', 'completed', 'cancelled']" :key="status" :value="status">{{ status }}</option></select><label for="interview-limit">每页条数</label><input id="interview-limit" v-model="filters.limit" type="number" min="1" max="100" /><button type="submit">应用面谈筛选</button></fieldset></form>
      <p>组织授权日 {{ list.as_of }} · consistency {{ list.consistency }}；日期查询不能恢复旧权限。</p>
      <ul aria-label="获准面谈列表"><li v-for="item in list.items" :key="item.id"><a :href="`/interviews/${item.id}`" @click="navigate($event, `/interviews/${item.id}`)">查看面谈 {{ item.id }}</a> · {{ item.status }} · revision {{ item.revision }} · 计划 {{ item.scheduled_at }} · 实际 {{ item.actual_started_at ?? '尚未开始' }} / {{ item.actual_ended_at ?? '尚未结束' }} · 录入 {{ item.recorded_at }} · {{ item.backfilled ? '历史补录' : '计划录入' }}</li></ul>
      <p v-if="!list.items.length">此条件下无获准面谈。</p><button v-if="list.next_cursor" type="button" :disabled="busy || uncertain" @click="nextPage()">下一页面谈</button>
      <form v-if="permits('interview.read', 'metadata') && (permits('interview.write', 'metadata') || permits('interview.create', 'metadata'))" aria-label="安排或历史补录" @submit.prevent="createInterview"><h2>安排或历史补录</h2><fieldset :disabled="busy || uncertain"><label for="interview-scheduled">计划时间（RFC3339 UTC）</label><input id="interview-scheduled" v-model="schedule.at" required autocomplete="off" /><label for="interview-backfilled"><input id="interview-backfilled" v-model="schedule.backfilled" type="checkbox" />历史补录（完成事实，不伪造及时录入）</label><template v-if="schedule.backfilled"><label for="interview-actual-start">实际开始（RFC3339 UTC）</label><input id="interview-actual-start" v-model="schedule.start" required autocomplete="off" /><label for="interview-actual-end">实际结束（RFC3339 UTC）</label><input id="interview-actual-end" v-model="schedule.end" required autocomplete="off" /></template><label for="interview-participants">明确参与者（subject:UUID / employee:UUID，空白分隔；不授权限）</label><textarea id="interview-participants" v-model="schedule.participants" autocomplete="off" /><button type="submit">{{ schedule.backfilled ? '补录面谈' : '安排面谈' }}</button></fieldset></form>
    </template>
    <template v-if="mode === 'detail' && detail">
      <section aria-label="面谈事实"><h2>面谈 {{ detail.interview.id }}</h2><a :href="`/employees/${detail.interview.employee_id}/interviews`" @click="navigate($event, `/employees/${detail.interview.employee_id}/interviews`)">员工面谈列表</a><dl><dt>状态 / revision</dt><dd>{{ detail.interview.status }} / {{ detail.interview.revision }}</dd><dt>计划时间</dt><dd>{{ detail.interview.scheduled_at }}</dd><dt>实际开始 / 结束</dt><dd>{{ detail.interview.actual_started_at ?? '未开始' }} / {{ detail.interview.actual_ended_at ?? '未结束' }}</dd><dt>录入事实</dt><dd>{{ detail.interview.recorded_at }} · 作者 {{ detail.interview.author_subject_id }} · {{ detail.interview.backfilled ? '历史补录' : '正常安排' }}</dd><dt>参与者（不授权限）</dt><dd v-for="party in detail.interview.participants" :key="`${party.kind}:${party.id}`">{{ party.kind }} {{ party.id }}</dd></dl><p v-if="terminal">面谈已终结，不可重新打开；完成后的笔记纠正须新版本与明确理由，行动不会自动关闭。</p></section>
      <section aria-label="不可变面谈状态历史">
        <h2>当前获准状态与录入历史</h2>
        <ol><li v-for="event in detail.interview_events" :key="event.id">
          {{ event.status }} · revision {{ event.revision }} · 作者 {{ event.author_subject_id }} · 录入 {{ event.recorded_at }}
          · 实际开始 {{ event.actual_started_at ?? '未设置' }} / 结束 {{ event.actual_ended_at ?? '未设置' }} · {{ event.backfilled ? '明确历史补录' : '正常状态记录' }}
          <p v-if="event.reason !== undefined" class="plaintext">独立获准的安全原因：{{ event.reason }}</p>
        </li></ol>
      </section>
      <form aria-label="授权历史分页范围" @submit.prevent="changeHistoryScope">
        <label for="interview-history-scope">获准历史范围（更换范围重新读取，不混用游标）</label>
        <select id="interview-history-scope" v-model="historyScope" @change="changeHistoryScope"><option value="">全部当前获准内容</option><option v-for="category in sections.filter(category => permits('note.read', category))" :key="category" :value="category">{{ category }}</option><option v-if="permits('action.read', 'shared')" value="actions">共享行动</option></select>
      </form>
      <button v-if="detail.next_cursor" type="button" :disabled="busy || uncertain" @click="nextPage()">下一页获准内容</button>
      <form v-if="!terminal && permits('interview.write', 'metadata')" aria-label="面谈状态转换" @submit.prevent>
        <fieldset :disabled="busy || uncertain">
          <template v-if="detail.interview.status === 'scheduled'">
            <label for="transition-start">实际开始（UTC）</label><input id="transition-start" v-model="state.start" autocomplete="off" />
            <button type="button" @click="transitionInterview('start')">开始面谈</button>
            <label for="transition-backfill-confirm"><input id="transition-backfill-confirm" v-model="state.backfilledConfirmed" type="checkbox" />我明确确认这是已发生面谈的历史补录，不伪造及时录入</label>
            <template v-if="state.backfilledConfirmed">
              <label for="transition-backfill-end">补录实际结束（UTC）</label><input id="transition-backfill-end" v-model="state.end" autocomplete="off" />
              <button type="button" @click="transitionInterview('complete')">历史补录完成</button>
            </template>
          </template>
          <template v-if="detail.interview.status === 'in_progress'">
            <label for="transition-end">实际结束（UTC）</label><input id="transition-end" v-model="state.end" autocomplete="off" /><button type="button" @click="transitionInterview('complete')">完成面谈</button>
          </template>
          <label for="transition-reason">安全转换原因（取消必填）</label><textarea id="transition-reason" v-model="state.reason" autocomplete="off" /><button type="button" @click="transitionInterview('cancel')">取消面谈</button>
        </fieldset>
      </form>
      <section v-for="section in detail.sections" :key="section.category" :aria-label="`${section.category} 授权版本历史`">
        <h2>{{ section.category }} · 仅当前获准版本</h2><p v-if="section.head_revision">当前 head revision {{ section.head_revision }}</p>
        <article v-for="version in section.versions" :key="version.id" :data-note-version="version.id">
          <h3>{{ version.status }} · version {{ version.version_no }}</h3><p>作者 {{ version.author_subject_id }} · 录入 {{ version.recorded_at }}</p>
          <p class="plaintext">{{ version.text }}</p><p>修订理由：{{ version.edit_reason || '未设置' }}</p>
          <p v-for="source in version.source_refs" :key="source.id">当前独立获准的来源引用 {{ source.kind }} {{ source.id }} · expected version {{ source.expected_version }}（引用不授权限，不提供旁路）</p>
          <p v-if="version.supersedes_version_id">替代的获准版本 {{ version.supersedes_version_id }}</p>
          <button type="button" :disabled="uncertain" :aria-label="`重取历史版本 ${version.id}`" @click="readVersion(version)">重取此授权历史版本</button>
        </article>
      </section>
      <section v-if="historical" aria-label="独立重取的授权历史版本"><h2>不可变历史 version {{ historical.version_no }}</h2><p class="plaintext">{{ historical.text }}</p><p>{{ historical.edit_reason }} · 作者 {{ historical.author_subject_id }} · {{ historical.recorded_at }}</p></section>
      <form v-if="editableCategories.length && detail.interview.status !== 'cancelled'" :aria-label="`${note.category || '选择分区'} 笔记编辑`" @submit.prevent="saveNote('save_draft')"><h2>独立分区新版本（不修改类别或权限）</h2><label for="note-category">当前允许编辑的分区</label><select id="note-category" v-model="note.category" @change="chooseCategory"><option value="">明确选择</option><option v-for="category in editableCategories" :key="category" :value="category">{{ category }}</option></select><fieldset v-if="note.category" :disabled="busy || uncertain"><label for="note-supersedes">替代此分区的获准版本（已有分区必选，须理由）</label><select id="note-supersedes" v-model="note.supersedes" :required="Boolean(selectedSection)"><option value="">{{ selectedSection ? '明确选择获准被替代版本' : '首次独立版本' }}</option><option v-for="version in selectedSection?.versions" :key="version.id" :value="version.id">{{ version.status }} version {{ version.version_no }}</option></select><label for="note-text">手工新正文（不会复制源文字）</label><textarea id="note-text" v-model="note.text" required autocomplete="off" /><label for="note-reason">明确修订理由（已有分区/已完成必填）</label><textarea id="note-reason" v-model="note.reason" :required="Boolean(selectedSection) || detail.interview.status === 'completed'" autocomplete="off" /><label for="note-sources">明确已获准读取的发布来源版本</label><select id="note-sources" v-model="note.sourceIDs" multiple><option v-for="source in sources" :key="source.id" :value="source.id">{{ source.category }} version {{ source.version_no }} · {{ source.id }}</option></select><label for="note-minimized"><input id="note-minimized" v-model="note.minimized" type="checkbox" />我已人工选取最小必要内容；跨分区来源另经独立批准，不自动复制</label><button type="submit">保存新草稿</button><template v-if="permits('note.publish', note.category)"><label for="note-publish-confirm"><input id="note-publish-confirm" v-model="note.publishConfirmed" type="checkbox" />明确发布新不可变版本，不增加读者权限</label><button type="button" @click="saveNote('publish')">发布新版本</button></template></fieldset></form>
      <section v-if="permits('action.read', 'shared')" aria-label="共享行动项">
        <h2>当前获准共享行动</h2>
        <label for="action-filter-status">行动状态筛选（当前获准页）</label><select id="action-filter-status" v-model="actionStatus"><option value="">全部获准</option><option v-for="status in ['todo', 'in_progress', 'done', 'cancelled']" :key="status" :value="status">{{ status }}</option></select>
        <label for="action-filter-due">行动截止日期筛选（当前获准页）</label><input id="action-filter-due" v-model="actionDue" type="date" />
        <article v-for="item in visibleActions" :key="item.id" :data-action-item="item.id">
          <h3>{{ item.status }} · revision {{ item.revision }}</h3><p class="plaintext">{{ item.minimal_shared_text }}</p>
          <p v-for="source in item.source_refs" :key="source.id">保留的当前获准来源引用 {{ source.kind }} {{ source.id }} · expected version {{ source.expected_version }}（不复制源正文）</p>
          <p>责任人 {{ item.owner.kind }} {{ item.owner.id }} · 截止 {{ item.due_date ?? '未设置' }} · {{ item.overdue ? '当前组织日已逾期' : '未逾期' }}</p><p class="plaintext">{{ item.safe_blocker_text }}</p>
          <ol aria-label="不可变行动历史"><li v-for="event in item.events" :key="event.id">{{ event.status }} · revision {{ event.revision }} · 作者 {{ event.author_subject_id }} · {{ event.recorded_at }} · {{ event.safe_blocker_text }}</li></ol>
          <template v-if="permits('action.write', 'shared') && !['done', 'cancelled'].includes(item.status)">
            <button v-if="item.status === 'todo'" type="button" :disabled="busy || uncertain" :aria-label="`开始行动 ${item.id}`" @click="transitionAction(item, 'start')">开始行动</button>
            <button type="button" :disabled="busy || uncertain" :aria-label="`完成行动 ${item.id}`" @click="transitionAction(item, 'complete')">完成行动</button>
            <button type="button" :disabled="busy || uncertain" :aria-label="`取消行动 ${item.id}`" @click="transitionAction(item, 'cancel')">取消行动</button>
          </template>
        </article>
        <label v-if="permits('action.write', 'shared')" for="action-blocker">安全状态说明（不可写私有源正文）</label><textarea v-if="permits('action.write', 'shared')" id="action-blocker" v-model="blocker" autocomplete="off" />
      </section>
      <form v-if="!terminal && permits('action.read', 'shared') && permits('action.write', 'shared')" aria-label="创建共享行动" @submit.prevent="createAction"><h2>创建独立共享行动</h2><fieldset :disabled="busy || uncertain"><label for="action-text">手工最小共享行动文字</label><textarea id="action-text" v-model="action.text" required autocomplete="off" /><label for="action-owner-kind">现有责任人类型</label><select id="action-owner-kind" v-model="action.ownerKind"><option value="subject">subject</option><option value="employee">employee</option></select><label for="action-owner-id">现有同组织责任人 ID</label><input id="action-owner-id" v-model="action.ownerID" required autocomplete="off" /><label for="action-due">截止日（留空明确未设置）</label><input id="action-due" v-model="action.due" type="date" /><label for="action-sources">明确获准发布来源版本</label><select id="action-sources" v-model="action.sourceIDs" multiple><option v-for="source in sources" :key="source.id" :value="source.id">{{ source.category }} version {{ source.version_no }} · {{ source.id }}</option></select><label for="action-minimized"><input id="action-minimized" v-model="action.minimized" type="checkbox" />人工最小化；私有来源已另经独立目标批准</label><button type="submit">创建共享行动</button></fieldset></form>
      <section v-if="exportObjects.length" aria-label="有限对象敏感导出"><h2>明确所选对象 NDJSON 导出</h2><p>最多 100 个对象 / 8 MiB；额外读取、导出与会话 MFA，每个实际输出均重新授权。不保存明文到浏览器存储或 URL。</p><label v-for="object in exportObjects" :key="`${object.kind}:${object.id}`"><input v-model="exportSelection" type="checkbox" :value="`${object.kind}:${object.id}`" :disabled="busy || uncertain" />{{ object.kind }} {{ object.id }} · expected revision {{ object.expected_revision }}</label><button type="button" :disabled="busy || uncertain" @click="exportSelected">导出所选对象</button><p v-if="exportStatus" role="status">{{ exportStatus }}</p><pre v-if="exportOutput" aria-label="当前内存 NDJSON 输出">{{ exportOutput }}</pre></section>
    </template>
    <section v-if="uncertain" aria-label="面谈命令结果尚未确认"><p>原命令可能已提交。仅显式重放同一键与原正文，重新核对当前权限；不创建新键、不覆盖新 head。</p><button type="button" :disabled="busy" @click="lastCommand && execute(lastCommand, true)">重试原命令</button></section>
    <button v-if="mode === 'detail' && !uncertain" type="button" :disabled="busy" @click="grantOpen = !grantOpen">{{ grantOpen ? '关闭独立授权管理' : '独立授权与最小来源批准（P-SEC-01）' }}</button>
    <GrantPage v-if="grantOpen" @session-expired="expire" @grant-result="grantResult" />
  </main>
</template>

<style scoped>
main { max-width: 72rem; margin: 1.5rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; }
section, form { margin: 1.5rem 0; padding: 1rem; border: 1px solid #9ba4ae; border-radius: .25rem; }
fieldset { display: grid; gap: .5rem; border: 0; padding: 0; } input, select, textarea { padding: .45rem; max-width: 46rem; } textarea { min-height: 5rem; }
button { padding: .5rem .8rem; margin: .4rem .5rem .4rem 0; cursor: pointer; } button:disabled { cursor: not-allowed; }
article { border-top: 1px solid #9ba4ae; padding: .7rem 0; } li, dd { overflow-wrap: anywhere; } dt { font-weight: 600; margin-top: .7rem; } dd { margin-left: 0; }
.plaintext, pre { white-space: pre-wrap; overflow-wrap: anywhere; } [role="alert"] { color: #8a1717; } [role="status"] { color: #165129; }
</style>
