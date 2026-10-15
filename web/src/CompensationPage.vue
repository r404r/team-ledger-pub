<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from 'vue'
import GrantPage from './GrantPage.vue'
import CompensationTermsEditor from './CompensationTermsEditor.vue'
import { uuid, validDate, validRevision, validCompRevision, timestamp, validCurrent, validChanges, validSession, validProposal, validMapping, validCommand, formTerms, termsForm, emptyTerms, sameIdentity, statuses, type Session, type CurrentView, type ChangesView, type ProposalView, type CorrectionMember, type ProposalCommand, type TermsForm, type ExportObject, type Result, type TransitionCommand } from './compensationDTO'
import { FinancialFailure, financialJSON, financialRequest, financialExport, type FinancialCommand } from './compensationAPI'
import type { ApprovalEvent } from './compensationDTO'
const props = defineProps<{ queryDate?: string }>()
const emit = defineEmits<{ 'session-expired': [] }>()
type Operation = { generation: number; controller: AbortController }
type MemberForm = { key: string; action: 'replace' | 'reverse'; original: string; date: string; refKind: string; ref: string; terms: TermsForm }
const session = shallowRef<Session | null>(null), current = shallowRef<CurrentView | null>(null)
const proposals = shallowRef<ChangesView | null>(null), approvals = shallowRef<ChangesView | null>(null)
const revisions = shallowRef<ChangesView | null>(null), revisionBusy = ref(false), revisionError = ref('')
const revisionTarget = shallowRef<{ id: string } | null>(null), revisionFirstPage = ref(true), revisionAuthorizationUntil = ref('')
const revisionPageLimit = 20
const employee = ref(''), active = ref(false), phase = ref('idle'), error = ref(''), notice = ref('')
const currentDenied = ref(false), proposalsDenied = ref(false), approvalsDenied = ref(false)
const query = reactive({ asOf: '', from: '', to: '', status: '', proposalID: '', limit: '50', futureLimit: '20' })
const applied = reactive({ asOf: '', from: '', to: '', status: '', proposalID: '', limit: '50', futureLimit: '20' })
const editor = reactive({ open: false, id: '', revision: '', basis: '', kind: 'initial' as ProposalCommand['kind'], date: '', before: '', reason: '', terms: emptyTerms(), members: [] as MemberForm[] })
const decision = reactive({ id: '', action: '' as TransitionCommand['action'] | '', revision: '', basis: '', reason: '', confirmed: false })
const confirmed = ref(false), replayConfirmed = ref(false), uncertain = ref(false), grantOpen = ref(false)
const pending = shallowRef<FinancialCommand | null>(null)
const queuedViewDate = ref('')
const exportSelection = ref<string[]>([]), exportOutput = ref(''), exportStatus = ref(''), exportConfirmed = ref(false)
const exactExportRows = ref<{ kind: string; id: string; revision: string }[]>([])
const transitionStatuses: Record<string, string> = { submit: 'submitted', withdraw: 'withdrawn', approve: 'approved', reject: 'rejected' }
let alive = false, generation = 0, controller: AbortController | null = null
let revisionGeneration = 0, revisionController: AbortController | null = null
let timer: ReturnType<typeof setInterval> | null = null
const busy = computed(() => phase.value !== 'idle')
const basis = computed(() => current.value?.comp_revision ?? proposals.value?.comp_revision ?? approvals.value?.comp_revision ?? '')
const permissions = computed(() => current.value?.permissions ?? session.value?.compensation_permissions ?? [])
const correctionContext = computed(() => {
  const visible = (approvals.value?.approvals ?? []).flatMap(approval => approval.events)
  const successors = new Map<string, ApprovalEvent[]>()
  for (const event of visible) if (event.before_term_id) { const list = successors.get(event.before_term_id) ?? []; list.push(event); successors.set(event.before_term_id, list) }
  const queue = visible.filter(event => editor.members.some(member => member.original === event.id))
  const seen = new Set<string>(), result: ApprovalEvent[] = []
  for (let index = 0; index < queue.length; index++) {
    const event = queue[index]!
    if (seen.has(event.id)) continue
    seen.add(event.id); result.push(event)
    if (event.after_term_id) queue.push(...successors.get(event.after_term_id) ?? [])
  }
  return result
})
const correctionDates = computed(() => [...editor.members.map(member => member.date), ...correctionContext.value.map(event => event.effective_date)].filter(validDate).sort())
function proposalPermits(p: ProposalView, capability: string): boolean { return p.permissions.some(hint => hint.capability === 'compensation.read' && hint.category === 'financial') && p.permissions.some(hint => hint.capability === capability && hint.category === 'financial') }
function commandAllowed(path: string, capability: string): boolean {
  const match = /^\/compensation\/proposals\/([0-9a-f-]+)(?:\/transitions)?$/.exec(path)
  if (match) { const p = proposals.value?.proposals.find(p => p.id === match[1]); return Boolean(p && proposalPermits(p, capability)) }
  return Boolean(current.value && permits('compensation.read') && permits(capability))
}
const exportObjects = computed<ExportObject[]>(() => {
  if (!permits('sensitive.export') && !currentDenied.value && !(proposals.value?.proposals.some(p => proposalPermits(p, 'sensitive.export')))) return []
  const objects: ExportObject[] = [], seen = new Set<string>()
  for (const p of proposals.value?.proposals ?? []) if (permits('sensitive.export') || currentDenied.value || proposalPermits(p, 'sensitive.export')) objects.push({ kind: 'compensation_proposal', id: p.id, expected_revision: p.revision })
  const addTerm = (t: NonNullable<CurrentView['current_term']>) => { if (!seen.has(t.id)) { seen.add(t.id); objects.push({ kind: 'compensation_term', id: t.id, expected_revision: t.revision }) } }
  if (permits('sensitive.export') || currentDenied.value) {
    if (current.value?.current_term) addTerm(current.value.current_term)
    for (const t of current.value?.future_terms ?? []) addTerm(t)
    for (const a of approvals.value?.approvals ?? []) for (const e of a.events) { objects.push({ kind: 'compensation_event', id: e.id, expected_revision: e.revision }); if (e.before) addTerm(e.before); if (e.after) addTerm(e.after) }
  }
  return objects
})
function permits(capability: string): boolean { return permissions.value.some(p => p.capability === capability && p.category === 'financial') }
function clearForms() {
  editor.open = false; editor.id = ''; editor.revision = ''; editor.basis = ''; editor.kind = 'initial'; editor.date = ''; editor.before = ''; editor.reason = ''; editor.terms = emptyTerms(); editor.members = []
  decision.id = ''; decision.action = ''; decision.revision = ''; decision.basis = ''; decision.reason = ''; decision.confirmed = false
  confirmed.value = false; replayConfirmed.value = false; exportSelection.value = []; exportOutput.value = ''; exportStatus.value = ''; exportConfirmed.value = false
  exactExportRows.value = []
}
function clearRevisions() {
  revisionGeneration += 1; revisionController?.abort(); revisionController = null
  revisions.value = null; revisionTarget.value = null; revisionBusy.value = false; revisionError.value = ''; revisionFirstPage.value = true; revisionAuthorizationUntil.value = ''
}
function clearSensitive() { current.value = null; proposals.value = null; approvals.value = null; clearRevisions(); clearForms(); pending.value = null; uncertain.value = false; notice.value = '' }
function cancel() { generation += 1; controller?.abort(); controller = null; phase.value = 'idle'; clearRevisions() }
function begin(next: string): Operation { cancel(); controller = new AbortController(); phase.value = next; error.value = ''; notice.value = ''; return { generation, controller } }
function deadlinesValid(): boolean {
  const now = timestamp(new Date().toISOString())!
  return Boolean(session.value && session.value.mfa_recent && timestamp(session.value.mfa_valid_until)! > now && (!session.value.sensitivity_valid_until || timestamp(session.value.sensitivity_valid_until)! > now) && (!revisionAuthorizationUntil.value || timestamp(revisionAuthorizationUntil.value)! > now) && [current.value, proposals.value, approvals.value, revisions.value].every(v => !v || timestamp(v.authorization_until)! > now))
}
function isCurrent(op: Operation): boolean { return alive && active.value && generation === op.generation && !op.controller.signal.aborted }
async function json<T>(path: string, op: Operation, command?: FinancialCommand): Promise<T> { return financialJSON<T>(path, op.controller.signal, () => isCurrent(op) && (!session.value || deadlinesValid()), command, session.value?.csrf_token) }
async function readSession(op: Operation, expected?: Session, replay = false) {
  const next = await json<Session>('/session', op)
  if (!validSession(next)) throw new FinancialFailure(503)
  if (expected && (!sameIdentity(expected, next) || !replay && expected.auth_epoch !== next.auth_epoch)) throw new FinancialFailure(403)
  if (session.value && (!sameIdentity(session.value, next) || session.value.auth_epoch !== next.auth_epoch)) clearSensitive()
  session.value = next
  if (!deadlinesValid()) throw new FinancialFailure(403)
}
async function readCurrent(op: Operation) {
  if (!applied.asOf) return
  const params = new URLSearchParams({ as_of: applied.asOf, future_limit: applied.futureLimit })
  try {
    const next = await json<CurrentView>(`/employees/${employee.value}/compensation?${params}`, op)
    if (!validCurrent(next, employee.value) || next.as_of !== applied.asOf || timestamp(next.authorization_until)! <= timestamp(new Date().toISOString())!) throw new FinancialFailure(503)
    current.value = next; currentDenied.value = false
  } catch (cause) { if (cause instanceof FinancialFailure && cause.status === 404) { current.value = null; currentDenied.value = true } else throw cause }
}
async function readChanges(kind: 'proposals' | 'approvals', op: Operation, cursor = '', selectedProposal = '') {
  if (!applied.from || !applied.to) return
  const params = new URLSearchParams({ from: applied.from, to: applied.to, record_kind: kind, limit: applied.limit })
  if (kind === 'proposals' && applied.status && !selectedProposal) params.set('status', applied.status)
  if (selectedProposal || applied.proposalID) params.set('proposal_id', selectedProposal || applied.proposalID)
  if (cursor) params.set('cursor', cursor)
  try {
    const next = await json<ChangesView>(`/employees/${employee.value}/compensation/changes?${params}`, op)
    if (!validChanges(next, employee.value, kind) || timestamp(next.authorization_until)! <= timestamp(new Date().toISOString())!) throw new FinancialFailure(503)
    if (kind === 'proposals') { proposals.value = next; proposalsDenied.value = false } else { approvals.value = next; approvalsDenied.value = false }
  } catch (cause) { if (cause instanceof FinancialFailure && cause.status === 404) { if (kind === 'proposals') { proposals.value = null; proposalsDenied.value = true } else { approvals.value = null; approvalsDenied.value = true } } else throw cause }
}
async function revisionPage(proposal: ProposalView, older = false) {
  const context = session.value, previous = revisions.value
  const cursor = older && revisionTarget.value?.id === proposal.id ? previous?.next_cursor ?? '' : ''
  const before = cursor ? previous?.revisions.at(-1)?.revision : undefined
  if (busy.value || uncertain.value || !context || !proposalPermits(proposal, 'compensation.read') || older && (!cursor || revisionBusy.value)) return
  if (!deadlinesValid()) { expire(); return }
  clearRevisions()
  revisionTarget.value = { id: proposal.id }; revisionBusy.value = true
  if (cursor) revisionAuthorizationUntil.value = previous!.authorization_until
  revisionController = new AbortController()
  const localGeneration = revisionGeneration, localController = revisionController, mainGeneration = generation, selectedEmployee = employee.value
  const currentRequest = () => alive && active.value && mainGeneration === generation && localGeneration === revisionGeneration && !localController.signal.aborted && session.value !== null && sameIdentity(context, session.value) && context.auth_epoch === session.value.auth_epoch
  try {
    const nextSession = await financialJSON<Session>('/session', localController.signal, () => currentRequest() && deadlinesValid())
    if (!validSession(nextSession)) throw new FinancialFailure(503)
    if (!sameIdentity(context, nextSession) || context.auth_epoch !== nextSession.auth_epoch) throw new FinancialFailure(403)
    session.value = nextSession
    if (!deadlinesValid()) throw new FinancialFailure(403)
    const params = new URLSearchParams({ record_kind: 'proposal_revisions', proposal_id: proposal.id, limit: String(revisionPageLimit) })
    if (cursor) params.set('cursor', cursor)
    const next = await financialJSON<ChangesView>(`/employees/${selectedEmployee}/compensation/changes?${params}`, localController.signal, () => currentRequest() && deadlinesValid())
    if (!validChanges(next, selectedEmployee, 'proposal_revisions', proposal.id, revisionPageLimit) || !cursor && next.revisions[0]?.revision !== next.proposals[0]!.revision || before && next.revisions.some(r => BigInt(r.revision) >= BigInt(before))) throw new FinancialFailure(503)
    if (timestamp(next.authorization_until)! <= timestamp(new Date().toISOString())!) { expire(); return }
    if (next.proposals[0]!.revision !== proposal.revision) throw new FinancialFailure(409)
    revisions.value = next; revisionFirstPage.value = !cursor; revisionAuthorizationUntil.value = next.authorization_until
  } catch (cause) {
    if (!currentRequest()) return
    if (!deadlinesValid()) { expire(); return }
    const status = cause instanceof FinancialFailure ? cause.status : 503
    revisions.value = null; revisionAuthorizationUntil.value = ''
    if ([401, 403, 404].includes(status)) {
      cancel(); clearSensitive(); session.value = null; grantOpen.value = false
      error.value = '修订历史当前授权、会话或 MFA 已失效；财务内容已销毁，请重新验证后手动重载。'
      if (status === 401) emit('session-expired')
    } else {
      revisionError.value = [409, 422].includes(status) ? '修订页版本或游标已失效；本页已销毁。请手动刷新当前提案，再明确打开最新修订页，不会自动续接旧版本。' : '修订页未确认；本页已销毁，请手动重新加载最新页。'
    }
  } finally {
    if (localGeneration === revisionGeneration) { revisionBusy.value = false; revisionController = null }
  }
}
async function readViews(op: Operation) { await readCurrent(op); await readChanges('proposals', op); await readChanges('approvals', op); if (!deadlinesValid()) throw new FinancialFailure(403) }
function fail(cause: unknown, op: Operation) {
  if (!isCurrent(op)) return
  const status = cause instanceof FinancialFailure ? cause.status : 503
  if (!uncertain.value || [401, 403, 404, 409].includes(status)) clearSensitive()
  if ([401, 403, 404].includes(status)) { cancel(); session.value = null; grantOpen.value = false; if (status === 401) emit('session-expired') }
  error.value = status === 401 ? '会话已失效，财务内容与表单已销毁。' : [403, 404].includes(status) ? '当前对象、purpose、scope、授权或 MFA 不满足要求；财务内容已清空。重新验证后须重载并明确重新确认。' : status === 409 ? '版本或完整依赖冲突（409）：未覆盖批准历史。请手动刷新后重新核对整个下游依赖组；不会自动重试或改基准。' : [400, 422].includes(status) ? '输入被拒绝；请核对明确口径、规范金额、版本、日期、原事件和完整依赖组。' : '服务或网络不可用，结果未确认；不显示成功，不自动重发。'
}
async function refresh() {
  if (busy.value || uncertain.value || !active.value) return
  const op = begin('loading'); clearSensitive()
  try { await readSession(op); await readViews(op) } catch (cause) { fail(cause, op) } finally { if (isCurrent(op)) { phase.value = 'idle'; controller = null } }
}
async function applyQueries() {
  if (busy.value || uncertain.value) return
  if (!validDate(query.asOf) || !timestamp(query.from) || !timestamp(query.to) || timestamp(query.from)! >= timestamp(query.to)! || query.proposalID && !uuid.test(query.proposalID) || query.status && !statuses.includes(query.status) || !/^[1-9][0-9]{0,2}$/.test(query.limit) || Number(query.limit) > 100 || !/^[1-9][0-9]{0,2}$/.test(query.futureLimit) || Number(query.futureLimit) > 100) { error.value = '请明确查询日、[from,to) 录入 UTC 时间窗口、允许状态/提案 UUID；历史与未来查询上限均须 1..100。'; return }
  Object.assign(applied, query); await refresh()
}
async function nextPage(kind: 'proposals' | 'approvals') {
  const cursor = (kind === 'proposals' ? proposals.value : approvals.value)?.next_cursor, context = session.value
  if (!cursor || busy.value || uncertain.value || !context) return
  const op = begin('loading'); clearSensitive()
  try { await readSession(op, context); await readCurrent(op); await readChanges(kind, op, cursor) } catch (cause) { fail(cause, op) } finally { if (isCurrent(op)) { phase.value = 'idle'; controller = null } }
}
function newProposal() {
  if (!current.value || !permits('compensation.propose') || busy.value || uncertain.value) return
  clearForms(); editor.open = true; editor.basis = current.value.comp_revision
}
function editProposal(p: ProposalView) {
  if (p.status !== 'draft' || !proposalPermits(p, 'compensation.propose') || busy.value || uncertain.value) return
  clearForms(); Object.assign(editor, { open: true, id: p.id, revision: p.revision, basis: basis.value, kind: p.kind, date: p.effective_date, before: p.before_term_id ?? '', reason: p.reason, terms: p.after ? termsForm(p.after) : emptyTerms(), members: p.members.map(m => ({ key: m.member_key, action: m.action, original: m.original_event_id, date: m.effective_date, refKind: m.before_ref?.term_id ? 'term_id' : m.before_ref?.member_key ? 'member_key' : '', ref: m.before_ref?.term_id ?? m.before_ref?.member_key ?? '', terms: m.after ? termsForm(m.after) : emptyTerms() })) })
}
function addMember() { if (editor.members.length < 100) editor.members.push({ key: '', action: 'replace', original: '', date: '', refKind: '', ref: '', terms: emptyTerms() }) }
function commandBody(): ProposalCommand | null {
  const members: CorrectionMember[] = editor.kind === 'correction' ? editor.members.map(m => ({ member_key: m.key, action: m.action, original_event_id: m.original, effective_date: m.date, before_ref: m.action === 'reverse' || !m.refKind ? null : { term_id: m.refKind === 'term_id' ? m.ref : null, member_key: m.refKind === 'member_key' ? m.ref : null }, after: m.action === 'reverse' ? null : formTerms(m.terms) })) : []
  const body: ProposalCommand = { kind: editor.kind, effective_date: editor.date, comp_revision: editor.basis, before_term_id: editor.kind === 'adjustment' ? editor.before : null, after: editor.kind === 'correction' ? null : formTerms(editor.terms), reason: editor.reason, members }
  return validCommand(body) ? body : null
}
function saveProposal() {
  const body = commandBody()
  if (!body || !confirmed.value || editor.id && !validRevision(editor.revision)) { error.value = '须明确完整条款、规范金额/费率、理由、真实日期、原始 R/B、严格引用及全部纠错成员，并人工确认；不自动补入下游。'; return }
  queue(editor.id ? `/compensation/proposals/${editor.id}` : `/employees/${employee.value}/compensation/proposals`, editor.id ? 'PATCH' : 'POST', editor.id ? { ...body, revision: editor.revision } : body, 'compensation.propose')
}
function selectTransition(p: ProposalView, action: TransitionCommand['action']) {
  if (busy.value || uncertain.value || (['approve', 'reject'].includes(action) ? !proposalPermits(p, 'compensation.approve') || p.status !== 'submitted' || action === 'approve' && p.author_subject_id === session.value?.subject_id : !proposalPermits(p, 'compensation.propose') || !['draft', 'submitted'].includes(p.status) || action === 'submit' && p.status !== 'draft')) return
  clearForms(); Object.assign(decision, { id: p.id, action, revision: p.revision, basis: basis.value })
}
function transition() {
  if (!decision.action || !decision.confirmed || !validRevision(decision.revision) || !validCompRevision(decision.basis) || new TextEncoder().encode(decision.reason).length > 4096 || decision.action !== 'submit' && !decision.reason.trim()) { error.value = '请核对冻结提案 R、当前员工 B 和独立决策理由并明确确认。提交冻结原提案原因，不增加审批决策。'; return }
  queue(`/compensation/proposals/${decision.id}/transitions`, 'POST', { action: decision.action, revision: decision.revision, comp_revision: decision.basis, decision_reason: decision.action === 'submit' ? '' : decision.reason }, ['approve', 'reject'].includes(decision.action) ? 'compensation.approve' : 'compensation.propose')
}
function queue(path: string, method: 'POST' | 'PATCH', body: unknown, capability: string, exporting = false) {
  if (busy.value || uncertain.value || !session.value || !deadlinesValid() || !exporting && !commandAllowed(path, capability)) return
  const command: FinancialCommand = { path, method, body: JSON.stringify(body), key: crypto.randomUUID(), context: { ...session.value }, capability, exporting }
  pending.value = command; void execute(command)
}
function adoptQueuedViewDate(reload: boolean) {
  if (!queuedViewDate.value) return
  const next = queuedViewDate.value
  queuedViewDate.value = ''
  query.asOf = next
  applied.asOf = next
  if (reload) void refresh()
}
async function execute(command: FinancialCommand, replay = false) {
  if (busy.value) return
  const op = begin('submitting'); let sent = false, committed = false
  uncertain.value = false; clearRevisions(); clearForms(); current.value = null; proposals.value = null; approvals.value = null
  try {
    await readSession(op, command.context, replay); await readViews(op)
    const target = /^\/compensation\/proposals\/([0-9a-f-]+)(?:\/transitions)?$/.exec(command.path)
    if (target) await readChanges('proposals', op, '', target[1]!)
    if (!deadlinesValid() || !command.exporting && !commandAllowed(command.path, command.capability)) throw new FinancialFailure(403)
    // Frozen command bytes and original R/B survive authorization refresh; never rebase.
    sent = true
    if (command.exporting) {
      const objects: ExportObject[] = JSON.parse(command.body).objects
      const response = await financialRequest(command.path, op.controller.signal, () => isCurrent(op) && deadlinesValid(), command, session.value!.csrf_token)
      const status = await financialExport(response, employee.value, objects, () => isCurrent(op) && deadlinesValid(), line => { exportOutput.value += line })
      if (status === 'partial') { clearSensitive(); error.value = '导出部分释放后中断；当前内存已销毁，未确认完整导出。已收到的外部副本无法远程撤回。'; return }
      pending.value = null; exportStatus.value = '所选明确对象导出完成；仅在当前内存显示，已复制内容不能远程撤回。'; return
    }
    const result = await json<Result>(command.path, op, command)
    if (!result || !uuid.test(result.id) || !validRevision(result.revision) || !validCompRevision(result.comp_revision) || !statuses.includes(result.status) || result.proposal !== null && !validProposal(result.proposal, employee.value) || !Array.isArray(result.members) || !result.members.every(validMapping)) throw new FinancialFailure(503)
    const expectedStatus = command.path.endsWith('/transitions') ? transitionStatuses[JSON.parse(command.body).action] : 'draft'
    if (result.status !== expectedStatus || target && result.id !== target[1]) throw new FinancialFailure(503)
    committed = true; clearSensitive(); phase.value = 'verifying'
    await readSession(op, command.context, true); await readViews(op)
    notice.value = '服务器已确认此独立命令提交，并重载当前获准事实；提案不等于批准，授权请求也不是组合事务。'
  } catch (cause) {
    if (!isCurrent(op)) return
    const status = cause instanceof FinancialFailure ? cause.status : 503
    if (sent && !committed && !command.exporting && ![400, 401, 403, 404, 409, 422].includes(status)) { clearSensitive(); pending.value = command; uncertain.value = true }
    else if (command.exporting || !sent) clearSensitive()
    fail(cause, op)
    if ([401, 403, 404].includes(status)) adoptQueuedViewDate(false)
    if (committed) { clearSensitive(); notice.value = '此命令已提交，但当前授权回读未完成；不宣称已提交事实回滚。请手动刷新。' }
  } finally {
    if (isCurrent(op)) {
      phase.value = 'idle'
      controller = null
      if (!uncertain.value) adoptQueuedViewDate(true)
    }
  }
}
function replay() { if (!replayConfirmed.value || !uncertain.value || !pending.value) return; const command = pending.value; void execute(command, true) }
function exportSelected() {
  const selected = exportObjects.value.filter(o => exportSelection.value.includes(`${o.kind}:${o.id}`))
  if (!exportConfirmed.value || selected.length !== exportSelection.value.length || exactExportRows.value.some(row => !['compensation_proposal', 'compensation_event', 'compensation_term'].includes(row.kind) || !uuid.test(row.id) || !validRevision(row.revision))) { error.value = '请明确选择或输入确切对象类型、规范 UUID、正 int64 版本字符串，并人工确认独立财务导出。'; return }
  selected.push(...exactExportRows.value.map(row => ({ kind: row.kind as ExportObject['kind'], id: row.id, expected_revision: row.revision })))
  if (!selected.length || selected.length > 100 || new Set(selected.map(object => `${object.kind}:${object.id}`)).size !== selected.length) { error.value = '须为至多一百个不重复的明确对象及版本；不会自动去重或改版本。'; return }
  queue('/sensitive-exports', 'POST', { format: 'ndjson', objects: selected }, 'sensitive.export', true)
}
async function grantResult() {
  grantOpen.value = false
  await refresh()
  if (alive && active.value && session.value && !error.value) notice.value = '独立授权操作完成；财务事实已重新加载，须重新编辑并确认，未自动提出、审批或导出。'
}
function expire() { cancel(); clearSensitive(); queuedViewDate.value = ''; session.value = null; grantOpen.value = false; error.value = '财务授权或近期 MFA 期限已到，内容与命令已销毁；重新验证后须重载并明确确认。' }
function readRoute() {
  const url = new URL(location.href), match = /^\/employees\/([0-9a-f-]+)\/compensation\/?$/.exec(url.pathname)
  cancel(); clearSensitive(); queuedViewDate.value = ''; session.value = null; grantOpen.value = false
  active.value = Boolean(match && uuid.test(match[1]!)); employee.value = active.value ? match![1]! : ''
  Object.assign(query, { asOf: '', from: '', to: '', status: '', proposalID: '', limit: '50', futureLimit: '20' }); Object.assign(applied, query)
  const globalDate = validDate(props.queryDate) ? props.queryDate! : ''
  if (globalDate) { query.asOf = globalDate; applied.asOf = globalDate }
  else if (url.searchParams.getAll('as_of').length === 1 && validDate(url.searchParams.get('as_of'))) { query.asOf = url.searchParams.get('as_of')!; applied.asOf = query.asOf }
  if (active.value) void refresh()
}
function onFocus() { if (!active.value) return; if (!deadlinesValid()) expire(); else void refresh() }
watch(() => props.queryDate, (next) => {
  if (!alive || !active.value || !validDate(next)) return
  if (next === applied.asOf) {
    queuedViewDate.value = ''
    return
  }
  if (uncertain.value || busy.value && phase.value !== 'loading') {
    queuedViewDate.value = next!
    exportOutput.value = ''
    exportStatus.value = ''
    exportSelection.value = []
    exactExportRows.value = []
    return
  }
  if (phase.value === 'loading') cancel()
  queuedViewDate.value = ''
  query.asOf = next!
  applied.asOf = next!
  void refresh()
})
onMounted(() => { alive = true; readRoute(); window.addEventListener('popstate', readRoute); window.addEventListener('focus', onFocus); window.addEventListener('pagehide', expire); timer = setInterval(() => { if (session.value && !deadlinesValid()) expire() }, 250) })
onBeforeUnmount(() => { alive = false; window.removeEventListener('popstate', readRoute); window.removeEventListener('focus', onFocus); window.removeEventListener('pagehide', expire); if (timer) clearInterval(timer); cancel(); clearSensitive(); session.value = null })
</script>

<template>
  <main v-if="active" aria-label="员工薪酬工作台">
    <h1>员工薪酬 · {{ employee }}</h1>
    <p>financial / compensation_management · 当前独立 scope、grant 与 MFA。读、提出、审批和导出彼此独立；作者、普通经理、HR 或员工身份不自动授权。金额与版本保持原始字符串。</p>
    <p v-if="error" role="alert">{{ error }}</p><p v-if="notice" role="status">{{ notice }}</p>
    <button type="button" :disabled="busy || uncertain" @click="refresh">手动刷新当前授权与事实（清空草稿）</button>
    <form v-if="!queuedViewDate" aria-label="薪酬查询条件" @submit.prevent="applyQueries">
      <fieldset :disabled="busy || uncertain">
        <template v-if="!validDate(props.queryDate)"><label for="comp-as-of">查看日期</label><input id="comp-as-of" v-model="query.asOf" type="date" /></template>
        <label for="comp-from">历史录入 UTC from（包含，最多六位小数）</label><input id="comp-from" v-model="query.from" placeholder="YYYY-MM-DDTHH:mm:ssZ" autocomplete="off" />
        <label for="comp-to">历史录入 UTC to（不包含，最多六位小数）</label><input id="comp-to" v-model="query.to" placeholder="YYYY-MM-DDTHH:mm:ssZ" autocomplete="off" />
        <label for="comp-status">提案状态（不作用批准历史）</label><select id="comp-status" v-model="query.status"><option value="">全部获准状态</option><option v-for="status in statuses" :key="status">{{ status }}</option></select>
        <label for="comp-proposal-filter">确切提案 ID（可空）</label><input id="comp-proposal-filter" v-model="query.proposalID" autocomplete="off" />
        <label for="comp-limit">历史页大小（1..100）</label><input id="comp-limit" v-model="query.limit" inputmode="numeric" />
        <label for="comp-future-limit">未来条款上限（1..100）</label><input id="comp-future-limit" v-model="query.futureLimit" inputmode="numeric" />
        <button type="submit">查询四栏</button>
      </fieldset>
    </form>
    <section v-if="uncertain" aria-label="财务命令结果尚未确认">
      <p>可能已提交但未收到回包；不会自动重发、换键或更改原正文 / R / B。</p>
      <label for="comp-replay-confirm"><input id="comp-replay-confirm" v-model="replayConfirmed" type="checkbox" />确认仅以同一原键和逐字节原正文查询已提交结果，仍重新检查当前授权</label>
      <button type="button" :disabled="busy || !replayConfirmed" @click="replay">确认原命令结果</button>
    </section>
    <p v-if="queuedViewDate" role="status">查看日期已改变；旧日期财务内容已隐藏，将在当前命令结果明确后加载新日期。</p>
    <template v-if="!queuedViewDate">
    <div class="panes">
      <section aria-label="指定日现状">
        <h2>指定日现状</h2>
        <p v-if="currentDenied">整名员工现状未获授权；精确历史对象授权不授 aggregate。</p>
        <template v-else-if="current"><p>查询日 {{ current.as_of }} · 员工 B {{ current.comp_revision }}</p><p v-if="!current.current_term">未建立有效条款（不是零工资）</p><dl v-else><dt>条款 / 版本 / 原事件 / 当前有效区间</dt><dd>{{ current.current_term.id }} / {{ current.current_term.revision }} / {{ current.current_term.event_id }} / [{{ current.current_term.effective_date }}, {{ current.current_term.valid_to ?? '未结束' }})</dd><dt>完整条款</dt><dd><pre>{{ JSON.stringify(current.current_term.terms, null, 2) }}</pre></dd></dl></template>
        <p v-else-if="!currentDenied">请明确查询日并加载获准事实；尚未读取，不推断工资。</p>
      </section>
      <section aria-label="未来已批准条款">
        <h2>未来已批准条款（不提前改变现状）</h2>
        <p v-if="current && !current.future_terms.length">本次有界查询无未来已批准条款</p>
        <article v-for="term in current?.future_terms ?? []" :key="term.id"><h3>[{{ term.effective_date }}, {{ term.valid_to ?? '未结束' }})</h3><p>条款 {{ term.id }} · 版本 {{ term.revision }} · 原事件 {{ term.event_id }}</p><pre>{{ JSON.stringify(term.terms, null, 2) }}</pre></article>
      </section>
      <section aria-label="薪酬提案">
        <h2>提案（草稿、待审与终态从不自行成为工资）</h2><p v-if="proposalsDenied">此提案范围未获授权</p>
        <article v-for="proposal in proposals?.proposals ?? []" :key="proposal.id" :data-proposal="proposal.id">
          <h3>{{ proposal.id }} · {{ proposal.kind }} · {{ proposal.status }}</h3>
          <p>R {{ proposal.revision }} · 提案基准 B {{ proposal.comp_revision }} · 作者 {{ proposal.author_subject_id }} · 录入 {{ proposal.recorded_at }} · 拟生效 {{ proposal.effective_date }}</p>
          <p>原因 {{ proposal.reason }} · 决策 {{ proposal.decision_reason }} · before {{ proposal.before_term_id ?? '无' }} · 批准关联 {{ proposal.approval_id ?? '无' }}</p>
          <pre v-if="proposal.after">{{ JSON.stringify(proposal.after, null, 2) }}</pre><pre v-if="proposal.members.length">{{ JSON.stringify(proposal.members, null, 2) }}</pre>
          <button v-if="proposalPermits(proposal, 'compensation.read')" type="button" :disabled="busy || uncertain || revisionBusy && revisionTarget?.id === proposal.id" :aria-label="`查看修订历史 ${proposal.id}`" @click="revisionPage(proposal)">明确查看此提案修订历史</button>
          <section v-if="revisionTarget?.id === proposal.id" :aria-label="`提案修订历史 ${proposal.id}`" :aria-busy="revisionBusy">
            <h4>不可变提案修订 / 冻结记录</h4>
            <p>仅显示当前一页（每页最多 {{ revisionPageLimit }} 条），按 R 从新到旧；换页替换本页，不累积或假称完整原史。</p>
            <p v-if="revisionBusy" role="status">正在加载修订页</p><p v-if="revisionError" role="alert">{{ revisionError }}</p>
            <template v-if="revisions">
              <p>当前提案 head R {{ revisions.proposals[0]!.revision }} · UTC {{ revisions.proposals[0]!.recorded_at }} · {{ revisionFirstPage ? '最新修订页' : '较旧修订页' }}</p>
              <article v-for="revision in revisions.revisions" :key="revision.revision" :data-revision="revision.revision">
                <h5>R {{ revision.revision }} · {{ revision.status }} · UTC {{ revision.recorded_at }}</h5>
                <p>原原因 {{ revision.command.reason }} · 独立决策 {{ revision.decision_reason }}</p>
                <pre>{{ JSON.stringify(revision.command, null, 2) }}</pre>
              </article>
              <p v-if="!revisions.next_cursor">本页已到最旧修订；较新页未保留在本页。</p>
            </template>
            <button type="button" :disabled="busy || uncertain || revisionBusy" :aria-label="`重载最新修订页 ${proposal.id}`" @click="revisionPage(proposal)">重载最新页 / 回到首个修订页</button>
            <button v-if="revisions?.next_cursor" type="button" :disabled="busy || uncertain || revisionBusy" :aria-label="`下一旧修订页 ${proposal.id}`" @click="revisionPage(proposal, true)">下一旧修订页</button>
            <button type="button" @click="clearRevisions">关闭并销毁修订页</button>
          </section>
          <p>此提案的当前对象权限仅限本对象；不授整名员工现状或其他历史。每次提交仍重新核对 read / capability / grant / purpose / MFA。</p>
          <button v-if="proposal.status === 'draft' && proposalPermits(proposal, 'compensation.propose')" type="button" :disabled="busy || uncertain" :aria-label="`编辑草稿 ${proposal.id}`" @click="editProposal(proposal)">编辑草稿</button>
          <button v-if="proposal.status === 'draft' && proposalPermits(proposal, 'compensation.propose')" type="button" :disabled="busy || uncertain" :aria-label="`提交提案 ${proposal.id}`" @click="selectTransition(proposal, 'submit')">审阅提交</button>
          <button v-if="['draft', 'submitted'].includes(proposal.status) && proposalPermits(proposal, 'compensation.propose')" type="button" :disabled="busy || uncertain" :aria-label="`撤回提案 ${proposal.id}`" @click="selectTransition(proposal, 'withdraw')">审阅撤回</button>
          <button v-if="proposal.status === 'submitted' && proposalPermits(proposal, 'compensation.approve')" type="button" :disabled="busy || uncertain || proposal.author_subject_id === session?.subject_id" :aria-label="`批准提案 ${proposal.id}`" @click="selectTransition(proposal, 'approve')">独立审阅批准（默认禁止自批）</button>
          <button v-if="proposal.status === 'submitted' && proposalPermits(proposal, 'compensation.approve')" type="button" :disabled="busy || uncertain" :aria-label="`拒绝提案 ${proposal.id}`" @click="selectTransition(proposal, 'reject')">独立审阅拒绝</button>
        </article>
        <button v-if="proposals?.next_cursor" type="button" :disabled="busy || uncertain" @click="nextPage('proposals')">下一页获准提案</button>
      </section>
      <section aria-label="不可变批准历史">
        <h2>不可变批准历史 / 完整纠错</h2><p v-if="approvalsDenied">此批准范围未获授权</p>
        <article v-for="approval in approvals?.approvals ?? []" :key="approval.id" :data-approval="approval.id">
          <h3>批准 {{ approval.id }}</h3><p>冻结提案 {{ approval.proposal_id }} / R {{ approval.proposal_revision }} · B {{ approval.comp_revision }} · 独立批准者 {{ approval.approver_subject_id }} · UTC {{ approval.approved_at }}</p><p>原原因 {{ approval.reason }} · 决策 {{ approval.decision_reason }}</p>
          <article v-for="event in approval.events" :key="event.id" :data-event="event.id"><h4>{{ event.kind }} · {{ event.effective_date }} · {{ event.id }} · 事件版本 {{ event.revision }}</h4><p>原纠错目标 {{ event.corrects_event_id ?? '无' }} · member_key {{ event.member_key || '无' }} · before {{ event.before_term_id ?? '无' }} → after {{ event.after_term_id ?? '无' }}</p><pre>{{ JSON.stringify({ before: event.before, after: event.after }, null, 2) }}</pre></article>
          <pre v-if="approval.members.length">{{ JSON.stringify(approval.members, null, 2) }}</pre>
        </article>
        <button v-if="approvals?.next_cursor" type="button" :disabled="busy || uncertain" @click="nextPage('approvals')">下一页获准批准历史</button>
      </section>
    </div>
    <button v-if="current && permits('compensation.propose')" type="button" :disabled="busy || uncertain" @click="newProposal">创建明确薪酬提案</button>
    <form v-if="editor.open" aria-label="完整薪酬提案编辑" @submit.prevent="saveProposal">
      <fieldset :disabled="busy || uncertain"><legend>{{ editor.id ? `编辑草稿 ${editor.id} · R ${editor.revision}` : '新提案' }} · 原员工 B {{ editor.basis }}</legend>
        <label for="comp-kind">明确提案类型</label><select id="comp-kind" v-model="editor.kind" @change="confirmed = false"><option value="initial">initial</option><option value="adjustment">adjustment</option><option value="correction">correction（完整替代 / 撤销组）</option></select>
        <label for="comp-effective">提案拟生效日 / 纠错窗口起点</label><input id="comp-effective" v-model="editor.date" type="date" />
        <p v-if="editor.kind === 'initial'">initial before 为 null；须整条过去与未来有效链均无 active initial。完整合法 reverse 后可重建，不删除原史。</p>
        <template v-if="editor.kind === 'adjustment'"><label for="comp-before">确切原 before term ID（不按相同金额接链）</label><input id="comp-before" v-model="editor.before" autocomplete="off" /></template>
        <CompensationTermsEditor v-if="editor.kind !== 'correction'" :model="editor.terms" prefix="comp-after" :disabled="busy || uncertain" />
        <template v-else>
          <p>逐项列所有受影响原批准事件及下游，参考只读批准栏。移除 / 替代后的每个日期必须保持唯一合法初始链；不自动补依赖、重写金额或推测遗漏。请核对所列有效日期窗口与各 before identity。</p>
          <section aria-label="获准原事件与可见下游依赖">
            <h3>只读原事件 / 可见下游依赖</h3>
            <p v-if="correctionDates.length">所列影响日期范围 {{ correctionDates[0] }} 至 {{ correctionDates[correctionDates.length - 1] }}（含所列日期；完整排程由服务端逐日期验证）</p>
            <p>仅显示当前查询页和当前权限可见事实，不推断隐藏事件或宣称闭包已完整；须查询足够窗口、逐项人工列入全部受影响下游。未列入者不会自动追加，服务端整组核对。</p>
            <article v-for="event in correctionContext" :key="event.id"><h4>{{ event.id }} · {{ event.effective_date }}</h4><p>before {{ event.before_term_id ?? '无' }} → after {{ event.after_term_id ?? '无' }} · {{ editor.members.some(member => member.original === event.id) ? '已显式列入本组' : '尚未列入，须核对下游 identity' }}</p><pre>{{ JSON.stringify({ before: event.before, after: event.after, corrects_event_id: event.corrects_event_id }, null, 2) }}</pre></article>
          </section>
          <fieldset v-for="(member, index) in editor.members" :key="index" :aria-label="`纠错成员 ${index + 1}`"><legend>成员 {{ index + 1 }}</legend>
            <label :for="`comp-member-${index}-key`">仅命令内 member_key</label><input :id="`comp-member-${index}-key`" v-model="member.key" autocomplete="off" />
            <label :for="`comp-member-${index}-original`">原批准 event ID</label><input :id="`comp-member-${index}-original`" v-model="member.original" autocomplete="off" />
            <label :for="`comp-member-${index}-action`">显式动作</label><select :id="`comp-member-${index}-action`" v-model="member.action"><option value="replace">replace</option><option value="reverse">reverse</option></select>
            <label :for="`comp-member-${index}-date`">成员拟生效日</label><input :id="`comp-member-${index}-date`" v-model="member.date" type="date" />
            <template v-if="member.action === 'replace'"><label :for="`comp-member-${index}-ref-kind`">新的 before 引用</label><select :id="`comp-member-${index}-ref-kind`" v-model="member.refKind"><option value="">无（替代初始）</option><option value="term_id">保留的确切 term_id</option><option value="member_key">本组 replacement member_key</option></select><label v-if="member.refKind" :for="`comp-member-${index}-ref`">引用值（严格 one-of）</label><input v-if="member.refKind" :id="`comp-member-${index}-ref`" v-model="member.ref" autocomplete="off" /><CompensationTermsEditor :model="member.terms" :prefix="`comp-member-${index}-after`" :disabled="busy || uncertain" /></template>
            <p v-else>reverse 不提交 before_ref / after，不写负工资；排除原事件后保留的有效条款由服务端完整链推导，原事实不删。</p>
            <button type="button" @click="editor.members.splice(index, 1)">移除纠错成员 {{ index + 1 }}</button>
          </fieldset><button type="button" :disabled="editor.members.length >= 100" @click="addMember">增加纠错成员</button>
        </template>
        <label for="comp-reason">保密原因（必填，至多 4096 UTF-8 字节）</label><textarea id="comp-reason" v-model="editor.reason" autocomplete="off" />
        <label for="comp-save-confirm"><input id="comp-save-confirm" v-model="confirmed" type="checkbox" />已核对完整口径、原 R/B、日期与全部下游依赖；仅保存草稿，不批准</label>
        <button type="submit">{{ editor.id ? '保存草稿新修订' : '保存新提案草稿' }}</button>
      </fieldset>
    </form>
    <form v-if="decision.id" aria-label="独立提案状态确认" @submit.prevent="transition"><fieldset :disabled="busy || uncertain"><legend>{{ decision.action }} · {{ decision.id }} · 冻结 R {{ decision.revision }} · 员工 B {{ decision.basis }}</legend><p>批准须独立审批者、完整已提交冻结条款与最新基准；409 不自动重批。拒绝 / 撤回不改变有效工资。</p><template v-if="decision.action !== 'submit'"><label for="comp-decision-reason">保密决策理由</label><textarea id="comp-decision-reason" v-model="decision.reason" autocomplete="off" /></template><p v-else>提交冻结已有提案条款与原因；decision_reason 为空，不伪造审批决策。</p><label for="comp-decision-confirm"><input id="comp-decision-confirm" v-model="decision.confirmed" type="checkbox" />明确确认此独立 {{ decision.action }} 动作</label><button type="submit">确认 {{ decision.action }}</button></fieldset></form>
    <section v-if="session && (exportObjects.length || currentDenied)" aria-label="明确财务对象导出">
      <h2>金融导出请求（独立 read / export / purpose / MFA）</h2>
      <p>可见对象和手工填写 ID 不表示已获导出权。只请求所选明确 kind / ID / 版本，服务端重新核对确切对象独立读与导出授权；精确历史授权不授 aggregate。拒绝不是成功导出。</p>
      <fieldset :disabled="busy || uncertain">
        <label v-for="object in exportObjects" :key="`${object.kind}:${object.id}`"><input v-model="exportSelection" type="checkbox" :value="`${object.kind}:${object.id}`" />{{ object.kind }} {{ object.id }} · expected_revision {{ object.expected_revision }}</label>
        <fieldset v-for="(row, index) in exactExportRows" :key="index" :aria-label="`确切导出对象 ${index + 1}`">
          <legend>明确已知对象（不猜测工资或 aggregate 许可）</legend>
          <label :for="`comp-export-${index}-kind`">确切对象类型</label><select :id="`comp-export-${index}-kind`" v-model="row.kind"><option value="">请选择</option><option value="compensation_proposal">compensation_proposal</option><option value="compensation_event">compensation_event</option><option value="compensation_term">compensation_term</option></select>
          <label :for="`comp-export-${index}-id`">明确对象 UUID</label><input :id="`comp-export-${index}-id`" v-model="row.id" autocomplete="off" />
          <label :for="`comp-export-${index}-revision`">确切 expected_revision（原始正整数字符串）</label><input :id="`comp-export-${index}-revision`" v-model="row.revision" inputmode="numeric" autocomplete="off" />
          <button type="button" @click="exactExportRows.splice(index, 1)">移除确切导出对象 {{ index + 1 }}</button>
        </fieldset>
        <button type="button" :disabled="exactExportRows.length >= 100" @click="exactExportRows.push({ kind: '', id: '', revision: '' })">输入明确已知导出对象</button>
        <label for="comp-export-confirm"><input id="comp-export-confirm" v-model="exportConfirmed" type="checkbox" />确认仅请求所选确切版本导出；已释放副本不能远程撤回</label><button type="button" @click="exportSelected">导出所选财务对象</button>
      </fieldset>
    </section>
    <p v-if="exportStatus" role="status">{{ exportStatus }}</p><pre v-if="exportOutput" aria-label="当前内存财务 NDJSON 输出">{{ exportOutput }}</pre>
    </template>
    <button type="button" :disabled="busy || uncertain" @click="clearSensitive(); grantOpen = !grantOpen">独立请求 / 核对已批准财务授权</button>
    <GrantPage v-if="grantOpen" @session-expired="expire(); emit('session-expired')" @grant-result="grantResult" />
  </main>
</template>
<style scoped>
main { max-width: 90rem; margin: auto; padding: 1rem; font-family: system-ui, sans-serif; }
.panes { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; }
section, article, fieldset { border: 1px solid #999; padding: 1rem; margin: 1rem 0; min-width: 0; overflow-wrap: anywhere; }
label { display: block; margin-top: .6rem; } input, textarea, select { max-width: 100%; } textarea { display: block; width: 90%; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; } button { margin: .5rem; } [role='alert'] { color: #9b1824; }
</style>
