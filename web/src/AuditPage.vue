<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()
type Session = { subject_id: string; org_id: string; capabilities: string[]; mfa_recent: boolean; mfa_valid_until: string }
type AuditEvent = { id: string; subject_id: string | null; employee_id: string | null; grant_id: string | null; operation: string; purpose: string; request_id: string; outcome: 'allowed' | 'denied' | 'partial'; recorded_at: string; actor_kind: 'application' | 'local_maintenance' | 'legacy_unattributed'; target_subject_id: string | null; target_employee_id: string | null }
type Page = { items: AuditEvent[]; next_cursor: string | null; consistency: 'current'; authorization_until: string }
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const session = shallowRef<Session | null>(null)
const page = shallowRef<Page | null>(null)
const filters = reactive({ subject: '', employee: '', grant: '', operation: '', purpose: '', outcome: '', from: '', to: '', limit: '50' })
const busy = ref(false), error = ref<string | null>(null)
let applied = '', generation = 0, controller: AbortController | null = null, alive = false
function timestamp(value: unknown): value is string { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value) }
function clear() { page.value = null; session.value = null }
function begin() { generation++; controller?.abort(); controller = new AbortController(); busy.value = true; error.value = null; return { generation, controller } }
function current(op: { generation: number; controller: AbortController }) { return alive && generation === op.generation && !op.controller.signal.aborted }
async function get<T>(path: string, op: { generation: number; controller: AbortController }): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { credentials: 'same-origin', cache: 'no-store', signal: op.controller.signal, headers: { 'X-Access-Purpose': 'security_administration' } })
  if (!current(op)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw Object.assign(new Error('request failed'), { status: response.status })
  return response.json() as Promise<T>
}
function validEvent(item: AuditEvent) {
  return item && uuid.test(item.id) && uuid.test(item.request_id) && typeof item.operation === 'string' && item.operation.length <= 32 && typeof item.purpose === 'string' && ['allowed', 'denied', 'partial'].includes(item.outcome) && timestamp(item.recorded_at) && ['application', 'local_maintenance', 'legacy_unattributed'].includes(item.actor_kind) && [item.subject_id, item.employee_id, item.grant_id, item.target_subject_id, item.target_employee_id].every(id => id === null || uuid.test(id))
}
async function load(query = applied) {
  const op = begin(); page.value = null
  try {
    const nextSession = await get<Session>('/session', op)
    if (!nextSession || !uuid.test(nextSession.subject_id) || !uuid.test(nextSession.org_id) || !Array.isArray(nextSession.capabilities) || !nextSession.capabilities.includes('audit.read') || !nextSession.mfa_recent || !timestamp(nextSession.mfa_valid_until)) throw Object.assign(new Error('forbidden'), { status: 403 })
    session.value = nextSession
    const next = await get<Page>(`/audit-events?${query || 'limit=50'}`, op)
    if (!next || next.consistency !== 'current' || !timestamp(next.authorization_until) || !Array.isArray(next.items) || next.items.length > 100 || !next.items.every(validEvent) || next.next_cursor !== null && typeof next.next_cursor !== 'string') throw Object.assign(new Error('invalid response'), { status: 503 })
    page.value = next
  } catch (cause) {
    if (!current(op)) return
    const status = Number((cause as { status?: number }).status ?? 503)
    clear()
    error.value = status === 401 ? '会话已失效，审计数据已清空。' : status === 403 || status === 404 ? '当前独立审计权限或近期 MFA 不满足，数据已清空。' : '审计服务不可用，未显示缓存结果。'
    if (status === 401) emit('session-expired')
  } finally { if (current(op)) { busy.value = false; controller = null } }
}
function apply() {
  if ([filters.subject, filters.employee, filters.grant].some(id => id && !uuid.test(id)) || !/^[1-9][0-9]*$/.test(filters.limit) || Number(filters.limit) > 100 || filters.outcome && !['allowed', 'denied', 'partial'].includes(filters.outcome)) { error.value = '筛选 ID 须为规范 UUID，页大小须为 1..100。'; return }
  const query = new URLSearchParams({ limit: filters.limit })
  for (const [key, value] of Object.entries({ subject_id: filters.subject, employee_id: filters.employee, grant_id: filters.grant, operation: filters.operation, purpose: filters.purpose, outcome: filters.outcome, from: filters.from, to: filters.to })) if (value) query.set(key, value)
  applied = query.toString(); void load()
}
function next() { if (!page.value?.next_cursor || busy.value) return; const query = new URLSearchParams(applied || 'limit=50'); query.set('cursor', page.value.next_cursor); void load(query.toString()) }
onMounted(() => { alive = true; void load() })
onBeforeUnmount(() => { alive = false; generation++; controller?.abort(); clear() })
</script>

<template>
  <main>
    <header><p class="eyebrow">P-SEC-02 · 独立审计</p><h1>安全审计事件</h1><p>仅安全 metadata；不显示正文、金额、模型请求内容或底层日志。</p></header>
    <p v-if="error" role="alert">{{ error }}</p>
    <form @submit.prevent="apply">
      <label>主体 ID<input v-model.trim="filters.subject"></label><label>员工 ID<input v-model.trim="filters.employee"></label><label>授权 ID<input v-model.trim="filters.grant"></label>
      <label>操作<input v-model.trim="filters.operation" placeholder="OP-SEC-04"></label><label>目的<input v-model.trim="filters.purpose"></label>
      <label>结果<select v-model="filters.outcome"><option value="">全部</option><option>allowed</option><option>denied</option><option>partial</option></select></label>
      <label>起始 UTC<input v-model.trim="filters.from" placeholder="2026-10-12T00:00:00Z"></label><label>截止 UTC<input v-model.trim="filters.to" placeholder="2026-10-13T00:00:00Z"></label><label>页大小<input v-model.trim="filters.limit" inputmode="numeric"></label>
      <button :disabled="busy">筛选</button>
    </form>
    <p v-if="busy" role="status">正在读取当前授权范围内的审计事件…</p>
    <section v-if="page" aria-label="审计事件"><p>授权有效至 {{ page.authorization_until }}</p><table><thead><tr><th>时间</th><th>操作</th><th>结果</th><th>主体 / 员工</th><th>请求 ID</th></tr></thead><tbody><tr v-for="item in page.items" :key="item.id"><td>{{ item.recorded_at }}</td><td>{{ item.operation }}<br><small>{{ item.purpose || '—' }}</small></td><td>{{ item.outcome }}</td><td>{{ item.subject_id || '本地维护' }}<br><small>{{ item.employee_id || item.target_employee_id || '—' }}</small></td><td>{{ item.request_id }}</td></tr></tbody></table><p v-if="page.items.length === 0">当前筛选无可见事件。</p><button v-if="page.next_cursor" :disabled="busy" @click="next">下一页</button></section>
  </main>
</template>

<style scoped>
main{max-width:72rem;margin:auto;padding:1rem;font-family:system-ui,sans-serif;color:#18231e}.eyebrow{color:#356c52;font-weight:700}form{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.75rem;padding:1rem;background:#eef5f0;border-radius:.75rem}label{display:grid;gap:.25rem}input,select,button{font:inherit;padding:.55rem}table{width:100%;border-collapse:collapse;margin-top:1rem}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #ccd8d0;vertical-align:top}[role=alert]{background:#fde8e8;padding:.75rem}
</style>
