<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()
type Session = { subject_id: string; org_id: string; capabilities: string[]; csrf_token: string; mfa_recent: boolean; mfa_valid_until: string }
type LocalUser = { account_id: string; subject_id: string; username: string; active: boolean; password_change_required: boolean; mfa_status: 'enrollment_required' | 'active'; created_at: string }
type UserPage = { items: LocalUser[]; next_cursor: string | null; consistency: 'current' }
type Operation = { generation: number; controller: AbortController }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const usernamePattern = /^[a-z0-9][a-z0-9._-]{2,63}$/
const session = shallowRef<Session | null>(null)
const users = ref<LocalUser[]>([])
const nextCursor = ref<string | null>(null)
const busy = ref(false)
const creating = ref(false)
const error = ref('')
const notice = ref('')
const form = reactive({ username: '', password: '', confirm: '' })
let alive = false
let generation = 0
let controller: AbortController | null = null

const canSubmit = computed(() => !creating.value && usernamePattern.test(form.username) && form.password.length >= 12 && form.password.length <= 256 && form.password === form.confirm)
function timestamp(value: unknown): value is string { return typeof value === 'string' && !Number.isNaN(Date.parse(value)) && /^\d{4}-\d{2}-\d{2}T/.test(value) }
function validSession(value: unknown): value is Session {
  if (!value || typeof value !== 'object') return false
  const item = value as Session
  return uuid.test(item.subject_id) && uuid.test(item.org_id) && Array.isArray(item.capabilities) && item.capabilities.every(capability => typeof capability === 'string') && typeof item.csrf_token === 'string' && item.csrf_token.length > 0 && typeof item.mfa_recent === 'boolean' && timestamp(item.mfa_valid_until)
}
function validUser(value: unknown): value is LocalUser {
  if (!value || typeof value !== 'object') return false
  const item = value as LocalUser
  return uuid.test(item.account_id) && uuid.test(item.subject_id) && usernamePattern.test(item.username) && typeof item.active === 'boolean' && typeof item.password_change_required === 'boolean' && ['enrollment_required', 'active'].includes(item.mfa_status) && timestamp(item.created_at)
}
function begin(): Operation {
  generation += 1
  controller?.abort()
  controller = new AbortController()
  busy.value = true
  error.value = ''
  return { generation, controller }
}
function current(operation: Operation) { return alive && generation === operation.generation && !operation.controller.signal.aborted }
function clearProtected() { session.value = null; users.value = []; nextCursor.value = null; form.password = ''; form.confirm = '' }
async function request(path: string, operation: Operation, init: RequestInit = {}) {
  const response = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
    ...init, headers: { 'X-Access-Purpose': 'security_administration', ...(init.headers ?? {}) },
  })
  if (!current(operation)) throw new DOMException('Cancelled', 'AbortError')
  if (!response.ok) throw Object.assign(new Error('request failed'), { status: response.status })
  return response
}
async function load(cursor = '', append = false) {
  const operation = begin()
  if (!append) { users.value = []; nextCursor.value = null; session.value = null }
  try {
    const sessionResponse = await request('/session', operation)
    const nextSession: unknown = await sessionResponse.json()
    if (!current(operation) || !validSession(nextSession)) throw Object.assign(new Error('invalid session'), { status: 503 })
    if (!nextSession.mfa_recent) throw Object.assign(new Error('mfa required'), { status: 428 })
    if (!nextSession.capabilities.includes('identity.manage')) throw Object.assign(new Error('forbidden'), { status: 403 })
    session.value = nextSession
    const query = new URLSearchParams({ limit: '25' })
    if (cursor) query.set('cursor', cursor)
    const listResponse = await request(`/security/users?${query}`, operation)
    const page: unknown = await listResponse.json()
    if (!current(operation) || !page || typeof page !== 'object') throw Object.assign(new Error('invalid page'), { status: 503 })
    const candidate = page as UserPage
    if (candidate.consistency !== 'current' || !Array.isArray(candidate.items) || candidate.items.length > 25 || !candidate.items.every(validUser) || candidate.next_cursor !== null && typeof candidate.next_cursor !== 'string') throw Object.assign(new Error('invalid page'), { status: 503 })
    users.value = append ? [...users.value, ...candidate.items] : candidate.items
    nextCursor.value = candidate.next_cursor
  } catch (cause) {
    if (!current(operation)) return
    const status = Number((cause as { status?: number }).status ?? 503)
    clearProtected()
    error.value = status === 401
      ? '会话已失效，用户资料已清空。'
      : status === 428
        ? '用户管理要求近期 MFA。请在右上角“会话与安全”中重新验证后再进入本页。'
        : status === 403 || status === 404
          ? '当前账号没有 identity.manage 权限；创建登录账号与业务授权是两项独立职责。'
          : '用户管理服务不可用，未显示缓存结果。'
    if (status === 401) emit('session-expired')
  } finally {
    if (current(operation)) { busy.value = false; controller = null }
  }
}
async function createUser() {
  if (!session.value || !canSubmit.value) {
    error.value = form.password !== form.confirm ? '两次输入的新用户初始密码不一致。' : '账号须为 3..64 位小写字母、数字、点、下划线或连字符；初始密码须为 12..256 位。'
    return
  }
  const operation = begin()
  creating.value = true
  notice.value = ''
  const username = form.username
  const key = crypto.randomUUID()
  try {
    const response = await request('/security/users', operation, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.value.csrf_token, 'Idempotency-Key': key },
      body: JSON.stringify({ username, initial_password: form.password }),
    })
    form.password = ''; form.confirm = ''
    const result: unknown = await response.json()
    if (!current(operation) || !result || typeof result !== 'object' || !uuid.test((result as { account_id?: string }).account_id ?? '') || !uuid.test((result as { subject_id?: string }).subject_id ?? '')) throw Object.assign(new Error('invalid result'), { status: 503 })
    form.username = ''
    notice.value = `账号 ${username} 已创建。初始密码不会再次显示；用户首次登录必须修改密码并登记 TOTP。`
    await load()
  } catch (cause) {
    form.password = ''; form.confirm = ''
    if (!current(operation)) return
    const status = Number((cause as { status?: number }).status ?? 503)
    error.value = status === 401 ? '会话已失效，创建结果未保留在页面。' : status === 403 ? 'identity.manage 权限或近期 MFA 已失效。' : status === 409 ? '账号已存在，或相同请求标识对应了不同内容。' : status === 422 ? '账号或初始密码格式不符合要求。' : '创建结果不确定。请先刷新用户列表核对，避免重复创建。'
    if (status === 401) { clearProtected(); emit('session-expired') }
  } finally {
    creating.value = false
    if (current(operation)) { busy.value = false; controller = null }
  }
}
function statusLabel(user: LocalUser) {
  if (!user.active) return '已停用'
  if (user.password_change_required) return '等待首次改密'
  return user.mfa_status === 'active' ? '可登录' : '等待 TOTP 登记'
}
function loadMore() { if (nextCursor.value && !busy.value) void load(nextCursor.value, true) }
onMounted(() => { alive = true; void load() })
onBeforeUnmount(() => { alive = false; generation += 1; controller?.abort(); clearProtected() })
</script>

<template>
  <main class="user-admin-page">
    <header class="page-hero">
      <p class="eyebrow">P-SEC-03 · 本地身份</p>
      <h1>用户管理</h1>
      <p>创建可登录 TeamLedger 的本地账号。账号创建与员工资料、业务授权相互独立；新用户默认没有业务权限。</p>
    </header>
    <p v-if="error" class="error-banner" role="alert">{{ error }}</p>
    <p v-if="notice" class="notice-banner" role="status">{{ notice }}</p>
    <section v-if="session" class="surface-card user-create-card" aria-labelledby="create-user-title">
      <div class="section-heading"><div><p class="eyebrow">一次性初始凭证</p><h2 id="create-user-title">追加用户</h2></div><p>初始密码提交后立即从页面清除，管理员无法再次查看。</p></div>
      <form class="user-create-form" @submit.prevent="createUser">
        <label>登录账号<input v-model.trim="form.username" name="username" autocomplete="off" required minlength="3" maxlength="64" pattern="[a-z0-9][a-z0-9._-]{2,63}" placeholder="例如: shanghai.hr"></label>
        <label>初始密码<input v-model="form.password" name="initial-password" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
        <label>确认初始密码<input v-model="form.confirm" name="confirm-password" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
        <div class="form-action"><button class="primary-action" type="submit" :disabled="!canSubmit">{{ creating ? '正在创建…' : '创建用户' }}</button></div>
      </form>
    </section>
    <section v-if="session" class="surface-card user-list-card" aria-labelledby="local-users-title">
      <div class="section-heading"><div><p class="eyebrow">当前本地账号</p><h2 id="local-users-title">用户一览</h2></div><button type="button" :disabled="busy" @click="load()">刷新</button></div>
      <div class="table-scroll">
        <table>
          <thead><tr><th>账号</th><th>登录状态</th><th>MFA</th><th>创建时间</th><th>主体 ID</th></tr></thead>
          <tbody><tr v-for="user in users" :key="user.account_id"><td><strong>{{ user.username }}</strong><small>{{ user.account_id }}</small></td><td><span class="status-pill" :data-state="user.active && !user.password_change_required && user.mfa_status === 'active' ? 'ready' : 'pending'">{{ statusLabel(user) }}</span></td><td>{{ user.mfa_status === 'active' ? '已登记 TOTP' : '未登记' }}</td><td>{{ new Date(user.created_at).toLocaleString() }}</td><td><code>{{ user.subject_id }}</code></td></tr></tbody>
        </table>
      </div>
      <p v-if="!busy && users.length === 0" class="empty-state">尚无本地用户。</p>
      <div class="list-footer"><span>已显示 {{ users.length }} 个账号</span><button v-if="nextCursor" type="button" :disabled="busy" @click="loadMore">加载更多</button></div>
    </section>
    <p v-if="busy" class="loading-line" role="status">正在核对权限并读取当前用户…</p>
  </main>
</template>

<style scoped>
.user-admin-page{max-width:92rem;margin:0 auto;padding:3rem clamp(1rem,3vw,3rem) 5rem}.page-hero{max-width:58rem;margin-bottom:2rem}.page-hero h1{font-size:clamp(2.5rem,5vw,4.5rem);line-height:1;margin:.45rem 0 1rem}.page-hero>p:last-child,.section-heading>p{color:var(--text-muted,#587085);line-height:1.7}.surface-card{background:#fff;border:1px solid #dce5e9;border-radius:1.25rem;box-shadow:0 16px 42px rgba(14,40,55,.06);margin:1.25rem 0;overflow:hidden}.section-heading{display:flex;align-items:end;justify-content:space-between;gap:2rem;padding:1.5rem 1.75rem;border-bottom:1px solid #e5ecef}.section-heading h2{margin:.2rem 0;font-size:1.55rem}.section-heading p{max-width:35rem;margin:0}.user-create-form{display:grid;grid-template-columns:repeat(3,minmax(12rem,1fr)) auto;gap:1rem;align-items:end;padding:1.75rem}.user-create-form label{display:grid;gap:.5rem;font-weight:700}.user-create-form input{width:100%}.form-action{display:flex;align-items:end}.primary-action{min-height:3.25rem;white-space:nowrap}.table-scroll{overflow:auto;padding:0 1.25rem}.user-list-card table{width:100%;border-collapse:collapse;min-width:68rem}.user-list-card th,.user-list-card td{text-align:left;padding:1rem .75rem;border-bottom:1px solid #edf1f3;vertical-align:middle}.user-list-card th{color:#526676;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}.user-list-card td small{display:block;color:#718493;margin-top:.3rem}.user-list-card code{font-size:.78rem}.status-pill{display:inline-flex;padding:.35rem .65rem;border-radius:999px;background:#fff1d4;color:#7b5314;font-weight:750;font-size:.82rem}.status-pill[data-state=ready]{background:#dff4ec;color:#17634d}.list-footer{display:flex;align-items:center;justify-content:space-between;padding:1.25rem 1.75rem;color:#607687}.empty-state{padding:2rem;text-align:center;color:#607687}.error-banner,.notice-banner,.loading-line{max-width:92rem;border-radius:.75rem;padding:1rem 1.25rem}.error-banner{background:#fff1f1;color:#8d252d;border:1px solid #f0c7ca}.notice-banner{background:#eaf7f2;color:#175e4a;border:1px solid #bce3d5}.loading-line{background:#edf5f7;color:#315668}@media(max-width:64rem){.user-create-form{grid-template-columns:1fr 1fr}.form-action{grid-column:1/-1}.section-heading{align-items:start;flex-direction:column;gap:.75rem}}@media(max-width:42rem){.user-admin-page{padding-top:2rem}.user-create-form{grid-template-columns:1fr}.section-heading{padding:1.25rem}.user-create-form{padding:1.25rem}}
</style>
