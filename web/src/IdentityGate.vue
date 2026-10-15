<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'

type SessionHint = {
  subject_id: string
  org_id: string
  auth_epoch: string
  business_date: string
  csrf_token: string
  mfa_recent: boolean
  identity_available?: boolean
  identity_mode?: 'local' | 'oidc'
  sensitivity_valid_until?: string
}
type Phase = 'checking' | 'authenticated' | 'logged-out' | 'expired' | 'changed' | 'unavailable' |
  'logging-out' | 'logout-failed' | 'mfa-starting' | 'mfa-redirecting' | 'mfa-failed' | 'login-redirecting' | 'login-failed'
type Operation = { generation: number; controller: AbortController }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revision = /^[1-9][0-9]*$/
const phase = ref<Phase>('checking')
const session = shallowRef<SessionHint | null>(null)
const globalViewDate = ref('')
const returnTo = ref(knownReturnRoute())
const interviewIntent = ref<'note.publish' | 'sensitive.export'>('note.publish')
const compensationIntent = ref<'compensation.read' | 'compensation.propose' | 'compensation.approve' | 'bonus.target.manage' | 'bonus.propose' | 'bonus.approve' | 'bonus.payment.record' | 'compensation.extension.manage' | 'sensitive.export'>('compensation.read')
const identityMode = ref<'local' | 'oidc' | null>(null)
const username = ref('')
const password = ref('')
const currentPassword = ref('')
const newPassword = ref('')
const protectedGeneration = ref(0)
let alive = false
let generation = 0
let controller: AbortController | null = null
let logoutCSRF: string | null = null
let expiryTimer: ReturnType<typeof setInterval> | null = null

const loginURL = computed(() => `/api/v1/auth/login?${new URLSearchParams({ return_to: returnTo.value })}`)
const identityAvailable = computed(() => session.value?.identity_available !== false)
const canLogout = computed(() => session.value !== null && !['logging-out', 'logout-failed', 'login-redirecting'].includes(phase.value))
const interviewRoute = computed(() => /^\/interviews(?:\/|$)/.test(returnTo.value) || /^\/employees\/[^/]+\/interviews$/.test(returnTo.value))
const followupRoute = computed(() => /^\/employees\/[^/]+\/followup$/.test(returnTo.value))
const compensationRoute = computed(() => /^\/employees\/[^/]+\/(?:compensation|bonuses)(?:\?|$)/.test(returnTo.value) || /^\/orgs\/[^/]+\/compensation-adjustments(?:\?|$)/.test(returnTo.value))
const stepUpAction = computed(() => returnTo.value.split('?')[0] === '/security/grants' ? 'access_grant.manage' : compensationRoute.value ? compensationIntent.value : followupRoute.value ? 'interview_policy.manage' : interviewRoute.value ? interviewIntent.value : 'pii.write')

function validDate(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}
function setGlobalViewDate(value: string) {
  if (!validDate(value)) return false
  globalViewDate.value = value
  return true
}
function requestedViewDate() {
  const values = new URL(window.location.href).searchParams.getAll('as_of')
  return values.length === 1 && validDate(values[0]!) ? values[0]! : ''
}
function knownReturnRoute() {
  const url = new URL(window.location.href)
  let path: string
  const employee = /^\/employees\/([0-9a-f-]+)(?:\/profile)?\/?$/.exec(url.pathname)
  const history = /^\/employees\/([0-9a-f-]+)\/organization-history\/?$/.exec(url.pathname)
  const organization = /^\/orgs\/([0-9a-f-]+)\/(tree|employees)\/?$/.exec(url.pathname)
  const interview = /^\/interviews\/([0-9a-f-]+)\/?$/.exec(url.pathname)
  const employeeInterviews = /^\/employees\/([0-9a-f-]+)\/interviews\/?$/.exec(url.pathname)
  const compensation = /^\/employees\/([0-9a-f-]+)\/(compensation|bonuses)\/?$/.exec(url.pathname)
  const followup = /^\/employees\/([0-9a-f-]+)\/followup\/?$/.exec(url.pathname)
  const compensationBatches = /^\/orgs\/([0-9a-f-]+)\/compensation-adjustments\/?$/.exec(url.pathname)
  if (employee && uuid.test(employee[1]!)) path = `/employees/${employee[1]}`
  else if (history && uuid.test(history[1]!)) path = `/employees/${history[1]}/organization-history`
  else if (organization && uuid.test(organization[1]!)) path = `/orgs/${organization[1]}/${organization[2]}`
  else if (interview && uuid.test(interview[1]!)) path = `/interviews/${interview[1]}`
  else if (employeeInterviews && uuid.test(employeeInterviews[1]!)) path = `/employees/${employeeInterviews[1]}/interviews`
  else if (compensation && uuid.test(compensation[1]!)) path = `/employees/${compensation[1]}/${compensation[2]}`
  else if (compensationBatches && uuid.test(compensationBatches[1]!)) path = `/orgs/${compensationBatches[1]}/compensation-adjustments`
  else if (/^\/interviews\/?$/.test(url.pathname)) path = '/interviews'
  else if (/^\/security\/grants\/?$/.test(url.pathname)) path = '/security/grants'
  else if (url.pathname === '/') path = '/'
  else return '/'
  const query = Array.from(url.searchParams.entries())
  if (history && query.length === 2 && url.searchParams.getAll('from').length === 1 && url.searchParams.getAll('to').length === 1) {
    const from = url.searchParams.get('from')!, to = url.searchParams.get('to')!
    if (validDate(from) && validDate(to) && from < to) return `${path}?${new URLSearchParams({ from, to })}`
  } else if (!history && !interview && !employeeInterviews && path !== '/interviews' && query.length === 1 && query[0]![0] === 'as_of' && validDate(query[0]![1])) {
    return `${path}?${new URLSearchParams({ as_of: query[0]![1] })}`
  }
  return path
}
function cancelOperation() {
  generation += 1
  controller?.abort()
  controller = null
}
function beginOperation(next: Phase | null): Operation {
  cancelOperation()
  if (next !== null) {
    protectedGeneration.value += 1
    phase.value = next
  }
  controller = new AbortController()
  return { generation, controller }
}
function isCurrent(operation: Operation) {
  return alive && generation === operation.generation && !operation.controller.signal.aborted
}
function sessionHint(value: unknown): SessionHint | null {
  if (!value || typeof value !== 'object') return null
  const next = value as Partial<SessionHint>
  if (typeof next.subject_id !== 'string' || !uuid.test(next.subject_id) ||
      typeof next.org_id !== 'string' || !uuid.test(next.org_id) ||
      typeof next.business_date !== 'string' || !validDate(next.business_date) ||
      typeof next.auth_epoch !== 'string' || !revision.test(next.auth_epoch) ||
      next.auth_epoch.length > 19 || BigInt(next.auth_epoch) > 9223372036854775807n ||
      typeof next.csrf_token !== 'string' || !next.csrf_token ||
      typeof next.mfa_recent !== 'boolean' ||
      (next.identity_available !== undefined && typeof next.identity_available !== 'boolean') ||
      (next.identity_mode !== undefined && next.identity_mode !== 'local' && next.identity_mode !== 'oidc')) return null
  if (next.sensitivity_valid_until !== undefined) {
    if (typeof next.sensitivity_valid_until !== 'string') return null
    const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,6})?Z$/.exec(next.sensitivity_valid_until)
    if (!match || Number.isNaN(Date.parse(next.sensitivity_valid_until)) || new Date(`${match[1]}Z`).toISOString().slice(0, 19) !== match[1]) return null
  }
  // Do not retain the response's business capabilities, authorities or unrelated fields.
  return {
    subject_id: next.subject_id, org_id: next.org_id, auth_epoch: next.auth_epoch,
    business_date: next.business_date, csrf_token: next.csrf_token, mfa_recent: next.mfa_recent,
    identity_available: next.identity_available, identity_mode: next.identity_mode,
    sensitivity_valid_until: next.sensitivity_valid_until,
}
}
function sameIdentity(left: SessionHint, right: SessionHint) {
  return left.subject_id === right.subject_id && left.org_id === right.org_id && left.auth_epoch === right.auth_epoch
}
function expireSession() {
  cancelOperation()
  protectedGeneration.value += 1
  session.value = null
  globalViewDate.value = ''
  logoutCSRF = null
  phase.value = 'expired'
}
async function checkSession(preserveProtected = false) {
  const previous = session.value
  const preserve = preserveProtected && previous !== null && phase.value === 'authenticated'
  const operation = beginOperation(preserve ? null : 'checking')
  // Explicit checks destroy protected instances first. Route checks retain the
  // current shell until the server proves that the identity context changed.
  if (!preserve) await nextTick()
  if (!isCurrent(operation)) return
  try {
    const response = await fetch('/api/v1/session', {
      credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: compensationRoute.value ? { 'X-Access-Purpose': 'compensation_management' } : undefined,
    })
    if (!isCurrent(operation)) return
    if (response.status === 401) {
      identityMode.value = response.headers.get('X-TeamLedger-Identity-Mode') === 'local' ? 'local' : 'oidc'
      expireSession()
      return
    }
    if (!response.ok) throw new Error('Session unavailable')
    const next = sessionHint(await response.json())
    if (!isCurrent(operation)) return
    if (!next) throw new Error('Session unavailable')
    if (previous && !sameIdentity(previous, next) || next.sensitivity_valid_until && Date.parse(next.sensitivity_valid_until) <= Date.now()) {
      session.value = null
      phase.value = 'changed'
      return
    }
    session.value = next
    if (!previous || !validDate(globalViewDate.value)) globalViewDate.value = requestedViewDate() || next.business_date
    if (next.identity_mode) identityMode.value = next.identity_mode
    phase.value = 'authenticated'
  } catch {
    if (!isCurrent(operation)) return
    session.value = null
    globalViewDate.value = ''
    phase.value = 'unavailable'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
async function logout() {
  const csrf = session.value?.csrf_token ?? logoutCSRF
  if (!csrf || phase.value === 'logging-out' || phase.value === 'logged-out') return
  const operation = beginOperation('logging-out')
  logoutCSRF = csrf
  session.value = null
  await nextTick()
  globalViewDate.value = ''
  if (!isCurrent(operation)) return
  try {
    const response = await fetch('/api/v1/auth/logout', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: '{}',
    })
    if (!isCurrent(operation)) return
    if (response.status !== 204) throw new Error('Revocation unconfirmed')
    logoutCSRF = null
    phase.value = 'logged-out'
  } catch {
    if (isCurrent(operation)) phase.value = 'logout-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
async function stepUp() {
  if (phase.value !== 'authenticated' || !session.value || !identityAvailable.value) return
  const csrf = session.value.csrf_token
  returnTo.value = knownReturnRoute()
  const action = stepUpAction.value
  const route = returnTo.value
  const operation = beginOperation('mfa-starting')
  await nextTick()
  if (!isCurrent(operation)) return
  try {
    const response = await fetch('/api/v1/auth/step-up', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ action, return_to: route }),
    })
    if (!isCurrent(operation)) return
    if (response.status === 401) { expireSession(); return }
    if (!response.ok) throw new Error('Identity verification unavailable')
    const next: unknown = await response.json()
    if (!isCurrent(operation)) return
    if (!next || typeof next !== 'object' || !('authorization_url' in next) || typeof next.authorization_url !== 'string') {
      throw new Error('Identity verification unavailable')
    }
    const destination = new URL(next.authorization_url)
    if (destination.protocol !== 'https:' || destination.username || destination.password || destination.hash) {
      throw new Error('Identity verification unavailable')
    }
    phase.value = 'mfa-redirecting'
    window.location.assign(destination.href)
  } catch {
    if (isCurrent(operation)) phase.value = 'mfa-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
function login() {
  cancelOperation()
  protectedGeneration.value += 1
  session.value = null
  logoutCSRF = null
  phase.value = 'login-redirecting'
}
async function localLogin() {
  if (identityMode.value !== 'local' || phase.value === 'login-redirecting') return
  const operation = beginOperation('login-redirecting')
  try {
    const response = await fetch('/api/v1/auth/local/login', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value, return_to: returnTo.value }),
    })
    password.value = ''
    if (!isCurrent(operation)) return
    if (!response.ok) { phase.value = 'login-failed'; return }
    const body: unknown = await response.json()
    if (!body || typeof body !== 'object' || !('return_to' in body) || typeof body.return_to !== 'string') {
      phase.value = 'login-failed'; return
    }
    window.location.assign(body.return_to)
  } catch {
    password.value = ''
    if (isCurrent(operation)) phase.value = 'login-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
async function changePassword() {
  if (identityMode.value !== 'local' || !session.value) return
  const csrf = session.value.csrf_token
  const operation = beginOperation('logging-out')
  await nextTick()
  try {
    const response = await fetch('/api/v1/auth/local/password', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ current_password: currentPassword.value, new_password: newPassword.value }),
    })
    currentPassword.value = ''; newPassword.value = ''
    if (!isCurrent(operation)) return
    if (response.status !== 204) { phase.value = 'login-failed'; return }
    session.value = null
    phase.value = 'logged-out'
  } catch {
    currentPassword.value = ''; newPassword.value = ''
    if (isCurrent(operation)) phase.value = 'login-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
function routeChanged() {
  returnTo.value = knownReturnRoute()
  if (phase.value === 'authenticated' || phase.value === 'checking') void checkSession(true)
}
function resume() {
  if (phase.value === 'authenticated' || phase.value === 'checking') void checkSession()
}
function suspend() {
  if (phase.value !== 'authenticated' && phase.value !== 'checking') return
  cancelOperation()
  protectedGeneration.value += 1
  phase.value = 'checking'
}
function clearExpiredSensitivity() {
  const deadline = session.value?.sensitivity_valid_until
  if (!deadline || !['authenticated', 'mfa-starting'].includes(phase.value) || Date.parse(deadline) > Date.now()) return
  cancelOperation(); protectedGeneration.value += 1; session.value = null; logoutCSRF = null
  phase.value = 'changed'
}
onMounted(() => {
  alive = true
  window.addEventListener('popstate', routeChanged)
  window.addEventListener('focus', resume)
  window.addEventListener('pageshow', resume)
  window.addEventListener('pagehide', suspend)
  expiryTimer = setInterval(clearExpiredSensitivity, 1000)
  void checkSession()
})
onBeforeUnmount(() => {
  alive = false
  window.removeEventListener('popstate', routeChanged)
  window.removeEventListener('focus', resume)
  window.removeEventListener('pageshow', resume)
  window.removeEventListener('pagehide', suspend)
  if (expiryTimer) clearInterval(expiryTimer)
  cancelOperation()
  session.value = null
  logoutCSRF = null
})
</script>

<template>
  <section class="identity-shell" aria-label="共同身份与会话" :data-identity-state="phase" :aria-busy="['checking', 'logging-out', 'mfa-starting'].includes(phase)">
    <details v-if="phase === 'authenticated'" class="identity-session-panel">
      <summary>
        <span class="identity-indicator" aria-hidden="true"></span>
        <span class="identity-copy">
          <strong>会话已核对</strong>
          <span>{{ session?.mfa_recent ? 'MFA 近期有效' : 'MFA 按需验证' }}</span>
        </span>
        <span class="identity-disclosure">会话与安全</span>
      </summary>
      <div class="identity-session-body">
        <p>身份摘要不是业务访问许可；页面仍按当前scope、purpose和能力独立授权。</p>
        <div class="identity-actions">
          <button type="button" @click="checkSession()">重新核对会话（清空当前页面）</button>
          <button v-if="canLogout" type="button" @click="logout">注销本会话</button>
        </div>
        <div class="identity-tools">
          <div v-if="identityAvailable" class="identity-tools-row">
            <label v-if="interviewRoute" for="interview-stepup-intent">重新验证意图<select id="interview-stepup-intent" v-model="interviewIntent"><option value="note.publish">发布笔记</option><option value="sensitive.export">敏感导出</option></select></label>
            <label v-if="compensationRoute" for="compensation-stepup-intent">财务重新验证意图<select id="compensation-stepup-intent" v-model="compensationIntent"><option value="compensation.read">财务读取</option><option value="compensation.propose">薪酬提出</option><option value="compensation.approve">独立薪酬审批</option><option value="bonus.target.manage">奖金目标维护</option><option value="bonus.propose">奖金奖励维护</option><option value="bonus.approve">独立奖金审批</option><option value="bonus.payment.record">奖金支付事实</option><option value="compensation.extension.manage">薪酬有限扩展</option><option value="sensitive.export">财务敏感导出</option></select></label>
            <button type="button" @click="stepUp">{{ compensationRoute ? '重新验证财务 MFA' : stepUpAction === 'access_grant.manage' ? '重新验证授权管理 MFA' : stepUpAction === 'interview_policy.manage' ? '重新验证跟进策略 MFA' : stepUpAction === 'note.publish' ? '重新验证笔记发布 MFA' : stepUpAction === 'sensitive.export' ? '重新验证敏感导出 MFA' : '重新验证资料写入 MFA' }}</button>
          </div>
          <p v-if="interviewRoute || compensationRoute || followupRoute">MFA 是会话级近期认证；认证后重载并明确重新确认，不自动提交、审批、生成结论或导出。</p>
          <p v-if="!identityAvailable">可信登录与 MFA 设施未启用，不能在本地完成验证。</p>
          <details v-if="identityMode === 'local'" class="identity-account-panel">
            <summary>账号安全与密码</summary>
            <form @submit.prevent="changePassword">
              <label for="current-password">当前密码<input id="current-password" v-model="currentPassword" type="password" autocomplete="current-password" required minlength="12" maxlength="256"></label>
              <label for="new-password">新密码<input id="new-password" v-model="newPassword" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
              <button type="submit">修改密码并注销全部会话</button>
            </form>
          </details>
        </div>
      </div>
    </details>
    <template v-else>
      <div class="auth-heading">
        <span class="brand-mark" aria-hidden="true">TL</span>
        <div><h1>TeamLedger</h1><p>受保护的人员运营工作区</p></div>
      </div>
      <p v-if="phase === 'checking'" role="status">正在核对服务端会话；受保护页面尚未开放。</p>
      <p v-else-if="phase === 'logged-out'" role="status">服务端已确认撤销本会话，当前页面资料已清空。未请求外部身份站点的全局登出。</p>
      <p v-else-if="phase === 'expired'" role="alert">会话不存在或已失效，受保护页面与表单已清空。请通过可信身份设施登录。</p>
      <p v-else-if="phase === 'changed'" role="alert">主体、组织、授权上下文或当前敏感显示期限已改变。旧页面已销毁；请重新核对会话后再操作。</p>
      <p v-else-if="phase === 'unavailable'" role="alert">无法核对会话，受保护页面保持关闭。可手动重新核对。</p>
      <p v-else-if="phase === 'logging-out'" role="status">页面资料已清空，正在等待服务端撤销会话的确认。</p>
      <p v-else-if="phase === 'logout-failed'" role="alert">页面资料已清空，但服务端撤销尚未确认。不能视为已注销；可重试撤销本会话。</p>
      <p v-else-if="phase === 'mfa-starting' || phase === 'mfa-redirecting'" role="status">正在前往可信身份设施重新验证 MFA。返回后将重新读取会话，不自动提交业务操作。</p>
      <p v-else-if="phase === 'mfa-failed'" role="alert">未能开始可信 MFA 验证，未获得新的认证证明。页面保持关闭；可重新核对会话后再尝试。</p>
      <p v-else-if="phase === 'login-redirecting'" role="status">正在前往可信身份设施登录。</p>
      <p v-else-if="phase === 'login-failed'" role="alert">账号、密码或登录状态无效；请稍后重试。</p>
      <div class="identity-actions">
        <button v-if="canLogout" type="button" @click="logout">注销本会话</button>
        <button v-if="phase === 'logout-failed'" type="button" @click="logout">重试注销本会话</button>
        <button v-if="['expired', 'changed', 'unavailable', 'mfa-failed'].includes(phase)" type="button" @click="checkSession()">重新核对会话</button>
      </div>
      <form v-if="identityMode === 'local' && ['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed', 'login-failed'].includes(phase)" @submit.prevent="localLogin">
        <label for="local-username">账号<input id="local-username" v-model="username" name="username" autocomplete="username" required minlength="3" maxlength="64"></label>
        <label for="local-password">密码<input id="local-password" v-model="password" name="password" type="password" autocomplete="current-password" required minlength="12" maxlength="256"></label>
        <button type="submit">登录</button>
      </form>
      <a v-else-if="identityMode === 'oidc' && ['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed'].includes(phase)" :href="loginURL" role="button" @click="login">通过可信身份设施登录</a>
    </template>
  </section>
  <div v-if="phase === 'authenticated'" :key="protectedGeneration">
    <slot :expireSession="expireSession" :orgID="session?.org_id" :asOf="globalViewDate" :setAsOf="setGlobalViewDate" />
  </div>
</template>
