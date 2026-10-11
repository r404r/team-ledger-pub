<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'

type SessionHint = {
  subject_id: string
  org_id: string
  auth_epoch: string
  csrf_token: string
  mfa_recent: boolean
  identity_available?: boolean
}
type Phase = 'checking' | 'authenticated' | 'logged-out' | 'expired' | 'changed' | 'unavailable' |
  'logging-out' | 'logout-failed' | 'mfa-starting' | 'mfa-redirecting' | 'mfa-failed' | 'login-redirecting'
type Operation = { generation: number; controller: AbortController }

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const revision = /^[1-9][0-9]*$/
const phase = ref<Phase>('checking')
const session = shallowRef<SessionHint | null>(null)
const returnTo = ref(knownReturnRoute())
const protectedGeneration = ref(0)
let alive = false
let generation = 0
let controller: AbortController | null = null
let logoutCSRF: string | null = null

const loginURL = computed(() => `/api/v1/auth/login?${new URLSearchParams({ return_to: returnTo.value })}`)
const identityAvailable = computed(() => session.value?.identity_available !== false)
const canLogout = computed(() => session.value !== null && !['logging-out', 'logout-failed', 'login-redirecting'].includes(phase.value))
const stepUpAction = computed(() => returnTo.value.split('?')[0] === '/security/grants' ? 'access_grant.manage' : 'pii.write')

function validDate(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}
function knownReturnRoute() {
  const url = new URL(window.location.href)
  let path: string
  const employee = /^\/employees\/([0-9a-f-]+)(?:\/profile)?\/?$/.exec(url.pathname)
  const history = /^\/employees\/([0-9a-f-]+)\/organization-history\/?$/.exec(url.pathname)
  const organization = /^\/orgs\/([0-9a-f-]+)\/(tree|employees)\/?$/.exec(url.pathname)
  if (employee && uuid.test(employee[1]!)) path = `/employees/${employee[1]}`
  else if (history && uuid.test(history[1]!)) path = `/employees/${history[1]}/organization-history`
  else if (organization && uuid.test(organization[1]!)) path = `/orgs/${organization[1]}/${organization[2]}`
  else if (/^\/security\/grants\/?$/.test(url.pathname)) path = '/security/grants'
  else if (url.pathname === '/') path = '/'
  else return '/'
  const query = Array.from(url.searchParams.entries())
  if (history && query.length === 2 && url.searchParams.getAll('from').length === 1 && url.searchParams.getAll('to').length === 1) {
    const from = url.searchParams.get('from')!, to = url.searchParams.get('to')!
    if (validDate(from) && validDate(to) && from < to) return `${path}?${new URLSearchParams({ from, to })}`
  } else if (!history && query.length === 1 && query[0]![0] === 'as_of' && validDate(query[0]![1])) {
    return `${path}?${new URLSearchParams({ as_of: query[0]![1] })}`
  }
  return path
}
function cancelOperation() {
  generation += 1
  controller?.abort()
  controller = null
}
function beginOperation(next: Phase): Operation {
  cancelOperation()
  protectedGeneration.value += 1
  phase.value = next
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
      typeof next.auth_epoch !== 'string' || !revision.test(next.auth_epoch) ||
      next.auth_epoch.length > 19 || BigInt(next.auth_epoch) > 9223372036854775807n ||
      typeof next.csrf_token !== 'string' || !next.csrf_token ||
      typeof next.mfa_recent !== 'boolean' ||
      (next.identity_available !== undefined && typeof next.identity_available !== 'boolean')) return null
  // Do not retain the response's business capabilities, authorities or unrelated fields.
  return {
    subject_id: next.subject_id, org_id: next.org_id, auth_epoch: next.auth_epoch,
    csrf_token: next.csrf_token, mfa_recent: next.mfa_recent, identity_available: next.identity_available,
  }
}
function sameIdentity(left: SessionHint, right: SessionHint) {
  return left.subject_id === right.subject_id && left.org_id === right.org_id && left.auth_epoch === right.auth_epoch
}
function expireSession() {
  cancelOperation()
  protectedGeneration.value += 1
  session.value = null
  logoutCSRF = null
  phase.value = 'expired'
}
async function checkSession() {
  const previous = session.value
  const operation = beginOperation('checking')
  // Destroy protected instances and abort their operations before checking a new context.
  await nextTick()
  if (!isCurrent(operation)) return
  try {
    const response = await fetch('/api/v1/session', {
      credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
    })
    if (!isCurrent(operation)) return
    if (response.status === 401) { expireSession(); return }
    if (!response.ok) throw new Error('Session unavailable')
    const next = sessionHint(await response.json())
    if (!isCurrent(operation)) return
    if (!next) throw new Error('Session unavailable')
    if (previous && !sameIdentity(previous, next)) {
      session.value = null
      phase.value = 'changed'
      return
    }
    session.value = next
    phase.value = 'authenticated'
  } catch {
    if (!isCurrent(operation)) return
    session.value = null
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
function routeChanged() {
  returnTo.value = knownReturnRoute()
  if (phase.value === 'authenticated' || phase.value === 'checking') void checkSession()
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
onMounted(() => {
  alive = true
  window.addEventListener('popstate', routeChanged)
  window.addEventListener('focus', resume)
  window.addEventListener('pageshow', resume)
  window.addEventListener('pagehide', suspend)
  void checkSession()
})
onBeforeUnmount(() => {
  alive = false
  window.removeEventListener('popstate', routeChanged)
  window.removeEventListener('focus', resume)
  window.removeEventListener('pageshow', resume)
  window.removeEventListener('pagehide', suspend)
  cancelOperation()
  session.value = null
  logoutCSRF = null
})
</script>

<template>
  <section aria-label="共同身份与会话" :data-identity-state="phase" :aria-busy="['checking', 'logging-out', 'mfa-starting'].includes(phase)">
    <template v-if="phase === 'authenticated'">
      <p>会话已核对。{{ session?.mfa_recent ? '近期 MFA 已由身份设施验证。' : '敏感操作可能需要重新完成可信 MFA。' }} 身份摘要不是业务访问许可。</p>
      <button type="button" @click="checkSession">重新核对会话（清空当前页面）</button>
      <button v-if="identityAvailable" type="button" @click="stepUp">{{ stepUpAction === 'access_grant.manage' ? '重新验证授权管理 MFA' : '重新验证资料写入 MFA' }}</button>
      <p v-else>可信登录与 MFA 设施未启用，不能在本地完成验证。</p>
    </template>
    <p v-else-if="phase === 'checking'" role="status">正在核对服务端会话；受保护页面尚未开放。</p>
    <p v-else-if="phase === 'logged-out'" role="status">服务端已确认撤销本会话，当前页面资料已清空。未请求外部身份站点的全局登出。</p>
    <p v-else-if="phase === 'expired'" role="alert">会话不存在或已失效，受保护页面与表单已清空。请通过可信身份设施登录。</p>
    <p v-else-if="phase === 'changed'" role="alert">主体、组织或授权 epoch 已改变。旧页面已销毁；请重新核对会话后再操作。</p>
    <p v-else-if="phase === 'unavailable'" role="alert">无法核对会话，受保护页面保持关闭。可手动重新核对。</p>
    <p v-else-if="phase === 'logging-out'" role="status">页面资料已清空，正在等待服务端撤销会话的确认。</p>
    <p v-else-if="phase === 'logout-failed'" role="alert">页面资料已清空，但服务端撤销尚未确认。不能视为已注销；可重试撤销本会话。</p>
    <p v-else-if="phase === 'mfa-starting' || phase === 'mfa-redirecting'" role="status">正在前往可信身份设施重新验证 MFA。返回后将重新读取会话，不自动提交业务操作。</p>
    <p v-else-if="phase === 'mfa-failed'" role="alert">未能开始可信 MFA 验证，未获得新的认证证明。页面保持关闭；可重新核对会话后再尝试。</p>
    <p v-else-if="phase === 'login-redirecting'" role="status">正在前往可信身份设施登录。</p>
    <button v-if="canLogout" type="button" @click="logout">注销本会话</button>
    <button v-if="phase === 'logout-failed'" type="button" @click="logout">重试注销本会话</button>
    <button v-if="['expired', 'changed', 'unavailable', 'mfa-failed'].includes(phase)" type="button" @click="checkSession">重新核对会话</button>
    <a v-if="['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed'].includes(phase)" :href="loginURL" @click="login">通过可信身份设施登录</a>
  </section>
  <div v-if="phase === 'authenticated'" :key="protectedGeneration">
    <slot :expireSession="expireSession" :orgID="session?.org_id" />
  </div>
</template>

<style scoped>
section { max-width: 72rem; margin: 1rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; }
button, a { margin-right: 1rem; }
[role="alert"] { color: #9b1c1c; }
</style>
