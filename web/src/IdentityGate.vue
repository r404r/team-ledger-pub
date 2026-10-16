<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import QRCode from 'qrcode'

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
  can_manage_users: boolean
}
type Phase = 'checking' | 'authenticated' | 'logged-out' | 'expired' | 'changed' | 'unavailable' |
  'logging-out' | 'logout-failed' | 'mfa-starting' | 'mfa-redirecting' | 'mfa-failed' | 'login-redirecting' | 'login-failed' | 'login-totp' | 'password-change' | 'password-changing' | 'password-change-failed' | 'password-changed' | 'enrollment-loading' | 'enrolling' | 'mfa-confirming' | 'recovery-code' | 'recovery-failed'
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
const totpCode = ref('')
const recoveryCodeInput = ref('')
const loginKind = ref<'password' | 'recovery'>('password')
const temporaryPassword = ref('')
const replacementPassword = ref('')
const replacementConfirm = ref('')
const passwordChangeError = ref('')
const restrictedCSRF = ref('')
const enrollment = shallowRef<{ secret: string; uri: string; mode: 'initial' | 'replace' | 'recovery'; expires_at: string } | null>(null)
const enrollmentCode = ref('')
const enrollmentCanvas = ref<HTMLCanvasElement | null>(null)
const oneTimeRecoveryCode = ref('')
const recoverySaved = ref(false)
const securityMode = ref<'stepup' | 'replace' | 'replace-confirm' | 'recovery-code' | 'code' | null>(null)
const securityPassword = ref('')
const securityTOTP = ref('')
const securityError = ref('')
const securityBusy = ref(false)
const securityRecoveryCode = ref('')
const securitySaved = ref(false)
const securityEnrollment = shallowRef<{ secret: string; uri: string; mode: 'initial' | 'replace' | 'recovery'; expires_at: string } | null>(null)
const securityCanvas = ref<HTMLCanvasElement | null>(null)
const securityNotice = ref('')
const protectedGeneration = ref(0)
const sessionPanel = ref<HTMLDetailsElement | null>(null)
const sessionSummary = ref<HTMLElement | null>(null)
let alive = false
let generation = 0
let controller: AbortController | null = null
let logoutCSRF: string | null = null
let expiryTimer: ReturnType<typeof setInterval> | null = null
let recoveryRequestID = ''

const loginURL = computed(() => `/api/v1/auth/login?${new URLSearchParams({ return_to: returnTo.value })}`)
const identityAvailable = computed(() => session.value?.identity_available !== false)
const canLogout = computed(() => session.value !== null && !['logging-out', 'logout-failed', 'login-redirecting'].includes(phase.value))
const interviewRoute = computed(() => /^\/interviews(?:\/|$)/.test(returnTo.value) || /^\/employees\/[^/]+\/interviews$/.test(returnTo.value))
const followupRoute = computed(() => /^\/employees\/[^/]+\/followup$/.test(returnTo.value))
const compensationRoute = computed(() => /^\/employees\/[^/]+\/(?:compensation|bonuses)(?:\?|$)/.test(returnTo.value) || /^\/orgs\/[^/]+\/compensation-adjustments(?:\?|$)/.test(returnTo.value))
const stepUpAction = computed(() => returnTo.value.split('?')[0] === '/security/grants' ? 'access_grant.manage' : returnTo.value.split('?')[0] === '/security/audit' ? 'audit.read' : returnTo.value.split('?')[0] === '/security/users' ? 'identity.manage' : compensationRoute.value ? compensationIntent.value : followupRoute.value ? 'interview_policy.manage' : interviewRoute.value ? interviewIntent.value : 'pii.write')
const canManageUsers = computed(() => session.value?.can_manage_users === true)

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
  else if (/^\/security\/audit\/?$/.test(url.pathname)) path = '/security/audit'
  else if (/^\/security\/users\/?$/.test(url.pathname)) path = '/security/users'
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
  const next = value as Partial<SessionHint> & { capabilities?: unknown }
  if (typeof next.subject_id !== 'string' || !uuid.test(next.subject_id) ||
      typeof next.org_id !== 'string' || !uuid.test(next.org_id) ||
      typeof next.business_date !== 'string' || !validDate(next.business_date) ||
      typeof next.auth_epoch !== 'string' || !revision.test(next.auth_epoch) ||
      next.auth_epoch.length > 19 || BigInt(next.auth_epoch) > 9223372036854775807n ||
      typeof next.csrf_token !== 'string' || !next.csrf_token ||
      typeof next.mfa_recent !== 'boolean' ||
      (next.identity_available !== undefined && typeof next.identity_available !== 'boolean') ||
      (next.identity_mode !== undefined && next.identity_mode !== 'local' && next.identity_mode !== 'oidc') ||
      (next.capabilities !== undefined && (!Array.isArray(next.capabilities) || !next.capabilities.every(capability => typeof capability === 'string')))) return null
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
    sensitivity_valid_until: next.sensitivity_valid_until, can_manage_users: Array.isArray(next.capabilities) && next.capabilities.includes('identity.manage'),
}
}
function sameIdentity(left: SessionHint, right: SessionHint) {
  return left.subject_id === right.subject_id && left.org_id === right.org_id && left.auth_epoch === right.auth_epoch
}
function validEnrollment(value: unknown) {
  if (!value || typeof value !== 'object') return null
  const candidate = value as Record<string, unknown>
  if (typeof candidate.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(candidate.secret) ||
      typeof candidate.uri !== 'string' || !candidate.uri.startsWith('otpauth://totp/') ||
      !['initial', 'replace', 'recovery'].includes(String(candidate.mode)) ||
      typeof candidate.expires_at !== 'string' || Number.isNaN(Date.parse(candidate.expires_at))) return null
  return candidate as { secret: string; uri: string; mode: 'initial' | 'replace' | 'recovery'; expires_at: string }
}
async function drawEnrollmentQR(target: HTMLCanvasElement | null, uri: string) {
  if (!target || navigator.userAgent.includes('jsdom')) return
  try {
    await QRCode.toCanvas(target, uri, { width: 216, margin: 1, errorCorrectionLevel: 'M' })
  } catch {
    // The manual Base32 key remains the local, service-independent fallback.
  }
}
function clearRestrictedSecrets() {
  enrollment.value = null
  enrollmentCode.value = ''
  restrictedCSRF.value = ''
  recoveryCodeInput.value = ''
  temporaryPassword.value = ''
  replacementPassword.value = ''
  replacementConfirm.value = ''
  passwordChangeError.value = ''
}
function clearSecuritySecrets() {
  securityPassword.value = ''
  securityTOTP.value = ''
  securityEnrollment.value = null
  securityRecoveryCode.value = ''
  securitySaved.value = false
  securityError.value = ''
  securityMode.value = null
}

function expireSession() {
  cancelOperation()
  protectedGeneration.value += 1
  session.value = null
  globalViewDate.value = ''
  logoutCSRF = null
  clearRestrictedSecrets()
  oneTimeRecoveryCode.value = ''
  recoverySaved.value = false
  clearSecuritySecrets()
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
  clearRestrictedSecrets()
  oneTimeRecoveryCode.value = ''
  recoverySaved.value = false
  clearSecuritySecrets()
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
  if (identityMode.value === 'local') {
    securityPassword.value = ''
    securityTOTP.value = ''
    securityError.value = ''
    securityMode.value = 'stepup'
    return
  }
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
async function loadRestrictedEnrollment(next: 'enroll' | 'recover', operation: Operation) {
  const response = await fetch(next === 'enroll' ? '/api/v1/auth/local/mfa/enrollment' : '/api/v1/auth/local/mfa/pending', {
    method: next === 'enroll' ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
    headers: next === 'enroll' ? { 'Content-Type': 'application/json', 'X-CSRF-Token': restrictedCSRF.value } : undefined,
    body: next === 'enroll' ? '{}' : undefined,
  })
  if (!isCurrent(operation)) return
  if (!response.ok) throw new Error('Enrollment unavailable')
  const pending = validEnrollment(await response.json())
  if (!isCurrent(operation) || !pending) throw new Error('Enrollment unavailable')
  enrollment.value = pending
  phase.value = 'enrolling'
  await nextTick()
  await drawEnrollmentQR(enrollmentCanvas.value, pending.uri)
}
async function localLogin() {
  if (identityMode.value !== 'local' || phase.value === 'login-redirecting') return
  const operation = beginOperation('login-redirecting')
  try {
    const recovering = loginKind.value === 'recovery'
    const payload: Record<string, string> = { username: username.value, password: password.value, return_to: returnTo.value }
    if (recovering) payload.recovery_code = recoveryCodeInput.value
    else if (totpCode.value) payload.totp_code = totpCode.value
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (recovering) {
      if (!recoveryRequestID) recoveryRequestID = crypto.randomUUID()
      headers['Idempotency-Key'] = recoveryRequestID
    }
    const response = await fetch(recovering ? '/api/v1/auth/local/recover' : '/api/v1/auth/local/login', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers, body: JSON.stringify(payload),
    })
    password.value = ''
    totpCode.value = ''
    recoveryCodeInput.value = ''
    if (!isCurrent(operation)) return
    const body: unknown = await response.json()
    if (!response.ok) {
      if (recovering) recoveryRequestID = ''
      if (!recovering && response.status === 403 && body && typeof body === 'object' && 'code' in body && body.code === 'MFA_REQUIRED') phase.value = 'login-totp'
      else phase.value = recovering ? 'recovery-failed' : 'login-failed'
      return
    }
    if (!body || typeof body !== 'object' || !('return_to' in body) || typeof body.return_to !== 'string') {
      if (recovering) recoveryRequestID = ''
      phase.value = recovering ? 'recovery-failed' : 'login-failed'
      return
    }
    if (response.status === 202) {
      if (!('csrf_token' in body) || typeof body.csrf_token !== 'string' || !body.csrf_token ||
          !('next' in body) || body.next !== 'enroll' && body.next !== 'recover' && body.next !== 'change_password') {
        phase.value = 'login-failed'
        return
      }
      restrictedCSRF.value = body.csrf_token
      logoutCSRF = body.csrf_token
      if (body.next === 'change_password') {
        passwordChangeError.value = ''
        phase.value = 'password-change'
      } else {
        phase.value = 'enrollment-loading'
        await loadRestrictedEnrollment(body.next, operation)
      }
      recoveryRequestID = ''
      return
    }
    window.location.assign(body.return_to)
  } catch {
    password.value = ''
    totpCode.value = ''
    recoveryCodeInput.value = ''
    if (isCurrent(operation)) phase.value = loginKind.value === 'recovery' ? 'recovery-failed' : 'login-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
async function submitInitialPassword() {
  if (!restrictedCSRF.value || phase.value !== 'password-change' && phase.value !== 'password-change-failed') return
  if (replacementPassword.value !== replacementConfirm.value || replacementPassword.value === temporaryPassword.value) {
    passwordChangeError.value = replacementPassword.value !== replacementConfirm.value ? '两次输入的新密码不一致。' : '新密码不能与初始密码相同。'
    return
  }
  const operation = beginOperation('password-changing')
  passwordChangeError.value = ''
  const payload = JSON.stringify({ current_password: temporaryPassword.value, new_password: replacementPassword.value })
  const request = fetch('/api/v1/auth/local/initial-password', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': restrictedCSRF.value }, body: payload,
  })
  temporaryPassword.value = ''
  replacementPassword.value = ''
  replacementConfirm.value = ''
  try {
    const response = await request
    if (!isCurrent(operation)) return
    if (response.status !== 204) {
      passwordChangeError.value = response.status === 401 ? '受限会话已失效，请重新登录。' : '密码修改失败。请重新输入初始密码，并使用不同的 12..256 位新密码。'
      phase.value = response.status === 401 ? 'expired' : 'password-change-failed'
      if (response.status === 401) { restrictedCSRF.value = ''; logoutCSRF = null }
      return
    }
    restrictedCSRF.value = ''
    logoutCSRF = null
    phase.value = 'password-changed'
  } catch {
    if (isCurrent(operation)) {
      passwordChangeError.value = '无法确认密码修改结果。请返回登录页，先尝试使用新密码登录。'
      restrictedCSRF.value = ''
      logoutCSRF = null
      phase.value = 'password-changed'
    }
  } finally {
    if (isCurrent(operation)) controller = null
  }
}

async function confirmEnrollment() {
  if (!enrollment.value || !restrictedCSRF.value || phase.value !== 'enrolling') return
  const operation = beginOperation('mfa-confirming')
  try {
    const response = await fetch('/api/v1/auth/local/mfa/confirm', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': restrictedCSRF.value },
      body: JSON.stringify({ totp_code: enrollmentCode.value }),
    })
    enrollmentCode.value = ''
    if (!isCurrent(operation)) return
    if (!response.ok) { phase.value = 'enrolling'; return }
    const body: unknown = await response.json()
    if (!body || typeof body !== 'object' || !('recovery_code' in body) || typeof body.recovery_code !== 'string' ||
        !('csrf_token' in body) || typeof body.csrf_token !== 'string') throw new Error('Invalid enrollment response')
    oneTimeRecoveryCode.value = body.recovery_code
    restrictedCSRF.value = body.csrf_token
    logoutCSRF = body.csrf_token
    enrollment.value = null
    phase.value = 'recovery-code'
  } catch {
    if (isCurrent(operation)) phase.value = enrollment.value ? 'enrolling' : 'login-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
async function cancelEnrollment() {
  if (!restrictedCSRF.value) return
  const operation = beginOperation('logging-out')
  try {
    const response = await fetch('/api/v1/auth/local/mfa/cancel', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': restrictedCSRF.value }, body: '{}',
    })
    if (!isCurrent(operation)) return
    if (response.status !== 204) throw new Error('Cancel unavailable')
    clearRestrictedSecrets()
    logoutCSRF = null
    recoveryRequestID = ''
    phase.value = 'logged-out'
  } catch {
    if (isCurrent(operation)) phase.value = 'logout-failed'
  } finally {
    if (isCurrent(operation)) controller = null
  }
}
function finishRecoveryCode() {
  if (!recoverySaved.value) return
  oneTimeRecoveryCode.value = ''
  recoveryRequestID = ''
  recoverySaved.value = false
  clearRestrictedSecrets()
  logoutCSRF = null
  void checkSession()
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
function openSecurity(mode: 'replace' | 'recovery-code') {
  closeSessionPanel()
  securityPassword.value = ''
  securityTOTP.value = ''
  securityError.value = ''
  securityNotice.value = ''
  securityMode.value = mode
}
function applyRotatedCSRF(csrf: string) {
  if (!session.value || !csrf) return false
  session.value = { ...session.value, csrf_token: csrf, mfa_recent: true }
  logoutCSRF = csrf
  return true
}
async function submitSecurity() {
  if (!session.value || !securityMode.value || securityBusy.value || !['stepup', 'replace', 'recovery-code'].includes(securityMode.value)) return
  const mode = securityMode.value
  const csrf = session.value.csrf_token
  const operation = beginOperation(null)
  securityBusy.value = true
  securityError.value = ''
  try {
    const path = mode === 'stepup' ? '/api/v1/auth/step-up' : mode === 'replace' ? '/api/v1/auth/local/mfa/replace' : '/api/v1/auth/local/mfa/recovery-code'
    const payload = mode === 'stepup'
      ? { action: stepUpAction.value, return_to: knownReturnRoute(), current_password: securityPassword.value, totp_code: securityTOTP.value }
      : { current_password: securityPassword.value, totp_code: securityTOTP.value }
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: JSON.stringify(payload),
    })
    securityPassword.value = ''
    securityTOTP.value = ''
    if (!isCurrent(operation)) return
    if (response.status === 401) { expireSession(); return }
    if (!response.ok) { securityError.value = '验证失败。请使用当前密码和验证器中的新验证码重试。'; return }
    const body: unknown = await response.json()
    if (mode === 'replace') {
      const next = validEnrollment(body)
      if (!next || next.mode !== 'replace') throw new Error('Invalid replacement')
      securityEnrollment.value = next
      securityMode.value = 'replace-confirm'
      await nextTick()
      await drawEnrollmentQR(securityCanvas.value, next.uri)
      return
    }
    if (!body || typeof body !== 'object' || !('csrf_token' in body) || typeof body.csrf_token !== 'string' || !applyRotatedCSRF(body.csrf_token)) {
      throw new Error('Invalid security response')
    }
    if (mode === 'recovery-code') {
      if (!('recovery_code' in body) || typeof body.recovery_code !== 'string') throw new Error('Invalid recovery code')
      securityRecoveryCode.value = body.recovery_code
      securityMode.value = 'code'
    } else {
      securityMode.value = null
      securityNotice.value = 'MFA 已重新验证。请重新执行刚才的敏感操作。'
    }
  } catch {
    if (isCurrent(operation)) securityError.value = '账号安全操作未完成；未改变当前验证器或恢复码。'
  } finally {
    if (isCurrent(operation)) controller = null
    securityBusy.value = false
  }
}
async function confirmSecurityEnrollment() {
  if (!session.value || !securityEnrollment.value || securityMode.value !== 'replace-confirm' || securityBusy.value) return
  const operation = beginOperation(null)
  securityBusy.value = true
  securityError.value = ''
  try {
    const response = await fetch('/api/v1/auth/local/mfa/confirm', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.value.csrf_token },
      body: JSON.stringify({ totp_code: securityTOTP.value }),
    })
    securityTOTP.value = ''
    if (!isCurrent(operation)) return
    if (response.status === 401) { expireSession(); return }
    if (!response.ok) { securityError.value = '验证码无效或已使用；请输入验证器中的新验证码。'; return }
    const body: unknown = await response.json()
    if (!body || typeof body !== 'object' || !('csrf_token' in body) || typeof body.csrf_token !== 'string' ||
        !('recovery_code' in body) || typeof body.recovery_code !== 'string' || !applyRotatedCSRF(body.csrf_token)) {
      throw new Error('Invalid replacement confirmation')
    }
    securityEnrollment.value = null
    securityRecoveryCode.value = body.recovery_code
    securityMode.value = 'code'
  } catch {
    if (isCurrent(operation)) securityError.value = '新验证器尚未启用；原验证器仍然有效。'
  } finally {
    if (isCurrent(operation)) controller = null
    securityBusy.value = false
  }
}
async function cancelSecurityEnrollment() {
  if (!session.value || securityMode.value !== 'replace-confirm' || securityBusy.value) {
    clearSecuritySecrets()
    return
  }
  const operation = beginOperation(null)
  securityBusy.value = true
  try {
    const response = await fetch('/api/v1/auth/local/mfa/cancel', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: operation.controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.value.csrf_token }, body: '{}',
    })
    if (!isCurrent(operation)) return
    if (response.status !== 204) throw new Error('Cancel unavailable')
    session.value = null
    clearSecuritySecrets()
    phase.value = 'logged-out'
  } catch {
    if (isCurrent(operation)) securityError.value = '无法确认取消。为避免误用，请注销当前会话。'
  } finally {
    if (isCurrent(operation)) controller = null
    securityBusy.value = false
  }
}
function finishSecurityCode() {
  if (!securitySaved.value) return
  clearSecuritySecrets()
  securityNotice.value = '新的恢复码已生效，旧恢复码已失效。'
}

function closeSessionPanel(returnFocus = false) {
  if (!sessionPanel.value?.open) return
  sessionPanel.value.open = false
  if (returnFocus) sessionSummary.value?.focus()
}
function closeSessionPanelFromPointer(event: PointerEvent) {
  if (sessionPanel.value?.open && event.target instanceof Node && !sessionPanel.value.contains(event.target)) closeSessionPanel()
}
function closeSessionPanelFromKey(event: KeyboardEvent) {
  if (event.key !== 'Escape') return
  if (sessionPanel.value?.open) {
    event.preventDefault()
    closeSessionPanel(true)
    return
  }
  if (securityMode.value && ['stepup', 'replace', 'recovery-code'].includes(securityMode.value) && !securityBusy.value) {
    event.preventDefault()
    clearSecuritySecrets()
  }
}
function routeChanged() {
  closeSessionPanel()
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
  clearRestrictedSecrets(); clearSecuritySecrets(); oneTimeRecoveryCode.value = ''
  phase.value = 'changed'
}
onMounted(() => {
  alive = true
  window.addEventListener('popstate', routeChanged)
  window.addEventListener('focus', resume)
  window.addEventListener('pageshow', resume)
  window.addEventListener('pagehide', suspend)
  expiryTimer = setInterval(clearExpiredSensitivity, 1000)
  document.addEventListener('pointerdown', closeSessionPanelFromPointer)
  document.addEventListener('keydown', closeSessionPanelFromKey)
  void checkSession()
})
onBeforeUnmount(() => {
  alive = false
  window.removeEventListener('popstate', routeChanged)
  document.removeEventListener('pointerdown', closeSessionPanelFromPointer)
  document.removeEventListener('keydown', closeSessionPanelFromKey)
  window.removeEventListener('focus', resume)
  window.removeEventListener('pageshow', resume)
  window.removeEventListener('pagehide', suspend)
  if (expiryTimer) clearInterval(expiryTimer)
  cancelOperation()
  session.value = null
  logoutCSRF = null
  clearRestrictedSecrets()
  clearSecuritySecrets()
  oneTimeRecoveryCode.value = ''
  recoveryRequestID = ''
})
</script>

<template>
  <section :class="{ 'identity-shell': phase !== 'authenticated', 'identity-shell-wide': ['password-change', 'password-changing', 'password-change-failed', 'enrolling', 'mfa-confirming', 'recovery-code'].includes(phase) }" aria-label="共同身份与会话" :data-identity-state="phase" :aria-busy="['checking', 'logging-out', 'mfa-starting', 'password-changing', 'enrollment-loading', 'mfa-confirming'].includes(phase)">
    <template v-if="phase === 'authenticated'">
      <div :key="protectedGeneration">
        <slot :expireSession="expireSession" :orgID="session?.org_id" :asOf="globalViewDate" :setAsOf="setGlobalViewDate" :canManageUsers="canManageUsers" />
      </div>
      <Teleport defer :key="`session-${protectedGeneration}`" to="#identity-session-target">
        <details ref="sessionPanel" class="identity-session-panel">
          <summary ref="sessionSummary">
            <span class="identity-indicator" aria-hidden="true"></span>
            <span class="identity-copy">
              <strong>会话正常</strong>
              <span>{{ session?.mfa_recent ? 'MFA 有效' : identityMode === 'local' ? 'MFA 未提供' : 'MFA 待验证' }}</span>
            </span>
            <span class="identity-disclosure" aria-hidden="true"></span>
            <span class="sr-only">会话与安全</span>
          </summary>
          <div class="identity-session-body">
            <p>身份摘要不是业务访问许可；页面仍按当前scope、purpose和能力独立授权。</p>
            <div class="identity-actions">
              <button type="button" @click="closeSessionPanel(); checkSession()">重新核对会话（清空当前页面）</button>
              <button v-if="canLogout" type="button" @click="closeSessionPanel(); logout()">注销本会话</button>
            </div>
            <div class="identity-tools">
              <div v-if="identityAvailable" class="identity-tools-row">
                <label v-if="interviewRoute" for="interview-stepup-intent">重新验证意图<select id="interview-stepup-intent" v-model="interviewIntent"><option value="note.publish">发布笔记</option><option value="sensitive.export">敏感导出</option></select></label>
                <label v-if="compensationRoute" for="compensation-stepup-intent">财务重新验证意图<select id="compensation-stepup-intent" v-model="compensationIntent"><option value="compensation.read">财务读取</option><option value="compensation.propose">薪酬提出</option><option value="compensation.approve">独立薪酬审批</option><option value="bonus.target.manage">奖金目标维护</option><option value="bonus.propose">奖金奖励维护</option><option value="bonus.approve">独立奖金审批</option><option value="bonus.payment.record">奖金支付事实</option><option value="compensation.extension.manage">薪酬有限扩展</option><option value="sensitive.export">财务敏感导出</option></select></label>
                <button type="button" @click="closeSessionPanel(); stepUp()">{{ compensationRoute ? '重新验证财务 MFA' : stepUpAction === 'access_grant.manage' ? '重新验证授权管理 MFA' : stepUpAction === 'audit.read' ? '重新验证审计 MFA' : stepUpAction === 'identity.manage' ? '重新验证用户管理 MFA' : stepUpAction === 'interview_policy.manage' ? '重新验证跟进策略 MFA' : stepUpAction === 'note.publish' ? '重新验证笔记发布 MFA' : stepUpAction === 'sensitive.export' ? '重新验证敏感导出 MFA' : '重新验证资料写入 MFA' }}</button>
              </div>
              <p v-if="interviewRoute || compensationRoute || followupRoute || stepUpAction === 'audit.read' || stepUpAction === 'identity.manage'">MFA 是会话级近期认证；认证后重载并明确重新确认，不自动提交、审批、创建用户、生成结论、查询审计或导出。</p>
              <p v-if="securityNotice" class="security-success" role="status">{{ securityNotice }}</p>
              <details v-if="identityMode === 'local'" class="identity-account-panel">
                <summary>账号安全、验证器与密码</summary>
                <div class="identity-actions">
                  <button type="button" @click="openSecurity('replace')">更换 TOTP 验证器</button>
                  <button type="button" @click="openSecurity('recovery-code')">生成新恢复码</button>
                </div>
                <form @submit.prevent="closeSessionPanel(); changePassword()">
                  <label for="current-password">当前密码<input id="current-password" v-model="currentPassword" type="password" autocomplete="current-password" required minlength="12" maxlength="256"></label>
                  <label for="new-password">新密码<input id="new-password" v-model="newPassword" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
                  <button type="submit">修改密码并注销全部会话</button>
                </form>
              </details>
            </div>
          </div>
        </details>
      </Teleport>
      <div v-if="securityMode" class="security-modal-backdrop">
        <section class="security-modal" role="dialog" aria-modal="true" aria-labelledby="security-dialog-title">
          <header>
            <div><p class="eyebrow">本地账号安全</p><h2 id="security-dialog-title">{{ securityMode === 'stepup' ? '重新验证 MFA' : securityMode === 'replace' || securityMode === 'replace-confirm' ? '更换验证器' : securityMode === 'recovery-code' ? '生成新恢复码' : '保存恢复码' }}</h2></div>
            <button v-if="securityMode !== 'replace-confirm' && securityMode !== 'code'" type="button" aria-label="关闭账号安全窗口" @click="clearSecuritySecrets()">关闭</button>
          </header>
          <p v-if="securityError" class="security-error" role="alert">{{ securityError }}</p>
          <form v-if="['stepup', 'replace', 'recovery-code'].includes(securityMode)" class="security-form" @submit.prevent="submitSecurity">
            <p>{{ securityMode === 'stepup' ? '验证成功后请重新执行刚才的敏感操作；系统不会自动重放。' : securityMode === 'replace' ? '确认新验证器前，原验证器保持有效。' : '生成后旧恢复码立即失效；新码只显示一次。' }}</p>
            <label for="security-current-password">当前密码<input id="security-current-password" v-model="securityPassword" type="password" autocomplete="current-password" required minlength="12" maxlength="256" autofocus></label>
            <label for="security-totp">TOTP 验证码<input id="security-totp" v-model="securityTOTP" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label>
            <div class="identity-actions"><button type="button" @click="clearSecuritySecrets()">取消</button><button type="submit" :disabled="securityBusy">{{ securityBusy ? '正在验证…' : '确认' }}</button></div>
          </form>
          <div v-else-if="securityMode === 'replace-confirm' && securityEnrollment" class="enrollment-card">
            <p>使用验证器扫描二维码；若无法扫描，请手工输入密钥。密钥只在当前窗口显示。</p>
            <canvas ref="securityCanvas" class="totp-qr" aria-label="TOTP 登记二维码"></canvas>
            <div class="manual-secret"><span>手工密钥</span><code>{{ securityEnrollment.secret }}</code></div>
            <form class="security-form" @submit.prevent="confirmSecurityEnrollment">
              <label for="replacement-totp">新验证器验证码<input id="replacement-totp" v-model="securityTOTP" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required autofocus></label>
              <div class="identity-actions"><button type="button" :disabled="securityBusy" @click="cancelSecurityEnrollment">取消更换并注销</button><button type="submit" :disabled="securityBusy">启用新验证器</button></div>
            </form>
          </div>
          <div v-else-if="securityMode === 'code'" class="recovery-code-card">
            <p>这是唯一一次显示。请离线保存，不要存入共享文档或聊天工具。</p>
            <code>{{ securityRecoveryCode }}</code>
            <label><input v-model="securitySaved" type="checkbox">我已将恢复码保存在安全的离线位置</label>
            <button type="button" :disabled="!securitySaved" @click="finishSecurityCode">完成</button>
          </div>
        </section>
      </div>
    </template>
    <template v-else>
      <div class="auth-heading">
        <span class="brand-mark" aria-hidden="true">TL</span>
        <div><h1>TeamLedger</h1><p>受保护的人员运营工作区</p></div>
      </div>
      <p v-if="phase === 'checking'" role="status">正在核对服务端会话；受保护页面尚未开放。</p>
      <p v-else-if="phase === 'enrollment-loading'" role="status">正在建立仅限验证器登记的受限会话。</p>
      <p v-else-if="phase === 'logged-out'" role="status">服务端已确认撤销本会话，当前页面资料已清空。</p>
      <p v-else-if="phase === 'expired'" role="alert">会话不存在或已失效，受保护页面与表单已清空。请重新登录。</p>
      <p v-else-if="phase === 'changed'" role="alert">主体、组织、授权上下文或当前敏感显示期限已改变。旧页面已销毁；请重新核对会话后再操作。</p>
      <p v-else-if="phase === 'unavailable'" role="alert">无法核对会话，受保护页面保持关闭。可手动重新核对。</p>
      <p v-else-if="phase === 'logging-out'" role="status">页面资料已清空，正在等待服务端撤销会话的确认。</p>
      <p v-else-if="phase === 'logout-failed'" role="alert">页面资料已清空，但服务端撤销尚未确认。不能视为已注销；可重试撤销本会话。</p>
      <p v-else-if="phase === 'mfa-starting' || phase === 'mfa-redirecting'" role="status">正在前往可信身份设施重新验证 MFA。返回后将重新读取会话，不自动提交业务操作。</p>
      <p v-else-if="phase === 'mfa-failed'" role="alert">未能开始可信 MFA 验证，未获得新的认证证明。页面保持关闭；可重新核对会话后再尝试。</p>
      <p v-else-if="phase === 'login-redirecting'" role="status">{{ identityMode === 'local' ? '正在验证本地账号。' : '正在前往可信身份设施登录。' }}</p>
      <p v-else-if="phase === 'login-totp'" role="status">密码已确认。请输入验证器中的 6 位新验证码；密码需要再次输入且不会保留。</p>
      <p v-else-if="phase === 'login-failed'" role="alert">账号、密码、验证码或登录状态无效；请稍后重试。</p>
      <p v-else-if="phase === 'password-changed'" role="status">密码修改请求已经结束，受限会话已撤销。请使用新密码重新登录；若刚才网络中断，请先尝试新密码，再尝试初始密码。</p>
      <p v-else-if="phase === 'recovery-failed'" role="alert">账号、密码或恢复码无效；未开始账号恢复。</p>
      <section v-if="['password-change', 'password-changing', 'password-change-failed'].includes(phase)" class="enrollment-card" aria-labelledby="initial-password-title">
        <p class="eyebrow">首次登录 · 必须完成</p>
        <h2 id="initial-password-title">修改初始密码</h2>
        <p>当前会话只能修改密码或注销，不能打开用户、员工、授权或审计资料。修改成功后，请用新密码重新登录并登记 TOTP。</p>
        <p v-if="passwordChangeError" role="alert">{{ passwordChangeError }}</p>
        <form @submit.prevent="submitInitialPassword">
          <label for="temporary-password">初始密码<input id="temporary-password" v-model="temporaryPassword" type="password" autocomplete="current-password" required minlength="12" maxlength="256" autofocus></label>
          <label for="replacement-password">新密码<input id="replacement-password" v-model="replacementPassword" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
          <label for="replacement-confirm">再次输入新密码<input id="replacement-confirm" v-model="replacementConfirm" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
          <div class="identity-actions"><button type="button" :disabled="phase === 'password-changing'" @click="logout">取消并注销</button><button type="submit" :disabled="phase === 'password-changing' || replacementPassword !== replacementConfirm">{{ phase === 'password-changing' ? '正在修改…' : '修改密码并注销' }}</button></div>
        </form>
      </section>
      <section v-else-if="(phase === 'enrolling' || phase === 'mfa-confirming') && enrollment" class="enrollment-card" aria-labelledby="enrollment-title">
        <p class="eyebrow">仅限账号安全</p>
        <h2 id="enrollment-title">{{ enrollment.mode === 'recovery' ? '恢复并设置新验证器' : '设置 TOTP 验证器' }}</h2>
        <p>使用任一标准离线验证器扫描二维码；TeamLedger 不调用外部 MFA 服务。无法扫描时可手工输入密钥。</p>
        <canvas ref="enrollmentCanvas" class="totp-qr" aria-label="TOTP 登记二维码"></canvas>
        <div class="manual-secret"><span>手工密钥</span><code>{{ enrollment.secret }}</code></div>
        <p class="expiry-note">本次登记于 {{ new Date(enrollment.expires_at).toLocaleString() }} 失效。</p>
        <form @submit.prevent="confirmEnrollment">
          <label for="enrollment-totp">验证器验证码<input id="enrollment-totp" v-model="enrollmentCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required autofocus></label>
          <div class="identity-actions"><button type="button" :disabled="phase === 'mfa-confirming'" @click="cancelEnrollment">取消并注销</button><button type="submit" :disabled="phase === 'mfa-confirming'">{{ phase === 'mfa-confirming' ? '正在确认…' : '确认并启用' }}</button></div>
        </form>
      </section>
      <section v-else-if="phase === 'recovery-code'" class="recovery-code-card" aria-labelledby="recovery-code-title">
        <p class="eyebrow">一次性显示</p><h2 id="recovery-code-title">保存账号恢复码</h2>
        <p>验证器遗失时，此恢复码与当前密码可用于设置新验证器。系统只保存不可逆校验值，无法再次显示原码。</p>
        <code>{{ oneTimeRecoveryCode }}</code>
        <label><input v-model="recoverySaved" type="checkbox">我已将恢复码保存在安全的离线位置</label>
        <button type="button" :disabled="!recoverySaved" @click="finishRecoveryCode">进入 TeamLedger</button>
      </section>
      <section v-else-if="phase === 'password-changed'" class="identity-actions"><button type="button" @click="phase = 'logged-out'">返回登录</button></section>
      <template v-else>
        <div class="identity-actions">
          <button v-if="canLogout" type="button" @click="logout">注销本会话</button>
          <button v-if="phase === 'logout-failed'" type="button" @click="logout">重试注销本会话</button>
          <button v-if="['expired', 'changed', 'unavailable', 'mfa-failed'].includes(phase)" type="button" @click="checkSession()">重新核对会话</button>
        </div>
        <div v-if="identityMode === 'local' && ['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed', 'login-failed', 'login-totp', 'recovery-failed'].includes(phase)" class="login-kind-switch" role="group" aria-label="本地登录方式">
          <button type="button" :aria-pressed="loginKind === 'password'" @click="loginKind = 'password'">密码与验证器</button>
          <button type="button" :aria-pressed="loginKind === 'recovery'" @click="loginKind = 'recovery'">使用恢复码</button>
        </div>
        <form v-if="identityMode === 'local' && ['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed', 'login-failed', 'login-totp', 'recovery-failed'].includes(phase)" @submit.prevent="localLogin">
          <label for="local-username">账号<input id="local-username" v-model="username" name="username" autocomplete="username" required minlength="3" maxlength="64"></label>
          <label for="local-password">密码<input id="local-password" v-model="password" name="password" type="password" autocomplete="current-password" required minlength="12" maxlength="256"></label>
          <label v-if="loginKind === 'password' && phase === 'login-totp'" for="local-totp">TOTP 验证码<input id="local-totp" v-model="totpCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label>
          <label v-if="loginKind === 'recovery'" for="local-recovery-code">恢复码<input id="local-recovery-code" v-model="recoveryCodeInput" autocomplete="off" pattern="[A-Za-z2-7-]{32,39}" minlength="32" maxlength="39" required></label>
          <button type="submit">{{ loginKind === 'recovery' ? '恢复账号' : phase === 'login-totp' ? '验证并登录' : '继续' }}</button>
        </form>
        <a v-else-if="identityMode === 'oidc' && ['logged-out', 'expired', 'changed', 'unavailable', 'logout-failed', 'mfa-failed'].includes(phase)" :href="loginURL" role="button" @click="login">通过可信身份设施登录</a>
      </template>
    </template>
  </section>
</template>
