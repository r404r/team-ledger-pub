import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import UserPage from './UserPage.vue'

const SUBJECT = '10000000-0000-4000-8000-000000000001'
const ORG = '10000000-0000-4000-8000-000000000002'
const ACCOUNT = '10000000-0000-4000-8000-000000000003'
const CREATED_SUBJECT = '10000000-0000-4000-8000-000000000004'
const session = { subject_id: SUBJECT, org_id: ORG, capabilities: ['identity.manage'], csrf_token: 'csrf-users', mfa_recent: true, mfa_valid_until: '2027-01-01T00:00:00Z' }
const user = { account_id: ACCOUNT, subject_id: SUBJECT, username: 'admin.user', active: true, password_change_required: false, mfa_status: 'active', created_at: '2026-10-16T01:02:03Z' }
const page = (items = [user], next_cursor: string | null = null) => ({ items, next_cursor, consistency: 'current' })
function response(status: number, body?: unknown) { return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
type Call = { url: URL; method: string; headers: Headers; body?: string }
let calls: Call[]

beforeEach(() => { calls = [] })
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

function install(handler?: (call: Call) => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const call = { url: new URL(String(input), location.href), method: init?.method ?? 'GET', headers: new Headers(init?.headers), body: init?.body as string | undefined }
    calls.push(call)
    if (handler) return handler(call)
    if (call.url.pathname === '/api/v1/session') return response(200, session)
    return response(200, page())
  }))
}
async function open() { const wrapper = mount(UserPage); await flushPromises(); return wrapper }

describe('P-SEC-03 local user administration', () => {
  it('lists only after independent permission and recent MFA checks', async () => {
    install()
    const wrapper = await open()
    expect(wrapper.text()).toContain('admin.user')
    expect(wrapper.text()).toContain('可登录')
    expect(calls.map(call => call.url.pathname)).toEqual(['/api/v1/session', '/api/v1/security/users'])
    expect(calls.every(call => call.headers.get('X-Access-Purpose') === 'security_administration')).toBe(true)
    wrapper.unmount()
  })

  it('does not call the user API when identity.manage is absent or MFA is stale', async () => {
    install(() => response(200, { ...session, capabilities: [] }))
    const denied = await open()
    expect(denied.text()).toContain('没有 identity.manage 权限')
    expect(denied.find('form').exists()).toBe(false)
    expect(calls.map(call => call.url.pathname)).toEqual(['/api/v1/session'])
    denied.unmount()

    calls = []
    install(() => response(200, { ...session, capabilities: ['identity.manage'], mfa_recent: false }))
    const stale = await open()
    expect(stale.text()).toContain('用户管理要求近期 MFA')
    expect(calls.map(call => call.url.pathname)).toEqual(['/api/v1/session'])
    stale.unmount()
  })

  it('creates a user with CSRF and idempotency, clears the password, then reloads the authoritative list', async () => {
    let listReads = 0
    install(call => {
      if (call.url.pathname === '/api/v1/session') return response(200, session)
      if (call.method === 'POST') return response(201, { account_id: ACCOUNT, subject_id: CREATED_SUBJECT })
      listReads += 1
      return response(200, page(listReads === 1 ? [user] : [user, { ...user, account_id: '10000000-0000-4000-8000-000000000005', subject_id: CREATED_SUBJECT, username: 'new.operator', password_change_required: true, mfa_status: 'enrollment_required' }]))
    })
    const wrapper = await open()
    await wrapper.get('input[name="username"]').setValue('new.operator')
    await wrapper.get('input[name="initial-password"]').setValue('temporary horse battery staple')
    await wrapper.get('input[name="confirm-password"]').setValue('temporary horse battery staple')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const create = calls.find(call => call.method === 'POST')!
    expect(create.url.pathname).toBe('/api/v1/security/users')
    expect(create.headers.get('X-Access-Purpose')).toBe('security_administration')
    expect(create.headers.get('X-CSRF-Token')).toBe('csrf-users')
    expect(create.headers.get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/)
    expect(JSON.parse(create.body!)).toEqual({ username: 'new.operator', initial_password: 'temporary horse battery staple' })
    expect((wrapper.get('input[name="initial-password"]').element as HTMLInputElement).value).toBe('')
    expect((wrapper.get('input[name="confirm-password"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.text()).not.toContain('temporary horse battery staple')
    expect(wrapper.text()).toContain('new.operator 已创建')
    expect(wrapper.text()).toContain('等待首次改密')
    expect(listReads).toBe(2)
    wrapper.unmount()
  })

  it('uses the opaque cursor to append the next page', async () => {
    install(call => {
      if (call.url.pathname === '/api/v1/session') return response(200, session)
      return call.url.searchParams.get('cursor') === 'opaque.cursor'
        ? response(200, page([{ ...user, account_id: '10000000-0000-4000-8000-000000000006', username: 'next.operator' }]))
        : response(200, page([user], 'opaque.cursor'))
    })
    const wrapper = await open()
    await wrapper.get('.list-footer button').trigger('click')
    await flushPromises()
    expect(calls.at(-1)?.url.searchParams.get('cursor')).toBe('opaque.cursor')
    expect(wrapper.text()).toContain('admin.user')
    expect(wrapper.text()).toContain('next.operator')
    expect(wrapper.text()).toContain('已显示 2 个账号')
    wrapper.unmount()
  })
})
