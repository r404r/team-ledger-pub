import { uuid, timestamp, validProposal, validEvent, validTerm, type Session, type ExportObject } from './compensationDTO'
export class FinancialFailure extends Error {
  constructor(readonly status: number) { super('Financial request failed') }
}
export type FinancialCommand = { path: string; method: 'POST' | 'PATCH'; body: string; key: string; context: Session; capability: string; exporting: boolean }
export async function financialRequest(path: string, signal: AbortSignal, current: () => boolean, command?: FinancialCommand, csrf?: string): Promise<Response> {
  const headers: Record<string, string> = { 'X-Access-Purpose': 'compensation_management' }
  if (command) { headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = csrf ?? ''; headers['Idempotency-Key'] = command.key }
  const response = await fetch(`/api/v1${path}`, { method: command?.method ?? 'GET', credentials: 'same-origin', cache: 'no-store', headers, body: command?.body, signal })
  if (!current()) { await response.body?.cancel(); throw new DOMException('Cancelled', 'AbortError') }
  if (!response.ok) throw new FinancialFailure(response.status)
  return response
}
export async function financialJSON<T>(path: string, signal: AbortSignal, current: () => boolean, command?: FinancialCommand, csrf?: string): Promise<T> {
  const response = await financialRequest(path, signal, current, command, csrf)
  const result: T = await response.json()
  if (!current()) throw new DOMException('Cancelled', 'AbortError')
  return result
}
export async function financialExport(response: Response, employee: string, objects: ExportObject[], current: () => boolean, emit: (line: string) => void): Promise<'complete' | 'partial'> {
  if (!response.headers.get('Content-Type')?.startsWith('application/x-ndjson') || !response.body) throw new FinancialFailure(503)
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
  let pending = '', received = 0, exportID = '', terminal: 'complete' | 'partial' | null = null
  const seen = new Set<string>()
  function accept(line: string) {
    if (!current() || terminal) throw new FinancialFailure(503)
    const event = JSON.parse(line)
    if (!event || !uuid.test(event.export_id)) throw new FinancialFailure(503)
    if (!exportID) {
      if (event.kind !== 'header' || event.status !== 'prepared' || Object.keys(event).some(key => !['kind', 'export_id', 'status'].includes(key))) throw new FinancialFailure(503)
      exportID = event.export_id
    } else {
      if (event.export_id !== exportID) throw new FinancialFailure(503)
      if (event.kind === 'object') {
        if (event.status !== 'prepared') throw new FinancialFailure(503)
        const keys = ['compensation_proposal', 'compensation_event', 'compensation_term'].filter(key => event[key] !== undefined)
        if (keys.length !== 1) throw new FinancialFailure(503)
        const kind = keys[0]! as ExportObject['kind'], value = event[kind]
        if (Object.keys(event).some(key => !['kind', 'export_id', 'status', ...keys, ...(kind === 'compensation_event' ? ['approval'] : [])].includes(key))) throw new FinancialFailure(503)
        if (kind === 'compensation_event') {
          const a = event.approval
          if (!a || !uuid.test(a.id) || !uuid.test(a.approver_subject_id) || !timestamp(a.approved_at) || [a.reason, a.decision_reason].some(s => s !== undefined && (typeof s !== 'string' || new TextEncoder().encode(s).length > 4096)) || Object.keys(a).some(key => !['id', 'approver_subject_id', 'approved_at', 'reason', 'decision_reason'].includes(key))) throw new FinancialFailure(503)
        }
        const selected = objects.find(object => object.kind === kind && object.id === value?.id)
        const key = `${kind}:${value?.id}`
        if (!selected || seen.has(key) || value.revision !== selected.expected_revision || (kind === 'compensation_proposal' ? !validProposal(value, employee) : kind === 'compensation_event' ? !validEvent(value, employee) : !validTerm(value, employee))) throw new FinancialFailure(503)
        seen.add(key)
      } else if (event.kind === 'complete' && event.status === 'complete' && seen.size === objects.length && Object.keys(event).every(key => ['kind', 'export_id', 'status'].includes(key))) terminal = 'complete'
      else if (event.kind === 'partial' && event.status === 'partial' && ['RELEASE_DENIED', 'WRITE_FAILED'].includes(event.reason) && Object.keys(event).every(key => ['kind', 'export_id', 'status', 'reason'].includes(key))) terminal = 'partial'
      else throw new FinancialFailure(503)
    }
    emit(`${line}\n`)
  }
  try {
    while (true) {
      const chunk = await reader.read()
      if (!current()) throw new DOMException('Cancelled', 'AbortError')
      if (chunk.done) { pending += decoder.decode(); break }
      received += chunk.value.byteLength
      if (received > 8 * 1024 * 1024) throw new FinancialFailure(503)
      pending += decoder.decode(chunk.value, { stream: true })
      let newline: number
      while ((newline = pending.indexOf('\n')) >= 0) { const line = pending.slice(0, newline); pending = pending.slice(newline + 1); if (!line) throw new FinancialFailure(503); accept(line) }
    }
    if (pending) accept(pending)
    if (!terminal) throw new FinancialFailure(503)
    return terminal
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock() }
}
