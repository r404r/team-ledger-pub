export const sections = ['shared', 'manager_private', 'hr_confidential'] as const
export type Category = typeof sections[number]
export type Party = { kind: 'subject' | 'employee'; id: string }
export type SourceRef = { kind: 'note_version'; id: string; expected_version: string }
export type Interview = { id: string; employee_id: string; status: 'scheduled' | 'in_progress' | 'completed' | 'cancelled'; revision: string; scheduled_at: string; actual_started_at: string | null; actual_ended_at: string | null; backfilled: boolean; recorded_at: string; author_subject_id: string; participants: Party[] }
export type InterviewEvent = { id: string; status: Interview['status']; revision: string; author_subject_id: string; recorded_at: string; actual_started_at: string | null; actual_ended_at: string | null; backfilled: boolean; reason?: string }
export type Note = { id: string; head_id?: string; interview_id: string; employee_id: string; category: Category; status: 'draft' | 'published'; version_no: string; author_subject_id: string; recorded_at: string; supersedes_version_id?: string | null; text: string; edit_reason: string; source_refs: SourceRef[] }
export type Section = { head_id?: string; category: Category; head_revision?: string | null; versions: Note[]; draft_version_id?: string | null; published_version_id?: string | null }
export type ActionItem = { id: string; interview_id: string; employee_id: string; revision: string; status: 'todo' | 'in_progress' | 'done' | 'cancelled'; minimal_shared_text: string; safe_blocker_text: string; owner: Party; due_date: string | null; overdue: boolean; recorded_at: string; source_refs: SourceRef[]; events: { id: string; status: string; revision: string; author_subject_id: string; recorded_at: string; safe_blocker_text: string }[] }
export type Permission = { capability: string; category: string }
export type Detail = { interview: Interview; interview_events: InterviewEvent[]; sections: Section[]; action_items: ActionItem[]; permissions: Permission[]; next_cursor: string | null }
export type List = { items: Interview[]; next_cursor: string | null; as_of: string; consistency: 'current'; permissions: Permission[] }
export type Result = { id: string; revision: string; status: string; head_id?: string; head_revision?: string; version_no?: string; interview_revision?: string }
export type ExportObject = { kind: 'interview' | 'note_version' | 'action_item'; id: string; expected_revision: string }
export type ExportEvent = { kind: 'header' | 'object' | 'complete' | 'partial'; export_id: string; status?: string; reason?: string; note_version?: Note; action_item?: ActionItem; interview?: Interview }
export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export function validRevision(value: unknown): value is string { return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) && value.length <= 19 && BigInt(value) <= 9223372036854775807n }
export function validDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}
export function timestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/.exec(value)
  if (!match) return null
  const date = new Date(`${match[1]}Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 19) === match[1] ? `${match[1]}.${(match[2] ?? '').padEnd(6, '0')}Z` : null
}
export function validParty(value: Party): boolean { return Boolean(value && ['subject', 'employee'].includes(value.kind) && uuid.test(value.id)) }
export function validSources(value: SourceRef[]): boolean { return Array.isArray(value) && value.length <= 10 && value.every(ref => ref && ref.kind === 'note_version' && uuid.test(ref.id) && validRevision(ref.expected_version)) && new Set(value.map(ref => ref.id)).size === value.length }
export function validInterview(value: Interview): boolean {
  return Boolean(value && uuid.test(value.id) && uuid.test(value.employee_id) && validRevision(value.revision) && ['scheduled', 'in_progress', 'completed', 'cancelled'].includes(value.status) && timestamp(value.scheduled_at) && timestamp(value.recorded_at) && (value.actual_started_at === null || timestamp(value.actual_started_at)) && (value.actual_ended_at === null || timestamp(value.actual_ended_at)) && typeof value.backfilled === 'boolean' && uuid.test(value.author_subject_id) && Array.isArray(value.participants) && value.participants.length <= 20 && value.participants.every(validParty))
}
export function validNote(value: Note, interview: Interview): boolean {
  return Boolean(value && uuid.test(value.id) && (value.head_id === undefined || uuid.test(value.head_id)) && value.interview_id === interview.id && value.employee_id === interview.employee_id && sections.includes(value.category) && ['draft', 'published'].includes(value.status) && validRevision(value.version_no) && uuid.test(value.author_subject_id) && timestamp(value.recorded_at) && typeof value.text === 'string' && new TextEncoder().encode(value.text).length <= 12288 && typeof value.edit_reason === 'string' && (value.supersedes_version_id == null || uuid.test(value.supersedes_version_id)) && validSources(value.source_refs))
}
export function validAction(value: ActionItem, interview: Interview): boolean {
  return Boolean(value && uuid.test(value.id) && value.interview_id === interview.id && value.employee_id === interview.employee_id && validRevision(value.revision) && ['todo', 'in_progress', 'done', 'cancelled'].includes(value.status) && typeof value.minimal_shared_text === 'string' && typeof value.safe_blocker_text === 'string' && validParty(value.owner) && (value.due_date === null || validDate(value.due_date)) && typeof value.overdue === 'boolean' && (!['done', 'cancelled'].includes(value.status) || !value.overdue) && (value.due_date !== null || !value.overdue) && timestamp(value.recorded_at) && validSources(value.source_refs) && Array.isArray(value.events) && value.events.length <= 100 && value.events.every(event => uuid.test(event.id) && validRevision(event.revision) && ['todo', 'in_progress', 'done', 'cancelled'].includes(event.status) && uuid.test(event.author_subject_id) && timestamp(event.recorded_at) && typeof event.safe_blocker_text === 'string'))
}
export function validInterviewEvent(event: InterviewEvent): boolean {
  return Boolean(event && uuid.test(event.id) && ['scheduled', 'in_progress', 'completed', 'cancelled'].includes(event.status) && validRevision(event.revision) && uuid.test(event.author_subject_id) && timestamp(event.recorded_at) && (event.actual_started_at === null || timestamp(event.actual_started_at)) && (event.actual_ended_at === null || timestamp(event.actual_ended_at)) && typeof event.backfilled === 'boolean' && (event.reason === undefined || typeof event.reason === 'string' && new TextEncoder().encode(event.reason).length <= 4096))
}
