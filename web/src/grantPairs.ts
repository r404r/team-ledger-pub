export const grantObjectKinds = ['interview', 'note_head', 'note_version', 'action_item', 'compensation_proposal', 'compensation_event', 'compensation_term'] as const
export type ObjectReference = { kind: typeof grantObjectKinds[number]; id: string }
export const grantCapabilities: readonly string[] = ['organization.read', 'organization.write', 'pii.read', 'pii.write', 'audit.read', 'identity.manage', 'interview.read', 'interview.write', 'interview_policy.manage', 'assessment.request', 'assessment.read', 'assessment.input.approve', 'assessment.publish', 'note.read', 'note.write', 'note.publish', 'action.read', 'action.write', 'compensation.read', 'compensation.propose', 'compensation.approve', 'bonus.target.manage', 'bonus.propose', 'bonus.approve', 'bonus.payment.record', 'compensation.extension.manage', 'sensitive.export']
export const readableGrantCapabilities = ['access_grant.manage', ...grantCapabilities]
const categories = ['shared', 'manager_private', 'hr_confidential']
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export function validGrantPair(capability: string, category: string, purpose: string): boolean {
  if (purpose === 'security_administration') return ['audit.read', 'identity.manage'].includes(capability) && category === 'audit'
  if (purpose === 'organization_management') return ['organization.read', 'organization.write'].includes(capability) && category === 'metadata' || ['pii.read', 'pii.write', 'sensitive.export'].includes(capability) && category === 'pii'
  if (purpose === 'compensation_management') return ['compensation.read', 'compensation.propose', 'compensation.approve', 'bonus.target.manage', 'bonus.propose', 'bonus.approve', 'bonus.payment.record', 'compensation.extension.manage', 'sensitive.export'].includes(capability) && category === 'financial'
  if (purpose !== 'interview_followup') return false
  if (['interview.read', 'interview.write', 'interview_policy.manage', 'assessment.request', 'assessment.read', 'assessment.input.approve', 'assessment.publish'].includes(capability)) return category === 'metadata'
  if (['note.read', 'note.write', 'note.publish'].includes(capability)) return categories.includes(category)
  if (['action.read', 'action.write'].includes(capability)) return category === 'shared'
  return capability === 'sensitive.export' && ['metadata', ...categories].includes(category)
}
export function validPersistedGrantPair(capability: string, category: string, purpose: string): boolean {
  return validGrantPair(capability, category, purpose) ||
    capability === 'access_grant.manage' && category === 'audit' && purpose === 'security_administration'
}
export function validObjectReference(value: unknown): value is ObjectReference {
  if (!value || typeof value !== 'object') return false
  const ref = value as ObjectReference
  return Object.keys(ref).length === 2 && grantObjectKinds.includes(ref.kind) && typeof ref.id === 'string' && uuid.test(ref.id)
}
export function validGrantObject(ref: ObjectReference | null, capability: string, category: string, purpose: string): boolean {
  if (!validGrantPair(capability, category, purpose)) return false
  if (ref === null) return true
  if (!validObjectReference(ref)) return false
  if (purpose === 'compensation_management') {
    if (!['compensation.read', 'compensation.propose', 'compensation.approve', 'sensitive.export'].includes(capability)) return false
    return ref.kind === 'compensation_proposal' || ['compensation_event', 'compensation_term'].includes(ref.kind) && ['compensation.read', 'sensitive.export'].includes(capability)
  }
  if (purpose !== 'interview_followup' || capability.startsWith('assessment.')) return false
  if (ref.kind === 'interview') return true
  if (capability.startsWith('note.')) return ['note_head', 'note_version'].includes(ref.kind) && (ref.kind !== 'note_version' || capability === 'note.read')
  if (capability.startsWith('action.')) return ref.kind === 'action_item' && category === 'shared'
  if (capability === 'sensitive.export') return ref.kind === 'action_item' ? category === 'shared' : ['note_head', 'note_version'].includes(ref.kind) && categories.includes(category)
  return false
}
export function validPersistedGrantObject(ref: ObjectReference | null, capability: string, category: string, purpose: string): boolean {
  if (!validPersistedGrantPair(capability, category, purpose)) return false
  return capability === 'access_grant.manage' ? ref === null : validGrantObject(ref, capability, category, purpose)
}
export function validSourceApproval(refs: ObjectReference[], capability: string, category: string): boolean {
  return Array.isArray(refs) && refs.length <= 10 && refs.every(ref => validObjectReference(ref) && ref.kind === 'note_version') && new Set(refs.map(ref => ref.id)).size === refs.length && (!refs.length || capability === 'note.publish' && categories.includes(category) || capability === 'action.write' && category === 'shared')
}
