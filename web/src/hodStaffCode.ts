// Mirrors organization.NormalizeHODStaffCode on the server: a real Staff Code never contains a
// hyphen, so a non-empty HOD value with one is "<Staff Code>-<Staff Name>" and only the text before
// the first hyphen, trimmed, is the manager's Staff Code. Values without a hyphen are unchanged.
// Every place that reads a HOD cell must use this function, never its own split.
export function normalizeHodStaffCode(raw: string): string {
  const hyphen = raw.indexOf('-')
  return hyphen < 0 ? raw : raw.slice(0, hyphen).trim()
}
