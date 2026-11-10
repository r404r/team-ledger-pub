// Display hints only. The server validates and saves the authoritative value.
export function normalizeStaffCode(raw: string): string | null {
  if (!raw || raw.trim() !== raw || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(raw)) return null
  const code = raw.normalize('NFC')
  if (new TextEncoder().encode(code).length > 64) return null
  if (/^[0-9]+$/.test(code)) return code.length > 10 ? null : code.padStart(6, '0')
  return code
}
