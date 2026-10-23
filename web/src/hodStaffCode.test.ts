import { describe, expect, it } from 'vitest'
import { normalizeHodStaffCode } from './hodStaffCode'

describe('HOD Staff Code normalization', () => {
  it.each([
    ['composite code and name', '002046-San Zhang', '002046'],
    ['spaces around hyphen', '002046 - San Zhang', '002046'],
    ['outer whitespace', '  002046  -  San Zhang ', '002046'],
    ['only the first hyphen splits', '002046-San-Zhang', '002046'],
    ['plain code is untouched', '002046', '002046'],
    ['blank stays blank', '', ''],
    ['missing code before the hyphen', '-San Zhang', ''],
    ['only hyphen with whitespace', ' - ', ''],
  ])('%s', (_name, raw, expected) => {
    expect(normalizeHodStaffCode(raw)).toBe(expected)
  })
})
