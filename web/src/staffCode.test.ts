import { describe, expect, it } from 'vitest'
import { normalizeStaffCode } from './staffCode'

describe('Staff Code save hint', () => {
  it.each([
    ['1', '000001'], ['2213', '002213'], ['12345', '012345'],
    ['002213', '002213'], ['1234567', '1234567'], ['1234567890', '1234567890'],
    ['A123', 'A123'], ['１２３', '１２３'], ['e\u0301', 'é'],
    ['12345678901', null], [' 2213', null], ['2213 ', null], ['', null],
  ])('normalizes %s', (raw, expected) => expect(normalizeStaffCode(raw)).toBe(expected))
})
