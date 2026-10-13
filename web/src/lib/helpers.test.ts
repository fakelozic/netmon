/** Tests pure formatting, byte selection, word boundaries and bounded retention.
 * Interactive components are tested separately in views.test.tsx.
 * Read the nested-field test for overlap and half-open range behaviour. */
import { describe, expect, it } from 'vitest'
import { formatBytes, formatDuration, formatTime } from './format'
import { coveredBytes, fieldAtByte, hexRows, inRange } from './hex'
import { splitGlossary } from './glossary'
import { mergeRows, nextIndex } from './navigation'
import { mockFilter } from './mock-filter'
import { fixtures } from '../api/mock-data'

describe('formatting', () => {
  it('uses exact relative microseconds instead of rounding to the next packet time', () => {
    expect(formatTime(2.0145159)).toBe('2.014515')
    expect(formatTime(-0.000001)).toBe('-0.000001')
    expect(formatTime(0)).toBe('0.000000')
  })
  it('formats decimal bytes and milliseconds, including ongoing and sub-millisecond values', () => {
    expect([0, 999, 1000, 1200000].map(formatBytes)).toEqual(['0 B', '999 B', '1.0 kB', '1.2 MB'])
    expect([null, 0, 0.016, 56.5, 2500].map(formatDuration)).toEqual([
      'Ongoing',
      '0 ms',
      '16 µs',
      '56.5 ms',
      '2.5 s',
    ])
  })
})
describe('packet bytes', () => {
  it('lays out sixteen bytes and printable ASCII, with absolute offsets', () => {
    const rows = hexRows('0020417f' + '61'.repeat(14))
    expect(rows).toHaveLength(2)
    expect(rows[0].bytes).toHaveLength(16)
    expect(rows[0].bytes.slice(0, 4).map((b) => b.ascii)).toEqual(['.', ' ', 'A', '.'])
    expect(rows[1].offset).toBe(16)
    expect(rows[1].bytes[1].offset).toBe(17)
    expect(hexRows('')).toEqual([])
  })
  it('clips ranges to captured bytes and excludes the end boundary', () => {
    expect(inRange(47, [46, 48])).toBe(true)
    expect(inRange(48, [46, 48])).toBe(false)
    expect(inRange(10, [10, 10])).toBe(false)
    expect(coveredBytes([-4, 3], 2)).toEqual([0, 1])
    expect(coveredBytes([6, 10], 6)).toEqual([])
  })
  it('selects the deepest child and uses deterministic header order for shared bytes', () => {
    const layers = fixtures.details.find((p) => p.no === 17)!.layers
    expect(fieldAtByte(layers, 47)?.label).toBe('CWR')
    expect(fieldAtByte(layers, 73)?.label).toBe('Window scale')
    expect(fieldAtByte(layers, 74)).toBeNull()
  })
})
it('matches whole glossary words, longest phrases first, without changing hostile characters', () => {
  const terms = fixtures.glossary.terms
  const text =
    '<img src=x onerror=1> DNS DNSSEC _DNS DNS_ TCPé "><script>alert(1)</script> window scale.'
  const parts = splitGlossary(text, terms)
  expect(parts.map((p) => p.text).join('')).toBe(text)
  expect(parts.filter((p) => p.definition).map((p) => p.text)).toEqual(['DNS', 'window scale'])
  expect(
    splitGlossary('x+y', [{ term: 'x+y', text: 'literal punctuation' }])[0].definition?.term,
  ).toBe('x+y')
  expect(splitGlossary('', [])).toEqual([{ text: '' }])
})
it('caps packet retention at 5,000 rows in either paging direction and deduplicates', () => {
  const rows = Array.from({ length: 6000 }, (_, i) => ({ ...fixtures.packets.rows[0], no: i + 1 }))
  expect(mergeRows(rows.slice(0, 5000), rows.slice(4999))[0].no).toBe(1001)
  expect(mergeRows(rows.slice(1000), rows.slice(0, 1001), true).at(-1)?.no).toBe(5000)
  expect(mergeRows(rows, rows)).toHaveLength(5000)
})
it('handles arrows, page keys and endpoints with clamping', () => {
  expect(
    ['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End'].map((key) =>
      nextIndex(key, 5, 20),
    ),
  ).toEqual([6, 4, 15, 0, 0, 19])
  expect(nextIndex('ArrowDown', 19, 20)).toBe(19)
  expect(nextIndex('Home', 0, 0)).toBeNull()
})
it('mock filters match server-language examples and preserve positioned errors', () => {
  expect(mockFilter(fixtures.packets.rows, 'dns and not problem').rows).toHaveLength(7)
  expect(mockFilter(fixtures.packets.rows, '(http or tls) and port 18080').rows).toHaveLength(4)
  expect(mockFilter(fixtures.packets.rows, 'port wrong').error?.position).toBe(5)
  expect(mockFilter(fixtures.packets.rows, 'tcp and').error).not.toBeNull()
})
it('reveals only arrived conversation steps and counts their carried bytes', async () => {
  const { visibleFlow, packetPayloadBytes } = await import('./mock-flow')
  const payloads = new Map(
    fixtures.details.map((packet) => [packet.no, packetPayloadBytes(packet)]),
  )
  const flow = visibleFlow(fixtures.flows[6], 20, fixtures.packets.rows, payloads)
  expect(flow.state).toBe('open')
  expect(flow.duration_ms).toBeNull()
  expect(flow.story).toHaveLength(4)
  expect(flow.last_packet).toBe(20)
  expect(flow.up_bytes).toBe(79)
  expect(flow.down_bytes).toBe(0)
  expect(flow.story[3].bytes).toBe(79)
  const ping = visibleFlow(fixtures.flows[1], 8, fixtures.packets.rows, payloads)
  expect(ping.up_bytes).toBe(112)
  expect(ping.down_bytes).toBe(112)
})
