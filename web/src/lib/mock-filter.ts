/** Evaluates the documented display-filter words over mock packet rows.
 * Production parsing belongs to the server; transport belongs to api/mock.ts.
 * Read mockFilter for bounded parsing with positioned errors. */
import type { FilterError, PacketRow } from '../api/types'
/** Mock filtering result with the same error shape as the API. */
export function mockFilter(
  rows: PacketRow[],
  text: string,
): { rows: PacketRow[]; error: FilterError | null } {
  const tokens = [...text.matchAll(/"(?:\\.|[^"\\])*"|[()]|[^\s()]+/g)].map((m) => ({
    text: m[0],
    position: m.index,
  }))
  let cursor = 0
  type Predicate = (row: PacketRow) => boolean
  const peek = () => tokens[cursor]?.text.toLowerCase()
  function fail(message: string): never {
    throw { position: tokens[cursor]?.position ?? text.length, message }
  }
  function term(depth: number): Predicate {
    if (depth > 64) fail('Filter is too complex.')
    if (peek() === 'not') {
      cursor++
      const p = term(depth + 1)
      return (row) => !p(row)
    }
    if (peek() === '(') {
      cursor++
      const p = or(depth + 1)
      if (peek() !== ')') fail('Expected a closing bracket.')
      cursor++
      return p
    }
    if (!peek() || ['and', 'or', ')'].includes(peek()!)) fail('Expected a filter term.')
    const token = tokens[cursor++].text
    const word = token.toLowerCase()
    if (['port', 'host', 'app'].includes(word)) {
      if (!peek() || ['and', 'or', ')', '('].includes(peek()!))
        fail('Expected a value after ' + word + '.')
      const value = tokens[cursor].text.replace(/^"|"$/g, '').toLowerCase()
      if (word === 'port' && (!/^\d+$/.test(value) || Number(value) > 65535))
        fail('Expected a port number after "port".')
      cursor++
      return (row) =>
        word === 'port'
          ? [row.src, row.dst].some((endpoint) => endpoint.endsWith(':' + value))
          : word === 'app'
            ? (row.app ?? '').toLowerCase().includes(value)
            : [row.src, row.dst, row.src_label, row.dst_label].some((endpoint) =>
                endpoint.toLowerCase().includes(value),
              )
    }
    if (word === 'problem') return (row) => row.problem
    const protos = [
      'tcp',
      'udp',
      'icmp',
      'icmpv6',
      'arp',
      'dns',
      'mdns',
      'dhcp',
      'tls',
      'http',
      'quic',
      'ip',
      'ipv6',
    ]
    return (row) =>
      protos.includes(word)
        ? row.proto.toLowerCase() === word ||
          (word === 'tcp' && ['HTTP', 'TLS'].includes(row.proto)) ||
          (word === 'udp' && ['DNS', 'DHCP', 'QUIC'].includes(row.proto))
        : row.info.toLowerCase().includes(word.replace(/^"|"$/g, ''))
  }
  function and(depth: number): Predicate {
    let p = term(depth)
    while (peek() && peek() !== ')' && peek() !== 'or') {
      if (peek() === 'and') cursor++
      const left = p,
        right = term(depth)
      p = (row) => left(row) && right(row)
    }
    return p
  }
  function or(depth: number): Predicate {
    let p = and(depth)
    while (peek() === 'or') {
      cursor++
      const left = p,
        right = and(depth)
      p = (row) => left(row) || right(row)
    }
    return p
  }
  if (!tokens.length) return { rows, error: null }
  try {
    if (tokens.length > 256) fail('Filter is too complex.')
    const predicate = or(0)
    if (cursor < tokens.length) fail('Unexpected filter term.')
    return { rows: rows.filter(predicate), error: null }
  } catch (error) {
    return { rows: [], error: error as FilterError }
  }
}
