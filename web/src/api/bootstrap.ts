/** Selects real transport or a separately loaded fixture replay.
 * Authentication belongs to client.ts; mock implementation stays behind a dynamic import.
 * Read createPageApi; production builds omit fixture code and data entirely. */
import { createClient } from './client'
import type { NetmonApi } from './types'

/** Query presence enables replay in dev or mock builds; mock=all delivers all 75 packets.
 * A null API means mock mode was requested in a build that does not include it.
 * forceMock selects replay by default only when the build includes mock support. */
export async function createPageApi(
  token: string | null,
  search: string,
  forceMock = false,
): Promise<{ api: NetmonApi | null; mock: boolean }> {
  const params = new URLSearchParams(search)
  const mock = forceMock || params.has('mock')
  if (!mock) return { api: createClient(token), mock }
  // The config supplies a constant, so an ordinary build removes this import's dependency graph.
  if (import.meta.env.NETMON_INCLUDE_MOCK === '1') {
    const { createMock } = await import('./mock')
    return { api: createMock(params.get('mock') === 'all' ? 75 : 0), mock }
  }
  return { api: null, mock: false }
}
