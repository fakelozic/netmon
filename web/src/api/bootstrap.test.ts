/** Verifies startup selection for development, mock builds and production.
 * Bundle omission is checked by finite Vite builds; these tests never contact real HTTP.
 * Read the production cases for requests that must not construct a replay. */
import { afterEach, assert, expect, it, vi } from 'vitest'
import { createPageApi } from './bootstrap'

afterEach(() => vi.unstubAllEnvs())

it('delivers all 75 packets at once for ?mock=all', async () => {
  const { api, mock } = await createPageApi(null, '?mock=all')
  assert(api)
  expect(mock).toBe(true)
  expect(await api.session()).toMatchObject({ state: 'ended', packets: 75 })
  const page = await api.packets({ after: 0, filter: '' })
  expect(page.rows).toHaveLength(75)
  expect(page.rows.map((row) => row.no)).toEqual(Array.from({ length: 75 }, (_, i) => i + 1))
})
it('replays a few at a time for ?mock or the build-time mock flag', async () => {
  for (const [search, flag] of [
    ['?mock', false],
    ['', true],
  ] as const) {
    const { api } = await createPageApi(null, search, flag)
    assert(api)
    expect((await api.session()).packets).toBe(5)
    expect((await api.session()).packets).toBe(10)
  }
})
it('constructs the real API without sending requests when mock mode is absent', async () => {
  vi.stubEnv('NETMON_INCLUDE_MOCK', '0')
  vi.stubEnv('DEV', false)
  vi.stubEnv('MODE', 'production')
  const fetcher = vi.spyOn(globalThis, 'fetch')
  const { api, mock } = await createPageApi('token', '')
  expect(api).not.toBeNull()
  expect(mock).toBe(false)
  expect(fetcher).not.toHaveBeenCalled()
})

it.each([
  ['?mock', false],
  ['?mock=all', false],
  ['', true],
] as const)(
  'declines production mock requests (%s, forced=%s) without fetching',
  async (search, flag) => {
    vi.stubEnv('NETMON_INCLUDE_MOCK', '0')
    vi.stubEnv('DEV', false)
    vi.stubEnv('MODE', 'production')
    const fetcher = vi.spyOn(globalThis, 'fetch')
    expect(await createPageApi('token', search, flag)).toEqual({ api: null, mock: false })
    expect(fetcher).not.toHaveBeenCalled()
  },
)

it.each([
  ['?mock', false, 5],
  ['?mock=all', false, 75],
  ['', true, 5],
] as const)(
  'keeps replay in the separate mock build (%s, forced=%s)',
  async (search, flag, packets) => {
    vi.stubEnv('NETMON_INCLUDE_MOCK', '1')
    vi.stubEnv('DEV', false)
    vi.stubEnv('MODE', 'mock')
    const { api, mock } = await createPageApi(null, search, flag)
    assert(api)
    expect(mock).toBe(true)
    expect((await api.session()).packets).toBe(packets)
  },
)

it('does not let a development NODE_ENV enable replay in an ordinary build', async () => {
  vi.stubEnv('NETMON_INCLUDE_MOCK', '0')
  vi.stubEnv('DEV', true)
  vi.stubEnv('MODE', 'production')
  expect(await createPageApi(null, '?mock')).toEqual({ api: null, mock: false })
})
