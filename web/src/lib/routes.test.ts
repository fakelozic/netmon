/** Tests route parsing and encoding independently of React or a browser layout.
 * Live history subscriptions belong to hooks/useRoute.ts and test/routes.test.tsx.
 * Read the round-trip cases for ids, terms and literal filter characters. */
import { expect, it } from 'vitest'
import { packetRoute, parseRoute, routeHash } from './routes'

it.each([
  '',
  '#k=token',
  '#/no-such-tab',
  '#/packets/0',
  '#/packets/-1',
  '#/connections/1/extra',
  '#/alerts/2',
  '#/glossary/%zz',
  '#/packets/9007199254740992',
])('falls back from invalid route %s', (hash) => expect(parseRoute(hash)).toEqual(packetRoute()))

it.each([
  '#/packets',
  '#/packets/18',
  '#/connections',
  '#/connections/7',
  '#/alerts',
  '#/glossary',
  '#/glossary/window%20scale',
  '#/packets?filter=dns',
  '#/packets/18?flow=7',
])('round-trips %s', (hash) => expect(routeHash(parseRoute(hash))).toBe(hash))

it('encodes filters and glossary terms as fragment data, including hostile punctuation', () => {
  const route = { ...packetRoute(), filter: 'host "><script>&?#' }
  expect(parseRoute(routeHash(route))).toEqual(route)
  const glossary = { ...packetRoute(), tab: 'glossary' as const, term: 'x/y?"<script>#' }
  expect(parseRoute(routeHash(glossary))).toEqual(glossary)
})
