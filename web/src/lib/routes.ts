/** Parses the page's fragment routes without contacting a server.
 * Browser subscriptions belong to hooks/useRoute.ts; capture queries belong to useMonitor.
 * Read parseRoute and routeHash for the two directions of navigation. */
/** A tab with its selected packet, conversation or glossary term; null means no explicit selection. */
export interface PageRoute {
  tab: 'packets' | 'connections' | 'alerts' | 'glossary'
  packet: number | null
  flow: number | null
  term: string | null
  filter: string
  /** An optional local conversation restriction, never sent as an API filter word. */
  scope: number | null
}

/** Default route used for absent or unrecognised fragments. */
export function packetRoute(): PageRoute {
  return { tab: 'packets', packet: null, flow: null, term: null, filter: '', scope: null }
}

function identifier(text: string | undefined): number | null {
  if (!text || !/^[1-9]\d*$/.test(text)) return null
  const value = Number(text)
  return Number.isSafeInteger(value) ? value : null
}

/** Unknown paths, malformed encodings and invalid numeric ids resolve to Packets. */
export function parseRoute(hash: string): PageRoute {
  const [path, query] = hash.replace(/^#/, '').split('?')
  const segments = path.split('/')
  const [, tab, selection] = segments
  const route = packetRoute()
  if (segments[0] !== '' || segments.length > 3) return route
  if (tab === 'packets') {
    if (selection !== undefined && identifier(selection) === null) return route
    const params = new URLSearchParams(query)
    return {
      ...route,
      packet: identifier(selection),
      filter: params.get('filter') ?? '',
      scope: identifier(params.get('flow') ?? undefined),
    }
  }
  if (tab === 'connections') {
    if (selection !== undefined && identifier(selection) === null) return route
    return { ...route, tab, flow: identifier(selection) }
  }
  if (tab === 'alerts' && selection === undefined) return { ...route, tab }
  if (tab === 'glossary') {
    try {
      return { ...route, tab, term: selection ? decodeURIComponent(selection) : null }
    } catch {
      return route
    }
  }
  return route
}

/** Builds a same-document hash; glossary terms and filters are encoded as data. */
export function routeHash(route: PageRoute): string {
  let path = '#/' + route.tab
  if (route.tab === 'packets' && route.packet !== null) path += '/' + route.packet
  if (route.tab === 'connections' && route.flow !== null) path += '/' + route.flow
  if (route.tab === 'glossary' && route.term !== null) path += '/' + encodeURIComponent(route.term)
  if (route.tab === 'packets') {
    const params = new URLSearchParams()
    if (route.filter) params.set('filter', route.filter)
    if (route.scope !== null) params.set('flow', String(route.scope))
    if (params.size) path += '?' + params
  }
  return path
}
