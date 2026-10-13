/** Keeps React selection in step with the browser's history.
 * Route syntax belongs to lib/routes.ts; token consumption belongs to api/client.ts.
 * Read useRoute; Back, Forward and manually changed fragments use the same subscription. */
import { useEffect, useSyncExternalStore } from 'react'
import { parseRoute, routeHash, type PageRoute } from '../lib/routes'

function subscribe(update: () => void) {
  window.addEventListener('hashchange', update)
  window.addEventListener('popstate', update)
  window.addEventListener('netmon-route', update)
  return () => {
    window.removeEventListener('hashchange', update)
    window.removeEventListener('popstate', update)
    window.removeEventListener('netmon-route', update)
  }
}

/** Returns the current route and a navigation action that creates a browser history entry. */
export function useRoute() {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash)
  const route = parseRoute(hash)
  useEffect(() => {
    const canonical = routeHash(parseRoute(hash))
    if (canonical !== hash) {
      history.replaceState(history.state, '', canonical)
      window.dispatchEvent(new Event('netmon-route'))
    }
  }, [hash])
  function navigate(next: PageRoute) {
    const nextHash = routeHash(next)
    if (nextHash === window.location.hash) return
    history.pushState(null, '', nextHash)
    window.dispatchEvent(new Event('netmon-route'))
  }
  return { route, navigate }
}
