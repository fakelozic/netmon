/** Tracks a CSS media query when the window changes size.
 * View layouts stay in CSS; this hook decides which keyboard-accessible pane model to render.
 * Read useMediaQuery for the subscription and cleanup. */
import { useEffect, useState } from 'react'

/** Returns the query's current match and updates it on browser media changes. */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const media = window.matchMedia(query)
    const update = () => setMatches(media.matches)
    update()
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [query])
  return matches
}
