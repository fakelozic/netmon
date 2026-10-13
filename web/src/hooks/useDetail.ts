/** Fetches one selected detail without letting old requests overwrite newer choices.
 * Capture polling belongs to useMonitor; component rendering stays in views.
 * Read useDetail; changing the key aborts the previous request. */
import { useEffect, useState } from 'react'
/** Returns keyed data so a previous selection is never briefly shown as the current one. */
export function useDetail<T>(
  key: number | null,
  load: (key: number, signal: AbortSignal) => Promise<T>,
  revision = 0,
) {
  const [result, setResult] = useState<{ key: number; data?: T; error?: string } | null>(null)
  useEffect(() => {
    if (key === null) return
    const controller = new AbortController()
    load(key, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setResult({ key, data })
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setResult({ key, error: reason instanceof Error ? reason.message : String(reason) })
      })
    return () => controller.abort()
  }, [key, load, revision])
  return {
    data: result?.key === key ? result.data : undefined,
    error: result?.key === key ? result.error : undefined,
  }
}
