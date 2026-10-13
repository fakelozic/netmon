/** Schedules non-overlapping polling with a consecutive-failure backoff.
 * Browser visibility wiring belongs to hooks/useMonitor.ts.
 * Read createPoller; requests are aborted when hidden or stopped. */
/** Null means stop; paused and failed sessions require an explicit refresh or control action. */
export function pollingDelay(
  visible: boolean,
  state: string | undefined,
  failures: number,
): number | null {
  if (!visible || (state !== undefined && state !== 'running')) return null
  return failures >= 3 ? 5000 : 500
}
/** A cancellable poll scheduler, with injectable timers for deterministic tests. */
export function createPoller(options: {
  tick: (signal: AbortSignal) => Promise<string>
  failure: (error: unknown, count: number) => void
  schedule?: (callback: () => void, ms: number) => ReturnType<typeof setTimeout>
  cancel?: (timer: ReturnType<typeof setTimeout>) => void
}) {
  const schedule = options.schedule ?? setTimeout
  const cancel = options.cancel ?? clearTimeout
  let timer: ReturnType<typeof setTimeout> | undefined
  let controller: AbortController | undefined
  let generation = 0,
    failures = 0
  function stop() {
    generation++
    if (timer !== undefined) cancel(timer)
    controller?.abort()
  }
  async function run(turn: number) {
    controller = new AbortController()
    let state: string | undefined
    try {
      state = await options.tick(controller.signal)
      failures = 0
    } catch (error) {
      if (turn !== generation) return
      failures++
      options.failure(error, failures)
    }
    if (turn !== generation) return
    const delay = pollingDelay(true, state, failures)
    if (delay !== null)
      timer = schedule(() => {
        void run(turn)
      }, delay)
  }
  return {
    stop,
    start() {
      stop()
      void run(generation)
    },
  }
}
