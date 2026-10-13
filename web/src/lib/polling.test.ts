/** Verifies polling cadence, cancellation and consecutive-failure backoff.
 * Browser visibility integration is covered in hooks/useMonitor.test.tsx.
 * Read the backoff test; fake timers keep the test deterministic. */
import { expect, it, vi } from 'vitest'
import { createPoller, pollingDelay } from './polling'

it('starts immediately, repeats every 500 ms and stops at end', async () => {
  vi.useFakeTimers()
  const tick = vi.fn().mockResolvedValueOnce('running').mockResolvedValueOnce('ended')
  const poller = createPoller({ tick, failure: vi.fn() })
  poller.start()
  await vi.advanceTimersByTimeAsync(499)
  expect(tick).toHaveBeenCalledTimes(1)
  await vi.advanceTimersByTimeAsync(1)
  expect(tick).toHaveBeenCalledTimes(2)
  await vi.advanceTimersByTimeAsync(10000)
  expect(tick).toHaveBeenCalledTimes(2)
  poller.stop()
})
it('backs off after three failures, recovers and resumes after being stopped', async () => {
  vi.useFakeTimers()
  const tick = vi
    .fn()
    .mockRejectedValueOnce(new Error('one'))
    .mockRejectedValueOnce(new Error('two'))
    .mockRejectedValueOnce(new Error('three'))
    .mockResolvedValue('running')
  const failure = vi.fn()
  const poller = createPoller({ tick, failure })
  poller.start()
  await vi.advanceTimersByTimeAsync(1000)
  expect(tick).toHaveBeenCalledTimes(3)
  expect(failure.mock.calls[2][1]).toBe(3)
  await vi.advanceTimersByTimeAsync(4999)
  expect(tick).toHaveBeenCalledTimes(3)
  await vi.advanceTimersByTimeAsync(1)
  expect(tick).toHaveBeenCalledTimes(4)
  await vi.advanceTimersByTimeAsync(500)
  expect(tick).toHaveBeenCalledTimes(5)
  poller.stop()
  await vi.advanceTimersByTimeAsync(5000)
  expect(tick).toHaveBeenCalledTimes(5)
  poller.start()
  expect(tick).toHaveBeenCalledTimes(6)
  poller.stop()
})
it('aborts a pending tick and never schedules an overlapping request', async () => {
  vi.useFakeTimers()
  let resolve: (state: string) => void = () => {}
  const tick = vi.fn(
    (_signal: AbortSignal) =>
      new Promise<string>((done) => {
        resolve = done
      }),
  )
  const poller = createPoller({ tick, failure: vi.fn() })
  poller.start()
  await vi.advanceTimersByTimeAsync(10000)
  expect(tick).toHaveBeenCalledTimes(1)
  const signal = tick.mock.calls[0][0] as unknown as AbortSignal
  poller.stop()
  expect(signal.aborted).toBe(true)
  resolve('running')
  await vi.advanceTimersByTimeAsync(10000)
  expect(tick).toHaveBeenCalledTimes(1)
})
it('hidden, paused, ended and failed sessions do not schedule periodic requests', () => {
  expect(pollingDelay(false, 'running', 0)).toBeNull()
  for (const state of ['paused', 'ended', 'failed']) expect(pollingDelay(true, state, 0)).toBeNull()
  expect(pollingDelay(true, undefined, 3)).toBe(5000)
})
