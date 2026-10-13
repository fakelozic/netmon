/** Tests the hook's visibility wiring, controls and stale-query cancellation.
 * Poll timing is tested separately in lib/polling.test.ts.
 * Read the hidden-tab case; fake timers never start a watcher or server. */
import { act, renderHook, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { createMock } from '../api/mock'
import { fixtures } from '../api/mock-data'
import { useMonitor } from './useMonitor'

it('polls while visible, stops when hidden, resumes, and stops at the end', async () => {
  vi.useFakeTimers()
  let visibility = 'visible'
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(
    () => visibility as DocumentVisibilityState,
  )
  const api = createMock(60),
    session = vi.spyOn(api, 'session')
  const hook = renderHook(() => useMonitor(api, '', 'recent', null))
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
  expect(session).toHaveBeenCalledTimes(1)
  await act(async () => {
    visibility = 'hidden'
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(5000)
  })
  expect(session).toHaveBeenCalledTimes(1)
  await act(async () => {
    visibility = 'visible'
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(500)
  })
  expect(hook.result.current.session?.state).toBe('ended')
  const calls = session.mock.calls.length
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5000)
  })
  expect(session).toHaveBeenCalledTimes(calls)
  hook.unmount()
})
it('pause stops periodic requests and resume restarts them', async () => {
  vi.useFakeTimers()
  const api = createMock(),
    session = vi.spyOn(api, 'session')
  const hook = renderHook(() => useMonitor(api, '', 'recent', null))
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
  await act(async () => {
    await hook.result.current.control({ action: 'pause' })
    await vi.advanceTimersByTimeAsync(0)
  })
  const calls = session.mock.calls.length
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5000)
  })
  expect(session).toHaveBeenCalledTimes(calls)
  expect(hook.result.current.session?.state).toBe('paused')
  await act(async () => {
    await hook.result.current.control({ action: 'resume' })
    await vi.advanceTimersByTimeAsync(500)
  })
  expect(session.mock.calls.length).toBeGreaterThan(calls)
  expect(hook.result.current.session?.state).toBe('running')
  hook.unmount()
})
it('discards rows arriving from an obsolete filter request', async () => {
  const api = createMock(75),
    packets = api.packets
  let complete: (() => void) | undefined
  api.packets = async (query, signal) => {
    if (query.filter === 'tcp')
      await new Promise<void>((done) => {
        complete = done
      })
    return packets(query, signal)
  }
  const hook = renderHook(({ filter }) => useMonitor(api, filter, 'recent', null), {
    initialProps: { filter: 'tcp' },
  })
  await waitFor(() => expect(complete).toBeDefined())
  hook.rerender({ filter: 'dns' })
  await waitFor(() => expect(hook.result.current.rows).toHaveLength(8))
  await act(async () => complete?.())
  expect(hook.result.current.rows.every((row) => row.proto === 'DNS')).toBe(true)
})

it('loads a selection outside the current page without discarding ordinary rows', async () => {
  const api = createMock(75)
  const original = api.packets
  const packets = vi.spyOn(api, 'packets').mockImplementation(async (query, signal) => {
    if (query.after === 89)
      return {
        total: 90,
        matched: 90,
        filter_error: null,
        rows: [{ ...fixtures.packets.rows[0], no: 90 }],
      }
    return original(query, signal)
  })
  const hook = renderHook(({ selected }) => useMonitor(api, '', 'recent', null, selected), {
    initialProps: { selected: 90 },
  })
  await waitFor(() => expect(hook.result.current.rows.some((row) => row.no === 90)).toBe(true))
  expect(hook.result.current.rows.some((row) => row.no === 1)).toBe(true)
  expect(packets).toHaveBeenCalledTimes(2)
  hook.rerender({ selected: 17 })
  expect(packets).toHaveBeenCalledTimes(2)
})
it('tries a filtered-out deep link once instead of starting a request loop', async () => {
  const api = createMock(75),
    packets = vi.spyOn(api, 'packets')
  const hook = renderHook(() => useMonitor(api, 'dns', 'recent', null, 17))
  await waitFor(() => expect(packets).toHaveBeenCalledTimes(2))
  hook.rerender()
  expect(packets).toHaveBeenCalledTimes(2)
  expect(hook.result.current.rows.every((row) => row.proto === 'DNS')).toBe(true)
})
