/** Owns capture polling, bounded packet pages and server controls.
 * Scheduling is a pure module in lib/polling.ts; detail fetches use useDetail.ts.
 * Read useMonitor for the single state owner used by App. */
import { useEffect, useRef, useState } from 'react'
import type {
  ControlAction,
  FilterError,
  Flow,
  FlowSort,
  GlossaryTerm,
  NetmonApi,
  PacketRow,
  Session,
  TrafficAlert,
} from '../api/types'
import { createPoller } from '../lib/polling'
import { mergeRows } from '../lib/navigation'

/** Capture snapshot and actions; query keys hide obsolete data; selected packets outside a page load once per query. */
export function useMonitor(
  api: NetmonApi,
  filter: string,
  sort: FlowSort,
  anchor: number | null,
  selected: number | null = null,
) {
  const queryKey = JSON.stringify([filter, anchor])
  const [session, setSession] = useState<Session | null>(null)
  const [packets, setPackets] = useState<{
    key: string
    rows: PacketRow[]
    error: FilterError | null
  }>({ key: '', rows: [], error: null })
  const [flows, setFlows] = useState<Flow[]>([])
  const [alerts, setAlerts] = useState<TrafficAlert[]>([])
  const [terms, setTerms] = useState<GlossaryTerm[]>([])
  const [error, setError] = useState<string | null>(null)
  const [failures, setFailures] = useState(0)
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const locationRequest = useRef('')
  const cursor = useRef(0)
  const queryGeneration = useRef(0)
  const rows = packets.key === queryKey ? packets.rows : []
  const filterError = packets.key === queryKey ? packets.error : null

  useEffect(() => {
    queryGeneration.current++
    cursor.current = anchor === null ? 0 : Math.max(0, anchor - 1)
    let previous: Session | null = null
    let glossaryLoaded = false
    async function tick(signal: AbortSignal) {
      const next = await api.session(signal)
      if (!glossaryLoaded) {
        const glossary = await api.glossary(signal)
        if (signal.aborted) return next.state
        setTerms(glossary.terms)
        glossaryLoaded = true
      }
      if (!previous || next.packets > previous.packets || cursor.current < next.packets) {
        // Heavy live traffic can outrun a page. Fetch the newest bounded page instead of growing a backlog.
        const newest =
          anchor === null &&
          next.mode === 'live' &&
          (previous === null || next.packets - cursor.current > 5000)
        const page = await api.packets(
          newest
            ? { before: next.packets + 1, limit: 500, filter }
            : { after: cursor.current, limit: 500, filter },
          signal,
        )
        if (signal.aborted) return next.state
        const replace = previous === null
        setPackets((old) => ({
          key: queryKey,
          rows: mergeRows(replace || old.key !== queryKey ? [] : old.rows, page.rows),
          error: page.filter_error,
        }))
        cursor.current = page.rows.length === 500 ? page.rows.at(-1)!.no : next.packets
      }
      const [connections, notifications] = await Promise.all([
        api.flows(sort, signal),
        api.alerts(signal),
      ])
      if (signal.aborted) return next.state
      previous = next
      setSession(next)
      setFlows(connections.flows)
      setAlerts(notifications.alerts)
      setError(null)
      setFailures(0)
      return next.state
    }
    const poller = createPoller({
      tick,
      failure: (reason, count) => {
        setError(reason instanceof Error ? reason.message : String(reason))
        setFailures(count)
      },
    })
    const visible = () => {
      if (document.visibilityState === 'hidden') poller.stop()
      else poller.start()
    }
    visible()
    document.addEventListener('visibilitychange', visible)
    return () => {
      poller.stop()
      document.removeEventListener('visibilitychange', visible)
    }
  }, [api, filter, sort, anchor, revision, queryKey])

  const loaded = session !== null
  const selectedInPage = rows.some((row) => row.no === selected)
  useEffect(() => {
    if (selected === null || !loaded || selectedInPage) return
    const generation = queryGeneration.current
    const key = JSON.stringify([queryKey, selected, generation])
    // A filter can exclude the selected packet. Try once, rather than refetching forever.
    if (locationRequest.current === key) return
    locationRequest.current = key
    const controller = new AbortController()
    api
      .packets({ after: Math.max(0, selected - 1), filter }, controller.signal)
      .then((page) => {
        if (controller.signal.aborted || generation !== queryGeneration.current) return
        setPackets((old) => ({
          key: queryKey,
          error: page.filter_error,
          rows: mergeRows(
            old.key === queryKey ? old.rows : [],
            page.rows,
            selected < (old.rows[0]?.no ?? 0),
          ),
        }))
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setError(reason instanceof Error ? reason.message : String(reason))
      })
    return () => controller.abort()
  }, [api, filter, queryKey, selected, loaded, selectedInPage, revision, sort])

  async function control(action: ControlAction) {
    setBusy(true)
    try {
      const reply = await api.control(action)
      setSession(reply.session)
      setError(null)
      setRevision((value) => value + 1)
      return reply
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
      return null
    } finally {
      setBusy(false)
    }
  }
  async function page(older: boolean) {
    const generation = queryGeneration.current
    const query = older
      ? { before: rows[0]?.no ?? 1, filter }
      : { after: rows.at(-1)?.no ?? 0, filter }
    try {
      const result = await api.packets(query)
      if (generation !== queryGeneration.current) return
      setPackets((old) => ({
        key: queryKey,
        rows: mergeRows(old.key === queryKey ? old.rows : [], result.rows, older),
        error: result.filter_error,
      }))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }
  return {
    session,
    rows,
    flows,
    alerts,
    terms,
    filterError,
    error,
    failures,
    loading: session === null && !error,
    busy,
    control,
    page,
    refresh: () => setRevision((value) => value + 1),
  }
}
