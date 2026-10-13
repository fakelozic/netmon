/** Replays checked-in fixture data a few packets per session poll.
 * JSON sources are documented in scripts/generate-mocks.py; real transport is client.ts.
 * Read createMock; every instance owns its bounded replay state. */
import type { NetmonApi, Session } from './types'
import { mockFilter } from '../lib/mock-filter'
import { ApiError } from './client'
import { packetPayloadBytes, visibleFlow } from '../lib/mock-flow'
import { fixtures } from './mock-data'

/** Creates an isolated mock API; initialPackets=75 provides a completed capture for tests. */
export function createMock(initialPackets = 0): NetmonApi {
  let shown = Math.max(0, Math.min(75, initialPackets))
  let session: Session = {
    ...fixtures.session,
    state: shown === 75 ? 'ended' : 'running',
    rate: [],
  }
  const clone = <T>(data: T): T => structuredClone(data)
  const payloads = new Map(
    fixtures.details.map((packet) => [packet.no, packetPayloadBytes(packet)]),
  )
  const visibleFlows = () =>
    fixtures.flows
      .filter((flow) => flow.first_packet <= shown)
      .map((flow) => visibleFlow(flow, shown, fixtures.packets.rows, payloads))
  function snapshot(): Session {
    return clone({
      ...session,
      packets: shown,
      bytes: fixtures.packets.rows.slice(0, shown).reduce((sum, r) => sum + r.bytes, 0),
      conversations: visibleFlows().length,
      alerts: fixtures.alerts.alerts.filter((a) => a.packet <= shown).length,
    })
  }
  return {
    session: async () => {
      if (session.state === 'running') {
        const prev = shown
        shown = Math.min(75, shown + 5)
        const bytes = fixtures.packets.rows.slice(prev, shown).reduce((sum, r) => sum + r.bytes, 0)
        session = {
          ...session,
          state: shown === 75 ? 'ended' : 'running',
          rate: [...session.rate, bytes * 2].slice(-60),
        }
      }
      return snapshot()
    },
    packets: async (query) => {
      const { rows, error } = mockFilter(fixtures.packets.rows.slice(0, shown), query.filter)
      const limit = Math.min(500, Math.max(1, query.limit ?? 200))
      const selected =
        query.before === undefined
          ? rows.filter((r) => r.no > (query.after ?? 0)).slice(0, limit)
          : rows.filter((r) => r.no < query.before!).slice(-limit)
      return clone({ total: shown, matched: rows.length, filter_error: error, rows: selected })
    },
    packet: async (no) => {
      const detail = fixtures.details.find((p) => p.no === no && no <= shown)
      if (!detail) throw new ApiError('This packet is no longer in memory.', 404)
      return clone(detail)
    },
    flows: async (sort) => {
      const flows = visibleFlows().map(({ story: _story, ...flow }) => flow)
      flows.sort((a, b) =>
        sort === 'bytes'
          ? b.up_bytes + b.down_bytes - a.up_bytes - a.down_bytes
          : sort === 'problems'
            ? b.problems - a.problems
            : b.last_packet - a.last_packet,
      )
      return clone({ total: flows.length, flows })
    },
    flow: async (id) => {
      const flow = visibleFlows().find((f) => f.id === id)
      if (!flow) throw new ApiError('This conversation is no longer in memory.', 404)
      return clone({ ...flow, story: flow.story.filter((s) => s.first_packet <= shown) })
    },
    alerts: async () => {
      const alerts = fixtures.alerts.alerts.filter((a) => a.packet <= shown)
      return clone({ total: alerts.length, alerts })
    },
    glossary: async () => clone(fixtures.glossary),
    control: async (action) => {
      if (action.action === 'pause') session = { ...session, state: 'paused' }
      if (action.action === 'resume')
        session = { ...session, state: shown === 75 ? 'ended' : 'running' }
      if (action.action === 'record_start') session = { ...session, recording: 'on' }
      if (action.action === 'record_stop') session = { ...session, recording: 'off' }
      if (action.action === 'export_story') {
        if (!visibleFlows().some((flow) => flow.id === action.flow))
          throw new ApiError('Conversation not found.', 404)
        return { ok: true, session: snapshot(), path: '/mock/session/story-' + action.flow + '.md' }
      }
      return { ok: true, session: snapshot() }
    },
  }
}
