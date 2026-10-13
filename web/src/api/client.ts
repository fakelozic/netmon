/** Handles same-origin JSON requests using a token retained for this browser tab.
 * Contract shapes belong to types.ts; mock transport belongs to mock.ts.
 * Start with createClient; readToken transfers the fragment into sessionStorage. */
import type {
  ControlReply,
  FlowDetail,
  FlowPage,
  Glossary,
  NetmonApi,
  PacketDetail,
  PacketPage,
  Session,
} from './types'
import { labels } from '../lib/labels'

/** Request failure with the server's exact sentence and HTTP status (zero for local failures). */
export class ApiError extends Error {
  readonly status: number
  constructor(message: string, status = 0) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}
/** Retains the startup token until this tab closes; reloads preserve existing hash routes. */
export function readToken(
  location: Location = window.location,
  history: History = window.history,
): string | null {
  const token = new URLSearchParams(location.hash.slice(1)).get('k')
  if (token) {
    window.sessionStorage.setItem('netmon-token', token)
    history.replaceState(history.state, '', location.pathname + location.search + '#/packets')
    return token
  }
  return window.sessionStorage.getItem('netmon-token')
}
/** Creates a transport; every endpoint checks authorization and sends the in-memory token. */
export function createClient(
  token: string | null = readToken(),
  fetcher: typeof fetch = globalThis.fetch.bind(globalThis),
): NetmonApi {
  async function request<T>(path: string, signal?: AbortSignal, body?: unknown): Promise<T> {
    if (!token) throw new ApiError(labels.missingToken, 401)
    const response = await fetcher(path, {
      signal,
      method: body ? 'POST' : 'GET',
      headers: { 'X-Netmon-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    let data: unknown
    try {
      data = await response.json()
    } catch {
      throw new ApiError(labels.malformedJson, response.status)
    }
    if (!response.ok) {
      const message =
        data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
          ? data.error
          : labels.requestFailed
      throw new ApiError(message, response.status)
    }
    return data as T
  }
  return {
    session: (signal) => request<Session>('/api/session', signal),
    packets: (query, signal) => {
      const params = new URLSearchParams({
        filter: query.filter,
        limit: String(query.limit ?? 500),
      })
      params.set(
        query.before === undefined ? 'after' : 'before',
        String(query.before ?? query.after ?? 0),
      )
      return request<PacketPage>('/api/packets?' + params, signal)
    },
    packet: (no, signal) => request<PacketDetail>('/api/packet/' + no, signal),
    flows: (sort, signal) => request<FlowPage>('/api/flows?limit=1000&sort=' + sort, signal),
    flow: (id, signal) => request<FlowDetail>('/api/flow/' + id, signal),
    alerts: (signal) => request('/api/alerts', signal),
    glossary: (signal) => request<Glossary>('/api/glossary', signal),
    control: (action, signal) => request<ControlReply>('/api/control', signal, action),
  }
}
