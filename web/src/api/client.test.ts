/** Verifies fragment handling and authenticated same-origin JSON requests.
 * Real transport belongs to client.ts; no test uses a network connection.
 * Read the token test for the URL-clearing evidence. */
import { describe, expect, it, vi } from 'vitest'
import { ApiError, createClient, readToken } from './client'
import { labels } from '../lib/labels'

describe('client', () => {
  it('consumes the token and removes the fragment while preserving the query', () => {
    history.replaceState({ saved: true }, '', '/?mock#k=a%2Bb')
    expect(readToken()).toBe('a+b')
    expect(location.hash).toBe('#/packets')
    expect(location.search).toBe('?mock')
    expect(history.state).toEqual({ saved: true })
    expect(sessionStorage.getItem('netmon-token')).toBe('a+b')
    history.replaceState(null, '', '#/packets/17?filter=dns')
    expect(readToken()).toBe('a+b')
    expect(location.hash).toBe('#/packets/17?filter=dns')
  })
  it('sends the token on every endpoint, including controls, and encodes filters literally', async () => {
    const fetcher = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    const api = createClient('secret', fetcher)
    await api.session()
    await api.packets({ before: 30, filter: 'host "><script>&' })
    await api.packet(17)
    await api.flows('problems')
    await api.flow(7)
    await api.alerts()
    await api.glossary()
    await api.control({ action: 'export_story', flow: 7 })
    expect(fetcher).toHaveBeenCalledTimes(8)
    for (const [url, request] of fetcher.mock.calls) {
      expect(url).toMatch(/^\/api\//)
      expect(request.headers['X-Netmon-Token']).toBe('secret')
    }
    const query = new URL(fetcher.mock.calls[1][0], 'http://localhost').searchParams
    expect(query.get('filter')).toBe('host "><script>&')
    expect(query.get('before')).toBe('30')
    expect(query.has('after')).toBe(false)
    expect(fetcher.mock.calls[7][1].body).toBe('{"action":"export_story","flow":7}')
  })
  it('reports a missing token before attempting a request', async () => {
    const fetcher = vi.fn()
    await expect(createClient(null, fetcher).session()).rejects.toMatchObject({
      status: 401,
      message: labels.missingToken,
    })
    expect(fetcher).not.toHaveBeenCalled()
  })
  it.each([400, 401, 403, 404, 500])(
    'preserves the exact server error sentence at %s',
    async (status) => {
      const sentence = '<img src=x onerror=1> is no longer in memory.'
      const api = createClient(
        'token',
        vi.fn().mockResolvedValue({ ok: false, status, json: async () => ({ error: sentence }) }),
      )
      await expect(api.session()).rejects.toBeInstanceOf(ApiError)
      await expect(api.session()).rejects.toMatchObject({ status, message: sentence })
    },
  )
  it('reports malformed JSON in successful and failed responses', async () => {
    for (const ok of [true, false]) {
      const api = createClient(
        'token',
        vi.fn().mockResolvedValue({
          ok,
          status: 200,
          json: async () => {
            throw new SyntaxError('invalid')
          },
        }),
      )
      await expect(api.session()).rejects.toMatchObject({ message: labels.malformedJson })
    }
  })
})
