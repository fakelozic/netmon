/** Verifies all mock files against the contract and reviewed fixture evidence.
 * Enum and tuple narrowing belongs to mock-data.ts; generation copies source wording.
 * Read the golden comparison; it checks exact strings rather than summaries. */
import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import type {
  AlertPage,
  Field,
  FlowDetail,
  Glossary,
  PacketDetail,
  PacketPage,
  Session,
} from './types'
import { fixtures } from './mock-data'
import { createMock } from './mock'
import packetJson from '../mocks/packets.json'
import detailJson from '../mocks/details.json'
import flowJson from '../mocks/flows.json'
import alertJson from '../mocks/alerts.json'
import glossaryJson from '../mocks/glossary.json'
import sessionJson from '../mocks/session.json'

it('imports every JSON file through a field-for-field typed assignment', () => {
  const typed: {
    session: Session
    packets: PacketPage
    details: PacketDetail[]
    flows: FlowDetail[]
    alerts: AlertPage
    glossary: Glossary
  } = fixtures
  for (const [raw, checked] of [
    [packetJson, typed.packets],
    [detailJson, typed.details],
    [flowJson, typed.flows],
    [alertJson, typed.alerts],
    [glossaryJson, typed.glossary],
    [sessionJson, typed.session],
  ])
    expect(checked).toEqual(raw)
  expect(typed.packets.rows).toHaveLength(75)
  expect(typed.details).toHaveLength(75)
  expect(typed.flows).toHaveLength(12)
  for (const packet of typed.details) {
    expect(packet.hex).toMatch(/^[0-9a-f]+$/)
    expect(packet.hex.length / 2).toBe(packet.captured_len)
    function check(fields: Field[]) {
      for (const field of fields) {
        expect(Object.keys(field).sort()).toEqual(
          ['label', 'value', 'range', 'what', 'here', 'why', 'children'].sort(),
        )
        expect(field.range[1]).toBeGreaterThanOrEqual(field.range[0])
        check(field.children)
      }
    }
    packet.layers.forEach((layer) => check(layer.fields))
  }
})
it('copies rows, reviewed packet fields, story steps, alert texts and glossary definitions verbatim', () => {
  const golden = readFileSync('../tests/golden/flows-loopback-list.txt', 'utf8')
  for (const row of fixtures.packets.rows) expect(golden).toContain(row.info)
  for (const no of [10, 14, 17, 20, 57, 73, 75]) {
    const text = readFileSync(`../tests/golden/packet-${no}.txt`, 'utf8')
    function check(fields: Field[]) {
      for (const field of fields) {
        for (const part of ['value', 'what', 'here', 'why'] as const)
          if (field[part]) expect(text).toContain(field[part])
        check(field.children)
      }
    }
    fixtures.details
      .find((packet) => packet.no === no)!
      .layers.forEach((layer) => check(layer.fields))
  }
  const stories = readFileSync('../tests/golden/flows-loopback-stories.txt', 'utf8')
  fixtures.flows.forEach((flow) =>
    flow.story.forEach((step) => expect(stories).toContain(step.text)),
  )
  const alerts = readFileSync('../tests/golden/alerts-examples.txt', 'utf8')
  fixtures.alerts.alerts.forEach((alert) =>
    ['title', 'seen', 'why', 'next'].forEach((part) =>
      expect(alerts).toContain(alert[part as 'title']),
    ),
  )
  const glossary = readFileSync('../src/explain/glossary.rs', 'utf8')
  fixtures.glossary.terms.forEach((term) => expect(glossary).toContain(term.text))
})
it('replays five packets per poll, supports all endpoints, and pauses without advancing', async () => {
  const api = createMock()
  expect((await api.session()).packets).toBe(5)
  expect((await api.control({ action: 'pause' })).session.state).toBe('paused')
  expect((await api.session()).packets).toBe(5)
  await api.control({ action: 'resume' })
  expect((await api.session()).packets).toBe(10)
  expect((await api.packet(10)).no).toBe(10)
  await expect(api.packet(17)).rejects.toMatchObject({ status: 404 })
  expect((await api.flows('bytes')).flows.length).toBeGreaterThan(0)
  expect((await api.flow(1)).story).toHaveLength(4)
  expect((await api.glossary()).terms).toHaveLength(53)
  for (let i = 0; i < 13; i++) await api.session()
  expect((await api.session()).state).toBe('ended')
  expect((await api.alerts()).alerts).toHaveLength(5)
  expect((await api.control({ action: 'record_start' })).session.recording).toBe('on')
  expect((await api.control({ action: 'record_stop' })).session.recording).toBe('off')
  expect((await api.control({ action: 'export_story', flow: 7 })).path).toBe(
    '/mock/session/story-7.md',
  )
  expect(
    (await api.packets({ before: 17, limit: 2, filter: '' })).rows.map((row) => row.no),
  ).toEqual([15, 16])
})

it('includes explicit secret ranges with zeroed bytes in the HTTP fixture', () => {
  const packet = fixtures.details.find((packet) => packet.hidden?.length)
  expect(packet).toBeDefined()
  for (const [start, end] of packet!.hidden!) {
    expect(packet!.hex.slice(start * 2, end * 2)).toBe('00'.repeat(end - start))
  }
})
