/** Type-checks JSON fixtures while narrowing string unions and byte-range tuples.
 * Replay state belongs to mock.ts; fixture generation belongs to scripts/generate-mocks.py.
 * Read fixtures; each object is assigned to its contract type without a type cast. */
import sessionJson from '../mocks/session.json'
import packetsJson from '../mocks/packets.json'
import detailsJson from '../mocks/details.json'
import flowsJson from '../mocks/flows.json'
import alertsJson from '../mocks/alerts.json'
import glossaryJson from '../mocks/glossary.json'
import type {
  AlertPage,
  ByteRange,
  Field,
  FlowDetail,
  Glossary,
  PacketDetail,
  PacketPage,
  Session,
} from './types'

function choice<T extends string>(value: string, choices: readonly T[]): T {
  const result = choices.find((item) => item === value)
  if (result === undefined) throw new Error('Invalid fixture enum: ' + value)
  return result
}
function direction(value: string | null) {
  return value === null ? null : choice(value, ['out', 'in'] as const)
}
function range(value: number[]): ByteRange {
  if (value.length !== 2) throw new Error('Invalid fixture byte range')
  return [value[0], value[1]]
}
interface RawField {
  label: string
  value: string
  range: number[]
  what: string
  here: string
  why: string
  children: RawField[]
}
function field(raw: RawField): Field {
  return { ...raw, range: range(raw.range), children: raw.children.map(field) }
}
const session: Session = {
  ...sessionJson,
  mode: choice(sessionJson.mode, ['live', 'file'] as const),
  state: choice(sessionJson.state, ['running', 'paused', 'ended', 'failed'] as const),
  recording: choice(sessionJson.recording, ['off', 'on', 'full', 'failed'] as const),
}
const packets: PacketPage = {
  ...packetsJson,
  rows: packetsJson.rows.map((row) => ({ ...row, dir: direction(row.dir) })),
}
const details: PacketDetail[] = detailsJson.map((packet) => ({
  ...packet,
  hidden: packet.hidden.map(range),
  layers: packet.layers.map((layer) => ({
    ...layer,
    range: range(layer.range),
    fields: layer.fields.map(field),
  })),
}))
const flows: FlowDetail[] = flowsJson.map((flow) => ({
  ...flow,
  state: choice(flow.state, [
    'opening',
    'open',
    'closing',
    'closed',
    'reset',
    'refused',
    'active',
    'idle',
  ] as const),
  story: flow.story.map((step) => ({ ...step, dir: direction(step.dir) })),
}))
const alerts: AlertPage = {
  ...alertsJson,
  alerts: alertsJson.alerts.map((alert) => ({
    ...alert,
    severity: choice(alert.severity, ['notice', 'warning', 'serious'] as const),
  })),
}
const glossary: Glossary = glossaryJson
/** All checked-in JSON data, assigned field for field to the API contract. */
export const fixtures = { session, packets, details, flows, alerts, glossary }
