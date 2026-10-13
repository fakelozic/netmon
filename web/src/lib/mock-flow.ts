/** Projects a complete fixture story onto the packets that have arrived so far.
 * Replay progression belongs to api/mock.ts; final fixture sentences are unchanged.
 * Read visibleFlow to keep mock summaries from describing future events. */
import type { FlowDetail, PacketDetail, PacketRow } from '../api/types'
/** Carried bytes described by top-level transport fields or the ping data layer. */
export function packetPayloadBytes(packet: PacketDetail): number {
  return packet.layers
    .flatMap((layer) => layer.fields)
    .reduce(
      (sum, field) =>
        ['Payload size', 'Data size'].includes(field.label) ? sum + Number(field.value) : sum,
      0,
    )
}
/** Returns a bounded partial story; duration remains null until its final packet has arrived. */
export function visibleFlow(
  flow: FlowDetail,
  shown: number,
  rows: PacketRow[],
  payloads: ReadonlyMap<number, number>,
): FlowDetail {
  const arrived = rows.filter((row) => row.flow === flow.id && row.no <= shown)
  const bytes = (first: number, last: number) =>
    arrived.reduce(
      (sum, row) => (row.no >= first && row.no <= last ? sum + (payloads.get(row.no) ?? 0) : sum),
      0,
    )
  const story = flow.story
    .filter((step) => step.first_packet <= shown)
    .map((step) => ({
      ...step,
      last_packet: Math.min(shown, step.last_packet),
      packets: Math.min(shown, step.last_packet) - step.first_packet + 1,
      bytes: bytes(step.first_packet, Math.min(shown, step.last_packet)),
    }))
  const finished = shown >= flow.last_packet
  const state =
    finished || flow.proto !== 'TCP'
      ? flow.state
      : story.some((step) => step.kind === 'fin')
        ? 'closing'
        : story.some((step) => step.kind === 'handshake_ack')
          ? 'open'
          : 'opening'
  return {
    ...flow,
    story,
    state,
    status: finished ? flow.status : (arrived.at(-1)?.info ?? flow.status),
    duration_ms: finished ? flow.duration_ms : null,
    packets: arrived.length,
    last_packet: arrived.at(-1)?.no ?? flow.first_packet,
    up_bytes: arrived
      .filter((row) => row.dir === 'out')
      .reduce((sum, row) => sum + (payloads.get(row.no) ?? 0), 0),
    down_bytes: arrived
      .filter((row) => row.dir === 'in')
      .reduce((sum, row) => sum + (payloads.get(row.no) ?? 0), 0),
    problems: story.filter((step) => step.problem).length,
  }
}
