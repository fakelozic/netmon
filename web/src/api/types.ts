/** Mirrors docs/web-api.md, including nulls and packet-relative units.
 * Transport belongs to client.ts; fixture data belongs to mock.ts.
 * Start with NetmonApi for the callable contract. */
/** Half-open byte offsets from the beginning of a packet. */
export type ByteRange = [number, number]
/** Capture status and totals; rate samples are bytes per second, oldest first. */
export interface Session {
  version: string
  mode: 'live' | 'file'
  source: string
  state: 'running' | 'paused' | 'ended' | 'failed'
  error: string | null
  started: string
  packets: number
  dropped: number
  bytes: number
  conversations: number
  alerts: number
  rate: number[]
  log_dir: string | null
  recording: 'off' | 'on' | 'full' | 'failed'
  problem: string | null
}
/** A parse error; position is the server's offset in the submitted filter. */
export interface FilterError {
  position: number
  message: string
}
/** A compact packet; time is seconds since the first packet. */
export interface PacketRow {
  no: number
  time: number
  clock: string
  src: string
  dst: string
  src_label: string
  dst_label: string
  app: string | null
  proto: string
  bytes: number
  info: string
  problem: boolean
  alerts: number
  flow: number | null
  dir: 'out' | 'in' | null
}
/** A bounded page of matching rows in ascending packet order. */
export interface PacketPage {
  total: number
  matched: number
  filter_error: FilterError | null
  rows: PacketRow[]
}
/** A field tree with server-authored explanation text; empty text is omitted in the UI. */
export interface Field {
  label: string
  value: string
  range: ByteRange
  what: string
  here: string
  why: string
  children: Field[]
}
/** A decoded protocol header and its packet-relative byte range. */
export interface Layer {
  proto: string
  range: ByteRange
  line: string
  about: string
  fields: Field[]
}
/** Captured bytes as lowercase hex; ranges may extend past truncated captured bytes. */
export interface PacketDetail {
  no: number
  time: number
  clock: string
  info: string
  wire_len: number
  captured_len: number
  truncated: boolean
  flow: number | null
  hex: string
  layers: Layer[]
  /** Secret byte ranges, already zeroed by the server; older replies may omit this field. */
  hidden?: ByteRange[]
}
/** Conversation summary; duration_ms is null while ongoing. */
export interface Flow {
  id: number
  title: string
  app: string | null
  pid: number | null
  local: string
  remote: string
  remote_name: string | null
  proto: string
  app_proto: string | null
  state: 'opening' | 'open' | 'closing' | 'closed' | 'reset' | 'refused' | 'active' | 'idle'
  status: string
  started: number
  duration_ms: number | null
  up_bytes: number
  down_bytes: number
  packets: number
  problems: number
  first_packet: number
  last_packet: number
}
/** Direction is relative to the conversation initiator, not necessarily this computer. */
export interface StoryStep {
  n: number
  dir: 'out' | 'in' | null
  kind: string
  text: string
  first_packet: number
  last_packet: number
  at_ms: number
  took_ms: number | null
  packets: number
  bytes: number
  problem: boolean
}
/** A conversation with steps in their observed order. */
export interface FlowDetail extends Flow {
  story: StoryStep[]
}
/** Conversation list sorted by the requested criterion. */
export interface FlowPage {
  total: number
  flows: Flow[]
}
/** A traffic observation; texts are explanations, not proof of malicious intent. */
export interface TrafficAlert {
  id: number
  kind: string
  severity: 'notice' | 'warning' | 'serious'
  time: number
  clock: string
  title: string
  seen: string
  why: string
  next: string
  packet: number
  first_packet: number
  subject: string
}
/** Server retains at most 1,000 alerts, newest last. */
export interface AlertPage {
  total: number
  alerts: TrafficAlert[]
}
/** One server-authored networking definition. */
export interface GlossaryTerm {
  term: string
  text: string
}
/** Definitions available for whole-word tooltips. */
export interface Glossary {
  terms: GlossaryTerm[]
}
/** Server error body for non-success responses. */
export interface ErrorReply {
  error: string
}
/** State-changing actions; only story export carries a conversation id. */
export type ControlAction =
  | { action: 'pause' | 'resume' | 'record_start' | 'record_stop' }
  | { action: 'export_story'; flow: number }
/** Export replies include path; other replies omit it. */
export interface ControlReply {
  ok: boolean
  session: Session
  path?: string
}
/** Supported server sort criteria. */
export type FlowSort = 'recent' | 'bytes' | 'problems'
/** Packet cursors are mutually exclusive; all queries send a filter. */
export type PacketQuery = { limit?: number; filter: string } & (
  { after?: number; before?: never } | { before: number; after?: never }
)
/** API surface shared by real transport and the deterministic mock. */
export interface NetmonApi {
  session(signal?: AbortSignal): Promise<Session>
  packets(query: PacketQuery, signal?: AbortSignal): Promise<PacketPage>
  packet(no: number, signal?: AbortSignal): Promise<PacketDetail>
  flows(sort: FlowSort, signal?: AbortSignal): Promise<FlowPage>
  flow(id: number, signal?: AbortSignal): Promise<FlowDetail>
  alerts(signal?: AbortSignal): Promise<AlertPage>
  glossary(signal?: AbortSignal): Promise<Glossary>
  control(action: ControlAction, signal?: AbortSignal): Promise<ControlReply>
}
