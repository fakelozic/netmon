//! Public conversation records for a packet-time tracker.
//! Packet decoding stays in `decode`; presentation stays in `explain::flows`.
//! Read `Tracker::observe` first, then `Flow` for the retained evidence.
use crate::decode::Proto;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

mod application;
mod packet;
mod story;
mod table;
mod tcp;
mod tls;
pub use table::Tracker;

// The brief fixes these limits so sustained traffic cannot grow memory forever.
const MAX_FLOWS: usize = 50_000;
const MAX_STEPS: usize = 400;
// Keep 256 sparse ranges/requests per side: ordinary in-order traffic uses one
// range, while deliberately missing bytes or unanswered queries remain bounded.
const MAX_RANGES: usize = 256;
const MAX_PENDING: usize = 256;
// A hello may span packets; 16 KiB is the brief's per-conversation assembly cap.
const MAX_HELLO: usize = 16 * 1024;
// A SYN and a FIN each use a sequence number without carrying data (RFC 9293, 3.4).
const SYN: u16 = 2;
const ACK: u16 = 16;
const FIN: u16 = 1;
const RST: u16 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A tracker-assigned conversation identifier. IDs can wrap and be reused after eviction.
pub struct FlowId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Direction relative to the opening SYN's sender, or the first captured sender.
pub enum Direction {
    /// From the conversation starter to its peer.
    Forward,
    Reverse,
}
impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Forward => 0,
            Self::Reverse => 1,
        }
    }
    fn opposite(self) -> Self {
        match self {
            Self::Forward => Self::Reverse,
            Self::Reverse => Self::Forward,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Observed conversation state; it does not promise the peer's actual socket state.
pub enum FlowState {
    Opening,
    Open,
    Closing,
    Closed,
    Reset,
    Refused,
    /// UDP or echo traffic with no explicit protocol close.
    Active,
    /// Ended because its packet-time inactivity limit was reached.
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Evidence about one packet. Times are elapsed durations; bytes exclude SYN and FIN.
/// Retransmission and gap notes describe sequence evidence, not proof of network loss.
pub enum Note {
    /// The first, second, or completing third packet of the opening exchange.
    HandshakeStep(u8),
    /// SYN to SYN+ACK elapsed time, not the entire three-packet exchange.
    HandshakeTime(Duration),
    /// Peer reset answers an opening SYN before acceptance was seen.
    Refused,
    /// Any other observed abort with the RST flag.
    Reset,
    /// Newly confirmed captured data, excluding repeat copies and control flags.
    AckedBytes(u64),
    /// A data/control sequence interval overlaps this sender's earlier captured interval.
    Retransmission,
    /// Consecutive repeated ACK/window pairs while captured data is outstanding.
    DuplicateAck(u32),
    /// Zero/one-byte probe at the previous expected sequence position.
    KeepAlive,
    /// Payload begins beyond the contiguous captured sequence position.
    Gap,
    /// Receiver advertises no buffer space on a non-control packet.
    ZeroWindow,
    /// Both sending directions sent FIN and both were confirmed.
    ClosedPolitely,
    /// Elapsed time from the matched DNS query in this conversation.
    DnsAnswerTime(Duration),
    /// Elapsed time from a matched echo identifier/sequence request.
    PingTime(Duration),
    /// Elapsed time from the latest opposite-direction HTTP request.
    HttpResponseTime(Duration),
    /// A bounded sanitised conversation name has become known or changed.
    ServerName(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
/// Result for exactly one observed packet. Empty notes mean no additional inference.
pub struct Observation {
    /// None for untracked protocols or an unmatched/ambiguous quoted ICMP error.
    pub flow: Option<FlowId>,
    /// None when there is no matched conversation.
    pub direction: Option<Direction>,
    pub new_flow: bool,
    /// True only if this packet explicitly finishes the conversation; not for timeouts.
    pub ended: bool,
    pub notes: Vec<Note>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// An IP endpoint. Echo conversations have no transport port.
pub struct Endpoint {
    pub addr: IpAddr,
    /// None for ICMP echo; Some(0) is a captured port number, not a missing value.
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Ladder event names follow the protocol message or the sequence inference.
/// Data includes runs of payload packets and the ACKs that confirm them.
pub enum StepKind {
    Syn,
    SynAck,
    HandshakeAck,
    TlsClientHello,
    TlsServerHello,
    TlsHandshake,
    HttpRequest,
    HttpResponse,
    DnsQuery,
    DnsResponse,
    PingRequest,
    PingReply,
    Data,
    Retransmission,
    Fin,
    CloseAck,
    Reset,
    Refused,
    IcmpError,
    KeepAlive,
    DuplicateAck,
    Gap,
    ZeroWindow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One retained ladder event or a grouped data run, bounded by the flow's story cap.
pub struct Step {
    pub kind: StepKind,
    /// Data direction for a grouped run, including ACKs travelling the other way.
    pub direction: Direction,
    /// Capture-global packet numbers; a range can include unrelated interleaved packets.
    pub first_packet: u64,
    pub last_packet: u64,
    /// First packet timestamp as a duration since the Unix epoch.
    pub time: Duration,
    /// Number of represented packets, including ACKs travelling the other way.
    pub packets: u64,
    /// Transport payload bytes, including repeated captured bytes, excluding headers.
    pub payload_bytes: u64,
    /// Matched response or handshake time; None when the initiating packet was unseen.
    pub duration: Option<Duration>,
    /// Sanitised application sentence; None when wording comes from the step kind.
    pub text: Option<String>,
    /// Payload is unreadable encryption data, rather than a readable hello.
    pub encrypted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Captured conversation facts. Array index 0 is Forward, index 1 is Reverse.
/// Counts describe captured traffic; absent packets cannot be inferred into totals.
pub struct Flow {
    pub id: FlowId,
    /// Capture-global numbers, including packets omitted from the bounded story.
    pub first_packet: u64,
    /// Most recently observed packet number, independent of its timestamp.
    pub last_packet: u64,
    /// Starter first. An observed opening SYN can correct a midstream orientation.
    pub endpoints: [Endpoint; 2],
    /// IP protocol number: 6 for TCP, 17 for UDP, 1 or 58 for echo.
    pub ip_proto: u8,
    pub state: FlowState,
    /// First captured timestamp, in time since the Unix epoch.
    pub first: Duration,
    /// Latest captured timestamp; backwards timestamps never decrease it.
    pub last: Duration,
    /// Capture packet counts per sender, including matched ICMP errors.
    pub packets: [u64; 2],
    /// Captured transport payload bytes per sender, including retransmissions.
    pub payload_bytes: [u64; 2],
    /// Unique captured data acknowledged by the peer, indexed by the data's sender.
    pub acked_bytes: [u64; 2],
    pub retransmissions: u64,
    pub duplicate_acks: u64,
    pub resets: u64,
    /// SYN to SYN+ACK duration; None when either opening packet was not matched.
    pub handshake_time: Option<Duration>,
    /// Sanitised SNI or HTTP Host for this conversation, without an HTTP port.
    pub server_name: Option<String>,
    /// Negotiated Server Hello version (e.g. 0x0304); None when unseen.
    pub tls_version: Option<u16>,
    /// Highest observed application layer; generic data never erases it.
    pub proto: Proto,
    /// Whether a SYN without ACK was observed, not whether every packet was captured.
    pub start_seen: bool,
    /// At most 400 ladder steps; later packets fold into data accumulators.
    pub story: Vec<Step>,
    /// Sender of the latest reset, or None if no reset was observed.
    pub reset_by: Option<Direction>,
    /// Packets folded after the story cap instead of retaining their event kind.
    pub story_omitted: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    protocol: u8,
    endpoints: [Endpoint; 2],
    echo_id: Option<u16>,
}
impl Key {
    fn new(protocol: u8, a: Endpoint, b: Endpoint, echo_id: Option<u16>) -> Self {
        // Canonical order joins both directions; the display order stays on Flow.
        let endpoints = if a <= b { [a, b] } else { [b, a] };
        Self {
            protocol,
            endpoints,
            echo_id,
        }
    }
}

#[derive(Clone, Copy)]
struct Span {
    start: i64,
    end: i64,
}

#[derive(Default)]
struct Side {
    // Contiguous captured sequence position. Seen ranges beyond a hole stay separate.
    next: Option<i64>,
    seen: Vec<Span>,
    outstanding: Vec<Span>,
    acknowledged: Option<i64>,
    last_ack: Option<(u32, u16)>,
    duplicate_count: u32,
    syn: Option<i64>,
    fin: Option<i64>,
    fin_acked: bool,
}

struct Query {
    id: u16,
    direction: Direction,
    time: Duration,
    name: String,
}
struct Ping {
    sequence: u16,
    direction: Direction,
    time: Duration,
}

struct Tracked {
    flow: Flow,
    key: Key,
    order: u64,
    sides: [Side; 2],
    syn_time: Option<Duration>,
    syn_ack_seen: bool,
    done: bool,
    echo_starter_request: bool,
    queries: VecDeque<Query>,
    pings: VecDeque<Ping>,
    http_request: Option<(Direction, Duration)>,
    hello: Option<Vec<u8>>,
    hello_next: Option<u32>,
}
