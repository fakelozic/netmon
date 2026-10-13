**1. Built**

Implemented bounded conversation tracking, passive names, contextual sentences, ladder stories, the runnable example, and reviewed golden files. Public paths remain stable after splitting the tracker into modules.

Direct evidence: [fixture tests](tests/flow_support/fixture_tests.rs) passed, including:
```rust
assert_eq!(tracker.flows().count(), 12);
```

**2. Acceptance results**

All commands passed. [Full command output, preserved verbatim](target/flows-acceptance.txt).

| Command | Result and final output |
|---|---|
| `cargo fmt --check` | Pass; no output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass; `Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s` |
| `cargo test --offline` | Pass; `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass; `Finished `release` profile [optimized] target(s) in 4.21s` |
| `ls -l target/release/netmon` | Pass; `-rwxr-xr-x. 2 user user 543400 Oct 12 23:39 target/release/netmon` |
| `cargo run --offline --example flows -- tests/fixtures/loopback-mixed.pcapng` | Pass; listing ends at packet 75 |
| `cargo run --offline --example flows -- tests/fixtures/loopback-mixed.pcapng --stories` | Pass; prints all conversation stories |
| Required `find … \| awk …` size check | Pass; only the five permitted legacy files appear |

Direct evidence for the conversation tests:
```text
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.82s
```

The two example commands end with:
```text
   75    3.044691  127.0.0.2              127.0.0.1              ICMP         76  Cannot deliver: nothing listens on that port — about a UDP packet to port 18998
```
```text
      12 µs  │ ◀─────────────────────── │  2. Cannot deliver: nothing listens on that port — about a UDP packet to port 18998  [packets 75–75]
```

Release binary: **543,400 bytes**.

Line counts for every created or changed Rust file:

| File | Lines |
|---|---:|
| `src/lib.rs` | 7 |
| `src/explain.rs` — permitted legacy exception | 1115 |
| `src/names.rs` | 183 |
| `src/explain/flows.rs` | 376 |
| `src/flow/mod.rs` | 287 |
| `src/flow/application.rs` | 217 |
| `src/flow/packet.rs` | 132 |
| `src/flow/story.rs` | 202 |
| `src/flow/table.rs` | 356 |
| `src/flow/tcp.rs` | 277 |
| `src/flow/tls.rs` | 151 |
| `examples/flows.rs` | 55 |
| `examples/flows/output.rs` | 44 |
| `tests/flows.rs` | 13 |
| `tests/flow_support/mod.rs` | 137 |
| `tests/flow_support/fixture_tests.rs` | 126 |
| `tests/flow_support/names_tests.rs` | 121 |
| `tests/flow_support/table_tests.rs` | 213 |
| `tests/flow_support/tcp_tests.rs` | 159 |

The owned-file header, public documentation, file-size, and function-size audit passed.

**3. Public interface**

The public records are defined in [flow/mod.rs](src/flow/mod.rs):

```rust
pub struct FlowId(pub u32);
pub enum Direction { Forward, Reverse }
pub enum FlowState {
    Opening, Open, Closing, Closed, Reset, Refused, Active, Idle
}
pub enum Note {
    HandshakeStep(u8), HandshakeTime(Duration), Refused, Reset,
    AckedBytes(u64), Retransmission, DuplicateAck(u32), KeepAlive,
    Gap, ZeroWindow, ClosedPolitely, DnsAnswerTime(Duration),
    PingTime(Duration), HttpResponseTime(Duration), ServerName(String)
}
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: Option<u16>,
}
pub struct Observation {
    pub flow: Option<FlowId>,
    pub direction: Option<Direction>,
    pub new_flow: bool,
    pub ended: bool,
    pub notes: Vec<Note>,
}
pub enum StepKind {
    Syn, SynAck, HandshakeAck, TlsClientHello, TlsServerHello,
    TlsHandshake, HttpRequest, HttpResponse, DnsQuery, DnsResponse,
    PingRequest, PingReply, Data, Retransmission, Fin, CloseAck,
    Reset, Refused, IcmpError, KeepAlive, DuplicateAck, Gap, ZeroWindow
}
pub struct Step {
    pub kind: StepKind,
    pub direction: Direction,
    pub first_packet: u64,
    pub last_packet: u64,
    pub time: Duration,
    pub packets: u64,
    pub payload_bytes: u64,
    pub duration: Option<Duration>,
    pub text: Option<String>,
    pub encrypted: bool,
}
pub struct Flow {
    pub id: FlowId,
    pub endpoints: [Endpoint; 2],
    pub ip_proto: u8,
    pub state: FlowState,
    pub first: Duration,
    pub last: Duration,
    pub packets: [u64; 2],
    pub payload_bytes: [u64; 2],
    pub acked_bytes: [u64; 2],
    pub retransmissions: u64,
    pub duplicate_acks: u64,
    pub resets: u64,
    pub handshake_time: Option<Duration>,
    pub server_name: Option<String>,
    pub tls_version: Option<u16>,
    pub proto: Proto,
    pub start_seen: bool,
    pub story: Vec<Step>,
    pub reset_by: Option<Direction>,
    pub story_omitted: u64,
}
```

Directional arrays use index 0 for Forward and 1 for Reverse.

```rust
// netmon::flow
pub struct Tracker { /* private */ }
impl Tracker {
    pub fn new() -> Self;
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Observation;
    pub fn tick(&mut self, now: Duration) -> Vec<FlowId>;
    pub fn flow(&self, id: FlowId) -> Option<&Flow>;
    pub fn flows(&self) -> impl Iterator<Item = &Flow>;
    pub fn names(&self) -> &Names;
    pub fn names_mut(&mut self) -> &mut Names;
}

// netmon::names
pub enum AddrClass {
    Unspecified, Loopback, Private, LinkLocal, Multicast, Broadcast, Public
}
pub enum NameSource { Dns, Mdns, Tls, Http }
pub struct Names { /* private */ }
impl Names {
    pub fn new() -> Self;
    pub fn classify(ip: &IpAddr) -> AddrClass;
    pub fn learn(&mut self, ip: IpAddr, name: &str, source: NameSource);
    pub fn name_of(&self, ip: &IpAddr) -> Option<&str>;
    pub fn set_local(&mut self, addrs: &[IpAddr]);
    pub fn set_gateway(&mut self, ip: Option<IpAddr>);
    pub fn is_local(&self, ip: &IpAddr) -> bool;
    pub fn label(&self, ip: &IpAddr) -> String;
}

// netmon::explain::flows
pub fn sentence(d: &Decoded, obs: &Observation,
                flow: Option<&Flow>, _names: &Names) -> String;
pub fn flow_title(flow: &Flow, names: &Names) -> String;
pub fn flow_status(flow: &Flow) -> String;
pub fn step_text(step: &Step, flow: &Flow) -> String;
pub fn story(flow: &Flow, names: &Names) -> String;
pub fn duration(d: Duration) -> String;
pub const EXAMPLE_USAGE: &str =
    "usage: cargo run --offline --example flows -- <FILE> [--stories]";
```

`Tracker`, `Names`, and `Observation` implement `Default`.

**4. Deviations**

- Replaced `src/flow.rs` with a folder module and split tests/output helpers, following your updated modularity instruction.
- Qualified refusal and gap wording with `"probably nothing is listening"` and `"may be missing from the capture"`, following the wording guide’s accuracy rule.
- Validate complete SNI bytes before accepting a parser-returned name; the existing decoder can return a truncated prefix.
- Added bounds of 256 sequence ranges/pending requests and 1,024 input bytes per stored name.
- TLS/HTTP names remain per conversation, as specified in `PLAN.md`; `Names::learn` still supports both sources.

Indirect evidence and logical-fallacy check: sequence gaps and resets establish observed symptoms, not their causes.

**5. Needed elsewhere**

Future integration must call `Tracker::observe` and the contextual wording functions. The standalone TLS decoder should also avoid exposing truncated SNI prefixes; the tracker currently guards against them.

**6. Not verified**

No evidence found from live capture or terminal screens; both were prohibited in this sandbox. Mutation tests are finite evidence, not a proof for every possible input.

**7. Suggested guide updates**

Update ownership references from `src/flow.rs` to `src/flow/`. The updated root guide also contains trailing whitespace on line 190; I left it untouched.

**8. Questions**

None.