# Task 02 — conversations: track connections and explain packets in context

Read `AGENTS.md`, `PLAN.md`, and the area guides for `src/explain` and `tests` first.

## Goal

Task 01 explains each packet on its own. This task adds memory: which conversation a packet belongs
to, what stage that conversation is at, what went wrong in it, and which hostname an address belongs to.

## Parallel work

Four other agents are working at the same time on the packets screen, app lookup, logging and alerts.
You cannot see their work.

**You own:** `src/flow.rs`, `src/names.rs`, `src/explain/flows.rs`, `examples/flows.rs`,
`tests/flows.rs`, `tests/flow_support/mod.rs`, and golden files named `tests/golden/flows-*`.

**Shared files:**
- `src/lib.rs` — add `pub mod flow;` and `pub mod names;` only.
- `src/explain.rs` — add one line, `pub mod flows;`, directly below the existing `mod fields;`. Nothing else.

Do not touch `src/main.rs`, `src/render.rs`, anything in `src/decode/`, or existing tests and golden files.

## 1. Names (`src/names.rs`)

```rust
pub enum AddrClass { Unspecified, Loopback, Private, LinkLocal, Multicast, Broadcast, Public }
pub enum NameSource { Dns, Mdns, Tls, Http }

pub struct Names { /* private */ }
impl Names {
    pub fn new() -> Self;
    pub fn classify(ip: &IpAddr) -> AddrClass;
    pub fn learn(&mut self, ip: IpAddr, name: &str, source: NameSource);
    pub fn name_of(&self, ip: &IpAddr) -> Option<&str>;
    pub fn set_local(&mut self, addrs: &[IpAddr]);     // this computer's addresses
    pub fn set_gateway(&mut self, ip: Option<IpAddr>); // the default router
    pub fn is_local(&self, ip: &IpAddr) -> bool;
    pub fn label(&self, ip: &IpAddr) -> String;        // see below
}
```

- A DNS or mDNS answer teaches every address in it the **name that was asked for**, even when a CNAME
  chain led there (`www.github.com`, not `github.com`).
- When two sources disagree, DNS and mDNS beat TLS and HTTP; within the same source the newest wins.
- `label` returns, in order: `this computer` for a local address, `router` for the gateway, the
  learned name, otherwise the address as text.
- At most 20,000 addresses are remembered; the least recently used is dropped first.
- Names are stored sanitised.

## 2. Tracker (`src/flow.rs`)

```rust
pub struct FlowId(pub u32);
pub enum Direction { Forward, Reverse }   // Forward = from the side that started the conversation
pub enum FlowState { Opening, Open, Closing, Closed, Reset, Refused, Active, Idle }

pub struct Tracker { /* private */ }
impl Tracker {
    pub fn new() -> Self;
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Observation; // once per packet, in order
    pub fn tick(&mut self, now: Duration) -> Vec<FlowId>;  // conversations that just ended by timeout
    pub fn flow(&self, id: FlowId) -> Option<&Flow>;
    pub fn flows(&self) -> impl Iterator<Item = &Flow>;    // oldest first
    pub fn names(&self) -> &Names;
    pub fn names_mut(&mut self) -> &mut Names;
}

pub struct Observation {
    pub flow: Option<FlowId>,
    pub direction: Option<Direction>,
    pub new_flow: bool,
    pub ended: bool,            // this packet finished the conversation
    pub notes: Vec<Note>,
}
```

`Note` says what the tracker concluded about this packet. At least:

| Note | When |
|---|---|
| `HandshakeStep(1 \| 2 \| 3)` | SYN; SYN+ACK; the ACK that completes the handshake |
| `HandshakeTime(Duration)` | on the SYN+ACK: time since the SYN |
| `Refused` | a reset that answers a SYN before any SYN+ACK |
| `Reset` | any other reset |
| `AckedBytes(u64)` | an ACK that confirms new data: how many bytes (not counting the SYN or FIN) |
| `Retransmission` | data, SYN or FIN whose sequence range was already seen from that side |
| `DuplicateAck(u32)` | an ACK with no data that repeats the previous ACK number and window while the other side has data outstanding; the count |
| `KeepAlive` | zero or one byte at one below the next expected sequence number |
| `Gap` | data that starts beyond the next expected sequence number |
| `ZeroWindow` | window 0 on a packet without SYN, FIN or RST |
| `ClosedPolitely` | both sides sent FIN and both were acknowledged |
| `DnsAnswerTime(Duration)` | a DNS response matched to its query by conversation and transaction id |
| `PingTime(Duration)` | an echo reply matched to its request by identifier and sequence |
| `HttpResponseTime(Duration)` | an HTTP response: time since the last request in that conversation |
| `ServerName(String)` | the server name became known for this conversation |

`Flow` records, at least: id, the two endpoints (address and port, starter first), IP protocol, state,
first and last packet time, packets and payload bytes in each direction, counts of retransmissions,
duplicate ACKs and resets, handshake time, server name (from the TLS Client Hello or the HTTP Host
header), TLS version from the Server Hello, the highest application protocol seen (`Proto`), whether
the start of the conversation was seen, and its `story`.

Rules:

- **What a conversation is.** TCP and UDP: the two address-and-port pairs, in either order. ICMP echo:
  the two addresses and the identifier. An ICMP error belongs to the conversation of the packet it
  quotes: find it by protocol, original sender (the error's destination) and the quoted ports. ARP,
  DHCP and anything else: no conversation (`flow: None`).
- **Who started it.** The sender of a SYN without ACK, else the sender of the first packet seen.
- **Sequence numbers wrap.** Compare them with wrapping arithmetic.
- **A capture can start in the middle.** With no SYN seen, the state starts as `Open` and nothing is
  reported as a retransmission until each side's position is known.
- **Server name across packets.** A TLS Client Hello can be larger than one packet. Keep up to 16 KB of
  the starter's in-order payload per TCP conversation until `decode::tls::parse_client_hello` reports
  `complete` or returns a server name, then drop the buffer.
- **Timeouts use packet time.** `tick(now)` ends UDP and ICMP conversations idle for 60 s, and TCP
  conversations idle for 300 s. `observe` calls the same logic with the packet's time.
- **Bounds.** At most 50,000 conversations; ended ones are dropped oldest first, then idle ones. Each
  story holds at most 400 steps; after that the last data step keeps absorbing.

### Story

`Flow::story` is a list of steps for the ladder diagram in `PLAN.md` section 6. A step has: kind,
direction, first and last packet number, time, packet count, payload bytes, and an optional duration.
Runs of data and the ACKs for it collapse into one step per direction.
Kinds, at least: Syn, SynAck, HandshakeAck, TlsClientHello, TlsServerHello, TlsHandshake, HttpRequest,
HttpResponse, DnsQuery, DnsResponse, PingRequest, PingReply, Data, Retransmission, Fin, Reset, Refused,
IcmpError.

## 3. Wording (`src/explain/flows.rs`)

```rust
pub fn sentence(d: &Decoded, obs: &Observation, flow: Option<&Flow>, names: &Names) -> String;
pub fn flow_title(flow: &Flow, names: &Names) -> String;
pub fn flow_status(flow: &Flow) -> String;
pub fn step_text(step: &Step, flow: &Flow) -> String;
pub fn story(flow: &Flow, names: &Names) -> String;   // the whole ladder as plain text
pub fn duration(d: Duration) -> String;                // "412 µs", "17 ms", "2.4 s"
```

`sentence` starts from `explain::sentence(d)` and improves it when the notes allow:

| Situation | Sentence |
|---|---|
| Handshake step 2 | `Accepts the connection (SYN+ACK) — handshake 2 of 3, {time} after the request` |
| Handshake step 3 | `Confirms (ACK) — handshake 3 of 3, the connection is open` |
| Refused | `Refuses the connection (RST) — nothing is listening on port {port}` |
| Reset | `Aborts the connection (RST)` |
| ACK of new data | `Confirms receipt of {n} bytes (ACK)` |
| Retransmission | `Sends {n} bytes again (retransmission) — the first copy was probably lost` |
| Duplicate ACK | `Repeats its last confirmation (duplicate ACK {count}) — it is still waiting for missing data` |
| Keep-alive | `Checks the connection is still alive (keep-alive)` |
| Gap | `Sends {n} bytes of data — an earlier packet is missing from the capture` |
| Zero window | `Says it cannot take more data right now (zero window)` |
| Final ACK of a polite close | `Confirms the close (ACK) — the connection has ended` |
| DNS answer | the task 01 sentence, then ` ({time})` |
| Ping reply | `Ping reply (seq {n}, {time})` |
| HTTP response | `Replies {code} {reason} ({time})` |

`flow_title` example: `127.0.0.1:51008 ⇄ netmon.test:18443   TCP + TLS 1.3 · 2.6 ms · 1,782 bytes up / 8,712 bytes down`.
`flow_status` examples: `closed normally`, `refused`, `reset by the server`, `still open`, `3 retransmissions`.
`step_text` gives each step a short plain line: the SYN is `"Can we talk?" (SYN)`, the SYN+ACK is
`"Yes. Can you hear me?" (SYN+ACK)`, the handshake ACK is `"Yes." The connection is open.`, data is
`{n} packets, {bytes} bytes of data`, encrypted data says the contents cannot be read.

Follow the writing standard in `src/explain/AGENTS.md`.

## 4. Example program (`examples/flows.rs`)

`cargo run --offline --example flows -- <FILE> [--stories]` prints the same columns as
`netmon explain`, with the improved sentence. With `--stories` it then prints every conversation's
title, status and story. This is how the result is inspected until the screens exist.

## 5. Tests

1. **Fixture facts** (`tests/flows.rs`, on `loopback-mixed.pcapng`): 12 conversations (two pings, four
   DNS lookups, three HTTP, one TLS, one refused, and one UDP that owns the ICMP error in packet 75).
   If you find a different number, report it and why rather than bending the test. Packets 17,
   18, 19 are handshake steps 1, 2, 3. The three HTTP conversations and the TLS one end
   `ClosedPolitely`. Packet 73 is `Refused`. The TLS conversation has server name `netmon.test` and
   TLS 1.3. Packet 10 has a `DnsAnswerTime`. After the file, `name_of` gives `example.com` for
   `172.66.147.243`, `104.20.23.154` and `2606:4700:8d95:72db:f2de:b99:ef6b:ff98`, and
   `www.github.com` for `20.207.73.82`. Total acknowledged bytes per direction equal the payload bytes sent.
2. **Built packets** (helpers in `tests/flow_support/mod.rs`): a retransmission; three duplicate ACKs;
   a gap; a zero window; a keep-alive; a reset in the middle; a capture that starts mid-connection
   (no false retransmissions); sequence numbers that wrap past zero; a Client Hello split across two
   segments (server name found); two conversations interleaved; a UDP conversation ended by `tick`;
   more conversations than the bound (memory stays bounded, oldest ended ones go first).
3. **Names**: classification of loopback, private, link-local, multicast, broadcast and public
   addresses in IPv4 and IPv6; the precedence and eviction rules; a name containing byte `0x1b` is
   stored sanitised.
4. **Never panics**: run the tracker over every fixture packet with 5,000 fixed-seed mutations.
5. **Golden** : the improved listing and the stories for `loopback-mixed.pcapng`, as
   `tests/golden/flows-loopback-list.txt` and `tests/golden/flows-loopback-stories.txt`. Read them
   and fix wording that is wrong or unclear before you finish.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
cargo run --offline --example flows -- tests/fixtures/loopback-mixed.pcapng
cargo run --offline --example flows -- tests/fixtures/loopback-mixed.pcapng --stories
```
