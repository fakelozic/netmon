# Task 06a — alert rules

Read `AGENTS.md`, `PLAN.md` (section 8, "Security alerts"), and the area guides for `src/explain` and
`tests` first.

## Goal

An engine that watches packets in order and raises an alert when it sees one of five patterns. Each
alert says what was seen and why it matters, in plain English, because the user is learning what these
patterns mean. A library module with tests; the Alerts screen and log wiring come later.

## Parallel work

Four other agents are working at the same time on conversations, the packets screen, app lookup and
logging. You cannot see their work, so this engine keeps its own small state and depends only on
task 01's `capture` and `decode` modules.

**You own:** `src/alerts.rs`, `src/explain/alerts.rs`, `examples/alerts.rs`, `tests/alerts.rs`,
`tests/alert_support/mod.rs`, and golden files named `tests/golden/alerts-*`.

**Shared files:**
- `src/lib.rs` — add `pub mod alerts;` only.
- `src/explain.rs` — add one line, `pub mod alerts;`, directly below the existing `mod fields;`. Nothing else.

Do not touch anything else.

## 1. Interface (`src/alerts.rs`)

```rust
pub enum AlertKind { PortScan, CleartextCredentials, ArpChange, SuspiciousDns, UnexpectedInbound }
pub enum Severity { Notice, Warning, Serious }

pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    pub ts: Duration,            // time of the packet that triggered it
    pub packet: u64,             // that packet's number
    pub first_packet: u64,       // where the pattern began
    pub subject: Option<IpAddr>, // the address the alert is about
    pub title: String,           // one line, e.g. "Port scan from 192.168.1.77"
    pub seen: String,            // what was observed, with the numbers
    pub why: &'static str,       // why it matters
    pub next: &'static str,      // what the user can do or check
}

pub struct Config {
    pub scan_ports: usize,          // 20
    pub scan_window: Duration,      // 10 s
    pub dns_label_len: usize,       // 50
    pub dns_name_len: usize,        // 120
    pub nxdomain_count: usize,      // 20
    pub nxdomain_window: Duration,  // 10 s
    pub repeat_after: Duration,     // 60 s: do not repeat the same alert for the same subject sooner
}
impl Default for Config { /* the values above */ }

pub struct Engine { /* private */ }
impl Engine {
    pub fn new(config: Config) -> Engine;
    pub fn set_local(&mut self, addrs: &[IpAddr]);       // this computer's addresses
    pub fn set_gateway(&mut self, ip: Option<IpAddr>);
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Vec<Alert>;  // once per packet, in order
    pub fn is_public(ip: &IpAddr) -> bool;
}
```

`observe` receives a `Decoded` made with `Detail::Summary`. When a rule needs field detail (rule 2),
decode that one packet again with `Detail::Full` inside the engine.

## 2. The five rules

1. **Port scan.** One source address sends a TCP SYN without ACK, or a UDP packet, to
   `scan_ports` or more different ports on one destination address within `scan_window`.
   Severity: Warning; Notice when both addresses are local to this computer.
2. **Cleartext credentials.** Any of: an HTTP request (not over TLS) with an `Authorization` or
   `Proxy-Authorization` header; a TCP payload to port 21 that starts with `USER ` or `PASS `;
   payload exchanged with port 23 (Telnet), once per conversation. Severity: Serious.
   **The alert never contains the secret or the user name**: say which protocol, which server, and
   that a login was sent without encryption.
3. **ARP mapping change.** An IPv4 address that ARP showed at one MAC address is now announced at
   another. Ignore sender address `0.0.0.0`. Severity: Serious when the address is the gateway, else
   Warning. The text must say this also happens innocently (a device was replaced, an address was
   reassigned) and how to tell the difference.
4. **Suspicious DNS.** A query whose name has a label longer than `dns_label_len`, or is longer than
   `dns_name_len` in total, or has a label of at least 24 characters with high entropy (at least 4.0
   bits per character); or `nxdomain_count` NXDOMAIN answers to one client within `nxdomain_window`.
   Severity: Notice for a single long name, Warning for the burst. The text must say what DNS
   tunnelling and name-guessing malware are in one sentence each, and that content networks also use
   long random names.
5. **Unexpected inbound.** A TCP SYN from a public address to one of this computer's addresses that is
   answered with SYN+ACK. Needs `set_local`; with no local addresses known the rule is off.
   Severity: Warning. The text names the port and its usual service.

Rules for all:

- Times come from packets. Windows slide.
- The same kind for the same subject is not repeated within `repeat_after`.
- **Bounds:** every table has a cap (at most 4,096 tracked address pairs, 1,024 ports per pair,
  8,192 ARP entries, 4,096 DNS clients, 8,192 half-open inbound connections), dropping the oldest.
- Never panics on any packet.

## 3. Wording (`src/explain/alerts.rs`)

Titles, `seen`, `why` and `next` text for every kind, built from values the engine passes in. Follow
`src/explain/AGENTS.md`. Each `why` explains the idea to a beginner in two or three sentences. Each
`next` is a concrete thing to check, not "be careful". Do not overstate: these are patterns worth a
look, not proof of an attack.

## 4. Example program (`examples/alerts.rs`)

`cargo run --offline --example alerts -- <CAPTURE>` prints each alert in full: severity, title, packet
numbers, then Seen, Why and Next.

## 5. Tests

Build packets with helpers in `tests/alert_support/mod.rs` (Ethernet + IPv4 or IPv6 + TCP, UDP, DNS,
ARP, HTTP as byte arrays that task 01's decoder reads correctly; assert that in the helper's own test).

1. **Each rule fires:** a 25-port SYN scan; the same over UDP; HTTP Basic auth; FTP `USER` then `PASS`;
   Telnet; an ARP change, and one for the gateway; a 60-character label; a random 32-character label;
   25 NXDOMAIN answers in 5 s; an accepted inbound SYN from a public address.
2. **Each rule stays quiet:** 19 ports; 25 ports spread over 60 s; an HTTP request with no
   credentials; credentials on port 443 over TLS; the same ARP mapping repeated; an ARP probe from
   `0.0.0.0`; a 40-character readable name; 25 NXDOMAIN spread over 5 minutes; an inbound SYN that is
   refused; an inbound connection from a private address; an outbound connection to a public address.
3. **No secrets:** for the credential tests, no alert field contains the password, the user name, or
   the base64 text from the header.
4. **Repeat suppression:** a scan that continues raises one alert, and another after `repeat_after`.
5. **Fixtures raise nothing:** `loopback-mixed.pcapng` and `cooked-any.pcapng` give zero alerts.
6. **Bounds and robustness:** 100,000 packets from distinct spoofed addresses leave every table at or
   under its cap; 5,000 fixed-seed mutations of the fixture packets cause no panic.
7. **Golden:** the full printed alerts for one example of each rule, as
   `tests/golden/alerts-examples.txt`. Read it and fix wording that is wrong, alarmist or unclear.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
cargo run --offline --example alerts -- tests/fixtures/loopback-mixed.pcapng ; echo "exit=$?"
```
