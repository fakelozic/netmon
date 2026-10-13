# Task 01 — the engine: read captures, decode packets, explain them

Read `AGENTS.md` and `PLAN.md` first. This brief is the exact specification for this task.

## Goal

A library plus one command, `netmon explain`, that reads a capture file and prints what every packet is
doing in plain English, with the full field tree, byte ranges and explanations on request.

There is no screen, no live capture and no memory between packets in this task. Each packet is explained
on its own.

## Out of scope (do not build, do not leave placeholders)

The terminal UI, spawning `dumpcap`, connection tracking, hostname learning, app lookup, logging, alerts,
and the filter language. `ratatui` and `libc` stay in `Cargo.toml` unused for now.

## What already exists

- `Cargo.toml` with the fixed dependencies, and a stub `src/main.rs` to replace.
- `tests/fixtures/loopback-mixed.pcapng` — 75 packets, Ethernet link type, nanosecond timestamps.
  Contents by packet number: 1–4 ping, 5–8 IPv6 ping, 9–16 DNS (A, AAAA, CNAME, NXDOMAIN),
  17–28 HTTP 200, 29–41 HTTP 404, 42–53 HTTP over IPv6, 54–71 TLS 1.3 with server name `netmon.test`,
  72–73 connection refused (SYN then RST), 74–75 UDP to a closed port then ICMP port unreachable.
- `tests/fixtures/cooked-any.pcapng` — 13 packets, Linux cooked capture v1 (SLL): ping and DNS.
- `tests/fixtures/loopback-first20.pcap` — the first 20 packets of the first file in classic pcap
  format with microsecond timestamps.
- `tshark` 4.6.9 is installed and works inside the sandbox for reading files.

## Files to create

```
src/lib.rs               module declarations only
src/main.rs              command line (lexopt); thin, calls the library
src/capture.rs           capture file and stream reader
src/text.rs              sanitise(), address and number formatting, hex dump
src/decode/mod.rs        the model (below) and the dispatch between layers
src/decode/link.rs       Ethernet (with 802.1Q VLAN), Linux cooked v1 and v2, ARP
src/decode/ip.rs         IPv4, IPv6 and extension headers, ICMP, ICMPv6
src/decode/transport.rs  TCP with options, UDP
src/decode/dns.rs        DNS and mDNS
src/decode/dhcp.rs       DHCPv4
src/decode/http.rs       HTTP/1.x
src/decode/tls.rs        TLS records, Client Hello, Server Hello
src/decode/quic.rs       QUIC detection
src/explain.rs           all wording (may become a folder src/explain/ if it grows long)
src/render.rs            turns decoded packets into the text that `netmon explain` prints
tests/...                as listed under Tests
tests/golden/...         expected outputs
```

## 1. Capture reader (`src/capture.rs`)

Public API. Keep these names; you may add to them.

```rust
pub enum LinkType { Ethernet, LinuxSll, LinuxSll2, RawIp, Other(u32) }  // LINKTYPE 1, 113, 276, 101

pub struct RawPacket {
    pub number: u64,     // 1-based, in file order; must equal tshark's frame.number
    pub ts: Duration,    // time since the Unix epoch
    pub link: LinkType,
    pub iface: u32,      // interface index; 0 for classic pcap
    pub orig_len: u32,   // length on the wire
    pub data: Vec<u8>,   // captured bytes; may be shorter than orig_len
}

pub struct Reader { /* private */ }
impl Reader {
    pub fn open(path: &Path) -> Result<Reader, CaptureError>;
    pub fn from_stream(r: Box<dyn Read + Send>) -> Result<Reader, CaptureError>;
}
impl Iterator for Reader { type Item = Result<RawPacket, CaptureError>; }
```

Requirements:

- Detect the format from the first four bytes: pcapng (`0A 0D 0D 0A`) or classic pcap (micro- and
  nanosecond magic numbers, both byte orders). Anything else is `CaptureError::NotACapture`.
- `from_stream` must not need `Seek`, must not read the whole input into memory, and must yield each
  packet as soon as its bytes have arrived. A later task feeds it the live pipe from `dumpcap`.
- pcapng: support several interfaces with different link types. Skip block types that are not packets.
- **Timestamp trap.** `pcap-file` 2.0 builds an Enhanced Packet Block's `timestamp` with
  `Duration::from_nanos(raw_ticks)` whatever the interface's resolution is. Recover the tick count with
  `as_nanos()` and scale it yourself using the interface's `if_tsresol` option: absent means 10⁻⁶ s;
  a value with the top bit clear is a power of ten; with the top bit set it is a power of two.
- Simple Packet Blocks have no timestamp: use zero and interface 0.
- A stream that ends cleanly between blocks ends the iterator. A stream that ends in the middle of a
  block yields `CaptureError::Truncated` once, after every complete packet, and then ends.

## 2. Decode model (`src/decode/mod.rs`)

Keep these names and meanings; you may add fields and variants.

```rust
pub enum Detail { Summary, Full }

pub fn decode(link: LinkType, data: &[u8], orig_len: u32, detail: Detail) -> Decoded;

pub struct Decoded {
    pub layers: Vec<Layer>,
    pub summary: Summary,
    pub truncated: bool,          // some header was cut short
}

pub struct Layer {
    pub proto: Proto,
    pub range: Range<usize>,      // the bytes this layer's header occupies in the packet
    pub line: String,             // short technical one-liner, e.g. "51008 → 18080 [SYN] seq=… win=65495"
    pub fields: Vec<Field>,       // empty when detail is Summary
}

pub struct Field {
    pub key: FieldKey,            // identifies the field; explain.rs maps it to label and text
    pub value: String,            // display form, already sanitised
    pub num: Option<u64>,         // numeric form when the field is a number or a set of flag bits
    pub range: Range<usize>,      // the bytes of this field within the packet
    pub children: Vec<Field>,     // flag bits, options, records, nested headers
}

pub enum Proto { Ethernet, LinuxCooked, Arp, Ipv4, Ipv6, Icmp, Icmpv6, Tcp, Udp,
                 Dns, Mdns, Dhcp, Http, Tls, Quic, Data }

pub enum Addr { Mac([u8; 6]), V4(Ipv4Addr), V6(Ipv6Addr) }

pub struct Summary {
    pub proto: Proto,             // highest layer recognised; this is the Protocol column
    pub src: Option<Addr>,        // IP address when there is an IP layer, otherwise MAC
    pub dst: Option<Addr>,
    pub ip_proto: Option<u8>,     // IPv4 protocol, or the final IPv6 next-header value
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp: Option<TcpInfo>,     // seq, ack, flags, window, payload length, MSS, window scale
    pub wire_len: u32,
    pub app: Option<AppInfo>,     // what the application layer said (see below)
}
```

`AppInfo` is an enum carrying what sentences and later tasks need. At least: ARP (operation, sender and
target MAC and IP), ICMP and ICMPv6 (type, code, id, sequence, and for errors the protocol and ports of
the embedded packet), DNS query (id, name, type), DNS response (id, name, type, response code, answers
with their type, value and TTL), DHCP (message type, offered and requested address, hostname),
HTTP request (method, target, host), HTTP response (status, reason), TLS Client Hello (server name, ALPN
list, offered versions), TLS Server Hello (chosen version, cipher suite), other TLS records (content
types present and byte counts), QUIC (long or short header, version, packet type).

Rules:

- `Summary` must be identical whether `detail` is `Summary` or `Full`. `Summary` mode must not build
  field lists; it exists so a live view can summarise every packet cheaply.
- Every `Field::range` and `Layer::range` satisfies `start <= end <= data.len()`.
- TCP payload length comes from the IP length fields, not from how many bytes were captured.
- No reassembly in this task: HTTP and TLS are recognised only when a segment's payload starts with
  them. Expose the Client Hello parser as a public function that accepts possibly incomplete bytes and
  reports whether it saw the whole message; a later task will call it on reassembled data.

## 3. What each decoder must produce

One `FieldKey` variant per field. Bit fields use the range of the byte or bytes that contain them.

| Protocol | Fields |
|---|---|
| Ethernet | destination MAC, source MAC, EtherType. With an 802.1Q tag: priority, drop-eligible bit, VLAN id, then the inner EtherType. |
| Linux cooked v1 | packet type, hardware type, address length, address, protocol |
| Linux cooked v2 | protocol, interface index, hardware type, packet type, address length, address |
| ARP | hardware type, protocol type, hardware size, protocol size, operation, sender MAC, sender IP, target MAC, target IP |
| IPv4 | version, header length, DSCP, ECN, total length, identification, flags (don't-fragment, more-fragments), fragment offset, TTL, protocol, header checksum (verified: say correct or incorrect), source, destination, options (raw). Only the first fragment's payload is decoded further. |
| IPv6 | version, traffic class, flow label, payload length, next header, hop limit, source, destination. Extension headers hop-by-hop, routing, fragment and destination options: next header, length, raw contents. |
| ICMP | type, code, checksum; echo: identifier, sequence; destination unreachable, time exceeded and redirect: the embedded IP header and first 8 bytes of its payload, decoded as children |
| ICMPv6 | type, code, checksum; echo: identifier, sequence; errors: embedded packet; neighbour and router discovery (133–136): target address and link-layer address options |
| TCP | source port, destination port, sequence number, acknowledgment number, data offset, flags (one child per flag: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN), window, checksum, urgent pointer, options (MSS, window scale, SACK permitted, SACK blocks, timestamps, NOP, end of list, unknown kinds raw), payload size |
| UDP | source port, destination port, length, checksum, payload size |
| DNS, mDNS | transaction id, flags (query/response, opcode, authoritative, truncated, recursion desired, recursion available, response code), the four counts, each question (name, type, class), each record in answer, authority and additional (name, type, class, TTL, data). Decode data for A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV and OPT; others raw. Follow compression pointers with a jump limit. mDNS is UDP port 5353; show its cache-flush and unicast-response bits. |
| DHCP | op, hardware type, transaction id, seconds, flags, the four addresses, client MAC, and options 1, 3, 6, 12, 50, 51, 53, 54, 55, 61 decoded; others raw |
| HTTP/1.x | request line (method, target, version) or status line (version, code, reason), each header, body size. Mask the values of `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` in `value` (show the scheme, hide the secret). |
| TLS | every record in the segment: content type, version, length. Client Hello: version, random, session id, cipher suite count, extensions with server name, ALPN, supported versions and key share groups decoded and the rest named with their length. Server Hello: version, random, cipher suite, supported version. Other handshake messages: type and length. Application data: "encrypted, N bytes". |
| QUIC | long header: form, version, packet type, connection id lengths and values. Treat as QUIC only for a long header with a known version (v1 `0x00000001`, v2 `0x6b3343cf`, or version negotiation), or a short header with the fixed bit set on UDP port 443. |
| anything else | a `Data` layer with its size; `Summary.proto` stays at the last recognised layer |

TCP and UDP checksums are shown but not verified. The explanation must say why: the network card often
computes them after the capture point, so locally captured outgoing packets can look wrong.

## 4. Explanations (`src/explain.rs`)

Three public pieces. Follow the writing standard in `AGENTS.md`.

### 4.1 One sentence per packet

`pub fn sentence(d: &Decoded) -> String`. Use these forms. Values in braces come from the packet.

| Case | Sentence |
|---|---|
| ARP request | `Who has {target ip}? Tell {sender ip}` |
| ARP reply | `{sender ip} is at {sender mac}` |
| ARP, sender ip equals target ip | `Announces: {ip} is at {mac}` |
| ARP request, sender ip 0.0.0.0 | `Is anyone using {target ip}?` |
| ICMP or ICMPv6 echo request | `Ping request (seq {n})` |
| ICMP or ICMPv6 echo reply | `Ping reply (seq {n})` |
| Destination unreachable | `Cannot deliver: {reason in plain words}`, then ` — about a {TCP or UDP} packet to port {p}` when the embedded packet shows it |
| Time exceeded | `Packet expired on the way (its hop counter reached 0)` |
| Neighbour solicitation | `Who has {target}? (IPv6 neighbour discovery)` |
| Neighbour advertisement | `{target} is at {mac}` |
| Router solicitation | `Asks: is there a router here?` |
| Router advertisement | `A router announces itself` |
| Other ICMP | `ICMP {type name}` |
| DNS query, A | `Asks: what is the IPv4 address of {name}?` |
| DNS query, AAAA | `Asks: what is the IPv6 address of {name}?` |
| DNS query, PTR | `Asks: what name belongs to {address}?` |
| DNS query, other | `Asks for the {TYPE} record of {name}` |
| DNS answer with addresses | `Answer: {name} is {first address}`, then ` (and {n} more)` if several, then ` (via {cname})` if a CNAME led there |
| DNS answer NXDOMAIN | `Answer: {name} does not exist (NXDOMAIN)` |
| DNS answer SERVFAIL | `Answer: the DNS server could not look up {name} (SERVFAIL)` |
| DNS answer, no records, no error | `Answer: {name} has no {TYPE} record` |
| mDNS query | `Asks the local network: who is {name}?` |
| mDNS answer | `Tells the local network: {name} is {value}` |
| DHCP Discover | `Asks the network for an IP address (DHCP Discover)` |
| DHCP Offer | `Offers the address {address} (DHCP Offer)` |
| DHCP Request | `Requests the address {address} (DHCP Request)` |
| DHCP ACK | `Confirms: use {address} (DHCP ACK)` |
| Other DHCP | `DHCP {message type name}` |
| HTTP request | `Requests {METHOD} {target} from {host}` (leave off ` from {host}` without a Host header) |
| HTTP response | `Replies {code} {reason}` |
| TLS Client Hello | `Starts encryption (TLS Client Hello) for {server name}` (leave off ` for …` without one) |
| TLS Server Hello | `Agrees on encryption settings (TLS Server Hello, {version})` |
| TLS change cipher spec only | `Switches to encrypted mode (TLS Change Cipher Spec)` |
| TLS application data | `Sends {n} bytes of encrypted data` |
| Other TLS | `Continues the TLS handshake` |
| QUIC Initial | `Starts a QUIC connection (encrypted from the first packet)` |
| Other QUIC | `Sends {n} bytes over QUIC (encrypted)` |
| TCP, SYN without ACK | `Opens a connection (SYN) — handshake 1 of 3` |
| TCP, SYN with ACK | `Accepts the connection (SYN+ACK) — handshake 2 of 3` |
| TCP, RST | `Aborts or refuses the connection (RST)` |
| TCP, FIN, no payload | `Finished sending, closing politely (FIN)` |
| TCP, payload and FIN | `Sends {n} bytes of data and finishes (FIN)` |
| TCP, payload | `Sends {n} bytes of data` |
| TCP, ACK only | `Acknowledges data received (ACK)` |
| UDP, unrecognised | `Sends {n} bytes over UDP`, then ` ({service})` when the port is well known |
| IP, non-first fragment | `Fragment of a larger packet (offset {n})` |
| IP, unknown protocol | `Carries IP protocol {n}`, then ` ({name})` when known |
| Unknown EtherType | `Unknown frame type {0xNNNN}` |

Append ` [cut short]` when `truncated` is set. When a TCP segment carries a recognised application
protocol (HTTP, TLS, DNS), use that protocol's sentence. Byte counts use thousands separators.

When one segment holds several TLS records, the sentence follows the most informative one, in this
order: Client Hello, Server Hello, another handshake message, alert, change cipher spec, application
data. For application data, `{n}` is the total encrypted bytes in the segment.

### 4.2 Three-part text per field

```rust
pub struct FieldText { pub label: &'static str, pub what: &'static str, pub here: String, pub why: &'static str }
pub fn field_text(field: &Field, packet: &Decoded) -> FieldText;
```

- `label` — the field's display name.
- `what` — what the field is and what it is for. Required for every `FieldKey`.
- `here` — what this value means in this packet. Required for at least: MAC addresses (broadcast,
  multicast, locally administered), EtherType, IPv4 header length, total length, don't-fragment flag,
  TTL and hop limit (likely starting value and hops travelled), IP protocol, IP addresses (loopback,
  private, link-local, multicast, public), ports (well-known service, or a temporary port picked by the
  operating system), sequence and acknowledgment numbers, each TCP flag, window (with window scale when
  the option is present in the same packet), MSS, checksums, UDP length, DNS response code, DNS record
  TTL (as a human duration), DNS record type, ICMP type and code, TLS version, TLS server name.
  May be empty for the rest.
- `why` — why it matters or what to watch for. May be empty for purely structural fields.

Look the text up with an exhaustive `match` on `FieldKey` so the compiler refuses a missing entry.
Include a table of well-known ports (about 40) and of IP protocol numbers and EtherTypes in common use.

### 4.3 Glossary

`pub const GLOSSARY: &[(&str, &str)]`, sorted by term, with at least: ACK, ARP, checksum, DHCP, DNS,
Ethernet, FIN, frame, fragment, handshake, hop, ICMP, IP address, IPv4, IPv6, MAC address, MSS, MTU,
packet, port, protocol, QUIC, RST, segment, sequence number, SYN, TCP, TLS, TTL, UDP, window.

## 5. Command line (`src/main.rs`)

```
netmon explain <FILE|->  [--tsv | --fields | --packet N]
netmon glossary [TERM]
netmon --help | --version
```

- `-` reads a capture from standard input through `Reader::from_stream`.
- `netmon` alone prints `netmon: the live view is not built yet; try: netmon explain <file>` to
  standard error and exits with status 2.
- Errors go to standard error as `netmon: <message>` with exit status 1.
- A truncated capture prints everything that was read, then a warning on standard error; exit status 0.
- A closed output pipe (`netmon explain f | head`) ends quietly with status 0, with no panic message.
- `glossary` prints all entries, or the entries whose term contains `TERM` (case-insensitive).

Output formats (produced by `src/render.rs`, so tests can call them directly):

**Default** — a header line, then one line per packet. Pad columns, never truncate them.

```
   No        Time  From                   To                     Proto    Bytes  What is happening
    9    0.901234  127.0.0.2:53123        127.0.0.53:53          DNS         94  Asks: what is the IPv4 address of example.com?
```

Time is seconds since the first packet, six decimals. Addresses: `1.2.3.4:80`, `[::1]:80`, a bare
address when there is no port, a MAC when there is no IP layer.

**`--tsv`** — a header line starting with `#`, then tab-separated columns:
`number`, `time_epoch` (seconds, nine decimals), `src`, `dst`, `src_port`, `dst_port`, `ip_proto`,
`wire_len`, `tcp_flags` (as `0x0012`, the form tshark prints), `tcp_seq`, `tcp_ack` (raw values),
`proto`, `sentence`.
Empty string when a column does not apply.

**`--fields`** — each packet line followed by its layers and fields, indented two spaces per level:

```
      TCP  [34..74]  51008 → 18080 [SYN] seq=… win=65495
        Source port  [34..36]  51008
```

**`--packet N`** — only packet N: its line, its fields with the three-part text under each field, and a
hex dump of the packet (offset, sixteen bytes in hex, ASCII).

```
        Time to live  [22..23]  64
            What: …
            Here: …
            Why:  …
```

Omit a `Here:` or `Why:` line when its text is empty.

## 6. Tests

All must pass under `cargo test --offline`.

1. **Fixtures decode** (`tests/fixtures_decode.rs`): the three files give 75, 13 and 20 packets; no
   packet is marked truncated; the classic-pcap file's packets equal the first 20 of the pcapng file in
   bytes, and in time to the microsecond; `Summary` is identical in both detail modes for every packet.
2. **Cross-check against tshark** (`tests/tshark_crosscheck.rs`): if `tshark` is not on `PATH`, print a
   notice and pass. Otherwise run it on both pcapng fixtures with
   `-o tcp.desegment_tcp_streams:FALSE -T fields -E occurrence=f` and compare, for every packet:
   `frame.number`, `frame.time_epoch`, `frame.len`, `ip.src`/`ipv6.src`, `ip.dst`/`ipv6.dst`,
   `ip.proto`/`ipv6.nxt`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, `tcp.flags`,
   `tcp.seq_raw`, `tcp.ack_raw`, `tcp.window_size_value`, `dns.id`, `dns.qry.name`, `dns.flags.rcode`,
   `http.request.method`, `http.response.code`, `tls.handshake.extensions_server_name`, `icmp.type`,
   `icmpv6.type`. Every one of these must match what netmon decoded.
   One special case: for an ICMP error such as packet 75, tshark's `udp.srcport` and `udp.dstport`
   come from the packet embedded inside the error. Compare those with the embedded-packet ports in
   `AppInfo`; `Summary.src_port` and `dst_port` stay empty for ICMP.
3. **Hand-built packets** (unit tests beside each decoder): ARP request and reply; DHCP Discover and
   Offer; a VLAN-tagged frame; IPv4 with options; a first and a later IPv4 fragment; IPv6 with
   hop-by-hop and fragment headers; TCP with MSS, window scale, SACK and timestamps; a DNS name with a
   compression-pointer loop (must terminate); a DNS answer with a CNAME chain; an mDNS answer; ICMP
   destination unreachable with an embedded UDP packet; Linux cooked v1 and v2; a Client Hello with
   server name, ALPN and supported versions; the same Client Hello cut in half; a QUIC v1 Initial; an
   HTTP request with an `Authorization` header (value masked).
4. **Never panics** (`tests/no_panic.rs`): for every fixture packet, decode every prefix length from
   0 to full, in both detail modes. Then 20,000 mutations from a fixed-seed xorshift generator (replace
   1 to 8 bytes, sometimes truncate). No panic, and every range stays within the data.
5. **Reader** (unit tests in `capture.rs`): pcapng built in memory with `if_tsresol` absent, 6, 9 and
   `0x80 | 10`, each giving the right time; a reader that returns one byte per `read` call still yields
   every packet; input cut mid-block yields the complete packets and then `Truncated`; four random
   bytes yield `NotACapture`.
6. **Sanitising**: a DNS name and an HTTP header containing byte `0x1b` produce output with no control
   characters other than newline.
7. **Golden outputs** (`tests/explain_golden.rs`): the default listing of both pcapng fixtures, and the
   `--packet` output of packets 10, 14, 17, 20, 57, 73 and 75 of `loopback-mixed.pcapng`, compared with
   files in `tests/golden/`. Setting `NETMON_BLESS=1` rewrites them. Generate them, read them yourself,
   and fix any wording that is wrong, unclear or breaks the writing standard before you finish.

## 7. Acceptance commands

Run all of these and put the real results in your report.

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng
./target/release/netmon explain tests/fixtures/cooked-any.pcapng
./target/release/netmon explain tests/fixtures/loopback-first20.pcap --tsv
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng --packet 57
./target/release/netmon explain - < tests/fixtures/loopback-mixed.pcapng | head -5
./target/release/netmon explain /etc/hostname ; echo "exit=$?"
./target/release/netmon glossary ttl
```

Expected: the first four succeed with no warnings; the listing of `loopback-mixed.pcapng` has 75 packet
lines whose sentences match section 4.1; packet 57 shows the server name `netmon.test`; reading from
standard input works; `/etc/hostname` gives a `netmon:` error and `exit=1`.
