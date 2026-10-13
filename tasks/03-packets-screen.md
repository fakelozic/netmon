# Task 03 — live capture and the Packets screen

Read `AGENTS.md`, `PLAN.md` (sections 4, 6 and 7 especially), and the area guides for `src/ui`,
`src/explain` and `tests` first.

## Goal

Running `netmon` opens a terminal screen that shows packets as they arrive, each with its plain-English
sentence, and lets the user open any packet to see its layers, the explanation of each field, and the
exact bytes. `netmon -r FILE` shows a saved capture the same way.

## Parallel work

Four other agents are working at the same time on conversations, app lookup, logging and alerts.
You cannot see their work. This task builds the **Packets tab only**; do not draw Connections or
Alerts tabs. Build the tab bar so more tabs can be added later.

**You own:** `src/main.rs`, `src/live.rs`, `src/store.rs`, `src/filter.rs`, `src/sys.rs`, everything in
`src/ui/` (except its `AGENTS.md`), `src/explain/ui.rs`, `tests/ui.rs`, `tests/filter.rs`,
`tests/live.rs`, `tests/ui_support/mod.rs`, and golden files named `tests/golden/ui-*`.

**Shared files:**
- `src/lib.rs` — add your `pub mod` lines only.
- `src/explain.rs` — add one line, `pub mod ui;`, directly below the existing `mod fields;`. Do not
  change its constants; put new help text in `src/explain/ui.rs` and use that instead.
- `tests/cli.rs` — update only the assertions that this task makes untrue (help text, bare `netmon`).

Do not touch `src/decode/`, `src/capture.rs`, `src/render.rs`, or other existing tests and golden files.

**`unsafe` is allowed in `src/sys.rs` only**, for calling `libc::localtime_r` to turn a timestamp into
local clock time. Keep it to one small function with a comment explaining why it is sound.

## 1. Live capture (`src/live.rs`)

```rust
pub struct Interface { pub name: String, pub description: String }
pub fn parse_interfaces(dumpcap_d_output: &str) -> Vec<Interface>;
pub fn list_interfaces() -> Result<Vec<Interface>, LiveError>;       // runs `dumpcap -D`
pub fn default_interface(list: &[Interface]) -> Option<&Interface>;  // see below

pub struct Source { /* private */ }
impl Source {
    pub fn dumpcap(interface: &str, capture_filter: Option<&str>) -> Result<Source, LiveError>;
    pub fn command(program: &str, args: &[&str]) -> Result<Source, LiveError>; // used by dumpcap() and by tests
    pub fn file(path: &Path) -> Result<Source, LiveError>;
    pub fn receiver(&self) -> &Receiver<Message>;
    pub fn stop(&mut self);
}
pub enum Message { Packet(RawPacket), Ended, Failed(String) }
```

- `dumpcap` runs `dumpcap -i <interface> -w - -q` plus `-f <filter>` when given, and feeds its
  standard output to `capture::Reader::from_stream` on a reader thread. Packets go over a bounded
  channel of 8,192; when it is full the reader waits.
- `file` reads a saved capture on a thread through the same channel, so a large file never blocks the screen.
- Standard error of the child is collected. If the child exits with an error, the message is sent as
  `Failed`, sanitised. A missing `dumpcap` gives a message that names the Wireshark package and the
  `wireshark` group.
- `stop` and `Drop` kill the child and join the thread. No child process may outlive netmon.
- `default_interface` picks the first interface that is not `lo`, `any`, or one whose name starts with
  `bluetooth`, `usbmon`, `nflog`, `nfqueue`, `docker`, `br-` or `veth`; else `lo`.

Sample `dumpcap -D` output to parse:

```
1. enp5s0
2. br-000000000001
7. any
8. lo (Loopback)
12. bluetooth-monitor
13. usbmon2
16. nflog
```

## 2. Packet buffer (`src/store.rs`)

A ring buffer of packets. Each entry keeps the `RawPacket`, its `Summary`, its sentence and a
`problem` flag, all computed once on arrival with `Detail::Summary`. Limits: 200,000 packets
(`--max-packets`) and 256 MB of packet bytes; the oldest are dropped first, and the count dropped is kept.

It also holds the current filter and the list of entries that match it. That list is extended as
packets arrive, and rebuilt in slices of at most 20,000 entries per tick when the filter changes.

`problem` is true for a TCP reset, an ICMP error, a DNS response with an error code, and a truncated packet.

## 3. Filter language (`src/filter.rs`)

```rust
pub struct Row<'a> {
    pub summary: &'a Summary,
    pub sentence: &'a str,
    pub src_name: Option<&'a str>,
    pub dst_name: Option<&'a str>,
    pub app: Option<&'a str>,
    pub problem: bool,
}
pub struct FilterError { pub position: usize, pub message: String }
pub fn parse(text: &str) -> Result<Filter, FilterError>;
impl Filter {
    pub fn matches(&self, row: &Row<'_>) -> bool;
    pub fn is_empty(&self) -> bool;
}
```

Grammar, as in `PLAN.md` section 7: protocol words (`tcp udp icmp arp dns mdns dhcp http tls quic ip
ipv6`), `port N`, `host TEXT` (matches either address as text, or a name, case-insensitive substring),
`app TEXT`, `problem`, `and`, `or`, `not`, brackets, and quoted or bare words that search the sentence.
Two terms side by side mean `and`. `not` binds tightest, then `and`, then `or`. An empty filter
matches everything. `tcp` matches anything carried over TCP, including HTTP and TLS.
Names and apps are `None` for now; later tasks fill them in, so the syntax must already work.
Errors say what was expected and where, in plain words.

## 4. The screen (`src/ui/`)

Follow `src/ui/AGENTS.md`. Layout as in `PLAN.md` section 6:

- **Header**: `● LIVE`, `PAUSED` or `FILE`; interface or file name; packet count; packets dropped if
  any; bytes per second with a sparkline of the last 60 seconds; the active filter.
- **Tab bar**: `[1] Packets`, with `? help` and `g glossary` hints at the right.
- **Packet list**: columns No, Time, From, To, Proto, Bytes, What is happening. Coloured by protocol;
  problem rows carry a `!` mark as well as a warning colour. Follows new packets until the user moves
  up or pauses; `End` resumes following.
- **Layers**: the selected packet's layers and fields as a tree. Layers start collapsed except the
  highest one. Decode the selected packet with `Detail::Full` when the selection changes, not per frame.
- **Explain**: for the selected field, its label and the What, Here and Why text from
  `explain::field_text`. For a selected layer, a short description of that protocol.
- **Bytes**: hex and ASCII of the packet, with the selected field's or layer's byte range highlighted
  and scrolled into view.
- **Filter bar**: `/` opens it; Enter applies; Esc cancels; an error shows under it without losing the text.
- **Overlays**: help (`?`), glossary (`g`, with type-to-search over `explain::GLOSSARY`), interface
  picker (`i`, live mode only; choosing one restarts the capture).

Keys: as in the table in `PLAN.md` section 6, except `R` and `e`, which belong to a later task. Also
`Tab` and `Shift-Tab` move between panes, `←` `→` collapse and expand in the tree, `t` switches the
time column between seconds since the first packet and local clock time, `f` sets the filter to the
selected packet's conversation (both hosts and both ports), `c` clears the filter, `q` and Ctrl-C quit.
Mouse: click selects a row, a field or a tab; the wheel scrolls the pane under the pointer.

When there are no packets yet, the list area says what netmon is waiting for and how to generate
traffic. When capture fails, the message from `live` is shown in place of the list, with what to do.

## 5. Command line (`src/main.rs`)

```
netmon [-i IFACE] [-f CAPTURE_FILTER] [--max-packets N]   live screen
netmon -r FILE [--max-packets N]                          screen for a saved capture
netmon interfaces                                         list capture interfaces
netmon explain <FILE|-> [--tsv | --fields | --packet N]   unchanged
netmon glossary [TERM]                                    unchanged
netmon --help | --version
```

If standard output is not a terminal, the screen modes print an error that suggests `netmon explain`
and exit with status 2.

## 6. Tests

1. **Filter** (`tests/filter.rs`): every term; precedence; brackets; quoting; error positions; and on
   `loopback-mixed.pcapng`: `dns` matches 8 packets, `tls` matches 9, `http` matches 6,
   `port 18443` matches 18, `problem` matches 3 (packets 16, 73 and 75), and
   `tcp and not port 18080` and `icmp or arp` give the counts you compute by hand and state in the test.
2. **Live** (`tests/live.rs`): `parse_interfaces` on the sample above; `default_interface`;
   `Source::command("sh", ["-c", "cat tests/fixtures/loopback-mixed.pcapng"])` delivers 75 packets then
   `Ended`; a command that prints to standard error and exits 1 delivers `Failed` with that text; a
   command that never ends is killed by `stop` promptly; a missing program gives the install message.
3. **Store**: the limits drop the oldest; the matching list stays correct while packets arrive during
   a rebuild.
4. **Screen** (`tests/ui.rs`, `TestBackend`): load `loopback-mixed.pcapng`, then golden text of the
   screen at 140x40, 100x30 and 80x24 with packet 17 selected and the TCP layer open on Flags; the
   same at 140x40 with the help overlay, with the glossary overlay filtered to `ttl`, and with filter
   `dns` applied. Event tests: moving, paging, expanding, pane focus, pausing, filter entry with an
   error, clearing, `f` on packet 20 leaves 12 packets, a click selects a row, a 50x10 terminal shows
   the too-small message, and no event sequence from a fixed-seed generator of 20,000 random keys and
   clicks causes a panic.
5. **Command line** (`tests/cli.rs`): `interfaces` and the screen modes fail cleanly without a terminal.

## 7. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
./target/release/netmon --help
./target/release/netmon -r tests/fixtures/loopback-mixed.pcapng < /dev/null | cat ; echo "exit=$?"
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng | head -5
```

The live screen itself cannot be run in the sandbox. It will be tried by hand after your report, so
say in the report exactly which keys and paths you could not exercise.
