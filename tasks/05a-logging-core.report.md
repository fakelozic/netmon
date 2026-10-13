**1. Built**

Implemented the [logging library](src/log.rs), [wording](src/explain/log.rs), [demo](examples/logdemo.rs), and [17 logging tests](tests/log.rs).

Includes private session folders, buffered logs, JSON escaping, UTC conversion, capped pcapng recording with rotation, and safe export filenames. Only the five owned files and two permitted module declarations changed.

**2. Acceptance results**

All nine commands passed. Direct evidence, with final output reproduced below:

| Command | Result | Last output |
|---|---|---|
| `cargo fmt --check` | Pass | No output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass | `Finished dev profile [unoptimized + debuginfo] target(s) in 0.26s` |
| `cargo test --offline` | Pass — 48 tests | `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` — final doc-test result |
| `cargo build --release --offline` | Pass | `Finished release profile [optimized] target(s) in 3.87s` |
| `ls -l target/release/netmon` | Pass | `-rwxr-xr-x. 2 user user 542488 Oct 12 19:54 target/release/netmon` |
| `cargo run --offline --example logdemo -- tests/fixtures/loopback-mixed.pcapng target/logdemo` | Pass | `target/logdemo/20261012-124043Z` |
| `ls -la target/logdemo/*/` | Pass | `-rw-------. 1 user user 13574 Oct 12 19:55 packets.jsonl` |
| `head -3 target/logdemo/*/packets.jsonl` | Pass | Packet output below |
| `head -3 target/logdemo/*/events.log` | Pass | Event output below |

```json
{"no":1,"time":"2026-10-12T12:40:43.112Z","src":"127.0.0.1","dst":"127.0.0.2","proto":"ICMP","bytes":98,"info":"Ping request (seq 1)"}
{"no":2,"time":"2026-10-12T12:40:43.112Z","src":"127.0.0.2","dst":"127.0.0.1","proto":"ICMP","bytes":98,"info":"Ping reply (seq 1)"}
{"no":3,"time":"2026-10-12T12:40:43.413Z","src":"127.0.0.1","dst":"127.0.0.2","proto":"ICMP","bytes":98,"info":"Ping request (seq 2)"}
```

```text
12:40:45.129  NOTE   Records 25 packets so far.
12:40:45.541  NOTE   Records 50 packets so far.
12:40:46.156  NOTE   Records 75 packets so far.
```

Release binary: **542,488 bytes**. Both fixture recording round trips and `tshark` comparisons passed.

**3. Public interface**

In `netmon::log`:

```rust
pub struct Json { /* private */ }
impl Json {
    pub fn object() -> Json;
    pub fn str(mut self, key: &str, value: &str) -> Json;
    pub fn num(mut self, key: &str, value: u64) -> Json;
    pub fn int(mut self, key: &str, value: i64) -> Json;
    pub fn bool(mut self, key: &str, value: bool) -> Json;
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Json;
    pub fn opt_num(self, key: &str, value: Option<u64>) -> Json;
    pub fn finish(mut self) -> String;
}

pub struct Clock {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millis: u16,
}
pub type ClockFn = fn(Duration) -> Clock;
pub fn utc_clock(ts: Duration) -> Clock;

pub struct Options {
    pub base: PathBuf,
    pub clock: ClockFn,
    pub utc: bool,
    pub log_packets: bool,
    pub max_capture_bytes: u64,
}
pub fn default_base() -> PathBuf;

pub enum EventKind { Open, Close, Dns, Alert, Note }
pub enum Recording { Off, On, Full, Failed }

pub struct Session { /* private */ }
impl Session {
    pub fn create(options: Options, started: Duration) -> io::Result<Session>;
    pub fn dir(&self) -> &Path;
    pub fn event(&mut self, ts: Duration, kind: EventKind, text: &str);
    pub fn flow_line(&mut self, json: &str);
    pub fn alert_line(&mut self, json: &str);
    pub fn packet(&mut self, raw: &RawPacket, d: &Decoded, sentence: &str);
    pub fn start_recording(&mut self) -> Recording;
    pub fn stop_recording(&mut self);
    pub fn recording(&self) -> Recording;
    pub fn record(&mut self, raw: &RawPacket);
    pub fn export_text(&mut self, stem: &str, text: &str) -> io::Result<PathBuf>;
    pub fn flush(&mut self);
    pub fn problem(&self) -> Option<&str>;
}
```

`Options` implements `Default`: UTC clock, packet logging disabled, and a **200,000,000-byte** capture cap. `Session` implements `Drop` to flush.

In `netmon::explain::log`:

```rust
pub const DEMO_USAGE: &str = "Usage: logdemo <CAPTURE> <BASE_DIR>";
pub const DEMO_EMPTY: &str = "The capture contains no packets.";
pub const DEMO_RECORDING: &str = "The recording cannot start.";
pub const DEMO_PACKET_LIMIT: &str =
    "A packet does not fit within the recording size limit.";

pub fn demo_note(packets: u64) -> String;
pub fn demo_problem(error: &dyn Display) -> String;
```

**4. Deviations**

None from the brief. Its required `src/explain/log.rs` layout takes precedence over PLAN §5’s single-file wording description.

**5. Needed elsewhere**

Later integration must connect `Session` to live capture, CLI options, headless mode, and finished flow/alert values.

**6. Not verified**

Real disk exhaustion and opening recordings in the Wireshark GUI were not exercised. **Indirect evidence** for GUI compatibility comes from successful `tshark` checks; **no evidence found** from a GUI run.

Logical-fallacy check: passing fixture tests does not establish correctness for every possible input or filesystem failure.

**7. Suggested guide updates**

Clarify the scope of the exact rule, “Secrets never reach a screen or a log.” The brief requires raw recordings to preserve packet payload bytes; that guarantee should distinguish readable/JSON logs from raw captures.

**8. Questions**

None.