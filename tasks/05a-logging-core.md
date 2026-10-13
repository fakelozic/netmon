# Task 05a — logging core: session folder, log files, recording

Read `AGENTS.md`, `PLAN.md` (section 9), and the area guides for `src/explain` and `tests` first.

## Goal

A module that owns one session's folder on disk and writes everything netmon logs: a readable event
timeline, JSON lines, a per-packet log, a raw capture that opens in Wireshark, and exported text.
It is a library module with tests. Deciding **what** to log, and the headless mode, come in a later
task, once conversation tracking exists.

## Parallel work

Four other agents are working at the same time on conversations, the packets screen, app lookup and
alerts. You cannot see their work, so this module must not depend on theirs: callers hand it finished
values.

**You own:** `src/log.rs`, `src/explain/log.rs`, `examples/logdemo.rs`, `tests/log.rs`,
`tests/log_support/mod.rs`.

**Shared files:**
- `src/lib.rs` — add `pub mod log;` only.
- `src/explain.rs` — add one line, `pub mod log;`, directly below the existing `mod fields;`. Nothing else.

Do not touch anything else.

## 1. JSON writer

No serialisation crate is available. Write a small one in `src/log.rs`:

```rust
pub struct Json { /* private */ }
impl Json {
    pub fn object() -> Json;
    pub fn str(self, key: &str, value: &str) -> Json;
    pub fn num(self, key: &str, value: u64) -> Json;
    pub fn int(self, key: &str, value: i64) -> Json;
    pub fn bool(self, key: &str, value: bool) -> Json;
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Json;   // omits the key when None
    pub fn opt_num(self, key: &str, value: Option<u64>) -> Json;
    pub fn finish(self) -> String;                                  // one line, no trailing newline
}
```

Escaping follows RFC 8259: `"`, `\`, and every character below U+0020 (as `\n`, `\r`, `\t`, or
`\u00XX`). Other characters pass through as UTF-8. Keys are escaped too. Output is always one line.

## 2. Time

Logs need calendar time, and converting to the local time zone needs `unsafe`, which another agent
owns. So this module takes the conversion as a parameter:

```rust
pub struct Clock { pub year: i32, pub month: u8, pub day: u8, pub hour: u8, pub minute: u8, pub second: u8, pub millis: u16 }
pub type ClockFn = fn(Duration) -> Clock;      // Duration is time since the Unix epoch
pub fn utc_clock(ts: Duration) -> Clock;       // pure Rust, no unsafe; correct for all dates from 1970 to 2200
```

`utc_clock` is the default. Test it against known dates, including leap years and the last second of a year.

## 3. Session

```rust
pub struct Options {
    pub base: PathBuf,              // session folders are created inside this
    pub clock: ClockFn,
    pub utc: bool,                  // true when `clock` is UTC: times are then written with a trailing Z
    pub log_packets: bool,          // write packets.jsonl
    pub max_capture_bytes: u64,     // recording stops at this size; default 200 MB
}
pub fn default_base() -> PathBuf;   // $XDG_STATE_HOME/netmon, else $HOME/.local/state/netmon

pub enum EventKind { Open, Close, Dns, Alert, Note }
pub enum Recording { Off, On, Full, Failed }

pub struct Session { /* private */ }
impl Session {
    pub fn create(options: Options, started: Duration) -> io::Result<Session>;
    pub fn dir(&self) -> &Path;
    pub fn event(&mut self, ts: Duration, kind: EventKind, text: &str);
    pub fn flow_line(&mut self, json: &str);        // appends one line to flows.jsonl
    pub fn alert_line(&mut self, json: &str);       // appends one line to alerts.jsonl
    pub fn packet(&mut self, raw: &RawPacket, d: &Decoded, sentence: &str);
    pub fn start_recording(&mut self) -> Recording;
    pub fn stop_recording(&mut self);
    pub fn recording(&self) -> Recording;
    pub fn record(&mut self, raw: &RawPacket);      // no-op unless recording is On
    pub fn export_text(&mut self, stem: &str, text: &str) -> io::Result<PathBuf>;
    pub fn flush(&mut self);
    pub fn problem(&self) -> Option<&str>;          // first write error, as a plain sentence
}
```

Rules:

- **Folder.** `create` makes `<base>/<YYYYMMDD-HHMMSS>/` from `started`, with `Z` appended in UTC. If
  it exists, add `-2`, `-3`, and so on. Folders are created with mode `0700` and files with `0600`:
  the logs show what the user's computer talked to, and other accounts must not read them.
- **Files appear when first written.** An unused file is never created.
- **`events.log`:** `HH:MM:SS.mmm  KIND   text`, the kind padded to five characters
  (`OPEN`, `CLOSE`, `DNS`, `ALERT`, `NOTE`). `text` is written on one line: any newline or control
  character in it is escaped.
- **`flows.jsonl`, `alerts.jsonl`:** the given line plus a newline. A line containing a newline is
  refused and recorded as a problem; it must not corrupt the file.
- **`packets.jsonl`** (only when `log_packets`): one object per packet with `no`, `time` (ISO 8601
  with milliseconds), `src`, `dst`, `src_port`, `dst_port`, `proto`, `bytes`, `info` (the sentence).
  Absent values are omitted. Field values come from `Summary`, which already hides secrets; do not
  add packet payload.
- **`capture.pcapng`:** written with `pcap-file`. One interface block per link type seen, each
  declaring nanosecond time resolution (`if_tsresol` 9). This matters: `pcap-file` 2.0 writes the
  timestamp as raw nanoseconds, and a reader assumes microseconds unless the file says otherwise.
  Recording stops and becomes `Full` when the next packet would pass `max_capture_bytes`.
  `start_recording` after `Full` or `stop_recording` continues in `capture-2.pcapng`, and so on.
- **`export_text`:** writes `<stem>.txt`; if it exists, `<stem>-2.txt`. `stem` is reduced to letters,
  digits, `-` and `_`, so it can never leave the session folder.
- **Errors never panic and never stop netmon.** The first write error (disk full, permission denied)
  is kept for `problem()` as a plain sentence from `src/explain/log.rs`; that file's later writes
  become no-ops, and a failed recording becomes `Failed`. Other files keep working.
- Writes are buffered; `flush` writes them out, and `Drop` flushes.
- Wording of kinds, problems and any other text comes from `src/explain/log.rs`.

## 4. Example program (`examples/logdemo.rs`)

`cargo run --offline --example logdemo -- <CAPTURE> <BASE_DIR>` creates a session in `BASE_DIR`,
records every packet of the capture, writes `packets.jsonl`, writes one `NOTE` event per 25 packets,
and prints the session folder. It is how the result is inspected until the real wiring exists.

## 5. Tests

All files go under `env!("CARGO_TARGET_TMPDIR")`.

1. **JSON:** every control character, quotes, backslashes, non-ASCII text, empty strings, key
   escaping, omitted options, number extremes. Check each line with a small JSON reader written in
   `tests/log_support/mod.rs` that accepts only valid RFC 8259 text.
2. **Clock:** `utc_clock` on 1970-01-01, 2000-02-29, 2024-12-31 23:59:59, 2026-10-12 14:02:11.812,
   2100-03-01 (2100 is not a leap year).
3. **Session:** folder name from a fixed start time; the `-2` suffix; modes are exactly `0700` and
   `0600`; unused files are absent; event lines have the exact format; an event containing a newline
   and byte `0x1b` stays on one line with no raw control characters.
4. **Recording round trip:** record all of `loopback-mixed.pcapng` and all of `cooked-any.pcapng` into
   separate sessions, read each back with `capture::Reader`, and get the same packets: bytes, lengths,
   link type, and times to the nanosecond. If `tshark` is on `PATH`, also compare its
   `frame.time_epoch` and `frame.len` for every packet; otherwise print a notice.
5. **Size limit:** a 2,000-byte limit gives `Full`, a valid readable file under the limit, and
   `capture-2.pcapng` after restarting.
6. **Mixed link types:** packets with two link types in one recording read back with the right type each.
7. **Errors:** a base path that is a file; a session folder made read-only after creation. No panic,
   `problem()` is set, other files still work.
8. **`export_text`:** stems such as `../../etc/x`, `a/b`, an empty string and a 300-character string
   all stay inside the session folder.
9. **`packets.jsonl`:** for `loopback-mixed.pcapng`, 75 valid lines; packet 9's line has `proto` `DNS`
   and the task 01 sentence.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
cargo run --offline --example logdemo -- tests/fixtures/loopback-mixed.pcapng target/logdemo
ls -la target/logdemo/*/
head -3 target/logdemo/*/packets.jsonl
head -3 target/logdemo/*/events.log
```
