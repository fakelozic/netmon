# Task 08 — the pipeline: join the finished modules and write the logs

Read the root `AGENTS.md` in full first, then `PLAN.md` (sections 8 and 9), the area guides for
`src/explain` and `tests`, and these reports, which list each module's public interface:
`tasks/02-conversations.report.md`, `tasks/04a-apps.report.md`, `tasks/05a-logging-core.report.md`,
`tasks/05a-logging-core.fix-1.report.md`, `tasks/06a-alerts.report.md`.

## Goal

Conversation tracking, hostname learning, app lookup, alerts and logging all exist as separate modules
that nothing calls. Build the one value that owns them and feeds every packet through them, so that a
screen or a headless run only has to call `push` and read the result.

## Parallel work

Two other agents are working at the same time: one on the packets screen (it owns `src/main.rs` and
`src/ui/`), one tidying task 01's files. You cannot see their work.

**You own:** everything in `src/pipeline/`, `src/explain/pipeline.rs`, `examples/headless.rs`,
`tests/pipeline.rs`, everything in `tests/pipeline/` and `tests/pipeline_support/`, and golden files
named `tests/golden/pipeline-*`.

**Also yours for this task, because of section 3a:** everything in `src/log/`, `src/explain/log.rs`,
`examples/logdemo.rs`, `tests/logging.rs`, everything in `tests/log/` and `tests/log_support/`.
No other agent is working on the logging module.

**Shared files:**
- `src/lib.rs` — add `pub mod pipeline;` only.
- `src/explain.rs` — add one line, `pub mod pipeline;`, with the other `mod` lines. Nothing else.
- `src/procs/addresses.rs` and its tests — only the fix in section 4.

Do not touch `src/main.rs`, `src/ui/`, `src/decode/`, `src/capture.rs`, or the `flow`, `names`,
`alerts` and `procs` modules' files beyond what is listed above. Use those through their public
interfaces. If one is missing something you need, do not change it: work with what exists and list
the gap under "Needed elsewhere".

## 1. Interface (`src/pipeline/`)

```rust
pub struct Options {
    pub log: Option<crate::log::Options>,   // None: write no files
    pub record: bool,                       // start with raw recording on
    pub proc_root: Option<PathBuf>,         // Some("/proc") for live capture; None for saved files
    pub alerts: crate::alerts::Config,
}

pub struct Pipeline { /* private */ }
impl Pipeline {
    pub fn new(options: Options, started: Duration) -> Pipeline;
    pub fn push(&mut self, raw: &RawPacket) -> Row;   // once per packet, in order
    pub fn tick(&mut self, now: Duration);            // call about once a second with the latest packet time
    pub fn finish(&mut self);                         // end of capture: end every conversation, flush
    pub fn tracker(&self) -> &crate::flow::Tracker;
    pub fn recent_alerts(&self) -> impl Iterator<Item = &crate::alerts::Alert>; // newest last, at most 1,000 kept
    pub fn alert_count(&self) -> u64;
    pub fn app_of(&self, flow: crate::flow::FlowId) -> Option<&AppLabel>;
    pub fn session(&self) -> Option<&crate::log::Session>;
    pub fn session_mut(&mut self) -> Option<&mut crate::log::Session>;   // for record on/off and export
    pub fn problem(&self) -> Option<&str>;            // first logging problem, as a sentence
}

pub struct AppLabel { pub pid: u32, pub name: String }

/// Everything one line of the packet list needs. Owned, so it can be stored.
pub struct Row {
    pub number: u64,
    pub ts: Duration,
    pub summary: Summary,
    pub sentence: String,            // the context-aware sentence
    pub flow: Option<FlowId>,
    pub direction: Option<Direction>,
    pub src_label: String,           // name or address, with port when there is one
    pub dst_label: String,
    pub app: Option<String>,
    pub problem: bool,
    pub alerts: u8,                  // alerts this packet raised
}
```

## 2. What `push` does, in order

1. Decode with `Detail::Summary`.
2. `Tracker::observe`. Build the sentence with `explain::flows::sentence`.
3. Labels: `Names::label` for each side, plus the port.
4. **App.** When `proc_root` is set and the packet belongs to a TCP or UDP conversation with no app
   yet, look it up in the latest `ProcTable` snapshot. If it is not found, call `request_now()` and
   try again on that conversation's later packets, at most five times, then stop asking. The answer
   is remembered per conversation. With `proc_root` unset, never look.
5. `alerts::Engine::observe`. Keep the alerts in a ring of 1,000.
6. `problem` is true when the packet is a reset, a refusal, an ICMP error, a DNS failure, a
   retransmission, a zero window, truncated, or raised an alert.
7. Write logs (section 3).

At start, and again every 30 s of packet time when `proc_root` is set, read this computer's addresses
and default gateway from `procs` and give them to `Names` and to the alert engine.

`push` must never block on `/proc` or on disk beyond a buffered write. All lookups use the
`Refresher`'s latest snapshot.

## 3a. Files a person reads are Markdown (owner's request, added after this task started)

The owner reads these logs, and wants them as Markdown so they look good in an editor or viewer.
The rule: **a file meant for a person is `.md`; a file meant for a program stays as it is.**

| File | Was | Now |
|---|---|---|
| Event timeline | `events.log`, plain lines | **`events.md`**: a title, the session start, then one table that rows are appended to |
| Session summary | did not exist | **`summary.md`**: the report a person opens first (below) |
| Exported story | `<stem>.txt` | **`<stem>.md`**: a heading, a short facts list, and the ladder inside a fenced `text` block |
| `flows.jsonl`, `alerts.jsonl`, `packets.jsonl`, `capture.pcapng` | — | unchanged; they are for programs |

Change the logging module to match:

- `Session::event` appends a table row to `events.md`. The file starts with
  `# netmon events`, a line giving the session start time, a blank line, and the table header
  `| Time | Kind | What happened |`. Kinds are written as words (`Open`, `Close`, `DNS`, `Alert`,
  `Note`); `Alert` is bold. Rows are appended as they happen, so the file is readable mid-run.
- `Session::export_text` becomes `Session::export_markdown(stem, markdown)` and writes `<stem>.md`
  with the same rules for the stem as before.
- New `Session::write_summary(markdown: &str)`: replaces `summary.md` atomically (write a temporary
  file in the session folder, then rename), with the same private file mode.
- New module `src/log/markdown.rs` with the helpers every Markdown writer uses: `escape(text)`, a
  table-row builder, and a fenced-block builder.

**Escaping is a safety requirement, not decoration.** Names in these files come from the network and
from process names. A Markdown viewer renders HTML and follows links and images, so an unescaped
value could run markup or fetch a remote image when the owner opens the log. Therefore:

- Every value that is not fixed wording goes through `escape`, which neutralises at least
  `\`, `|`, `` ` ``, `*`, `_`, `[`, `]`, `(`, `)`, `<`, `>`, `&`, `#`, `!` and `~`, and turns any line
  break into a space. Values are sanitised (`text::sanitise`) before they are escaped.
- Text placed in a fenced block cannot contain a backtick run that would close the fence; the fence
  builder guarantees it.
- A table cell never contains a raw `|` or a line break.

`summary.md` is built by the pipeline (wording in `src/explain/pipeline.rs`, assembly in
`src/pipeline/summary.rs`) and written by `finish`, and also by `tick` at most once per 60 s of packet
time so that a long run always has a recent one. Its sections, in order:

1. `# netmon session summary` and a short facts list: started, ended, duration, packets, bytes,
   conversations, DNS lookups, alerts.
2. `## Alerts` — each alert as a `###` heading with its severity, packet numbers, and its Seen, Why
   and Next text. "None" when there are none.
3. `## Conversations` — a table: number, app, remote host, protocol, duration, up, down, how it ended.
   The 50 largest by bytes, then a line saying how many more are in `flows.jsonl`.
4. `## DNS lookups` — a table: name, answer, asked by, time taken, result. At most 100.
5. `## Problems` — refusals, resets, retransmissions, failed lookups, with packet numbers. At most 50.
6. `## Files in this folder` — one line per file present, saying what it is and what opens it.

Keep what the summary needs in bounded tables inside the pipeline; do not re-read the logs to build it.

Update the logging tests and `examples/logdemo.rs` for the new names. Add tests for escaping with
hostile values: `<img src=x onerror=1>`, `a|b`, `` `x` ``, `**bold**`, `[link](http://example.invalid)`,
`![img](http://example.invalid/a.png)`, a value with a line break, and a value containing three
backticks destined for a fenced block. Each must appear in the file as inert text.

## 3. What gets logged

Only when `log` is set. Text for every line comes from `src/explain/pipeline.rs`.
Where this section says `events.log`, read `events.md`: each entry is a table row as section 3a describes.

| Where | When | Content |
|---|---|---|
| `events.log` `OPEN` | a conversation's first packet (TCP, UDP) | `{app or "unknown app"} → {host or address}:{port} ({protocol})` |
| `events.log` `CLOSE` | a conversation ends | the same heading, then duration, bytes up and down, and how it ended (`flow_status`) |
| `events.log` `DNS` | a DNS answer | who asked, the name, the first answer and how many more, the time taken; or the failure |
| `events.log` `ALERT` | an alert | severity and title |
| `flows.jsonl` | a conversation ends | `start` (ISO 8601), `dur_ms`, `app`, `pid`, `proto`, `local`, `remote`, `host`, `tls`, `app_proto`, `up_bytes`, `down_bytes`, `packets`, `retransmits`, `end`; absent values omitted |
| `alerts.jsonl` | an alert | `time`, `kind`, `severity`, `title`, `seen`, `packet`, `first_packet`, `subject` |
| `packets.jsonl` | every packet, if enabled | through `Session::packet`, with the context-aware sentence |
| `capture.pcapng` | every packet, while recording | through `Session::record` |

- "Local" is the side whose address is this computer's; if neither or both are, it is the side that
  started the conversation. "Up" is from local to remote.
- ICMP conversations (pings) are logged as `OPEN` and `CLOSE` too, with no port.
- `finish` ends every open conversation as "still open when the capture ended" and writes it.
- Conversations ended by `tick` are logged the same way as those ended by a packet.
- No secret ever reaches a log. Use only values from `Summary`, `Flow`, `Alert` and the sentences.
- Times in logs use `log::utc_clock` for now. A later task switches to local time.
- Flush the session at most once per second of packet time, and in `finish`.

## 4. One fix in `procs`

`procs::local_addresses` returns network base addresses such as `127.0.0.0` as if they were this
computer's own. It must return only host addresses: in `net/fib_trie`, an address counts only when the
line after it contains both `/32` and `host LOCAL`. Update its doc comment and tests to match.

## 5. Example program (`examples/headless.rs`)

```
cargo run --offline --example headless -- <CAPTURE|-> [--log-dir DIR] [--record] [--log-packets] [--proc] [--quiet]
```

Reads a capture file, or a pcapng stream on standard input with `-`. Prints one line per packet
(number, time, from, to, app, sentence) unless `--quiet`, then a summary: packets, conversations,
alerts, and the session folder if any. `--proc` turns on app lookup from `/proc`.
Piping `dumpcap -i lo -w - -q` into it is how the live path will be tried after your report.

## 6. Tests

Files go under `env!("CARGO_TARGET_TMPDIR")`. Helpers in `tests/pipeline_support/`.

1. **Rows on `loopback-mixed.pcapng`** (no `/proc`): 75 rows; each sentence equals the matching line of
   `tests/golden/flows-loopback-list.txt`; `problem` is true for exactly packets 16, 73 and 75;
   12 conversations.
2. **Logs for that capture**, after `finish`: `events.md` has 12 `Open`, 12 `Close` and 4 `DNS` rows
   and no `Alert`; `flows.jsonl` has 12 valid JSON lines; the TLS conversation's line has `host`
   `netmon.test`, `tls` `1.3`, `end` saying it closed normally, and the byte counts from the tracker;
   no `alerts.jsonl` exists; `summary.md` exists with all six sections, 12 conversation rows and 4 DNS
   rows. Golden: `tests/golden/pipeline-events.md` and `tests/golden/pipeline-summary.md`. Read both
   as a person would and fix anything that looks cluttered or unclear.
2a. **Markdown is well formed and inert:** every table row in `events.md` and `summary.md` has the same
   number of cells as its header; with conversations whose server name, DNS name and app name are the
   hostile values from section 3a, no file in the session folder contains a raw `<`, an unescaped
   `|` inside a cell, or a link or image that Markdown would follow.
3. **Alerts flow through:** a built 25-port scan gives one `ALERT` line, one `alerts.jsonl` line,
   `alert_count() == 1`, and `problem` on the triggering row.
4. **Apps:** with a small fake `/proc` tree that has a socket matching a built TCP conversation, rows
   of that conversation get the app name, the `OPEN` line names it, and `flows.jsonl` has `app` and
   `pid`. A conversation with no matching socket stops asking after five tries and logs `unknown app`.
5. **No secrets:** a built HTTP request with Basic credentials, then an FTP `PASS`: no file in the
   session folder contains the password, the user name or the base64 text.
6. **Timeouts:** a UDP conversation with no further packets is closed and logged by `tick`.
7. **Logging failure:** a session folder made read-only mid-run does not panic or stop `push`;
   `problem()` returns a sentence.
8. **No logging:** with `log: None`, no file or folder is created and `push` still returns full rows.
9. **Robustness:** 5,000 fixed-seed mutations of the fixture packets through `push` cause no panic.
10. **`local_addresses`:** a sample `fib_trie` with `127.0.0.0 /8 host LOCAL` and
    `127.0.0.1 /32 host LOCAL` returns `127.0.0.1` and not `127.0.0.0`.

## 7. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
cargo run --offline --example headless -- tests/fixtures/loopback-mixed.pcapng --log-dir target/headless-demo --log-packets --record | tail -8
ls -la target/headless-demo/*/
cat target/headless-demo/*/events.md
cat target/headless-demo/*/summary.md
head -3 target/headless-demo/*/flows.jsonl
```

The size check may list only the five files named in `AGENTS.md`. Give the line count of every file
you created or changed in the report.
