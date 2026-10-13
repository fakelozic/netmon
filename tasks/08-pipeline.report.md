**Built**

Implemented the packet pipeline, bounded app/alert/report state, background process snapshots, Markdown events and story exports, atomic session summaries, the headless example, and the `/32 host LOCAL` fix.

**Direct evidence:** [acceptance output](target/pipeline-acceptance/results.json). Tests pass; the repository-wide file-size gate fails on five pre-existing files outside the permitted scope.

**Acceptance results**

All Cargo commands used `CARGO_BUILD_JOBS=4`. The test suites total **138 passed, 0 failed**. Last output lines are quoted below.

| Command | Outcome and last output |
|---|---|
| `cargo fmt --check` | PASS; no output |
| `cargo clippy --offline --all-targets -- -D warnings` | PASS: ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.42s`` |
| `cargo test --offline` | PASS: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | PASS: ``Finished `release` profile [optimized] target(s) in 5.23s`` |
| `ls -l target/release/netmon` | PASS: `-rwxr-xr-x. 2 user user 543624 Oct 13 11:54 target/release/netmon` |

Release binary size: **543,624 bytes**.

`find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'`

**FAIL against the current guide’s criterion**, although the command exits zero:

```text
   559 src/decode/dns.rs
   573 src/decode/ip.rs
   655 src/decode/mod.rs
  1118 src/explain.rs
  1021 src/explain/fields.rs
```

`cargo run --offline --example headless -- tests/fixtures/loopback-mixed.pcapng --log-dir target/headless-demo --log-packets --record | tail -8`

PASS; last lines:

```text
75 packets, 12 conversations, 0 alerts
Session: target/headless-demo/20261012-124043Z
```

`ls -la target/headless-demo/*/`

PASS; last line:

```text
-rw-------. 1 user user  2739 Oct 13 11:54 summary.md
```

`cat target/headless-demo/*/events.md`

PASS; last line:

```text
| 12:40:46.156 | Close | unknown app -&gt; 127.0.0.2:18998 \(UDP\), 12 us, 6 bytes up, 0 bytes down, still open when the capture ended |
```

`cat target/headless-demo/*/summary.md`

PASS; last line:

```text
- summary.md: Session report; open in a Markdown editor or viewer.
```

`head -3 target/headless-demo/*/flows.jsonl`

PASS; last line:

```json
{"start":"2026-10-12T12:40:45.538Z","dur_ms":2,"proto":"tcp","local":"[::1]:57506","remote":"[::1]:18081","host":"::1","app_proto":"HTTP","up_bytes":75,"down_bytes":245,"packets":12,"retransmits":0,"end":"closed normally"}
```

Reviewed both Markdown goldens. The recording-enabled example adds the expected `capture.pcapng` inventory entry. Its JSON files contain 12 valid flow records and 75 valid packet records. `git diff --check` passes.

Every created or changed Rust file:

| File | Lines |
|---|---:|
| examples/headless.rs | 139 |
| examples/logdemo.rs | 86 |
| src/explain.rs | 1118 |
| src/explain/log.rs | 123 |
| src/explain/pipeline.rs | 500 |
| src/lib.rs | 11 |
| src/log/json.rs | 106 |
| src/log/markdown.rs | 75 |
| src/log/markdown_files.rs | 98 |
| src/log/mod.rs | 77 |
| src/log/session.rs | 309 |
| src/pipeline/conversations.rs | 177 |
| src/pipeline/logging.rs | 112 |
| src/pipeline/mod.rs | 346 |
| src/pipeline/processes.rs | 115 |
| src/pipeline/summary.rs | 277 |
| src/procs/addresses.rs | 91 |
| tests/log/markdown.rs | 115 |
| tests/log/record.rs | 221 |
| tests/log/session.rs | 323 |
| tests/logging.rs | 16 |
| tests/pipeline.rs | 18 |
| tests/pipeline/apps.rs | 164 |
| tests/pipeline/behaviour.rs | 168 |
| tests/pipeline/fixture.rs | 121 |
| tests/pipeline/markdown.rs | 70 |
| tests/pipeline/robustness.rs | 37 |
| tests/pipeline/summary.rs | 114 |
| tests/pipeline_support/mod.rs | 165 |
| tests/pipeline_support/proc.rs | 72 |
| tests/procs_support/addresses.rs | 50 |

All task-owned Rust files meet the 500-line limit. The function-length audit found no changed owned function over 80 lines.

**Public interface**

Under `netmon::pipeline`:

```rust
pub struct Options {
    pub log: Option<crate::log::Options>,
    pub record: bool,
    pub proc_root: Option<PathBuf>,
    pub alerts: crate::alerts::Config,
}

pub struct AppLabel {
    pub pid: u32,
    pub name: String,
}

pub struct Row {
    pub number: u64,
    pub ts: Duration,
    pub summary: Summary,
    pub sentence: String,
    pub flow: Option<FlowId>,
    pub direction: Option<Direction>,
    pub src_label: String,
    pub dst_label: String,
    pub app: Option<String>,
    pub problem: bool,
    pub alerts: u8,
}

pub struct Pipeline { /* private fields */ }

impl Pipeline {
    pub fn new(options: Options, started: Duration) -> Pipeline;
    pub fn push(&mut self, raw: &RawPacket) -> Row;
    pub fn tick(&mut self, now: Duration);
    pub fn finish(&mut self);
    pub fn tracker(&self) -> &crate::flow::Tracker;
    pub fn recent_alerts(&self)
        -> impl Iterator<Item = &crate::alerts::Alert>;
    pub fn alert_count(&self) -> u64;
    pub fn app_of(&self, flow: FlowId) -> Option<&AppLabel>;
    pub fn session(&self) -> Option<&crate::log::Session>;
    pub fn session_mut(&mut self) -> Option<&mut crate::log::Session>;
    pub fn problem(&self) -> Option<&str>;
}
```

Under `netmon::log::markdown`:

```rust
pub fn escape(text: &str) -> String;
pub fn table_row(cells: &[&str]) -> String;
pub fn fenced_block(text: &str) -> String;
```

On `netmon::log::Session`:

```rust
pub fn export_markdown(
    &mut self, stem: &str, markdown: &str
) -> std::io::Result<PathBuf>;

pub fn write_summary(&mut self, markdown: &str);
```

`export_markdown` replaces `export_text`.

Under `netmon::explain::pipeline`:

```rust
pub const HEADLESS_USAGE: &str;

pub fn story_markdown(
    flow: &Flow, names: &Names, app: Option<&str>
) -> String;

pub fn headless_row(
    number: u64,
    times: [Duration; 2],
    labels: [&str; 2],
    app: Option<&str>,
    sentence: &str,
) -> String;

pub fn headless_summary(
    packets: u64,
    conversations: u64,
    alerts: u64,
    folder: Option<&str>,
) -> String;

pub fn headless_problem(error: &dyn std::fmt::Display) -> String;
```

Under `netmon::explain::log`:

```rust
pub fn demo_summary(packets: u64) -> String;
```

**Deviations**

- `Tracker` has no capture-end operation. `finish` uses `tick(Duration::MAX)` to end retained open flows; tracker state becomes `Idle`, while logs use `"still open when the capture ended"`.
- An active flow evicted by `Tracker` cannot subsequently receive a complete close record: its facts are no longer available through the public interface.
- `push` uses buffered session writers, but their first use can synchronously create a file. Thus the strict prohibition on disk operations beyond buffered writes is not fully met.
- Readable reports use ASCII `us` and arrows to remain readable through the shared ASCII sanitiser.
- Raw recording preserves packet bytes, as required; it can therefore preserve credentials. The secret-exclusion tests cover readable and JSON logs.

**Needed elsewhere**

Add tracker notifications containing evicted flow facts and an explicit capture-end operation. The five oversized files need the separate tidy task. Shared module roots also need headers and documentation; this brief permits only adding their module declarations.

**Not verified**

Live capture, real `/proc` attribution, GUI Markdown rendering, disk exhaustion, and disk latency under sustained traffic.

**Indirect evidence:** bounded state and escaping code support the intended safety properties. **No evidence found** establishes them for every possible input or Markdown renderer. The finite mutation tests are not a universal proof; treating them as one would be a hasty generalisation.

**Suggested guide updates**

Reconcile the current “no exemptions” size rule with the brief’s obsolete reference to five exempt files and this checkout’s actual contents. Clarify the secret rule for explicitly requested raw captures and whether lazy file creation is permitted in `push`.

**Questions**

None.