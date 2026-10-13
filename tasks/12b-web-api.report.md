**1. Built**

Implemented the engine-backed web API, `netmon web`, bounded retention, cached paging, controls, recording, story export, and all six requested fixes.

One limitation remains: terminal Ctrl-C uses key handling; direct SIGINT with redirected stdin does not shut down gracefully. This build embeds the placeholder page.

**2. Acceptance results**

All Cargo commands used `CARGO_BUILD_JOBS=4`. **Direct evidence:** [acceptance output](target/12b-acceptance/results.json).

| Command | Result and last output |
|---|---|
| `cargo fmt --check` | PASS; no output |
| `cargo clippy --offline --all-targets -- -D warnings` | PASS; ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.83s`` |
| `cargo test --offline` | PASS; 225 reported passed, zero failures; final line: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | PASS; ``Finished `release` profile [optimized] target(s) in 10.52s`` |
| `ls -l target/release/netmon` | PASS; `-rwxr-xr-x. 2 user user 1346728 Oct 13 17:18 target/release/netmon` |
| `find src tests examples build.rs -name '*.rs' -exec wc -l {} + \| awk '$2 != "total" && $1 > 500'` | PASS; no output |
| `./target/release/netmon --help` | PASS; `Screen keys: ? help, g glossary, / filter, q quit` |

Release binary: **1,346,728 bytes**. The three previously failing UI tests pass. Seven socket cases are permission skips included in the reported pass count.

Line counts for every created or changed Rust file:

```text
143 src/explain/fields/http.rs
241 src/explain/fields/meanings.rs
377 src/explain/fields/tcp.rs
123 src/explain/log.rs
425 src/explain/pipeline.rs
118 src/explain/pipeline/dns.rs
279 src/explain/ui.rs
 85 src/explain/web.rs
162 src/log/json.rs
 81 src/log/markdown.rs
105 src/log/markdown_files.rs
 77 src/log/mod.rs
286 src/main.rs
202 src/pipeline/conversations.rs
346 src/pipeline/mod.rs
289 src/pipeline/summary.rs
 64 src/ui/columns.rs
179 src/ui/packets.rs
182 src/web/api/control.rs
232 src/web/api/engine.rs
259 src/web/api/flows.rs
 50 src/web/api/mod.rs
168 src/web/api/packet.rs
211 src/web/api/packets.rs
 61 src/web/api/paging_tests.rs
135 src/web/api/records.rs
321 src/web/api/state.rs
 59 src/web/api/store.rs
188 src/web/command.rs
 99 src/web/mod.rs
469 tests/ui.rs
348 tests/ui_support/layout.rs
 30 tests/web_api.rs
 56 tests/web_api/cli.rs
163 tests/web_api/control.rs
 74 tests/web_api/edges.rs
309 tests/web_api/fixture.rs
 61 tests/web_api/hostile.rs
 60 tests/web_api/robustness.rs
 62 tests/web_api/sockets.rs
125 tests/web_api/support.rs
```

**3. Public interface**

Under `netmon::web::api`:

```rust
pub struct Options {
    pub live: bool,
    pub source: String,
    pub started: Duration,
    pub max_packets: usize,
    pub pipeline: netmon::pipeline::Options,
}

impl Options {
    pub fn file(
        source: String,
        started: Duration,
        pipeline: netmon::pipeline::Options,
    ) -> Self;
}

// Engine and WebApi have private fields.
// WebApi implements Clone and the existing Api trait.
pub struct Engine;
pub struct WebApi;

impl Engine {
    pub fn start(source: Source, options: Options) -> io::Result<Self>;
    pub fn channel(input: Receiver<Message>, options: Options) -> io::Result<Self>;
    pub fn api(&self) -> WebApi;
    pub fn stop(&mut self);
}

impl Api for WebApi {
    fn handle(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
    ) -> ApiReply;
}
```

Under `netmon::web::command`:

```rust
pub struct Options {
    pub file: Option<PathBuf>,
    pub interface: Option<String>,
    pub capture_filter: Option<String>,
    pub port: u16,
    pub no_open: bool,
    pub log_dir: Option<PathBuf>,
    pub record: bool,
    pub no_log: bool,
    pub max_packets: usize,
}

// Options implements Default.
pub fn run(
    options: Options,
    stop: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>>;
```

Under `netmon::log`:

```rust
pub struct JsonValue; // Private storage.

impl JsonValue {
    pub fn null() -> Self;
    pub fn string(value: &str) -> Self;
    pub fn number(value: u64) -> Self;
    pub fn float(value: f64) -> Self;
    pub fn array(values: impl IntoIterator<Item = Self>) -> Self;
}

impl Json {
    pub fn value(mut self, key: &str, value: JsonValue) -> Self;
    pub fn into_value(self) -> JsonValue;
}
```

Added public `&str` constants under `explain::web`: `ENGINE_TIMEOUT`, `ENGINE_BUSY`, `PACKET_GONE`, `FLOW_GONE`, `LOGGING_OFF`, `RECORDING_FAILED`, `RECORDING_FULL`, `EXPORT_FAILED`, `UNKNOWN_ACTION`, `PLACEHOLDER_NOTE`, `OPEN_FAILED`, and `PORT_ERROR`.

**4. Deviations**

- Used a separate API store because the existing store builds decoder-only rows. It preserves the terminal’s caps: 200,000 packets and 268,435,456 raw bytes. `src/store.rs` is unchanged.
- Fixed app retries in `pipeline/conversations.rs` and its caller, where the five-attempt limit actually lived.
- Added minimal module declarations/re-exports in `web/mod.rs` and `log/mod.rs`.
- Known HTTP secret ranges become zero bytes in `hex`, preserving offsets and valid hex while following the secret-hiding rule.
- Used terminal Ctrl-C key handling because [AGENTS.md:106](AGENTS.md:106) says: “**No `unsafe`** unless a task brief explicitly allows it, and then only in the file it names.” The requested SIGINT exemption remains unanswered.

**5. Needed elsewhere**

A scoped signal-handling exemption or safe signal dependency is needed for graceful direct SIGINT shutdown with redirected stdin. The frontend must also be built separately.

**6. Not verified**

**No execution evidence found** for live capture, browser behavior, desktop launching, real-terminal Ctrl-C restoration, or socket integration. The socket test explicitly printed:

```text
SKIPPED web_api socket integration: Operation not permitted (os error 1)
```

**Indirect evidence:** ownership and bounded-loop code support capture cleanup and responsiveness. Sustained live throughput was not measured.

Logical fallacy check: permission skips do not establish socket correctness; finite mutation tests do not prove safety for every input.

**7. Suggested guide updates**

Specify the SIGINT exception, reconcile literal raw hex with secret hiding, and document the required socket-test exception.

**8. Questions**

Should a follow-up brief permit narrowly scoped SIGINT handling in `src/main.rs`?