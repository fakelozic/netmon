1. **Built**

Completed the server review and fixed the findings below. `web/`, dependencies, fixtures, and project guides remain unchanged.

Severity ratings are reviewer judgments. **Direct evidence** links point to regression tests or their output; **indirect evidence** means source inspection without exercising the failure path.

| Finding and location | Severity | Result and reason | Evidence |
|---|---|---|---|
| `explain --packet` exposed credentials through hexadecimal and ASCII output. | High | Fixed: text rendering uses shared byte masking. | Direct: [privacy regression](tests/web_api/review.rs:19) |
| API/UI masking missed split TCP credentials, HTTP bodies, unparsed TCP payloads, and headers beyond the decoder limit. | High | Fixed: conservatively hide those byte ranges. | Direct: [API cases](tests/web_api/review.rs:19), [UI cases](tests/ui_support/privacy.rs) |
| HTTP queries and URI userinfo could carry credentials into fields, summaries, stories, and logs. | High | Fixed: targets containing `?` or `@` are hidden across these outputs. | Direct: [privacy regression](tests/web_api/review.rs:19) |
| Authorization formatting exposed arbitrary first words; malformed/folded headers and credential-named extension headers also leaked values. | High | Fixed: retain only recognized authorization scheme names; hide ambiguous lines and sensitive extension values. | Direct: [cases](tests/web_api/review.rs:19), [previous failure](target/13-extension-headers-before.log) |
| Missing addresses/labels and unrepresentable clock values violated nullable API fields. | Medium | Fixed: emit explicit `null`. | Direct: [regression](tests/web_api/review.rs:99) |
| Flow packet references depended on bounded story entries, omitting packets such as ACKs. | Medium | Fixed: track authoritative first/last packet numbers. | Direct: [regression](tests/web_api/review.rs:81) |
| Flow-ID wrapping could allocate reserved ID zero. | Low | Fixed: skip zero after wrapping. | Direct: [table regression](src/flow/table.rs) |
| Pausing hid subsequent recording-full/failure state. | Medium | Fixed: refresh recording health while keeping paused traffic counters frozen. | Direct: [regression](tests/web_api/review.rs:126) |
| Server-generated error statuses exceeded the documented contract. | Medium | Fixed: map client errors to 400 and unavailable/overload cases to 500, retaining documented access/not-found statuses. | Direct: [response implementation](src/web/response.rs), [contract tests](tests/web/rules.rs) |
| Pcapng interface retention and metadata-only scanning were unbounded. | High | Fixed: cap interface count, retained metadata, and intervening metadata blocks. | Direct: [adversarial regressions](tests/capture_limits.rs) |
| Partial writes could extend response time indefinitely; overload replies could block acceptance. | High | Fixed: total write deadline, shutdown polling, and a nonblocking overload reply. | Direct: [deterministic write regression](src/web/connection.rs) |
| SIGINT with redirected stdin bypassed graceful shutdown. | High | Fixed: scoped SIGINT/SIGTERM handling; spawned children restore ordinary signal delivery. | Direct: [signal and child tests](src/sys.rs) |
| Panic or worker-creation failure could leave capture running. | High | Fixed: panic cleanup kills the capture group; worker-start errors kill and reap the child. | Direct: [synthetic-child panic regression](src/web/command.rs). Indirect: [worker-start error paths](src/live/source.rs) |
| Session summaries could collect an unbounded exported-file inventory. | Medium | Fixed: inspect at most 4,096 directory entries. | Direct: [crowded-folder regression](tests/pipeline/robustness.rs) |
| An empty/incomplete `web/dist` produced a 404 instead of the documented placeholder. | Low | Fixed: use the fallback whenever `index.html` is absent. | Direct: [build regression](tests/web/build.rs) |
| Web help and numeric-option errors lacked useful command-specific detail. | Low | Fixed: dedicated help, defaults, shutdown behavior, and valid numeric ranges; README corrected. | Direct: [CLI tests](tests/web_api/cli.rs), [README](README.md) |
| Opt-in raw recordings retain original secrets. | Privacy limitation | Retained deliberately: raw capture recording preserves original bytes in private files. | Direct: [recording implementation](src/log/record.rs), [README](README.md) |

The new regressions failed against the original source. Verbatim evidence from the [before-fix log](target/13-before-regressions.log):

```text
test result: FAILED. 23 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
```

Verbatim evidence from the [final test log](target/13-tests.log):

```text
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
```

2. **Acceptance results**

All Cargo runs used **four parallel jobs**. Outcomes and output are recorded in [acceptance results](target/13-acceptance.json).

| Command | Outcome | Last output, verbatim |
|---|---|---|
| `cargo fmt --check` | Pass, exit 0 | No output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass, exit 0 | ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.79s`` |
| `cargo test --offline -- --nocapture` | Pass, exit 0 | `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass, exit 0 | ``Finished `release` profile [optimized] target(s) in 12.14s`` |
| `find src tests examples -name '*.rs' -exec wc -l {} + \| awk '$2 != "total" && $1 > 500'` | Pass, exit 0 | No output |
| `sh -n tools/build.sh` | Pass, exit 0 | No output |

The test command’s final output above is the doc-test result. The complete run reported **243 passes, zero failures, and seven permission skips**; those skipped cases do not establish socket behavior. `git diff --check` and release help checks also passed.

Release binary: **1,357,784 bytes**.

Line counts for every created or changed Rust file, from [the count record](target/13-lines.log):

```text
 70 build.rs
399 src/capture.rs
136 src/capture/pcapng.rs
298 src/decode/http.rs
112 src/decode/mod.rs
 56 src/decode/redact.rs
 82 src/explain/values.rs
 88 src/explain/web.rs
291 src/flow/mod.rs
387 src/flow/table.rs
284 src/live/source.rs
228 src/main.rs
291 src/pipeline/summary.rs
174 src/render.rs
191 src/sys.rs
127 src/ui/tree.rs
181 src/web/api/control.rs
232 src/web/api/engine.rs
255 src/web/api/flows.rs
187 src/web/api/packet.rs
135 src/web/api/records.rs
331 src/web/api/state.rs
255 src/web/command.rs
155 src/web/connection.rs
 95 src/web/response.rs
115 src/web/server.rs
 72 tests/capture_limits.rs
 57 tests/pipeline/robustness.rs
472 tests/ui.rs
 44 tests/ui_support/privacy.rs
117 tests/web/build.rs
155 tests/web/headers.rs
177 tests/web/rules.rs
247 tests/web/sockets.rs
 35 tests/web_api.rs
 79 tests/web_api/cli.rs
148 tests/web_api/hidden.rs
148 tests/web_api/review.rs
```

3. **Public interface**

Added external interfaces:

```rust
// netmon::sys
pub struct Interrupt { /* private fields */ }

impl Interrupt {
    pub fn start(stop: Arc<AtomicBool>) -> io::Result<Self>;
}

// Added fields on netmon::flow::Flow
pub first_packet: u64;
pub last_packet: u64;

// netmon::explain::web
pub const HELP: &str;
```

`Interrupt` must start on the main thread before workers/children. Dropping it joins its waiter and restores that thread’s previous signal mask. Flow packet numbers are capture-global and independent of retained story entries.

Added crate-internal helpers:

```rust
pub(crate) fn hidden_ranges(
    decoded: &Decoded,
    len: usize,
) -> Vec<Range<usize>>;

pub(crate) fn unmask_child(command: &mut std::process::Command);
```

No endpoint names were added.

4. **Deviations**

- Conservative masking also conceals harmless bytes in ambiguous TCP payloads, bodies, query/userinfo targets, malformed headers, and sensitive-name extension headers. Packet-local decoding cannot reliably distinguish credential continuations.
- Pathological pcapng metadata is rejected at explicit limits; session file inventories stop after 4,096 entries.
- Raw recording preserves original bytes as specified by the existing recording design, despite the general secret-free wording.
- Pcapng conversion moved into a private submodule to satisfy size/function limits; existing public paths remain stable.

5. **Needed elsewhere**

The frontend reviewer should check nullable address/label/clock fields and expanded `hidden` ranges against its rendering. No frontend files were changed.

6. **Not verified**

**No evidence found** for real socket, browser, frontend-build, live `dumpcap`, or complete web-command signal-and-log-flush behavior in this sandbox. Seven socket-related cases skipped; the log includes:

```text
SKIPPED web_api socket integration: Operation not permitted (os error 1)
```

Signal handling and panic cleanup were exercised with synthetic children. Resource-exhaustion and worker-creation failure branches have **indirect evidence** from source inspection only.

Logical-fallacy check: finite passing regressions cannot prove universal secret recognition or panic freedom; skipped tests cannot support a socket-success claim.

7. **Suggested guide updates**

Clarify the opt-in raw-recording exception to secret-free logs, document scoped signal handling in `src/sys.rs`, and describe conservative hidden ranges that may include harmless bytes.

8. **Questions**

None.