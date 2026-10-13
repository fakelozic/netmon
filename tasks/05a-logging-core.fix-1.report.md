**1. Built**

Split logging into [five modules](src/log/mod.rs) and tests into four focused files under one [test entry point](tests/logging.rs). Added API documentation, recording-state explanations, and required “why” comments. Removed the test helper’s global counter.

**Direct evidence:** all 17 original logging tests retain their code and assertions; all public signatures remain unchanged.

**2. Acceptance results**

All eight commands passed. Final output is reproduced exactly:

| Command | Result / last output |
|---|---|
| `cargo fmt --check` | Pass; no output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass; ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s`` |
| `cargo test --offline` | Pass; **48 tests**, including 17 logging tests. Final doc-test output: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass; ``Finished `release` profile [optimized] target(s) in 3.86s`` |
| `ls -l target/release/netmon` | Pass; `-rwxr-xr-x. 2 user user 543544 Oct 12 23:31 target/release/netmon` |
| `find src tests examples -name '*.rs' -exec wc -l {} + \| awk '$2 != "total" && $1 > 500'` | Pass; only the five exempt files, shown below |
| `cargo run --offline --example logdemo -- tests/fixtures/loopback-mixed.pcapng target/logdemo-fix` | Pass; `target/logdemo-fix/20261012-124043Z` |
| `head -3 target/logdemo-fix/*/packets.jsonl` | Pass; exact output below |

```text
   559 src/decode/dns.rs
   573 src/decode/ip.rs
   655 src/decode/mod.rs
  1115 src/explain.rs
  1021 src/explain/fields.rs
```

```json
{"no":1,"time":"2026-10-12T12:40:43.112Z","src":"127.0.0.1","dst":"127.0.0.2","proto":"ICMP","bytes":98,"info":"Ping request (seq 1)"}
{"no":2,"time":"2026-10-12T12:40:43.112Z","src":"127.0.0.2","dst":"127.0.0.1","proto":"ICMP","bytes":98,"info":"Ping reply (seq 1)"}
{"no":3,"time":"2026-10-12T12:40:43.413Z","src":"127.0.0.1","dst":"127.0.0.2","proto":"ICMP","bytes":98,"info":"Ping request (seq 2)"}
```

**Direct evidence** from comparison with the pre-refactor demo:

```text
capture.pcapng: byte-identical (20372 bytes)
events.log: byte-identical (144 bytes)
packets.jsonl: byte-identical (13574 bytes)
```

Release binary: **543,544 bytes**. Every surviving owned file is below 500 lines; longest function: **76 lines**.

| Rust file | Lines |
|---|---:|
| `src/log/mod.rs` | 75 |
| `src/log/json.rs` | 102 |
| `src/log/clock.rs` | 62 |
| `src/log/session.rs` | 350 |
| `src/log/record.rs` | 186 |
| `src/explain/log.rs` | 106 |
| `examples/logdemo.rs` | 76 |
| `tests/logging.rs` | 14 |
| `tests/log/json.rs` | 100 |
| `tests/log/clock.rs` | 67 |
| `tests/log/session.rs` | 317 |
| `tests/log/record.rs` | 221 |
| `tests/log_support/mod.rs` | 329 |
| `src/log.rs` — removed | 602 → 0 |
| `tests/log.rs` — removed | 693 → 0 |

**3. Public interface**

No public types or functions added. Existing paths are preserved through:

```rust
pub use clock::{Clock, ClockFn, utc_clock};
pub use json::Json;
pub use session::{Session, default_base};
```

`Options`, `EventKind`, and `Recording` remain at `netmon::log`. Existing methods and signatures are unchanged.

**4. Deviations**

None from the brief. Its required folder module supersedes PLAN’s `src/log.rs` layout. Tests share one entry point to avoid duplicate helpers and unused-code allowances.

**5. Needed elsewhere**

None for this fix.

**6. Not verified**

**No evidence found:** real disk exhaustion or Wireshark GUI behavior; neither was exercised. **Indirect evidence** for GUI compatibility comes from passing `tshark` comparisons.

Logical-fallacy check: passing tests and matching fixture output do not prove equivalence for every possible input or filesystem failure.

**7. Suggested guide updates**

Update the root guide’s `src/log.rs` entry to `src/log/`. Remove its existing trailing whitespace; the additional whole-tree check reported:

```text
AGENTS.md:190: trailing whitespace.
```

The owned-file whitespace check passed.

**8. Questions**

None.