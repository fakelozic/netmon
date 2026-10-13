**Built —** Task 01’s capture reader, decoders, field trees, explanations, glossary, CLI, and reviewed golden outputs. All **31 tests pass**. Release binary: **542424 bytes**.

**Acceptance results —** Direct evidence: [complete command outputs](target/acceptance-results.txt). Last-output excerpts below are verbatim.

| Command | Outcome | Last output |
|---|---|---|
| `cargo fmt --check` | Pass | No output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass | ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.30s`` |
| `cargo test --offline` | Pass, 31 tests | Final doc-test line: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass | ``Finished `release` profile [optimized] target(s) in 3.65s`` |
| `ls -l target/release/netmon` | Pass | `-rwxr-xr-x. 2 user user 542424 Oct 12 19:16 target/release/netmon` |
| `./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng` | Pass, 75 packets | `Cannot deliver: nothing listens on that port — about a UDP packet to port 18998` |
| `./target/release/netmon explain tests/fixtures/cooked-any.pcapng` | Pass, 13 packets | `Cannot deliver: nothing listens on that port — about a UDP packet to port 18998` |
| `./target/release/netmon explain tests/fixtures/loopback-first20.pcap --tsv` | Pass, 20 packets | `Requests GET / from 127.0.0.2:18080` |
| `./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng --packet 57` | Pass; shows `netmon.test` | `0660  8f 36 00 1b 00 03 02 00 01                       .6.......` |
| `./target/release/netmon explain - < tests/fixtures/loopback-mixed.pcapng \| head -5` | Pass, quiet exit | `Ping reply (seq 2)` |
| `./target/release/netmon explain /etc/hostname ; echo "exit=$?"` | Pass, expected rejection | `exit=1`; `netmon: not a pcap or pcapng capture` |
| `./target/release/netmon glossary ttl` | Pass | `TTL: Time to live: an IPv4 hop counter. Each router lowers it; at zero the packet is dropped so it cannot circle forever.` |

**Deviations —** QUIC version negotiation and Retry receive accurate unencrypted sentences instead of the brief’s blanket encrypted wording. Incomplete headers use `?` or incomplete-header wording when values are unavailable. The brief takes precedence over PLAN.md’s illustrative model, broader CLI, and stateful sentences.

**Not verified —** Live capture and UI are excluded by this task; no evidence found for their behavior. Finite prefix and mutation tests provide indirect evidence of robustness, not a formal proof for every input. Logical-fallacy check: no universal safety conclusion is drawn from passing samples.

**Questions —** None.