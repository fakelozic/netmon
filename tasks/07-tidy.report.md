**Built**

Split the five oversized files into focused decoder and wording modules, added documentation, and fixed incomplete TLS server names. `src/explain.rs` remains the module root; `src/decode/ip.rs` remains a compatibility façade. TLS also became a folder module to accommodate its comments and regression test.

**Acceptance results**

Direct evidence: `Passing tests: before 115; after 116`. Every baseline test remains, plus the TLS truncation test.

| Command | Result and final output |
|---|---|
| `cargo fmt --check` | PASS; no formatting differences. Its [output](target/tidy-after/fmt.txt) contains a mise cache warning ending `Read-only file system (os error 30)`. |
| `cargo clippy --offline --all-targets -- -D warnings` | PASS — ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.36s`` |
| `cargo test --offline` | PASS, 116 tests. Final doctest line: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | PASS — ``Finished `release` profile [optimized] target(s) in 5.00s`` |
| `ls -l target/release/netmon` | `-rwxr-xr-x. 2 user user 544968 Oct 13 10:05 target/release/netmon` |
| Brief’s Rust file-size command | PASS — no output |
| `git status --short tests/golden` | PASS — no output |
| Three-fixture comparison loop | PASS — `same: loopback-mixed.pcapng`, `same: cooked-any.pcapng`, `same: loopback-first20.pcap` |
| Packet 57 comparison | PASS — `same: packet 57` |

Release binary: **544,968 bytes**. [Exact test output](target/tidy-after/tests.txt).

Final line counts, grouped by directory:

| Directory | File: lines |
|---|---|
| `src/` | capture.rs: 477; explain.rs: 27; lib.rs: 31; render.rs: 167; text.rs: 104 |
| `src/decode/` | app.rs: 138; context.rs: 141; dhcp.rs: 300; http.rs: 287; icmp.rs: 198; ip.rs: 111; ipv4.rs: 164; ipv6.rs: 166; keys.rs: 215; link.rs: 267; mod.rs: 109; model.rs: 178; quic.rs: 137; transport.rs: 366; view.rs: 93 |
| `src/decode/dns/` | mod.rs: 373; name.rs: 107; rdata.rs: 187 |
| `src/decode/tls/` | extensions.rs: 261; hello.rs: 97; mod.rs: 38; records.rs: 165; tests.rs: 79 |
| `src/explain/` | cli.rs: 16; glossary.rs: 166; tables.rs: 199; values.rs: 73 |
| `src/explain/fields/` | data.rs: 29; dhcp.rs: 189; dns.rs: 342; http.rs: 85; icmp.rs: 120; ip.rs: 262; link.rs: 174; meanings.rs: 210; mod.rs: 304; quic.rs: 71; tcp.rs: 268; tls.rs: 188; udp.rs: 64 |
| `src/explain/sentence/` | dhcp.rs: 24; dns.rs: 101; http.rs: 18; icmp.rs: 64; link.rs: 35; mod.rs: 85; quic.rs: 21; tls.rs: 50; transport.rs: 72 |
| `tests/` | explain_golden.rs: 44; fixtures_decode.rs: 36; no_panic.rs: 72; sanitising.rs: 45; tshark_crosscheck.rs: 174 |
| Removed files | src/decode/dns.rs: 0; src/decode/tls.rs: 0; src/explain/fields.rs: 0 |

**Public interface**

No new externally public types or functions. Checked 19 unchanged type schemas, 50 unchanged public function signatures, and compiled imports for all 77 inventoried public paths.

The existing TLS entry point remains:

```rust
pub fn parse_client_hello(data: &[u8]) -> ClientHello
```

A temporary extra `FieldKey` produced the expected non-exhaustive-match compiler error, confirming the wording coverage guarantee.

**Deviations**

None from the brief. Its modular layout supersedes the monolithic paths described in `PLAN.md`.

**Needed elsewhere**

None.

**Not verified**

Universal equivalence across every possible input remains unproved. Fixture comparisons are direct evidence for those captures; broader equivalence is indirect evidence. Logical-fallacy check: passing finite tests supports only their exercised cases.

No evidence found from live-capture or screen testing; those were not run.

**Suggested guide updates**

Remove the five-file size exemption from root `AGENTS.md`. Update decoder and wording area maps to reflect the new module paths.

**Questions**

None.