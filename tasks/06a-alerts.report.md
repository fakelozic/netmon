**Built** — Implemented all five alert rules, bounded state, packet-time windows, repeat suppression, secret-free wording, the capture example and reviewed golden output. The [engine](src/alerts/mod.rs) and tests now use focused modules. All 20 owned Rust files have headers and public-item documentation; the longest function is 72 lines.

**Acceptance results** — **Direct evidence:** every command passed. Full output is saved in [acceptance results](target/tmp/alerts-acceptance/results.json).

| Command | Outcome and final output |
|---|---|
| `cargo fmt --check` | Pass; exit 0, no output |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass: ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s`` |
| `cargo test --offline` | Pass; final line: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass: ``Finished `release` profile [optimized] target(s) in 7.62s`` |
| `ls -l target/release/netmon` | Pass: `-rwxr-xr-x. 2 user user 543480 Oct 12 23:39 target/release/netmon` |
| `cargo run --offline --example alerts -- tests/fixtures/loopback-mixed.pcapng ; echo "exit=$?"` | Pass: `exit=0`; no alerts printed |

Release binary: **543,480 bytes**.

The [test log](target/tmp/alerts-acceptance/test.log) contains:

```text
test alerts::bounds::one_hundred_thousand_distinct_spoofed_sources_keep_all_tables_bounded ... ok
test golden_tests::full_printed_examples_match_reviewed_golden ... ok
test robustness_tests::both_recorded_fixtures_raise_nothing_even_with_loopback_addresses_known ... ok
test robustness_tests::fixture_prefixes_and_five_thousand_fixed_seed_mutations_do_not_panic ... ok
```

The fifth gate also passed:

```sh
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
```

Its complete output contains only the five exempt files:

```text
   559 src/decode/dns.rs
   573 src/decode/ip.rs
   655 src/decode/mod.rs
  1115 src/explain.rs
  1021 src/explain/fields.rs
```

Line counts for every current Rust file created or changed:

```text
    73 src/alerts/arp.rs
   129 src/alerts/bounds.rs
   180 src/alerts/credentials.rs
   184 src/alerts/dns.rs
   112 src/alerts/inbound.rs
   303 src/alerts/mod.rs
    89 src/alerts/scan.rs
    81 src/alerts/table.rs
   201 src/explain/alerts.rs
    46 examples/alerts.rs
   124 tests/alerts.rs
    57 tests/alerts/arp.rs
   290 tests/alerts/credentials.rs
   145 tests/alerts/dns.rs
    69 tests/alerts/golden.rs
   170 tests/alerts/inbound.rs
    84 tests/alerts/robustness.rs
   189 tests/alerts/scan.rs
   131 tests/alert_support/decodes.rs
   240 tests/alert_support/mod.rs
     6 src/lib.rs
  1115 src/explain.rs
```

**Public interface** — Paths remain under `netmon::alerts`:

```rust
pub enum AlertKind {
    PortScan, CleartextCredentials, ArpChange,
    SuspiciousDns, UnexpectedInbound,
}
pub enum Severity { Notice, Warning, Serious }

pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    pub ts: Duration,
    pub packet: u64,
    pub first_packet: u64,
    pub subject: Option<IpAddr>,
    pub title: String,
    pub seen: String,
    pub why: &'static str,
    pub next: &'static str,
}

pub struct Config {
    pub scan_ports: usize,
    pub scan_window: Duration,
    pub dns_label_len: usize,
    pub dns_name_len: usize,
    pub nxdomain_count: usize,
    pub nxdomain_window: Duration,
    pub repeat_after: Duration,
}

impl Default for Config {
    fn default() -> Self;
}

impl Engine {
    pub fn new(config: Config) -> Engine;
    pub fn set_local(&mut self, addrs: &[IpAddr]);
    pub fn set_gateway(&mut self, ip: Option<IpAddr>);
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Vec<Alert>;
    pub fn is_public(ip: &IpAddr) -> bool;
}
```

`Engine` has private state. `Alert` additionally implements `std::fmt::Display`. Public example-message constants are `netmon::explain::alerts::EXAMPLE_USAGE: &str` and `EXAMPLE_ERROR: &str`.

**Deviations** —

- Converted `src/alerts.rs` into `src/alerts/mod.rs` with submodules, and split tests, following your updated instructions.
- Inserted the explanation module declaration above `mod fields;`: rustfmt requires that order. Each shared file still has exactly one added line.
- Followed the brief over PLAN: HTTP checks include both authorization headers; NXDOMAIN bursts are counted per client address.
- Telnet wording does not assert that arbitrary payload proves a login occurred.
- Additional state limits cover Telnet, suppression and local addresses. Zero count thresholds act as one.

**Needed elsewhere** — Later integration must supply local/gateway addresses and connect alerts to screens and logs. Shared-file headers and existing-item documentation remain for their owners; this task only permits module declarations there.

**Not verified** — **No evidence found:** live-capture behavior and real attack detection were not tested in the sandbox. TCP messages split across packets are not reassembled. **Indirect evidence:** finite mutation and stress tests support robustness for tested inputs, not universal panic freedom.

Logical-fallacy review: wording preserves innocent explanations and avoids treating a matching pattern as proof of an attack.

**Suggested guide updates** — Change the alert-engine path to `src/alerts/mod.rs`; clarify shared-file documentation ownership and align the brief’s declaration placement with rustfmt.

**Questions** — None.