# Tests — area guide

Applies to everything in `tests/`. Read the root `AGENTS.md` first.

## Fixtures

`tests/fixtures/` holds capture files recorded from **synthetic loopback traffic only**. They contain
no real traffic, and it must stay that way: what an agent reads is sent to an outside service.

- Never add a capture of real network traffic. Build new test packets as byte arrays in test code.
- Never change the existing fixture files.

| File | Contents |
|---|---|
| `loopback-mixed.pcapng` | 75 packets, Ethernet, nanosecond times. 1–4 ping; 5–8 IPv6 ping; 9–16 DNS (A, AAAA, CNAME, NXDOMAIN); 17–28 HTTP 200; 29–41 HTTP 404; 42–53 HTTP over IPv6; 54–71 TLS 1.3 with server name `netmon.test`; 72–73 connection refused; 74–75 UDP to a closed port, then ICMP port unreachable |
| `cooked-any.pcapng` | 13 packets, Linux cooked capture v1: ping and DNS |
| `loopback-first20.pcap` | First 20 packets of the first file, classic pcap, microsecond times |

## Golden files

`tests/golden/` holds expected text output. `NETMON_BLESS=1 cargo test --offline` rewrites them.
Read every changed line before blessing. Name new golden files after your area
(`flows-…`, `ui-…`, `alerts-…`) so parallel agents never write the same file.

## Helpers

Shared test code goes in `tests/<area>_support/mod.rs` (for example `tests/flow_support/mod.rs`), not
in `tests/common/`. Each area has its own, so parallel agents never write the same file.

## Rules

- Deterministic: no network, no real capture, no wall-clock assertions, no system randomness. Random
  inputs come from a fixed-seed generator written in the test.
- Files a test needs to create go under `env!("CARGO_TARGET_TMPDIR")`, never in the source tree.
- `tshark` may be missing. A test that uses it must print a notice and pass when it is not on `PATH`.
- Every decoder change keeps `tests/no_panic.rs` passing.
- A test must be able to fail. Do not assert only that a function returned.
