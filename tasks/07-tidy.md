# Task 07 — tidy the task 01 code: split the large files, add comments

Read the root `AGENTS.md` in full first, especially **Comments** and **Modular code: file size and
structure**, then the area guides for `src/decode`, `src/explain` and `tests`.

## Goal

Task 01's code was written before the modular-code and commenting rules existed. Bring it in line.
**Behaviour must not change**, with the one exception in section 3.

## Parallel work

Two other agents are working at the same time: one on the packets screen, one on a pipeline that joins
the finished modules. You cannot see their work.

**You own:** `src/lib.rs`, `src/capture.rs`, `src/text.rs`, `src/render.rs`, `src/explain.rs`,
`src/explain/fields.rs`, everything in `src/decode/` except its `AGENTS.md`, and the tests
`tests/explain_golden.rs`, `tests/fixtures_decode.rs`, `tests/no_panic.rs`, `tests/sanitising.rs`,
`tests/tshark_crosscheck.rs`.

**Do not touch:** `src/main.rs`, `tests/cli.rs`, anything in `src/flow/`, `src/names.rs`,
`src/procs/`, `src/alerts/`, `src/log/`, `src/explain/flows.rs`, `src/explain/alerts.rs`,
`src/explain/log.rs`, their tests, or any golden file.

**Every public path that exists today must still work afterwards**, through `pub use` re-exports.
Other agents' code calls, among others: `crate::explain::sentence`, `crate::explain::field_text`,
`crate::explain::FieldText`, `crate::explain::GLOSSARY`, `crate::explain::service`,
`crate::explain::tcp_flags`, `crate::explain::tls_version`, `crate::explain::dns_type`,
`crate::explain::HELP` and the other message constants, `crate::decode::decode`, `crate::decode::Detail`,
and every type in `crate::decode` (`Decoded`, `Layer`, `Field`, `FieldKey`, `Proto`, `Addr`, `Summary`,
`TcpInfo`, `AppInfo`, `ClientHello`, `DnsAnswer`, `EmbeddedPacket`), plus
`crate::decode::tls::parse_client_hello`. Before you start, list every `pub` item in the files you own
and check each one still resolves at the same path when you finish.

## 1. Split the five oversized files

| File | Lines now | Suggested split |
|---|---|---|
| `src/explain.rs` | 1,117 | Keep `src/explain.rs` as a short module root: header, `mod` lines, re-exports. Move content into `src/explain/`: `sentence/` (one file per protocol family, plus the dispatch), `tables.rs` (ports, IP protocols, EtherTypes, TLS and DNS names), `values.rs` (small value formatters such as `tcp_flags`, checksum status, HTTP header masking), `glossary.rs`, `cli.rs` (command-line messages). |
| `src/explain/fields.rs` | 1,021 | `src/explain/fields/`: `mod.rs` with `FieldText`, `field_text` and the dispatch; one file per protocol family (link, IP, ICMP, TCP, UDP, DNS, DHCP, HTTP, TLS, QUIC). |
| `src/decode/mod.rs` | 655 | `model.rs` (the result types), `keys.rs` (`FieldKey`), `view.rs` (`View`), `context.rs` (`Context`); `mod.rs` keeps the header, re-exports and `decode`. |
| `src/decode/ip.rs` | 573 | `ipv4.rs`, `ipv6.rs`, `icmp.rs`. |
| `src/decode/dns.rs` | 559 | `src/decode/dns/`: message layout in `mod.rs`, name decompression in `name.rs`, record data in `rdata.rs`. |

These are suggestions; cut where the code is cleanest, and say what you chose and why in the report.

- `src/explain.rs` must stay at that path as the module root. Other branches add one `pub mod` line
  to it, and that merge only works if the file still exists.
- **Field text must stay compiler-checked.** Today one exhaustive `match` on `FieldKey` guarantees no
  field lacks text. After the split, keep that guarantee: no catch-all arm anywhere on the path from
  `field_text` to the text.
- Each decoder file keeps, or gains, its RFC number and header diagram at the top.

## 2. Add the required comments

To every file you own: a file header, a doc comment on every public item, and "why" comments at
non-obvious decisions, as `AGENTS.md` describes. In particular:

- `src/lib.rs`: a crate-level header that names each module in one line and shows the data flow
  (capture → decode → explain → conversations, names, apps, alerts, logs → screen).
- `src/decode/mod.rs`: how a packet moves through the layers, what `Detail::Summary` skips, and that
  byte ranges are absolute within the packet.
- `View` and `Context`: what each guarantees about bounds, so a new decoder author can rely on it.
- `Summary`, `TcpInfo`, `AppInfo`: what each field means, its units, and what `None` means.
- `src/capture.rs`: the timestamp scaling and why it is needed (`pcap-file` 2.0 treats every pcapng
  timestamp as nanoseconds).
- Every decoder: one sentence of plain networking background where a concept first appears.

Remove anything `AGENTS.md` forbids: comments that repeat the code, narration, dead code, unused
public items.

## 3. The one behaviour fix

`decode::tls::parse_client_hello` can return a server name that is only a prefix of the real one when
the Client Hello is cut off part-way through the name. It must return a server name only when all of
the name's bytes are present; otherwise `server_name` is `None` and `complete` is `false`.
Add a unit test that cuts a Client Hello at every byte inside the server name.

## 4. Proving nothing else changed

- Every test that passes now still passes. The count before you start is 115; it may only go up.
- Golden files are untouched: `git status --short tests/golden` prints nothing.
- `netmon explain` output on the three fixtures is byte-for-byte what it was. Save the output of the
  commands below before you start (under `target/tidy-before/`) and compare at the end.

## 5. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
git status --short tests/golden
for f in loopback-mixed.pcapng cooked-any.pcapng loopback-first20.pcap; do
  ./target/release/netmon explain tests/fixtures/$f | cmp - target/tidy-before/$f.txt && echo "same: $f"
done
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng --packet 57 | cmp - target/tidy-before/packet-57.txt && echo "same: packet 57"
```

Expected: the size check prints nothing at all; the golden check prints nothing; every `cmp` prints
`same`. In the report, give the line count of every file you created or changed.

When you finish, the sentence in `AGENTS.md` that exempts five files is out of date. Say so under
"Suggested guide updates".
