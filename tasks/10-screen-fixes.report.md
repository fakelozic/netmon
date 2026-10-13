**Built**

Implemented the owned screen fixes: single-line packet rows with `…`, a fixed full-sentence strip directly below the list, compact detail-pane switching, file-first selection, file totals, sparkline warm-up, and centred reference overlays.

**Direct evidence:** [regression tests](tests/ui_support/layout.rs:52) pass with **17 / 11 / 8 visible rows** at 140×40 / 100×30 / 80×24. Every fixture sentence, including packet 75’s, appears in full. Two changes outside ownership remain below.

**Acceptance results**

145 tests pass, including the existing 20,000-event test. All commands were run.

| Command | Result and final output |
|---|---|
| `cargo fmt --check` | **FAIL** — existing ordering difference in `src/explain.rs` |
| `cargo clippy --offline --all-targets -- -D warnings` | PASS — ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.49s`` |
| `cargo test --offline` | PASS — `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` (final doc-test suite) |
| `cargo build --release --offline` | PASS — ``Finished `release` profile [optimized] target(s) in 7.58s`` |
| `ls -l target/release/netmon` | PASS — `-rwxr-xr-x. 2 user user 916832 Oct 13 11:02 target/release/netmon` |
| `find src tests examples -name '*.rs' -exec wc -l {} + \| awk '$2 != "total" && $1 > 500'` | PASS — empty output |
| `./target/release/netmon --help` | PASS — `Screen keys: ? help, g glossary, / filter, q quit` |
| `./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng \| head -3` | PASS — quoted below |
| `cat tests/golden/ui-packets-80x24.txt` | PASS — pasted below |
| `cat tests/golden/ui-packets-140x40.txt` | PASS — `/ filter   f conversation   c clear   Space pause   Tab pane   q quit` |

Formatting failure excerpt:

```diff
 mod glossary;
 mod sentence;
 mod tables;
-mod values;
 pub mod ui;
+mod values;

 pub use cli::{COMMAND_ERROR, FILE_ERROR, HELP, LIVE_NOT_BUILT, MODE_ERROR, PACKET_NUMBER_ERROR};
 pub use fields::{FieldText, field_text};
```

Explain output:

```text
   No        Time  From                   To                     Proto    Bytes  What is happening
    1    0.000000  127.0.0.1              127.0.0.2              ICMP         98  Ping request (seq 1)
    2    0.000014  127.0.0.2              127.0.0.1              ICMP         98  Ping reply (seq 1)
```

Release binary: **916,832 bytes**. Every changed or created Rust file:

```text
 36 src/lib.rs
303 src/store.rs
272 src/explain/ui.rs
 59 src/ui/columns.rs
210 src/ui/details.rs
193 src/ui/events.rs
172 src/ui/layout.rs
112 src/ui/mod.rs
163 src/ui/overlays.rs
166 src/ui/packets.rs
279 src/ui/state.rs
 47 src/ui/widgets.rs
462 tests/ui.rs
341 tests/ui_support/layout.rs
```

The 80×24 golden deliberately selects packet 17 to show its TCP flags:

```text
netmon FILE  75 packets / 75 shown  3.044691 s  17,764 bytes
loopback-mixed.pcapng  filter: all
[1] Packets                                                 ? help  g glossary
┌Packets───────────────────────────────────────────────────────────────────────┐
│No    Time      To                Proto   What is happening                   │
│ 10   1.077     127.0.0.2:55921   DNS     Answer: example.com is 172.66.147.2…│
│ 11   1.292     127.0.0.53:53     DNS     Asks: what is the IPv6 address of e…│
│ 12   1.300     127.0.0.2:48891   DNS     Answer: example.com is 2606:4700:8d…│
│ 13   1.515     127.0.0.53:53     DNS     Asks: what is the IPv4 address of w…│
│ 14   1.577     127.0.0.2:44337   DNS     Answer: www.github.com is 20.207.73…│
│ 15   1.793     127.0.0.53:53     DNS     Asks: what is the IPv4 address of n…│
│ !16  1.793     127.0.0.2:35167   DNS     Answer: nonexistent-netmon-test.inv…│
│>17   2.014     127.0.0.2:18080   TCP     Opens a connection (SYN) — handshak…│
└──────────────────────────────────────────────────────────────────────────────┘
Opens a connection (SYN) — handshake 1 of 3
┌Layers - TCP - Tab switches───────────────────────────────────────────────────┐
│     Acknowledgment number: 0                                                 │
│     Window: 65495                                                            │
│     Checksum: 65073                                                          │
│     Urgent pointer: 0                                                        │
│     Data offset: 40                                                          │
│>  ▸ Flags: 0x0002 [SYN]                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
/ filter   f conversation   c clear   Space pause   Tab pane   q quit
```

**Public interface**

Added methods on `netmon::store::Store`:

```rust
pub fn total_bytes(&self) -> u64
pub fn capture_duration(&self) -> Duration
```

`Duration` is `std::time::Duration`. Totals include dropped and evicted arrivals.

Restricted internal additions:

```rust
pub(crate) fn detail_title(title: &str, single: bool) -> String

pub(super) struct Columns {
    pub(super) cells: [Rect; 7],
    pub(super) compact_time: bool,
}

pub(super) fn new(inner: Rect, number_width: u16, clock_time: bool) -> Self
```

`new` belongs to `Columns`; `Rect` is `ratatui::layout::Rect`.

**Deviations**

- Part A’s baseline tests passed before Part B, but formatting remained failing because `src/explain.rs` is outside ownership.
- UI timestamps truncate correctly and match every fixture packet’s rendered time. They still use a separate helper because the renderer’s helper is private in an unowned file.
- The task’s row and compact-layout requirements supersede PLAN §6 and the UI guide’s stacking/wrapping guidance.

**Needed elsewhere**

- Reorder `mod values;` below `pub mod ui;` in [src/explain.rs](src/explain.rs:14).
- Expose or relocate [render’s relative-time helper](src/render.rs:36), then replace the UI helper with calls to it.

**Not verified**

**No evidence found in this sandbox:** real-terminal rendering, live capture, and terminal restoration during this run.

**Indirect evidence:** TestBackend exercises the screen’s drawing and interaction logic. Logical fallacy check: passing those tests does not establish real-terminal correctness.

**Suggested guide updates**

Update `src/ui/AGENTS.md` to describe single-line packet rows, the fixed sentence strip, and one detail pane below 80 columns **or** 30 rows.

**Questions**

None.