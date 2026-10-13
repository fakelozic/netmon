# Task 10 — repair the merge, then fix what live testing found on the screen

Read the root `AGENTS.md` in full first, then `src/ui/AGENTS.md`, `src/explain/AGENTS.md` and
`tests/AGENTS.md`.

## Where things stand

Six branches have been merged into `main`: the engine, conversations, app lookup, logging, alerts,
the tidy pass, and the packets screen. The last merge left **one compile error**, and a first run of
the real screen in a terminal found usability problems. This task fixes both.

Two other agents are working at the same time, in their own worktrees: one on the pipeline
(`src/pipeline/`, `src/log/`), one on field wording (`src/explain/fields/`, `src/explain/glossary.rs`,
field order in the decoders). You cannot see their work. Do not touch those paths.

**You own:** `src/lib.rs`, everything in `src/ui/` (except its `AGENTS.md`), `src/store.rs`,
`src/explain/ui.rs`, `src/main.rs`, `tests/ui.rs`, everything in `tests/ui_support/`, `tests/cli.rs`,
and the golden files `tests/golden/ui-*`.

## Part A — repair the merge (do this first)

`src/lib.rs` declares `pub mod render;` twice, so nothing compiles. The merge also left the module
doc comments attached to the wrong lines.

- Declare each module once, in the order `cargo fmt` wants.
- Give each `pub mod` line a doc comment that says what the module is for in a useful phrase (not
  "Exposes X"). Include the modules that arrived with the screen: `filter`, `live`, `store`, `sys`, `ui`.
- Update the crate header to name every module and show the data flow.
- Then run all five quality gates. Every existing test must pass before you start Part B.

## Part B — what a real terminal showed

These were seen running `netmon -r tests/fixtures/loopback-mixed.pcapng` and `netmon -i lo` in a real
terminal at 140x40, 120x30 and 80x24. Capture and quitting work: packets arrive live, filters apply,
`q` restores the terminal and stops `dumpcap`. The problems are all in how the screen uses its space.

1. **Every packet takes two lines, even when its sentence fits on one.** A blank line follows each
   row. At 140x40 only 7 packets are visible; at 80x24 only **one**. The packet list is the main
   view and must show many packets.
   - One line per packet, always. No spacer lines, no wrapping inside the list.
   - A sentence too long for its column is cut with `…`.
   - The selected packet's **full** sentence is always readable somewhere fixed: a one-line strip
     directly under the list, or the first line of the Explain pane. Choose one and use it at every size.
   - At narrow widths, keep the sentence on the same row as the packet number by narrowing or
     dropping other columns, in this order: Bytes, then the ports' padding, then Time's precision
     (three decimals), then From. Proto and the sentence are never dropped.
   - Targets: at least **16** packet rows at 140x40, **11** at 100x30, **8** at 80x24.

2. **The detail panes crowd out the list on small terminals.** At 80x24 the screen stacks the list,
   Layers, Explain and Bytes, giving each between one and four lines.
   - The list always gets at least 45% of the rows below the header.
   - In the narrow layout (under 80 columns **or** under 30 rows), show the list plus **one** detail
     pane at a time. `Tab` cycles Layers, Explain, Bytes; the pane's title shows which is on screen
     and that `Tab` switches.

3. **A saved capture opens at the last packet.** Following the newest packet is right for live
   capture. A file should open with packet 1 selected and the list at the top. `End` still jumps to
   the last packet.

4. **The header shows a transfer rate for a file** (`124 B/s`) and a single stray block where the
   sparkline would be. In file mode show the packet count, the capture's duration and its total
   bytes instead, and no sparkline. In live mode keep the rate and sparkline, and draw no sparkline
   until there are at least two samples.

5. **The Time column disagrees with `netmon explain`.** Packet 18 of the fixture shows `2.014516` on
   screen and `2.014515` from `netmon explain`: one rounds, the other truncates. Both must use the
   same function. Truncate, as `explain` does, so the two views always agree.

6. **The help overlay is a full-screen box that is mostly empty.** Size it to its content, centred,
   and the same for the glossary overlay (which should use the freed room to list more entries when
   the search matches several).

Do not change which keys do what, the filter language, or the capture code.

## Tests

- Update the golden files `tests/golden/ui-*` for the new layout. Read each one as a user would
  before blessing it.
- Add assertions, so these cannot regress:
  - visible packet rows meet the targets in item 1 at each of the three sizes
  - no blank row between two packet rows in the list
  - a saved capture starts with packet 1 selected; a live source follows the newest
  - at 80x24 exactly one detail pane is drawn, and `Tab` changes which
  - file mode's header has no `B/s`; live mode's has
  - for every packet of the fixture, the time shown in the list equals the time `render` prints
  - the selected packet's full sentence appears on screen in full at all three sizes, including for
    packet 75, whose sentence is the longest in the fixture
- The existing 20,000-event random test still passes.

## Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
./target/release/netmon --help
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng | head -3
cat tests/golden/ui-packets-80x24.txt
cat tests/golden/ui-packets-140x40.txt
```

The size check must print nothing. In the report, paste the 80x24 golden screen so the result can be
seen at a glance, and say which fixed line you chose for the selected packet's full sentence.
The real terminal cannot be run in the sandbox; it will be tried again by hand after your report.
