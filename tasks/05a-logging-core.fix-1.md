# Fix 1 for task 05a — make the logging code modular and commented

Read the root `AGENTS.md` again first. It has two new sections since you finished this task:
**Comments** and **Modular code: file size and structure**, and a fifth quality gate. This fix brings
the logging work in line with them. **Behaviour must not change.**

## What is wrong now

| File | Lines | Limit |
|---|---|---|
| `src/log.rs` | 602 | 500 |
| `tests/log.rs` | 693 | 500 |

Comments are too thin: `src/log.rs` has 13 comment lines in 602, `tests/log.rs` has 2 in 693, and
`src/explain/log.rs` and `examples/logdemo.rs` have none beyond one line.

## What to do

1. **Split `src/log.rs` into a folder module `src/log/`** by responsibility. A sensible split:
   `mod.rs` (the public types, re-exports and the file header), `json.rs` (the JSON writer),
   `clock.rs` (`Clock`, `ClockFn`, `utc_clock`), `session.rs` (the session folder and the text logs),
   `record.rs` (pcapng recording and rotation). Choose differently if the code suggests a cleaner cut,
   and say why in the report.
2. **Keep every public path working.** `netmon::log::Json`, `netmon::log::Session`,
   `netmon::log::utc_clock` and the rest must still resolve, through `pub use` in `mod.rs`.
3. **Split `tests/log.rs`** into focused files, for example `tests/log_json.rs`,
   `tests/log_session.rs`, `tests/log_record.rs`. Every existing test must still exist and pass.
4. **Add the comments `AGENTS.md` now requires**: a header on every file you own; a doc comment on
   every public item, including what each `Recording` state means and when it changes; and a "why"
   comment at each non-obvious decision. At least these need one:
   - why interface blocks declare nanosecond resolution (`if_tsresol` 9)
   - why folders are `0700` and files `0600`
   - why a line containing a newline is refused
   - why the first write error is kept and later writes become no-ops
   - why `export_text` reduces the stem to a small set of characters
5. Remove anything `AGENTS.md` now forbids: narration comments, dead code, unused public items.

## You own

`src/log.rs` (to be replaced by `src/log/`), `src/explain/log.rs`, `examples/logdemo.rs`,
`tests/log.rs` (to be replaced by the split files), `tests/log_support/mod.rs`.

Shared: nothing. `src/lib.rs` already has `pub mod log;` and needs no change.

## Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
cargo run --offline --example logdemo -- tests/fixtures/loopback-mixed.pcapng target/logdemo-fix
head -3 target/logdemo-fix/*/packets.jsonl
```

Expected: the test count is the same as before (48), the size check lists only the five files named
in `AGENTS.md`, and the demo output is the same as in your first report apart from the folder name.
In the report, give the line count of every file you created or changed.
