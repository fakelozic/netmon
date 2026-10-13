# AGENTS.md

Standing rules for any coding agent implementing netmon. Task briefs live in `tasks/`; each brief says
exactly what to build. These rules apply to every task.

## What this project is

netmon is a terminal network monitor in Rust whose main job is to **explain** network traffic in plain
English, so its owner can learn TCP/IP by watching real packets. `PLAN.md` is the full design. Read it
before starting a task. If a task brief and `PLAN.md` disagree, the task brief wins; say so in your report.

## Area guides

Some folders have their own `AGENTS.md` with rules for that area. **Before changing or adding files in
a folder, read the `AGENTS.md` in it.** Where an area guide and this file differ, the area guide wins
for files in that folder.

| Area | Guide | What lives there |
|---|---|---|
| Decoders | `src/decode/AGENTS.md` | One file per protocol; turns bytes into layers, fields and a summary |
| Wording | `src/explain/AGENTS.md` | Every sentence a user reads; also covers `src/explain.rs` |
| Screens | `src/ui/AGENTS.md` | The terminal interface |
| Tests | `tests/AGENTS.md` | Fixtures, golden files, test helpers |

Areas without their own guide, which follow this file only:

| Path | Purpose |
|---|---|
| `src/capture.rs` | Reads pcap and pcapng files and streams into `RawPacket` |
| `src/text.rs` | Sanitising packet text, formatting, hex dump |
| `src/render.rs` | Plain-text output for `netmon explain` |
| `src/flow/`, `src/names.rs` | Conversation tracking and learned hostnames |
| `src/procs/` | Which program owns a connection, read from `/proc` |
| `src/alerts/` | Alert rules, one module per rule |
| `src/log/` | Session folder, Markdown and JSON-lines logs, recording |
| `src/pipeline/` | The one value that feeds each packet through the modules above |
| `src/live.rs`, `src/store.rs`, `src/filter.rs` | Live capture through `dumpcap`, the packet buffer, the filter language |
| `src/main.rs` | Command line; thin, calls the library |

Each folder module's `mod.rs` starts with a header that says what its submodules do. Read it first.

## How to work

1. Read `PLAN.md`, this file, the area guides for the folders you will touch, and the one task brief
   you were given, in full.
2. Build exactly what the brief asks. Do not start later tasks or leave placeholder files for them.
3. Run every acceptance command in the brief and fix what fails.
4. End with the report described at the bottom of this file.

If something in the brief is impossible or wrong, do the closest correct thing, and state the deviation
and the reason in your report. Do not deviate silently.

## Working in parallel

Several agents may be working at the same time, each in its own git worktree on its own branch. You
cannot see their work and they cannot see yours.

- Your brief lists the files you **own**. Create and change those freely.
- Your brief may list **shared files** and exactly what you may do in each. Do nothing else to them.
- Do not change any other file. If you believe another file must change, do not change it; describe
  the change under "Needed elsewhere" in your report.
- Do not rename, move or reformat files you do not own.
- Keep the public names you were told to provide exactly as written. Other agents are coding against them.

## Hard rules

- **Dependencies are fixed.** Do not add, remove, upgrade or change features of anything in
  `[dependencies]`, and do not change `[profile.release]`. The sandbox has no network; always pass
  `--offline` to cargo. If you believe a dependency change is needed, stop and say so in the report.
- **No live capture, no sudo, no tmux, no network.** `dumpcap` does not work inside the sandbox. All
  testing uses the capture files in `tests/fixtures/` and byte arrays built in tests.
- **Do not edit** `PLAN.md`, `CLAUDE.md`, any `AGENTS.md`, `mise.toml`, anything in `tasks/`, `.codex/`,
  `.claude/`, or the existing files in `tests/fixtures/`. If a guide is wrong or out of date, say so
  under "Suggested guide updates" in your report.
- **Stay inside this folder.** Do not read or write elsewhere, except reading the Rust toolchain and the
  cargo registry sources.
- **Git:** this is a git repository. Do not commit, branch, merge, stash, reset, check out, or change
  git state in any way. Read-only commands such as `git status` and `git diff` are fine. Your work is
  reviewed and committed for you.

## Code rules

- **Packet bytes are untrusted input.** Decoding must never panic, whatever the bytes are.
  - No indexing or slicing packet data without a bounds check (`get`, `split_at_checked`, or a small
    cursor type that returns `Option`).
  - No `unwrap`, `expect` or unchecked arithmetic on values that come from a packet. Lengths and offsets
    from packets use checked or saturating arithmetic.
  - A header that is cut short produces a partial decode marked as truncated, never an error or a panic.
  - Every loop driven by packet contents (options, extension headers, DNS name pointers, TLS extensions)
    must have a hard bound and must make progress on every iteration.
- **Anything that grows with traffic must be bounded.** Tables keyed by address, port, name or
  connection have a maximum size and an eviction rule. A hostile or busy network must not be able to
  make netmon use unbounded memory.
- **Time comes from packets.** Timeouts and rates use packet timestamps, not the wall clock, so that
  reading a saved file behaves the same as watching live.
- **Sanitise text that comes from outside** before it can reach a terminal, a file or a test snapshot:
  DNS names, HTTP headers, TLS server names, DHCP hostnames, process names, anything. One shared
  function does this (`text::sanitise`); bytes outside printable ASCII become `\xNN`. Nothing from the
  network or from `/proc` may be able to inject terminal escape codes.
- **Secrets never reach a screen or a log.** Passwords, cookies and authorization values are shown as
  hidden. Alerts and logs say that a secret was seen, never what it was.
- **Files a person reads are Markdown; files a program reads are not.** Summaries, timelines and
  exported stories are `.md`. JSON lines and packet captures keep their formats. Every value written
  into a Markdown file that is not fixed wording is sanitised and then escaped with the shared helper
  in `src/log/markdown.rs`, because a Markdown viewer renders HTML and follows links and images.
- **No `unsafe`** unless a task brief explicitly allows it, and then only in the file it names.
- **All user-facing explanatory wording lives under `src/explain`** (see its guide).
- **The owner reads this code to learn networking.** Every decoder file starts with a comment that names
  the RFC and draws the header layout as an RFC-style ASCII diagram. Prefer plain, direct code over
  clever code. Name things after the terms the RFCs use.
- No async runtime. Standard library threads and channels only, and only when a brief calls for them.
- Tests are deterministic: no network, no clock-dependent assertions, no random seeds from the system.

## Comments

Comments here have two readers: the next agent, who must change this code without breaking it, and
the owner, who reads it to learn networking. Write for both. A comment earns its place by saying
something the code cannot.

**Required**

1. **A header on every source file** (`//!`), three to ten lines: what this file is responsible for,
   what it deliberately leaves to another file (and which one), and which type or function to read
   first. Decoder files also keep their RFC number and header diagram.
2. **A doc comment (`///`) on every public struct, enum, trait, function and constant.** Say what it
   represents or does, and whatever a caller cannot see from the signature:
   - units and bases (bytes or bits; offsets from the start of the packet or of the header; time since
     the Unix epoch or since the first packet)
   - what `None`, zero or an empty list means
   - what the caller may rely on, and what it must do first
   - what happens at the edges: truncated input, a full table, a wrapped sequence number
3. **Doc comments on public fields and enum variants whose meaning is not obvious from the name.** A long
   list of plain names (such as `FieldKey`) needs one comment on the enum that explains the naming
   pattern, not one per variant.
4. **A "why" comment at every decision a reader might undo by mistake:**
   - a protocol rule: say the rule and cite the RFC section
   - a limit or constant: say why that number
   - an ordering that matters: say what breaks if it changes
   - a workaround for a library quirk: name the quirk
5. **One sentence of networking background where a concept first appears in a file**, in plain words.
   Example: `// A SYN and a FIN each use up one sequence number even though they carry no data (RFC 9293, 3.4).`

**Forbidden**

- Comments that repeat the code (`// increment the counter`).
- Commented-out code.
- History and narration: "added for task 03", "new", "fixed", "as requested". Git records history.
- `TODO` and `FIXME`. Finish it, or list it under "Needed elsewhere" in your report.
- A comment left untrue. When you change code, change its comment in the same edit.

Write comments in the plain style of `src/explain/AGENTS.md`. Aim for comments a careful reader is
glad to find: a file with no comments below its header is almost always under-explained, and a
comment on every line is noise.

## Modular code: file size and structure

The owner's rule: keep the code modular; no file may turn into thousands of lines. Small files with
one job each are also what lets an agent read a whole file and change it safely.

- **Modules have a small public surface.** Make an item `pub` only when another module uses it.
  Everything else is private, `pub(super)` or `pub(crate)`. A reader should be able to learn how to
  use a module from its `mod.rs` alone.
- **Dependencies point one way.** `capture` and `text` are at the bottom. `decode` and `explain` sit
  above them and depend on each other by design (decoders ask `explain` for wording; `explain` reads
  decoded values). `flow`, `names`, `procs`, `alerts`, `log`, `filter` and `store` use those and do
  not use each other unless a brief says so. `ui` and `main` are on top. Nothing lower imports
  something higher.
- **No global mutable state.** State belongs to one value that its owner passes around.
- **No Rust file over 500 lines.** This covers `src/`, `tests/` and `examples/`. Golden files and
  fixtures are exempt.
- **Split by responsibility, not by line count.** When a file would pass the limit, turn it into a
  folder module: `mod.rs` holds the public types and re-exports, and each submodule does one job.
  For example `src/flow.rs` becomes `src/flow/mod.rs` with `tcp.rs`, `story.rs` and `table.rs`.
- **Keep public paths stable when you split.** Re-export with `pub use` so `crate::flow::Tracker` still
  works. Other agents are coding against those paths.
- **No function over 80 lines**, except a flat lookup `match` or table with no logic in its arms.
- **One job per file.** If the file header needs the word "and" to describe it, split it.
- **No copy-paste.** A helper needed twice lives in one place and is called from both.
- **Nothing speculative.** No unused public items, no dead code, no options "for later".
- **Tests follow the same limit.** Prefer several focused test files to one long one, and
  table-driven cases to repeated blocks.

Every Rust file in the repository meets this limit today. Keep it that way: there are no exemptions.

## Quality gates (every task)

All five must pass before you finish:

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
```

The last command lists every Rust file over 500 lines. It must list nothing.

Do not silence a clippy lint with `#[allow]` unless you explain why in a comment beside it.

## Final report

Your last message must contain, in this order:

1. **Built** — what now exists, in a few lines.
2. **Acceptance results** — each acceptance command from the brief with its real outcome (pass or fail,
   plus the last lines of output). Include the release binary size in bytes, and the line count of
   every Rust file you created or changed.
3. **Public interface** — the exact public types and function signatures you added, so the agent that
   joins the branches can wire them together without reading every file.
4. **Deviations** — every place you departed from the brief or `PLAN.md`, and why. Write "None" if none.
5. **Needed elsewhere** — changes you believe are needed in files you do not own.
6. **Not verified** — anything you could not check inside the sandbox.
7. **Suggested guide updates** — corrections or additions for any `AGENTS.md`.
8. **Questions** — anything the next task needs decided.

Report failures plainly. A failing test reported honestly is better than a passing claim that is not true.
