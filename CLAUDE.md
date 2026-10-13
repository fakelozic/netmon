# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

netmon is a terminal network monitor in Rust. Its main job is to **explain** network traffic in plain
English so the owner can learn TCP/IP; it is a teaching tool first and a Wireshark-style inspector second.

The build was approved on 2026-10-12 and is being implemented **by Codex**. The folder is a git
repository (branch `main`).

**Lean mode (owner, 2026-10-13): Codex is used to save Claude tokens.** Claude Code does not review,
re-test or screenshot Codex's work, writes short instructions instead of long briefs, does not poll,
reports in two or three lines only when a run finishes or fails, and keeps doc updates to a line.
It commits and merges finished runs. If a check is needed, start a Codex run for it.
Nothing is running.

**Current state (2026-10-13, evening): every task through 14 is merged and nothing is running.**
`netmon web` works end to end on the test capture (page served, API answers). 243 Rust tests and 100
web tests pass. The release binary with the page embedded is about 1.96 MB. `tools/build.sh` builds
the page and then the binary.

Tasks 11 fix-1, 12b, 12c, 13 and 14 were merged **without a review by Claude Code** (lean mode); task
13 was a Codex review of the server side. Not yet checked by anyone: the web page in a real browser
after its layout fix, and `netmon web -i lo` on live traffic.

**What is left:**

1. The owner tries `netmon web` in a browser. What is wrong goes back to Codex as a fix brief.
2. Not approved: the AI question feature (`PLAN.md` section 19) and a Tauri desktop app (section 20,
   only once the web view works).

If a Codex run ends with "Selected model is at capacity", that is a temporary OpenAI error, not the
owner's usage limit: wait a minute and resume the same session. A usage-limit stop is different:
record the state and wait for the owner.

**Published on GitHub, public: `git@github.com:fakelozic/netmon.git`.** `main` there began as one
clean commit on 2026-10-13. The earlier history stays on this machine in the branch `local-history`
and the `task-*` branches. **Never push those**: they hold details of the owner's machine.
Commits use the owner's GitHub noreply address (set in this repository's git config).
Before every push, tracked files must hold no home path, username, real LAN or hardware address,
agent session id, or name of an app seen running here; `HUMAN.md` and `.vscode/` stay untracked.
A newly recorded test capture carries the CPU model and kernel version in its header: run
`python3 tools/strip_capture_metadata.py <file>` on it before committing.

`tools/drive_tui.py` is the review helper that runs the terminal screen in a private tmux server and
prints each step: `python3 tools/drive_tui.py <workdir> <cols> <rows> file|live`.

**The owner changed direction on 2026-10-13: the new views go into a local web page, not the terminal
screen.** After trying the terminal screen they said a GUI would be much better, chose a local web
page built with **Vite + React + TypeScript + Tailwind + shadcn/ui, React Compiler, package manager
`nub`**, and said to keep the terminal screen as it is. They also said it is an experiment they intend
to rebuild themselves later, so keep planning light and build.

### This machine has 16 GB of RAM and is the owner's desktop

On 2026-10-13 a scaffolding command (`nub dlx create-vite`) spawned processes without end and pushed
RAM to 96%. Since then:

- Every Codex run and every command that fetches or builds something unfamiliar runs inside
  `systemd-run --user --scope --quiet -p MemoryMax=3G -p MemorySwapMax=0 -p TasksMax=512 -- …`.
- At most three Codex agents at once, each capped at 2.5 GB, with `CARGO_BUILD_JOBS=4`. Check
  `free -h` first: the owner's VS Code and rust-analyzer use about 5 GB when open.
- Never run `nub dlx`. If a command hangs, do not rerun it uncapped; find out why.
- Measured: compiling and testing netmon peaks at about 1.2 GB, so the Rust side is not the risk.

The owner has asked about the worktree folders beside the project. The four finished ones
(`02-conversations`, `04a-apps`, `05a-logging-core`, `06a-alerts`) are merged and safe to remove, but
**the owner has not said to delete them; ask before removing any.** Put future worktrees somewhere
that does not clutter `learn-claude/`.

If Codex hits its usage limit again, the runs stop with "You've hit your usage limit ... try again at
<time>". Record the state in `PLAN.md` section 12 and **wait for the owner to say resume**; they
chose to restart it themselves rather than have it restart on a timer.

`PLAN.md` is the source of truth for scope, design and build order.

- Section 12 of `PLAN.md` tracks which task is done; section 16 explains the Codex workflow.
- `AGENTS.md` holds Codex's standing rules; `tasks/NN-name.md` is the exact brief for each task and
  `tasks/NN-name.report.md` is Codex's report on it.
- **Codex does every build task** (owner's rule, 2026-10-12: "don't do any task, let codex do it").
  Claude Code writes no netmon code, including fixes. A problem found in review goes back to Codex as
  a fix brief (`tasks/NN-name.fix-N.md`), not a direct edit.
- Claude Code's role: write each brief, record test captures, launch Codex, then review the code,
  re-run the tests and verify what Codex cannot (live capture, the screens), and report.
- The owner chose to **run all six tasks without pausing**: after each task, check it, send problems
  back to Codex, write the next brief and start Codex again. Stop when the owner says "stop".
- **Parallel agents, as many as useful** (owner, 2026-10-12: "use as much agents you want from codex
  and build it use fast mode"; fast mode was later turned off, see below). Each agent gets its own git worktree at
  `../netmon-<brief>` on branch `task-<brief>`, started with `codex exec -C`-style runs from inside
  that worktree. Rounds and their state: `PLAN.md` section 12. Procedure: section 16.
- **Git** is initialised (`main`); the owner asked for it to track the work. One commit per task. Codex
  makes no git changes; Claude Code commits after review. Merge conflicts and the wiring between
  branches go to a Codex integration run, not hand edits. `.vscode/` is the owner's and is left untracked.
- **Agent guides:** the owner asked for `AGENTS.md` files to manage each area. Root `AGENTS.md` plus
  `src/decode`, `src/explain`, `src/ui` and `tests`. Codex may not edit them; it proposes changes under
  "Suggested guide updates" in its report, and Claude Code applies the good ones.
- **Modular, commented code** (owner, 2026-10-12): no Rust file over 500 lines, split by
  responsibility, and useful comments (file headers, doc comments on public items, why-comments).
  The rules are in the root `AGENTS.md`. When reviewing a branch, check both before committing: run
  `find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'` and read
  the new files for comment quality. Send misses back to Codex as a fix brief. Background, the
  measured state and the three-step rollout: `PLAN.md` section 16, "Code quality rule".
- When resuming the paused round 1 agents, use the resume prompt in `PLAN.md` section 12; it tells
  them to re-read `AGENTS.md` and apply the new rules. The finished logging branch gets
  `tasks/05a-logging-core.fix-1.md` as a new run.
- Round 1 logs are in the session scratchpad as `codex-<brief>.log`; each agent's report lands in its
  worktree at `tasks/<brief>.report.md`.
- When a decision changes, update `PLAN.md`. The owner wants it kept in full detail, not condensed.
- Everything below marked "planned" comes from `PLAN.md` and may not exist yet. Replace it with what
  actually exists as tasks land.

### Running Codex on a task

```sh
systemd-run --user --scope --quiet -p MemoryMax=3G -p MemorySwapMax=0 -p TasksMax=512 -- \
  env CARGO_BUILD_JOBS=4 \
  codex exec --skip-git-repo-check -s workspace-write -c sandbox_workspace_write.network_access=false \
  -m gpt-6.1-sol -c model_reasoning_effort="xhigh" \
  -o tasks/NN-name.report.md "Read AGENTS.md, PLAN.md and tasks/NN-name.md in full, then carry out tasks/NN-name.md exactly."
```

Run it from inside the task's worktree, in the background. To continue a stopped run, use
`codex exec resume … <session id> "<prompt>"` with the same wrapper (`resume` takes `-c sandbox_mode='"workspace-write"'`
instead of `-s`).

### The web project (`web/`)

Vite 8, React 19 with React Compiler, TypeScript, Tailwind 4, shadcn/ui, Vitest. Rules: `web/AGENTS.md`.
Contract with the server: `docs/web-api.md`.

```sh
cd web && nub install      # after creating a worktree: node_modules is not shared
nub run build              # type-check and bundle into web/dist
nub exec vitest run        # tests
nub run dev                # dev server with hot reload (the owner's use; agents must not start it)
```

- Codex's sandbox has no network and cannot open sockets, so it cannot install packages, run the dev
  server or open the page. Install packages before launching it; check the page yourself afterwards,
  for example with headless Firefox screenshots.
- The shadcn tool calls `npm`, which fails in a `nub`-installed project. Components were generated in
  a throwaway npm copy and copied in. To add more, do the same, then `nub add` what they import.

The owner wants Codex kept on `gpt-6.1-sol` at `xhigh`. **Fast mode is off**: the owner turned it on
for round 1 and then said "turn off fast mode" on 2026-10-12, so do not pass `-c service_tier="fast"`
unless the owner asks for it again. `.codex/config.toml` records the model and effort, but Codex only
applies a project config in a folder it trusts, and a probe on 2026-10-12 showed an untrusted folder's
project config being ignored. Always pass the settings explicitly as above.

The sandbox has no network and cannot run `dumpcap`. Dependencies are already in the cargo cache, so
`cargo build --offline` works inside it. Fixtures in `tests/fixtures/` hold only synthetic loopback
traffic; keep it that way, since Codex sends what it reads to an outside service.

## Commands

The Rust toolchain comes from mise (`mise.toml` pins `rust = "latest"`, currently 1.99.0). mise shims are
on `PATH`, so call `cargo` directly.

Working on `main` today:

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline                                     # all tests (116 on main, 2026-10-13)
cargo test --offline --test tshark_crosscheck            # one integration test file
cargo test --offline <name>                              # one test by name
NETMON_BLESS=1 cargo test --offline                      # rewrite tests/golden after reading the diff
cargo build --release --offline && ls -l target/release/netmon   # size is tracked; 544,856 bytes now
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'   # must print nothing
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng             # one line per packet
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng --packet 18 # one packet in full
./target/release/netmon glossary
dumpcap -i lo -c 30 -w - -q | ./target/release/netmon explain -   # live; confirmed working 2026-10-12
cargo run --offline --example flows -- tests/fixtures/loopback-mixed.pcapng --stories   # conversations
cargo run --offline --example alerts -- <capture>        # alerts raised by a capture
cargo run --offline --example procs                      # which program owns each socket, from /proc
```

The live screen is on `main` since 2026-10-13:

```sh
./target/release/netmon                      # live on the default interface (needs a real terminal)
./target/release/netmon -i lo                # live on a chosen interface
./target/release/netmon -r tests/fixtures/loopback-mixed.pcapng   # a saved capture
./target/release/netmon interfaces           # list interfaces
```

On `main`: the engine, the Packets screen with live capture, the filter language, and as libraries
with example programs: conversations (`src/flow/`, `src/names.rs`), app lookup (`src/procs/`), logging
(`src/log/`) and alerts (`src/alerts/`). The screen does not use those four yet: no app names,
hostnames, context-aware sentences, Connections tab, Alerts tab or logging.

Also on `main`: the pipeline that joins those modules (`src/pipeline/`) and `netmon web`, which uses
it. How to run everything: `README.md`.

To look at the screen without a terminal of your own, use `tools/drive_tui.py` (see above); it uses a
private tmux server (`tmux -L netmon-test`), so it never touches the owner's own tmux sessions.

## Architecture (planned)

Data flows one way: **dumpcap child → pcapng stream → decoders → state → screen and logs**.

- **Capture** spawns `dumpcap -i <iface> -w - -q` and parses its stdout. netmon itself holds no
  privileges. Saved files go through the same parser, which is what makes offline tests possible.
- **Decoders are hand-written** and return a `Layer`/`Field` tree in which every field carries its byte
  range in the packet. The UI uses that range to highlight the field's bytes in the hex pane, which is
  why a parsing crate is not used. A new decoder must fill in byte ranges and an explanation key.
- **`src/explain/` holds all plain-English text**: the per-packet sentence (`sentence/`), the per-field
  "what it is / in this packet / why it matters" text (`fields/`), the glossary, and the wording for
  conversations, alerts and logs. `src/explain.rs` is only the module root. Decoders produce values;
  wording belongs here. Layout of each area: the `AGENTS.md` in that folder.
- **One thread owns all state.** A capture thread and a process-lookup thread feed the main loop over
  channels; the main loop drains them within a time budget, updates state, draws, and handles input.
  No locks. Headless mode is the same loop without drawing.
- Packets sit in a ring buffer with a compact summary computed on arrival; the full field tree is
  decoded only for the selected packet.
- App names come from `/proc/net/*` plus `/proc/<pid>/fd`; hostnames are learned passively from DNS
  answers, TLS server names and HTTP Host headers. No lookups are sent.

## Constraints

- **Small is a requirement.** Planned dependencies are `ratatui` (defaults off, `crossterm` only),
  `pcap-file`, `lexopt` and `libc`. No tokio, clap, serde or chrono. Ask before adding a dependency.
- `libpcap-devel` is not installed; do not add crates that link libpcap.
- Use stable crate versions: `pcap-file` 2.0 (3.0 is a release candidate), `libc` 0.2 (1.0 is an alpha).
- Explanations are the product. A feature that shows data without explaining it is unfinished.
- Passwords seen in cleartext protocols must never be written to logs.

## Verifying changes on this machine

- Live capture needs no sudo: the user is in the `wireshark` group and `/usr/bin/dumpcap` carries
  `cap_net_admin,cap_net_raw`. Never use sudo for capture. `tcpdump` has no capabilities here.
- `dumpcap` writes to a pipe packet by packet (tested), so a live display from its stdout works.
- Cross-check decoder output against `tshark` (installed, 4.6.9), for example
  `tshark -r <file> -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol`.
- To see the TUI, run it in a detached tmux session, drive it with `tmux send-keys`, and read the screen
  with `tmux capture-pane -p`. Check both a wide size (140x40) and 80x24.
- Record fixtures with `dumpcap -c <n> -w tests/fixtures/<name>.pcapng` while generating traffic.

## Working with the owner

The owner is learning both networking and Claude Code. Explain protocol concepts in plain English when
discussing changes, and talk through design decisions before building rather than building first.
