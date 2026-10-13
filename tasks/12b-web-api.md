# Task 12b — the web interface's data: the API and the `netmon web` command

Read the root `AGENTS.md` in full, then `docs/web-api.md` (the contract), and the reports
`tasks/12a-web-server-core.report.md`, `tasks/08-pipeline.report.md` and `tasks/03-packets-screen.report.md`
for the interfaces you build on.

## Goal

`netmon web` captures (or reads a file), runs every packet through the pipeline, and answers the
page's requests exactly as `docs/web-api.md` describes. After this task a person can run one command
and use netmon in a browser.

## What exists

- `src/web/`: the HTTP server, the token and safety rules, the page's embedded files, and the `Api`
  trait. You implement that trait.
- `src/pipeline/`: `Pipeline::push` turns a packet into a `Row` and keeps conversations, names, apps,
  alerts and logs up to date.
- `src/live/`: capture through `dumpcap` or from a file, delivered over a channel.
- `src/filter.rs`, `src/decode/`, `src/explain/`, `src/flow/`, `src/alerts/`, `src/log/`, `src/sys.rs`.

The web page is being built by another agent in `web/`. Do not touch `web/`.

**You own:** new files under `src/web/` for the API (for example `src/web/api/`), a new `src/session/`
module if you need one for the engine thread, `src/main.rs`, `src/explain/web.rs`, `tests/web_api.rs`
and `tests/web_api/`, and, for section 5 only, the files it names.

## 1. The engine thread

One thread owns the capture source, the `Pipeline`, a bounded store of rows and raw packets, and the
current control state. HTTP threads never touch that state: each API call is a message to the engine
thread with a reply channel.

- The store keeps at most 200,000 packets and 256 MB of packet bytes (`--max-packets` changes the
  first), oldest dropped first, like the terminal screen's store. Reuse `src/store.rs` if it fits;
  say in the report if it had to change.
- A request that the engine does not answer within 2 seconds gets `503` with a plain sentence.
- The engine keeps draining the capture channel while it serves requests; a slow browser must never
  make it fall behind on packets. Give each loop turn a time budget.
- `pause` stops the page seeing new packets but capture, the pipeline and logging continue; `resume`
  shows everything that arrived meanwhile.

## 2. Endpoints

Implement every endpoint in `docs/web-api.md`, field for field. Details the contract leaves to you:

- **`app` is looked up when the reply is built**, from the conversation (`Pipeline::app_of`), not
  copied from the row. An app that is identified a moment after a conversation starts then appears on
  that conversation's earlier rows too.
- **`dir`**: `out` when the source is one of this computer's addresses and the destination is not;
  `in` for the reverse; otherwise `null`.
- **`clock`**: local time from `sys::local_time`.
- **`/api/packet/N`**: decode the stored bytes with `Detail::Full`; `label`, `what`, `here`, `why` from
  `explain::field_text`; `about` for a layer from the glossary entry for that protocol, or an empty string.
- **`filter`**: `filter::parse` then `Filter::matches` with the row's labels, app and problem flag.
  A parse error fills `filter_error` and returns no rows; it is not an HTTP error.
- **Paging** must stay fast with 200,000 packets and a filter: do not scan the whole store on every
  poll. Remember, per filter text, how far you have matched (a small bounded cache is enough).
- **`export_story`** writes `story-<id>.md` through `Session::export_markdown` and returns its path;
  with logging off it returns `400` saying logging is off.
- Unknown paths under `/api/` are `404`; bad numbers and unknown query values are `400`; every error
  body is `{"error": "…"}` with wording from `src/explain/web.rs`.

JSON needs arrays and nested objects. Extend the small writer in `src/log/json.rs` (it is yours for
this purpose) or move it to a shared module; do not write a second one.

## 3. The command (`src/main.rs`)

```
netmon web [-i IFACE | -r FILE] [-f CAPTURE_FILTER] [--port N] [--no-open] [--log-dir DIR] [--record] [--no-log] [--max-packets N]
```

- Starts capture and the engine, binds the server, prints `netmon web: open <url>` on one line, and
  opens the URL with `xdg-open` unless `--no-open` (spawned detached; a failure to open is a note, not
  an error).
- `Ctrl-C` stops capture, ends every conversation into the logs, flushes, and exits with status 0.
  No `dumpcap` may be left running.
- Logging is on by default in `log::default_base()`. `--no-log` turns it off. `--record` starts with
  raw recording on.
- If `web/dist` was not built into the binary, print one line saying the page is a placeholder and how
  to build it; still serve the API.
- Update `--help`. `netmon` with no arguments still starts the terminal screen.

## 4. Tests

No sockets and no real capture inside the sandbox: drive the `Api` implementation directly, with a
file source reading `tests/fixtures/loopback-mixed.pcapng`.

1. `session`: counts match the fixture (75 packets, 12 conversations); `state` becomes `ended`.
2. `packets`: default page; `after` and `before`; `limit` bounds; `filter=dns` gives 8 rows;
   `filter=port` gives a `filter_error` with a position; each row has every field in the contract.
3. `packet/18`: layers in order; every field has label, value and a range inside the packet; ranges of
   children lie inside the packet; `hex` length is twice `captured_len`; `packet/9999` is `404`.
4. `flows` and `flow/ID`: 12 conversations; the TLS one has `remote_name` `netmon.test` and a story
   whose steps are in order with the right `dir`; sorting works.
5. `alerts`: empty for the fixture; one alert after a built 25-port scan is pushed.
6. `glossary`: non-empty, sorted.
7. `control`: pause hides new packets and resume shows them; `record_start` changes `recording`;
   `export_story` writes a `.md` file inside the session folder; unknown action is `400`.
8. Every reply is valid JSON (check with the JSON reader in `tests/log_support/`), with no key missing
   that the contract names.
9. Hostile text: a conversation whose server name and a DNS name contain `"`, `\`, a newline and
   `<script>` produce valid JSON with those characters escaped.
10. Robustness: 5,000 fixed-seed random API paths and queries never panic.
11. `tests/web/sockets.rs`-style end-to-end test over a real socket, skipped with a notice when the
    sandbox denies sockets: start the whole thing on the fixture, fetch `/api/session` and
    `/api/packets` with the token.

## 5. Small fixes to include

These were found while reviewing earlier tasks. Each is small; do them all.

1. **Three `ui` tests fail on `main`** because the field explanations changed after the screen tests
   were written: `screen_goldens`, `movement_pages_focus_expansion_pause_and_time` (`tests/ui.rs:132`)
   and `layout_tests::reference_overlays_fit_content_and_center` (`tests/ui_support/layout.rs:325`).
   Regenerate the `tests/golden/ui-*` files after reading them, and rewrite the two assertions so they
   do not depend on the exact order of fields or the number of glossary entries.
2. **Identifiers are printed with thousands separators** in field text ("Port 51,008", sequence and
   acknowledgment numbers). Ports, sequence numbers and identifiers are never grouped; byte counts
   still are. Fix in `src/explain/fields/` and regenerate `tests/golden/packet-*.txt`.
3. The HTTP `DELETE` explanation says "remove the target's association with its contents". Say that
   the client asks the server to delete the target.
4. **App lookup gives up too soon** (`src/pipeline/processes.rs`): it stops after five packets, and a
   connection's first five packets arrive within milliseconds, before a `/proc` scan can finish. Keep
   asking for 3 seconds of packet time after a conversation starts, at most once per 200 ms.
5. `summary.md`: omit the "0 more finished conversations" line when there are none; for a DNS answer
   that goes through a CNAME show the address and "via <name>", as the packet sentence does; write
   microseconds as `µs`, as everywhere else; an ICMP or UDP exchange that simply stopped is
   "finished", not "still open when the capture ended".
6. At 80 columns the terminal screen drops the From column and shows only To, which hides who sent a
   packet. Show both in one compact column (`from → to`) at that width instead.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples build.rs -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
./target/release/netmon --help
```

Every test must pass, including the three that fail today. The size check prints nothing.
The real thing (`netmon web -i lo`, then a browser) cannot run in the sandbox and will be tried by
hand after your report. In the report, list what you could not exercise.
