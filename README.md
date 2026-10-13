# netmon

netmon explains network packets in plain English. Select a packet to see its
protocol headers, field explanations and exact bytes. The terminal shows packets;
the local web interface also tracks conversations, program names and alerts.
It reads saved `.pcap` and `.pcapng` files or watches live traffic through `dumpcap`.
It cannot read encrypted application contents.

## Requirements

- Linux and Rust with Cargo to build the program.
- `dumpcap` from Wireshark for live capture. Configure its capture permissions and
  add your user to the `wireshark` group. netmon itself runs as your ordinary user.
  Saved files do not need `dumpcap`.
- `nub` to install and build the web page, plus a browser to view it.
  `xdg-open` opens the browser automatically when available.

## Build

From the repository root:

```sh
sh tools/build.sh
```

This installs the page's dependencies, builds the page, then builds Rust with four
parallel jobs. It prints the binary's path and size. Cargo builds offline, so its
dependencies must already be cached. The page installation needs network access
unless its dependencies are cached.

For the terminal and text commands alone:

```sh
cargo build --release --offline --jobs 4
```

The binary is `target/release/netmon`. Rust embeds `web/dist` at build time;
without a built page, `netmon web` serves a placeholder. Rebuild Rust after building
or changing the page. The examples below assume the binary is on your `PATH`;
otherwise use `./target/release/netmon`.

## Run

```sh
netmon                          # live terminal view; chooses an interface
netmon interfaces               # list capture interfaces
netmon -i lo -f 'port 53'        # live view with a capture filter
netmon -r capture.pcapng         # saved capture in the terminal
netmon web                      # live session in a local browser
netmon web -r capture.pcapng     # saved capture in the browser
netmon web --no-open --no-log    # print the URL; create no logs
netmon explain capture.pcapng    # print one explanation per packet
netmon explain capture.pcapng --packet 18  # one packet's fields and explanations
netmon explain capture.pcapng --tsv        # tab-separated rows
netmon explain -                # read a capture from standard input
netmon glossary                 # print the networking glossary
netmon glossary TCP             # search glossary term names
netmon --help
```

The terminal modes need a terminal. Use `?` for help, `/` to filter, `g` for the
glossary and `q` to quit. `--max-packets N` limits retained packets (1–200,000).
Ctrl-C (SIGINT) or SIGTERM stops a web session and flushes its logs, including
with redirected stdin. A saved web session stays open after the file ends.

## Logs

`netmon web` logs by default. Each session gets a private folder beneath
`$XDG_STATE_HOME/netmon`, or `~/.local/state/netmon` when that variable is unset or
empty. Use `netmon web --log-dir DIR` to change the parent folder, or `--no-log` to
disable file creation. The terminal and `explain` commands do not create sessions.

| File | Contents |
| --- | --- |
| `summary.md` | Totals, conversations, DNS lookups, problems and alerts; start here |
| `events.md` | Readable timeline of connections, lookups and alerts |
| `flows.jsonl` | One JSON record per finished conversation |
| `alerts.jsonl` | One JSON record per alert |
| `story-N.md` | A conversation's story, created on export |
| `capture.pcapng` | Original captured bytes, enabled by `--record` or a web control |

Event and JSON files appear when needed. Raw recording is off by default, capped
at 200,000,000 bytes per file, and uses numbered files when restarted. Raw captures
retain original contents, including any secrets; open them in Wireshark with care.
Session folders use mode `0700` and files `0600` (owner access only).

## Web safety

The server listens only on `127.0.0.1`, starting at port 7979 and trying through
7999 if needed (`--port N` changes the starting port). Use the printed URL and keep
its random session token private. Every API request needs that token; the server
checks Host and Origin and sends no CORS access headers. Browser security headers
restrict scripts and connections to this server. Outside text is sanitised;
HTTP credential and cookie headers, explicitly named password/token/API-key
headers, and targets containing queries or userinfo
are masked in decoded fields. HTTP bodies and unparsed TCP payloads are also
hidden because they may contain split credentials. These ranges are zeroed in
the API hex view and text dumps, masked on the terminal screen, and listed in
`hidden`. Recognised encrypted TLS bytes remain visible.
See [the API contract](docs/web-api.md) for endpoints and controls.

## Source map

| Path | Responsibility |
| --- | --- |
| `src/main.rs`, `src/lib.rs` | Command dispatch and library entry points |
| `src/capture.rs`, `src/live/` | Saved capture readers and `dumpcap` supervision |
| `src/decode/` | Checked protocol parsers with byte ranges |
| `src/explain/`, `src/explain.rs` | Packet sentences, field explanations and glossary |
| `src/flow/`, `src/names.rs` | Conversation tracking and passively learned names |
| `src/procs/` | Program ownership from Linux `/proc` |
| `src/alerts/` | Traffic alert rules |
| `src/pipeline/`, `src/log/` | Packet processing and session output |
| `src/filter.rs`, `src/store.rs` | Display filters and bounded packet storage |
| `src/ui/`, `src/render.rs` | Terminal screen and plain-text output |
| `src/web/`, `web/`, `build.rs` | Local HTTP API, browser page and asset embedding |
| `src/text.rs`, `src/sys.rs` | Text sanitising, formatting and OS helpers |
| `tests/`, `examples/`, `tools/` | Deterministic checks, examples and build utilities |
