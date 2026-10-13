# netmon — plan

A terminal network monitor that explains what it sees.

Status: **build in progress.** Codex is implementing the tasks in section 12; task 01 started on
2026-10-12. This file is the full record of what has been asked, checked and decided so far.

## Working agreement (set by the owner on 2026-10-12)

- **Codex does every build task.** Claude Code writes no netmon code, including fixes. A problem found
  in review goes back to Codex as a fix brief.
- **Run all six tasks without pausing.** After each task Claude Code checks the result, sends any
  problems back to Codex, writes the next brief and starts Codex again, reporting as it goes.
- **Parallel agents:** the owner first chose to try them on round 1 only, then said "use as much agents
  you want from codex and build it use fast mode". So Claude Code decides how many Codex agents run at
  once, all in fast mode, each in its own git worktree, with a merge step after each round. See
  sections 12 and 16.
- **Git:** the owner asked for `git init` to track the work, with a commit after each task.
- **Agent guides:** the owner asked for `AGENTS.md` files to manage each area. The root `AGENTS.md`
  holds the rules for everything; `src/decode`, `src/explain`, `src/ui` and `tests` each have their own.
- **Modular, commented code** (owner, 2026-10-12): "add useful comments so it becomes helpful when
  codex agents code" and "don't write 5k lines in one file make sure it's moduler". Now rules in the
  root `AGENTS.md`: no Rust file over 500 lines, split by responsibility, small public surface,
  one-way dependencies, and a commenting standard. See "Code quality rule" in section 16.
- **Codex settings:** `gpt-6.1-sol` at `xhigh`. Fast mode was on for the five round 1 agents; the
  owner turned it off on 2026-10-12 for everything started after that (section 18).
- **Say "stop" at any time** to end the current Codex run or pause between tasks.

What Claude Code does itself: write each brief, record test captures, start Codex, read the code,
re-run the tests, try what Codex's sandbox cannot (live capture, the screens), keep this file and
`CLAUDE.md` current, and report.

---

## 1. What you asked for

- First request: a network monitor "same as wireshark on terminal with good ui and easier to make sense
  and logging and stuff".
- Main goal, in your words: "help me understand networking like tcp ip udp and packets more better,
  wireshark do that but i want more readability and explanation".
- Uses you picked (all four): which app is talking, debug my services, explain packets simply, security alerts.
- Stack: Rust. Your reasons: you want it small, Cloudflare and Linux lean on Rust, and it suits networking.
- You are also learning Claude Code, so the plan stays open for discussion before anything is built.

## 2. Decisions so far

| Topic | Choice | Why | What else was considered |
|---|---|---|---|
| Language | Rust | Your pick: small binary, good fit for networking | Go + Bubble Tea (my first suggestion: your machine has a large Go module cache including Bubble Tea v2, pure-Go decoding with gopacket, fast builds). Python + Textual (quickest to build, pretty, but decoding is slow and would lag in heavy traffic). |
| UI library | ratatui 0.30 on crossterm | Standard Rust TUI library; tables, sparklines, mouse | — |
| Capture | Spawn `dumpcap`, read its pipe | No sudo, no `libpcap-devel`, tested working here | Own raw socket (teaches more, needs `sudo setcap` after every build). `libpcap` bindings (needs `libpcap-devel` installed). `tcpdump` (has no capabilities here, needs sudo). `tshark` as the decoder (every protocol, but slow, and it would just be termshark again). |
| Decoders | Hand-written | Every field needs its exact byte position for highlighting; also readable for learning | `etherparse` crate (returns structs without byte positions) |
| Concurrency | Plain threads and channels | Small; no async runtime needed | tokio |
| Focus | Explanation first | Your main goal | Wireshark-style field dump |

An existing tool, `termshark`, already clones Wireshark in a terminal (it is not installed here). Like
Wireshark, it shows fields without teaching them. netmon's difference is the explanation layer.

## 3. What I found on this machine

### Tools

| Tool | Version / state |
|---|---|
| rustc / cargo | 1.99.0 stable; targets `x86_64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` installed |
| Go | 1.27.1 (module cache includes `charm.land/bubbletea`, `bubbles`, `lipgloss`) |
| Python | 3.14.8, with `uv` 0.11.26; `rich`, `psutil`, `urwid` installed; `textual`, `scapy` not installed |
| Node | v26.8.1 |
| gcc | 16.2.1 |
| Wireshark, tshark, dumpcap | 4.6.9 |
| tcpdump | 4.99.6, no capabilities set |
| libpcap | 1.10.7 installed; `libpcap-devel` **not** installed |
| termshark | not installed |
| OS | Fedora 44, Linux 7.2.9 |
| Terminal | `tmux-256color`, truecolor; the shell I ran in reported 80x24 |

### Capture permissions

- `/usr/bin/dumpcap` is `-rwxr-x--- root wireshark` with `cap_net_admin,cap_net_raw=ep`.
- Your groups: `user wheel dialout ollama wireshark docker`. Being in `wireshark` lets you run dumpcap without sudo.
- `dumpcap -D` (no sudo) listed 17 interfaces:
  `enp5s0`, `br-000000000001`, `br-000000000002`, `veth0000001`, `veth0000002`, `veth0000003`, `any`, `lo`,
  `br-000000000003`, `br-000000000004`, `docker0`, `bluetooth-monitor`, `usbmon2`, `usbmon1`, `usbmon0`,
  `nflog`, `nfqueue`.
- `enp5s0` is your wired interface and is up. Two Docker bridges and three veths are up; `docker0` and two
  bridges are down.

### Live-streaming test

I ran `dumpcap -p -i lo -w - -q` for 5 seconds into a pipe while sending 4 pings 0.5 s apart, and timed
each chunk that arrived:

```
 0.00s  +260 bytes      file header
 1.23s  +264 bytes      ping 1 (request + reply)
 1.73s  +264 bytes      ping 2
 2.23s  +132 bytes      ping 3 request
 2.23s  +132 bytes      ping 3 reply
 2.73s  +132 bytes      ping 4 request
 2.73s  +132 bytes      ping 4 reply
 4.98s  +108 bytes      closing statistics
```

The stream starts with `0a0d0d0a`, the pcapng signature. Packets arrive as they happen, not in a batch
at the end, so reading dumpcap's pipe works for a live display.

### Finding the app behind a connection

- `/proc/net/tcp`, `/proc/net/tcp6` and `/proc/net/udp` are readable.
- `ss -tunp` without sudo named the owners of your own sockets, e.g. a chat app and `firefox` on port 443
  connections. So app labels work for programs running as you.

### Crates (looked up on crates.io)

| Crate | Version to use | Notes |
|---|---|---|
| ratatui | 0.30.2 | Needs Rust 1.88+. Default features are `all-widgets, crossterm, layout-cache, macros, underline-color`; plan is to turn defaults off and enable only `crossterm`. |
| crossterm | 0.29.0 | Comes in through ratatui |
| pcap-file | 2.0.0 | Reads and writes pcap and pcapng. 3.0.0 exists only as a release candidate. |
| lexopt | 0.3.2 | Tiny command-line parser |
| libc | 0.2.x | For local time and interface addresses. 1.0 exists only as an alpha. |
| etherparse | 0.21.0 | Looked up, **not** used (see decoders) |

### Project folder

`` existed and was empty. `learn-claude` is not a git repository.

---

## 4. Approach

### 4.1 Capture

netmon runs `dumpcap -i <iface> -w - -q [-f <capture filter>]` as a child process and parses the pcapng
stream from its stdout with `pcap-file`. The netmon binary itself needs no privileges. The same parser
opens saved `.pcap` and `.pcapng` files (`netmon -r file`), which is also how tests run.

### 4.2 Decoders

Each decoder produces a tree of fields, and every field carries its byte range in the packet:

```rust
struct Layer {
    name: &'static str,        // "TCP"
    range: Range<usize>,       // bytes this header occupies
    summary: String,           // "58926 → 443, SYN"
    fields: Vec<Field>,
}

struct Field {
    label: &'static str,       // "Flags"
    value: String,             // "SYN"
    range: Range<usize>,       // exact bytes, used for hex highlighting
    key: ExplainKey,           // looks up the explanation text
    children: Vec<Field>,      // e.g. individual flag bits, TCP options
}
```

Protocols covered:

| Layer | Protocols |
|---|---|
| Link | Ethernet, Linux cooked capture (SLL and SLL2, used by the `any` interface), ARP |
| Network | IPv4, IPv6, ICMP, ICMPv6 |
| Transport | TCP (including options), UDP |
| Application | DNS and mDNS, DHCP, HTTP/1.x, TLS hello (server name, version, ALPN), QUIC detection |

Anything else is shown as raw bytes with the port's usual service name.

### 4.3 What is stored per packet

- On arrival: number, timestamp, interface, raw bytes, and a compact summary (addresses, ports, protocol,
  length, connection id, flags) computed once.
- The full field tree is decoded only for the packet you select.
- Packets live in a ring buffer, default 200,000 packets with a memory cap; the oldest fall off.
- The filtered view is a list of packet indexes, rebuilt when the filter changes and extended as packets arrive.

### 4.4 Threads

| Thread | Job |
|---|---|
| Capture | Reads dumpcap's pipe, sends raw packets over a bounded channel |
| Main | About 20 frames a second: drains the channel within a time budget, updates all state, draws, handles keys and mouse. It owns all state, so there are no locks. |
| Process lookup | Every 1–2 s, and when a new connection appears, maps sockets to programs |

Headless mode runs the same main loop without drawing.

### 4.5 Small by design

```toml
[package]
name = "netmon"
version = "0.1.0"
edition = "2024"

[dependencies]
ratatui   = { version = "0.30", default-features = false, features = ["crossterm"] }
pcap-file = "2.0"
lexopt    = "0.3"
libc      = "0.2"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

- No tokio, clap, serde or chrono. JSON for logs is written by a ~30-line writer.
- Size goal is roughly 1 MB. I will measure and report the real number rather than promise it.
- A fully static build is available with `--target x86_64-unknown-linux-musl`.

---

## 5. Explanations (the core feature)

All explanation text lives in one file, `src/explain.rs`, so it is easy to read and improve.

### Level 1: a sentence per packet

The last column of the packet list says what is happening:

| Packet | Sentence |
|---|---|
| DNS query | Asks: what is the IP of github.com? |
| DNS answer | Answer: github.com is 20.207.73.82 (17 ms) |
| DNS failure | Answer: no such name (NXDOMAIN) |
| TCP SYN | Opens a connection (SYN) — handshake 1 of 3 |
| TCP SYN+ACK | Accepts the connection (SYN+ACK) — handshake 2 of 3 |
| TCP ACK after that | Confirms (ACK) — handshake 3 of 3, connection open |
| TCP ACK, no data | Confirms receipt of 1,448 bytes |
| TCP data | Sends 1,448 bytes |
| TCP retransmission | Sends the same 1,448 bytes again (the first copy seems lost) |
| TCP FIN | Finished sending, closing politely (FIN) |
| TCP RST | Aborts the connection (RST) |
| TLS Client Hello | Starts encryption, wants to reach github.com |
| ARP request | Who has 192.168.1.1? Tell 192.168.1.59 |
| ARP reply | 192.168.1.1 is at aa:bb:... |
| ICMP echo | Ping request / Ping reply (0.4 ms) |
| DHCP | Asks the network for an IP address / Offers 192.168.1.59 |

### Level 2: a panel per field

With the cursor on a field, the Explain pane shows three things:

1. **What it is** — "TTL (time to live): a counter every router lowers by one. At zero the packet is dropped, which stops packets circling forever."
2. **In this packet** — "57. It most likely started at 64, so this packet crossed about 7 routers."
3. **Why it matters** — "A lower value than usual from the same host can mean the route changed."

The exact bytes of that field are highlighted in the hex pane.

### Level 3: a story per connection

A ladder diagram of the whole exchange with each step narrated (section 6).

### Glossary

`g` opens short definitions: MAC address, IP address, port, packet, frame, TTL, checksum, SYN, ACK, FIN,
RST, sequence number, window, MSS, handshake, DNS, TLS, and so on.

---

## 6. Screens

Three tabs plus overlays. Mouse works; every action also has a key. The layout collapses to a single
column on an 80-column terminal.

### Tab 1: Packets

List on top; below it Layers (field tree), Explain, and Bytes.

```
 netmon ● LIVE enp5s0   1,284 pkts   312 KB/s ▁▂▅▇▅▂   rec ○   filter: dns or tls
 [1] Packets  [2] Connections  [3] Alerts (2)                      ? help  g glossary
  No  Time   From            To               Proto  What is happening
  41  0.812  firefox         router           DNS    Asks: what is the IP of github.com?
  42  0.829  router          firefox          DNS    Answer: github.com is 20.207.73.82 (17 ms)
▶ 43  0.830  firefox         github.com:443   TCP    Opens a connection (SYN) — handshake 1 of 3
 ┌ Layers ────────────────────┐┌ Explain ───────────────────────────────────────┐
 │ ▸ Ethernet   14 bytes      ││ TCP flag: SYN ("synchronise")                   │
 │ ▸ IPv4       20 bytes      ││ The first packet of every TCP connection.       │
 │ ▾ TCP        40 bytes      ││ Here: firefox asks github.com to start talking  │
 │   ▶ Flags    SYN           ││ and proposes a starting sequence number.        │
 └────────────────────────────┘└─────────────────────────────────────────────────┘
 ┌ Bytes ─ 0020  49 52 e6 2e 01 bb 9c 1f 6a 0c 00 00 00 00 a0 [02] fa f0 ...      ┐
```

Rows are coloured by protocol; problems (retransmissions, resets, failures) stand out in a warning colour.

### Tab 2: Connections

One row per conversation: app, remote name, protocol, state, bytes up and down, duration, problems.
Sort by any column or group by app. Enter opens the Story view:

```
 firefox ⇄ github.com:443     TCP + TLS 1.3 · 4.2 s · 18 KB up / 1.2 MB down
    you                              server
     │ ── SYN ────────────────────▶ │  1. "Can we talk?"
     │ ◀──────────────── SYN+ACK ── │  2. "Yes. Can you hear me?"        31 ms
     │ ── ACK ────────────────────▶ │  3. "Yes." Connection is open.
     │ ── TLS Client Hello ───────▶ │  4. Start encryption, for github.com
     │ ══ 212 encrypted packets ═══ │  Data (contents are not readable)
     │ ── FIN ────────────────────▶ │  Polite close
```

### Tab 3: Alerts

Each alert says what was seen and why it matters, and jumps to the packets involved.

### Proposed keys

| Key | Action |
|---|---|
| `1` `2` `3` | Switch tab |
| `Tab` | Move focus between panes |
| arrows or `j` `k`, `PgUp` `PgDn`, `Home` `End` | Move |
| `Enter` | Expand or collapse a field; open a connection's story |
| `/` | Edit filter; `Esc` clears or closes |
| `Space` | Pause or resume following live traffic |
| `f` | Show only the selected packet's connection |
| `R` | Start or stop recording raw packets |
| `e` | Export the selected connection's story as text |
| `i` | Pick interface |
| `t` | Switch time display (since start / clock time) |
| `g` | Glossary |
| `?` | Help |
| `q` | Quit |

---

## 7. Filter language

Deliberately simpler than Wireshark's:

| Example | Shows |
|---|---|
| `tcp`, `udp`, `icmp`, `arp`, `dns`, `tls`, `http` | That protocol |
| `port 443` | Either side uses port 443 |
| `host github` | Address or learned name contains "github" |
| `app firefox` | Connections owned by firefox |
| `problem` | Retransmissions, resets, failed lookups |
| `dns and not app firefox` | Combine with `and`, `or`, `not`, brackets |
| `hello` | Any other word searches the description text |

A separate capture filter (`-f "port 53"`) is passed to dumpcap and limits what is captured at all.

---

## 8. Features by area

### Which app is talking

1. Read `/proc/net/tcp`, `tcp6`, `udp`, `udp6`: each line has local and remote address, port and a socket id.
2. Walk `/proc/<pid>/fd/`: links reading `socket:[id]` say which process holds that socket.
3. Read `/proc/<pid>/comm` for the program name.
4. Cache the result per connection; refresh every 1–2 s and when a new connection appears.

Hostnames are learned passively, with no extra lookups sent:
- DNS answers seen on the wire (IP → name)
- TLS server name and HTTP Host header (per connection)
- mDNS names for local devices
- Labels for "this computer" and "router" (default gateway from `/proc/net/route`)
- Addresses are tagged local, public, multicast or broadcast

### Debug my services

| Check | How |
|---|---|
| Retransmission | A data segment whose sequence number was already sent |
| Duplicate ACK | The same ACK number three or more times with no data |
| Reset | RST flag, with who sent it |
| Zero window | Receiver advertises window 0 (it is overwhelmed) |
| Handshake time | Gap between SYN and SYN+ACK |
| DNS | Response time; NXDOMAIN and SERVFAIL flagged; unanswered queries |
| HTTP (cleartext only) | Request line, status code, response time |
| Docker | The interface picker lists your bridges and veths |

### Security alerts (five rules to start; thresholds are starting values to tune)

| Rule | Trigger |
|---|---|
| Port scan | One source tries 20 or more different ports on one host within 10 s |
| Cleartext credentials | HTTP Basic auth, FTP `USER`/`PASS`, Telnet sessions. The password itself is never written to logs. |
| ARP mapping change | An IP address that was at one MAC address now claims another |
| Suspicious DNS | A label over 50 characters, random-looking names, or 20 or more NXDOMAIN in 10 s from one app |
| Unexpected inbound | A public address connects to a listening port on this machine and is accepted |

---

## 9. Logging

Each session gets a folder under `~/.local/state/netmon/<date-time>/` (override with `--log-dir`).

| File | Contents | Default |
|---|---|---|
| `summary.md` | The report to open first: totals, alerts with their explanations, tables of conversations and DNS lookups, problems seen, and what each file in the folder is | On; rewritten at most once a minute and at the end |
| `events.md` | Readable timeline as a Markdown table: connections, DNS lookups, alerts | On (small) |
| `flows.jsonl` | One JSON line per finished connection | On |
| `alerts.jsonl` | One JSON line per alert | On |
| `capture.pcapng` | Raw packets; opens in Wireshark | Off; `-w` or `R`; size-capped |
| `packets.jsonl` | One line per packet with its plain-English sentence | Off; `--log-packets` |
| `story-<n>.md` | A connection's story, written when you press `e` | On demand |

**Files a person reads are Markdown** (owner, 2026-10-12: "if i want to read a log it's a md file so
it's good to look at compare to txt"). `summary.md`, `events.md` and exported stories are Markdown.
`flows.jsonl`, `alerts.jsonl`, `packets.jsonl` and `capture.pcapng` are for programs and stay as they
are. Because names in these files come from the network, every value is escaped so that opening a log
in a Markdown viewer can never render markup or fetch a remote image. This was added to
`tasks/08-pipeline.md` (section 3a) while that task was running. The `events.log` examples below
show the wording; in the file each one is a table row.

Illustrative format (the exact fields may change during the build):

```
14:02:11.812  DNS    firefox asked for github.com → 20.207.73.82 (17 ms)
14:02:11.830  OPEN   firefox → github.com:443 (TCP)
14:02:16.040  CLOSE  firefox → github.com:443   4.2 s, 18 KB up, 1.2 MB down, closed normally
14:02:20.511  ALERT  Port scan: 192.168.1.77 tried 120 ports on this computer in 3 s
```

```json
{"start":"2026-10-12T14:02:11.830Z","dur_ms":4210,"app":"firefox","pid":3688,"proto":"tcp","local":"192.168.1.59:58926","remote":"20.207.73.82:443","host":"github.com","tls":"1.3","up_bytes":18211,"down_bytes":1203450,"packets":241,"retransmits":0,"end":"fin"}
```

---

## 10. Command line

```
netmon [OPTIONS]              live view
netmon explain <FILE>         print explained packets to stdout

  -i, --interface <NAME>      interface to capture (default: the first one that is up and not loopback)
  -r, --read <FILE>           open a saved .pcap or .pcapng instead of capturing
  -f, --capture-filter <BPF>  passed to dumpcap, e.g. "port 53"
  -w, --write [FILE]          record raw packets
      --headless              no screen, log only
      --log-dir <DIR>         where session folders go
      --log-packets           also write packets.jsonl
      --no-log                write no logs
      --max-packets <N>       packets kept in memory (default 200000)
      --tsv                   with `explain`: tab-separated output
```

---

## 11. Files (all new, under `netmon/`)

```
Cargo.toml
PLAN.md                  this file
CLAUDE.md                guidance for Claude Code
AGENTS.md                standing rules for Codex
tasks/                   one exact brief per task, plus Codex's report for each
README.md
src/lib.rs               module declarations
src/main.rs              command line and mode dispatch
src/capture.rs           dumpcap child, interface list, pcapng stream and file reader
src/text.rs              sanitising packet text, formatting, hex dump
src/render.rs            text output for `netmon explain`
src/decode/mod.rs        Layer/Field model, pipeline, one-line summary
src/decode/link.rs       Ethernet, SLL/SLL2, ARP
src/decode/ip.rs         IPv4, IPv6, ICMP, ICMPv6
src/decode/transport.rs  TCP, UDP
src/decode/dns.rs, dhcp.rs, http.rs, tls.rs, quic.rs   one file per application protocol
src/explain.rs           all plain-English text: sentences, field explanations, glossary
src/flow.rs              connection table, TCP state and sequence tracking, story steps
src/names.rs             passive hostname table, well-known ports, local/public tagging
src/procs.rs             socket-to-program lookup from /proc
src/alerts.rs            alert rules
src/filter.rs            filter parser and matcher
src/store.rs             packet ring buffer and filtered index
src/log.rs               session folder, log writers, pcapng writer, tiny JSON writer
src/ui/mod.rs            app state, event loop, keys and mouse, layout, theme
src/ui/packets.rs        list, layers, explain, bytes
src/ui/flows.rs          connections table and story view
src/ui/overlays.rs       header, filter bar, help, glossary, interface picker, alerts tab
tests/fixtures/          small sample captures
tests/decode.rs
tests/explain_golden.rs
```

About 20 source files; my rough guess is 4,000–5,000 lines in total.

---

## 12. Build order

Each task ends with something you can run. The order was changed on 2026-10-12 to build the engine
before the screens, because the engine can be tested fully from saved capture files, while the screens
cannot be tested inside Codex's sandbox.

| Task | Brief | Delivers | State |
|---|---|---|---|
| 01 Engine | `tasks/01-engine.md` | Capture reader, all decoders, explanations, glossary, `netmon explain` | In progress |
| 02 Conversations | to be written | Connection tracking, handshake steps, retransmissions, DNS timing, hostname learning; richer sentences | Not started |
| 03 Packets screen | to be written | Live capture through `dumpcap`, the Packets tab, filter bar, help and glossary overlays | Not started |
| 04 Connections screen | to be written | Connections tab, Story view, app labels | Not started |
| 05 Logging | to be written | Session folder, logs, recording, `--headless`, story export | Not started |
| 06 Alerts and polish | to be written | The five alert rules, Alerts tab, narrow layout, size tuning, README | Not started |

Each brief is written after the previous task is reviewed, so it can refer to the code that exists.

### Rounds (parallel plan)

On 2026-10-12 the owner said to use as many Codex agents as wanted, in fast mode, so the pause after
round 1 no longer applies and the rounds were widened:

| Round | Runs together | Then |
|---|---|---|
| 0 | Task 01 alone (everything depends on it). **Done**: 31 tests pass, 542,424-byte binary. | Committed as the first commit |
| 1 | Five agents, one worktree each: `02-conversations`, `03-packets-screen`, `04a-apps`, `05a-logging-core`, `06a-alerts` | Review each, commit each, merge, then a Codex integration run that joins them |
| 2 | Screens for conversations and alerts; wiring of logging, apps and names into the live view; headless mode | Review, commit, merge |
| 3 | Final pass: explanation wording, narrow layout, size, README | Review, commit |

Round 1 was chosen so the five pieces barely overlap: each agent owns its own files, and the only
shared edits are one-line module declarations.

### Paused again by the owner (2026-10-13 12:22)

The owner said "pause the work we will continue later" and "save the state". Both running agents were
stopped; nothing is running. The exact state, session ids and resume command are at the top of
`CLAUDE.md`. In short:

- Merged since the last entry below: the pipeline with Markdown logs (`08`), the web server core
  (`12a`), and the web project scaffold.
- Direction change: after trying the terminal screen the owner asked for a GUI and chose a local web
  page (Vite, React, TypeScript, Tailwind, shadcn/ui, React Compiler, `nub`), keeping the terminal
  screen as it is. Contract: `docs/web-api.md`.
- Paused part-way: the web page (`11`) and the web API with the `netmon web` command (`12b`).
- Not yet done by anyone: opening the web page in a real browser.
- A memory incident on the owner's 16 GB desktop (a runaway `nub dlx create-vite`) led to every agent
  and unfamiliar command now running under a memory and process cap.

### Resumed (2026-10-13 09:50) and tidy merged (10:1x)

The owner said "okay resume the task then with codex". All three paused sessions were resumed.

- **`07-tidy` is done and merged into `main`** (`c9664bb`, merge `45a2635`). The five oversized files
  are split; the largest Rust file in the repository is now 477 lines. Output on every fixture is
  byte-for-byte unchanged, golden files untouched, 116 tests pass, release binary 544,856 bytes.
  The TLS decoder no longer returns a cut-off server name. The size exemption was removed from
  `AGENTS.md`, and the decode and explain guides now describe the new layout.
- `03-packets-screen` and `08-pipeline` are still running.
- **`09-field-wording` was started at 10:2x**, after the owner asked again whether more agents were
  needed. It rewrites the per-field explanations and glossary for a beginner and puts fields in header
  order. Worktree `.worktrees/09-field-wording` (inside the project, git-ignored, so it does not
  clutter `learn-claude/`), branch `task-09-field-wording`, Codex session
  `<session-id>`. It could start now because tidy has merged and it leaves the
  one-line sentences alone, which the other two branches' golden files quote. After it merges, the
  screen's golden files that show field text will need regenerating.

- **`03-packets-screen` finished and was merged at 10:5x** (`1a3c69c`, merge `02abdb9`). First run of
  the real screen, in a private tmux on a saved capture and on live loopback traffic:
  - **Works:** packets arrive live through `dumpcap`; the list, layer tree, Explain pane and bytes
    show; `/dns` filters to 8 packets; help and glossary overlays open; `q` exits with status 0,
    restores the terminal and leaves no `dumpcap` running. Release binary 931,368 bytes with the
    screen linked in.
  - **Problems found:** every packet takes two lines, so only 7 are visible at 140x40 and one at
    80x24; the detail panes crowd out the list on small terminals; a saved file opens at the last
    packet; file mode shows a meaningless transfer rate; the Time column rounds where `netmon explain`
    truncates; the overlays are full-screen and mostly empty.
  - **The merge left `main` not compiling:** the union merge duplicated `pub mod render;` in
    `src/lib.rs`. Lesson: union merging is safe only when each side adds lines in different places.
- **`10-screen-fixes` started at 11:0x** to repair `src/lib.rs` and fix the screen problems above.
  Worktree `.worktrees/10-screen-fixes`, branch `task-10-screen-fixes`. Until it merges, `main` does
  not build; the last building commit on `main` is `45a2635`.

- **`09-field-wording` finished and was merged at 11:0x** (`5811e8c`, merge `a091326`). Fields are in
  header order, flag bits are children shown by name (`0x4000 [DF]`), checksums are hex, clear flags
  read "Not set.", and the what/here/why text and glossary are rewritten for a beginner. 122 tests
  pass on its branch; only the seven `packet-*.txt` golden files changed. Codex could not compare the
  text against the RFCs (no network in its sandbox); the sample read in review was correct.
  Nits for the next run: port and sequence numbers are printed with thousands separators
  ("Port 51,008"), which is wrong for identifiers. After `10-screen-fixes` merges, the `ui-*` golden
  files must be regenerated, because they quote field text and order that this task changed.

- **Accuracy read-through of the field explanations (11:1x, by Claude Code).** Codex could not check
  its text against the RFCs, so the static what/why text for every protocol family was read in review
  (TCP, IP, UDP, ICMP, Ethernet/ARP, DNS, TLS, QUIC, HTTP, DHCP), plus the value-dependent logic for
  TCP, IP, ports, addresses, TTL and windows. **No factual error was found.** Things checked in
  particular: the fragment offset is converted to bytes before it is described as bytes; the TTL
  wording hedges the starting value; SYN and FIN are described as using a sequence number; the
  window text does not claim a byte count when the scale is unknown; the TLS record version is not
  presented as the negotiated version. This was a careful read by one reviewer, not a line-by-line
  comparison with each RFC. Wording nits for the next run:
  - ports and sequence numbers must not use thousands separators (and today ports with a known
    service print without them while others print with them);
  - HTTP DELETE reads "remove the target's association with its contents"; say "delete the target".

- **`10-screen-fixes` finished and was merged at 11:2x** (`9e7f727`, then a format commit `8d7726e`).
  `main` builds again; release binary 954,064 bytes. Checked by hand in tmux with `main`'s binary:
  one line per packet (8 rows at 80x24, 17 at 140x40), the selected packet's full sentence on a fixed
  line under the list, one detail pane with "Tab switches" at 80x24, saved captures open at packet 1,
  file mode shows duration and bytes, list times match `netmon explain`, live capture on loopback
  shows packets as they arrive and `q` leaves no `dumpcap` behind.
  **Three `ui` tests fail on `main`** because tasks 09 and 10 ran in parallel: the screen golden files
  quote field text and order that 09 changed, one movement test assumes the old field order
  (`tests/ui.rs:132`), and one overlay test assumes the old glossary size
  (`tests/ui_support/layout.rs:325`). 148 other tests pass. The next Codex run fixes these first.
  Seen but not yet fixed: at 80 columns the From column is dropped and only To is shown, which hides
  who sent each packet.

Before committing either of those branches, copy `AGENTS.md`, `src/decode/AGENTS.md` and
`src/explain/AGENTS.md` from `main` into its worktree so those files merge cleanly.

### Paused by the owner (2026-10-13 00:01)

The owner said "okay pause all the work". All three running Codex agents were stopped. Nothing is
running. Their files are in their worktrees, uncommitted, and each session can be resumed.

| Brief | Worktree and branch | Codex session id | Where it stopped |
|---|---|---|---|
| `03-packets-screen` | `../netmon-03-packets-screen`, `task-03-packets-screen` | `<session-id>` | 35 changed paths; the code builds; no report yet |
| `07-tidy` | `../netmon-07-tidy`, `task-07-tidy` | `<session-id>` | 24 changed paths; the code builds; no file over 500 lines; no report yet |
| `08-pipeline` | `../netmon-08-pipeline`, `task-08-pipeline` | `<session-id>` | 13 changed paths; mid-edit, does not compile yet (12 errors); no report yet |

To resume one, run from inside its worktree (the same command as under "Round 1 state" below, with
this prompt):

```sh
codex exec resume --skip-git-repo-check -c sandbox_mode='"workspace-write"' \
  -c sandbox_workspace_write.network_access=false -m gpt-6.1-sol \
  -c model_reasoning_effort='"xhigh"' -c service_tier='"default"' \
  -o tasks/<brief>.report.md <session id> \
  "You were paused part-way through this task and are now resuming it. Re-read AGENTS.md and tasks/<brief>.md in full, run git status to see what you have already written, then finish everything that remains, run every acceptance command and the size check, and end with the final report that AGENTS.md describes."
```

Before committing `03-packets-screen`, copy the current `AGENTS.md` from `main` into its worktree, so
the merge of that file is clean.

### State (updated 2026-10-12 23:55)

Round 1 was resumed at 23:22 after the limit reset. Four of its five branches are finished, reviewed
and **merged into `main`**. `main` now has 115 passing tests and a 543,496-byte release binary.

| Brief | Result | Commit on its branch |
|---|---|---|
| `05a-logging-core` + `fix-1` | Done. `src/log/` in five modules. 48 tests on the branch | `9f098b9` |
| `04a-apps` | Done. `src/procs/` in six modules. Matched 64 real sockets to programs on this machine | `b11fbd3` |
| `06a-alerts` | Done. `src/alerts/`, one module per rule. Port-scan rule confirmed on a real loopback scan | `67bf690` |
| `02-conversations` | Done. `src/flow/` in seven modules plus `src/names.rs`. 12 conversations found in the fixture | `9a10127` |
| `03-packets-screen` | **Still running** (session `<session-id>`, `../netmon-03-packets-screen`) | — |

The owner then said "if needed use more agents", so two more were started from the merged `main`,
on work that does not touch the screen:

| Brief | Worktree and branch | Does |
|---|---|---|
| `07-tidy` | `../netmon-07-tidy`, `task-07-tidy` | Splits task 01's five oversized files and adds comments; no behaviour change. Also stops the TLS decoder returning a cut-off server name |
| `08-pipeline` | `../netmon-08-pipeline`, `task-08-pipeline` | One `Pipeline` value that feeds each packet through conversations, names, app lookup, alerts and logging, with a headless example. Also fixes `procs::local_addresses` returning `127.0.0.0` |

Merging used `.gitattributes` with `merge=union` on `src/lib.rs` and `src/explain.rs`, so the one-line
module declarations from each branch combined without conflicts; `cargo fmt` then sorted them.

Still to come after these three finish: a Codex run that puts the pipeline behind the screen and adds
the Connections and Alerts tabs and the command-line options for logging and headless mode; then the
wording pass and README.

Small things noted for later:
- `AGENTS.md` line 190 has a trailing space (fix after the open branches merge, to avoid a conflict).
- The sentence in `AGENTS.md` exempting five files from the size limit goes away once `07-tidy` lands.
- IPv4 flags are shown as a number (16384) and some field text is stiff: the wording pass.

### Round 1 state (updated 2026-10-12 20:05)

The Codex usage limit was reached at about 20:00. Codex said to try again at **11:19 PM**. Four agents
stopped part-way; their files are in their worktrees, uncommitted, and their sessions can be resumed.

| Brief | Worktree and branch | Codex session id | State |
|---|---|---|---|
| `05a-logging-core` | `../netmon-05a-logging-core`, `task-05a-logging-core` | `<session-id>` | **Done.** Reviewed, 48 tests pass, committed as `69e2d8c` |
| `02-conversations` | `../netmon-02-conversations`, `task-02-conversations` | `<session-id>` | Stopped by the limit. Builds; 39 tests pass, 1 fails. No report yet |
| `03-packets-screen` | `../netmon-03-packets-screen`, `task-03-packets-screen` | `<session-id>` | Stopped by the limit while fixing compile errors. No report yet |
| `04a-apps` | `../netmon-04a-apps`, `task-04a-apps` | `<session-id>` | Stopped by the limit. Its tests were passing. No report yet |
| `06a-alerts` | `../netmon-06a-alerts`, `task-06a-alerts` | `<session-id>` | Stopped by the limit. 27 tests were passing. No report yet |

To resume one after the reset, from inside its worktree:

```sh
codex exec resume --skip-git-repo-check -c sandbox_mode='"workspace-write"' \
  -c sandbox_workspace_write.network_access=false -m gpt-6.1-sol \
  -c model_reasoning_effort='"xhigh"' -c service_tier='"default"' \
  -o tasks/<brief>.report.md <session id> \
  "You were stopped part-way through this task and are now resuming it. AGENTS.md has changed since you started: re-read it in full, especially the new sections 'Comments' and 'Modular code: file size and structure' and the fifth quality gate. Run git status to see what you have already written, re-read tasks/<brief>.md, then finish everything that remains. Before you finish, bring every file you own in line with the new rules: split any Rust file over 500 lines into a folder module while keeping public paths working, and add the required file headers, doc comments and why-comments. Run every acceptance command and the size check, and end with the final report that AGENTS.md describes."
```

For the finished logging branch, start a new run in `../netmon-05a-logging-core` on
`tasks/05a-logging-core.fix-1.md` instead (the normal launch command from `CLAUDE.md`).

This was done once already on 2026-10-12 (to switch fast mode off) and all five sessions continued.

Also confirmed on 2026-10-12: live capture works. `dumpcap -i lo -w - -q | netmon explain -` printed
real pings and a DNS lookup as they happened, so reading `dumpcap`'s pipe is no longer an open risk.

Noted for round 3 while checking task 01: some field explanations are correct but stiff or unhelpful
(for example the IPv4 flags value is shown as the number 16384, and the TTL text says "64 remains").
They need a wording pass.

**State on 2026-10-13, evening.** Tasks 11 (with fix 1), 12a, 12b, 12c, 13 and 14 are merged: the web
page, the web API and `netmon web`, hidden secret bytes, the build script, the README, a Codex review
of the server side, and a production page without mock data. 243 Rust tests and 100 web tests pass.
From task 11 fix 1 onward Claude Code merged without reviewing (the owner uses Codex to save Claude
tokens). The project was published to GitHub as one clean commit with machine details removed; the
full history stays local in the branch `local-history`. Not yet done: the owner trying the page in a
browser.

---

## 13. How it will be checked

- **Build and size**: `cargo build --release`; report `ls -lh target/release/netmon`.
- **Unit tests** (`cargo test`): each decoder against hand-built byte arrays; filter parser; connection state tracking.
- **Cross-check against tshark**: record a sample with `dumpcap -c 300 -w tests/fixtures/mixed.pcapng`
  while running `ping`, `dig` and `curl`, then compare packet count, addresses and protocol per packet
  between `netmon explain --tsv` and
  `tshark -r ... -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol`.
- **Golden test**: `netmon explain` output on the samples is compared with checked-in expected text.
- **Live screen**: run in a detached tmux session at 140x40 and at 80x24, drive it with `tmux send-keys`,
  read each screen with `tmux capture-pane -p`; generate traffic with `curl https://example.com`.
- **Logging**: a 10-second headless run; every line of `flows.jsonl` parses as JSON; `tshark -r capture.pcapng` reads the recording.
- **Alerts**: `nc -z 127.0.0.1 1-200` on `lo` must raise the port-scan alert.
- **Terminal safety**: quitting with `q`, Ctrl-C and a forced panic all restore the terminal.

---

## 14. Risks and limits

### Things to confirm early in the build

- `pcap-file` reading from a live pipe. It accepts any reader, so it should work. If it buffers badly,
  the fallback is a small pcapng reader of our own (three block types, roughly 150 lines).
- ratatui with only the `crossterm` feature. If a needed widget sits behind another feature, enable it.
- Heavy traffic. A fast download is tens of thousands of packets a second. The main loop's time budget
  and the ring buffer keep the screen responsive; the header shows any backlog; a capture filter narrows the load.

### Limits that will remain

- Encrypted contents (HTTPS, QUIC) cannot be read. You get the server name, sizes and timing, not the data.
- For QUIC (HTTP/3) even the server name is encrypted; the name is shown only if a DNS answer for that
  address was seen.
- App labels cover programs running as your user. Root-owned and very short-lived connections may show as unknown.
- Live capture needs `dumpcap` (from the Wireshark package, already installed). Opening saved files does not.
- Protocol coverage is the list in section 4.2, not Wireshark's thousands. Recordings open in Wireshark for deeper digging.

---

## 15. Decisions that were open

On 2026-10-12 the owner said to "instruct exactly what you want", so these were settled with the
defaults below. Any of them can still be changed; the cost of changing rises as tasks complete.

| # | Question | Settled as | Still cheap to change until |
|---|---|---|---|
| 1 | Capture method | Spawn `dumpcap` (no sudo) | Task 03 |
| 2 | Decoders | Hand-written, with an RFC header diagram at the top of each file | Task 01 (now) |
| 3 | Project size | Keep all four uses; alerts come last so they can be dropped | Task 06 |
| 4 | Build order | Engine first, then screens, then logging (section 12) | Each task boundary |
| 5 | Log location | `~/.local/state/netmon/`, with `--log-dir` to override | Task 05 |
| 6 | Name | `netmon` | Task 01 (now) |
| 7 | Keys and filter words | As proposed in sections 6 and 7 | Task 03 |
| 8 | Alert thresholds | As proposed in section 8 | Task 06 |

---

## 16. How the build is run

**Rule set by the owner on 2026-10-12: "don't do any task, let codex do it."** Claude Code writes no
netmon code. That includes fixes: when a review finds a problem, Claude Code writes it up as a fix
brief and Codex makes the change. Claude Code's part is instructions, launching Codex, checking the
result and reporting.

- **Claude Code** writes one exact brief per task in `tasks/`, records test captures, starts Codex,
  then reviews the result: reads the code, re-runs the acceptance commands, and checks live capture and
  the screens, which Codex cannot do.
- **Codex** implements one task per run, following `AGENTS.md` (standing rules) and the task brief.
  Its final report is saved beside the brief as `tasks/NN-name.report.md`.
- Codex runs in its `workspace-write` sandbox with the network off. Checked on this machine: inside it,
  an offline `cargo build` works and `tshark` can read capture files; the network, writes outside this
  folder, and `dumpcap` are all blocked.
- Because the sandbox has no network, the four dependencies were downloaded beforehand and Codex cannot
  add new ones. That enforces the "small" rule mechanically.
- Test captures in `tests/fixtures/` were recorded from loopback traffic generated for the purpose
  (pings, DNS lookups, a local web server and a local TLS server on `127.0.0.2` and `::1`). Capture
  filters limited recording to that traffic, so they contain none of your real traffic.

### Running agents in parallel

Two agents cannot share one folder: the project is a single Rust crate, so one agent's half-written
code would break the other's build. Each parallel agent therefore gets its own git worktree.

1. After the previous round is reviewed and committed on `main`, create one worktree and branch per
   task: `git worktree add ../netmon-task-NN -b task-NN`.
2. Warm each worktree's build outside the sandbox (`cargo build`, `cargo test --no-run`,
   `cargo build --release`), so Codex does not need to unpack or lock anything in the cargo cache.
3. Start one Codex run per worktree with `-C ../netmon-task-NN`. Codex still makes no git changes
   itself; Claude Code commits on each branch after reviewing it.
4. Merge the branches into `main`. If git reports conflicts, or the merged code needs wiring together,
   that is a Codex integration run with its own brief. Claude Code does not resolve conflicts by hand.
5. Remove the worktrees once merged.

Briefs for parallel tasks say which files each agent owns, to keep the overlap small.

Not yet tested on this machine: an offline cargo build in a fresh worktree inside Codex's sandbox.
Step 2 exists to avoid depending on it.

### Code quality rule (added 2026-10-12)

The owner asked for useful comments and modular code with no huge files. Measured at that moment:

| File | Lines | Comment lines | Where |
|---|---|---|---|
| `src/flow.rs` | 1,309 | 16 | branch `task-02-conversations` |
| `src/explain.rs` | 1,114 | 1 | `main` |
| `src/explain/fields.rs` | 1,021 | 0 | `main` |
| `tests/alerts.rs` | 1,020 | 8 | branch `task-06a-alerts` |
| `src/alerts.rs` | 944 | 22 | branch `task-06a-alerts` |
| `src/procs.rs` | 738 | 37 | branch `task-04a-apps` |
| `src/ui/mod.rs` | 703 | 6 | branch `task-03-packets-screen` |
| `tests/log.rs` | 693 | 2 | branch `task-05a-logging-core` |
| `src/decode/mod.rs` | 655 | 5 | `main` |
| `src/log.rs` | 602 | 13 | branch `task-05a-logging-core` |
| `src/decode/ip.rs` | 573 | 16 | `main` |
| `tests/procs.rs` | 570 | 5 | branch `task-04a-apps` |
| `src/decode/dns.rs` | 559 | 13 | `main` |
| `tests/flows.rs` | 545 | 1 | branch `task-02-conversations` |

No file is near 5,000 lines, but fourteen are over 500 and almost none are commented. The code works;
it is hard to read.

What changed:

- The root `AGENTS.md` gained two sections, **Comments** and **Modular code: file size and structure**,
  and a fifth quality gate that lists any Rust file over 500 lines.
- `src/explain/AGENTS.md` says to split wording by protocol family, like the decoders.

How it reaches the code (all through Codex; Claude Code edits no code):

1. **The four paused round 1 agents**: the updated guides are copied into their worktrees, and the
   resume prompt tells them to re-read `AGENTS.md` and bring their own files in line before finishing.
2. **The finished logging branch**: `tasks/05a-logging-core.fix-1.md` splits `src/log.rs` and
   `tests/log.rs` and adds comments, with no behaviour change.
3. **Task 01's five oversized files on `main`** (`explain.rs`, `explain/fields.rs`, `decode/mod.rs`,
   `decode/ip.rs`, `decode/dns.rs`): a tidy task after round 1 is merged. It must run alone, because
   it moves code that every branch touches. Until then `AGENTS.md` names those five as exempt.

Cost: restructuring uses Codex allowance without adding features. It is cheapest now, before more
code is built on top.

### What I found while preparing task 01

- `pcap-file` 2.0 treats every pcapng timestamp as nanoseconds, ignoring the resolution the file
  declares. `dumpcap` here does write nanoseconds, so live capture is unaffected, but files from other
  tools would show wrong times. The brief tells Codex to read the declared resolution and scale it.
- A modern TLS Client Hello can be larger than one packet, so the server name is sometimes split across
  two packets. Task 01 reads it when it fits in one packet; task 02 will join the pieces.
- QUIC (HTTP/3) encrypts its handshake from the first packet, so netmon cannot read the server name
  from QUIC traffic without adding cryptography. Those connections get names only from DNS answers.

---

## 17. Project `.claude/` folder

There is no `.claude/` folder in `netmon/` today (checked twice on 2026-10-12). The only one on this
machine is `~/.claude/` in the home directory, which Claude Code created for its own data.

### How a project gets one

A project `.claude/` folder is optional. It appears in one of two ways:

- **Automatically**, when Claude Code needs to save something for this project only. The usual trigger is
  answering a permission prompt with "yes, and don't ask again": the choice is saved to
  `.claude/settings.local.json` in the project.
- **Deliberately**, when you or Claude Code add project configuration: `.claude/settings.json`
  (permissions and hooks shared with anyone using the project), `.claude/agents/*.md` (custom
  subagents), or `.claude/skills/` (project skills).

`/init` does not create it. `/init` only writes `CLAUDE.md` in the project root.

### Why none was made at first

Nothing done at first needed project-level configuration, and an empty folder has no effect.

### What was created (2026-10-12, after the owner said "finish it then")

`netmon/.claude/settings.json` with a permission allowlist for the commands this project runs
repeatedly, so they stop prompting:

- `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`, `cargo tree`
- `tshark -r` and `capinfos` (reading capture files)
- running the built `./target/release/netmon` and `./target/debug/netmon`

Not on the allowlist, so they keep prompting: `codex exec`, `dumpcap` live capture, and anything that
deletes files.

---

## 18. Project Codex config

Asked for on 2026-10-12: put Codex's settings in this project so Codex picks them up there, and keep it
on `gpt-6.1-sol` at `xhigh`.

### The file

`netmon/.codex/config.toml`:

```toml
# Codex settings for netmon.
# Pins the model and reasoning effort used for the build tasks, so they stay the
# same even if the global default in ~/.codex/config.toml changes later.
model = "gpt-6.1-sol"
model_reasoning_effort = "xhigh"
```

Only these two settings go in. Nothing else is copied from the global Codex config.

### What was checked

- The global `~/.codex/config.toml` already has exactly these two values on its first two lines, which
  is why the running task-01 session uses them. So the project file changes nothing today; what it
  adds is that this project stays on these settings if the global default changes.
- Codex 0.162.1 supports the file. Its own text says: "Project `.codex/config.toml`: settings for a
  trusted repository, including sandbox, MCP, hooks, model, and reasoning defaults."
- "Trusted" matters: the global Codex config has no trust entry for `learn-claude` or `netmon`, so Codex
  may ignore the project file until this folder is trusted.
- Not yet known: whether Codex accepts `netmon` as a project root. It looks for a `.git` folder by
  default and `netmon` is not a git repository. `codex doctor` reports "project source: cwd", which
  suggests the current folder is used, but that is not confirmed.

### Steps

1. Create `netmon/.codex/config.toml` with the contents above.
2. Run `codex doctor` in `netmon` and check whether it now lists the project config as loaded.
3. If it is not loaded because the folder is untrusted, say so. Trusting the folder is the owner's
   decision: run `codex` once in `netmon` and accept its trust prompt. Claude Code does not edit
   `~/.codex/config.toml` unless asked.
4. As a guarantee that does not depend on trust, pass the settings explicitly on every Codex run that
   Claude Code starts: `-m gpt-6.1-sol -c model_reasoning_effort="xhigh"`. Update the command shown in
   `CLAUDE.md` to match.
5. The task-01 session already running is unaffected; it started on these settings.

### Done on 2026-10-12

- `netmon/.codex/config.toml` created (the owner said "do it").
- Result of the check: Codex does **not** apply it yet. A throwaway folder whose project config set a
  made-up model still reported the global model in `codex doctor`. Most likely cause: the folder is
  not trusted. The owner can fix that by running `codex` once in `netmon` and accepting the trust prompt.
- The launch command in `CLAUDE.md` now passes the model and effort explicitly, so runs started by
  Claude Code use them regardless of trust.

### Fast mode (asked for on 2026-10-12)

- Codex's model catalog lists a Fast tier for `gpt-6.1-sol`: "2x speed, increased usage".
- It cannot be switched on for a run that has already started, so the owner chose: leave task 01
  running at standard speed, and use fast mode from task 02 on.
- Setting: `service_tier = "fast"`. Checked with three tiny probe runs: `"fast"` and `"priority"` are
  both accepted without complaint, while a made-up value prints
  "Configured service tier ... is not advertised as supported ... and will be omitted from requests".
- Applied in two places: the launch command in `CLAUDE.md` (`-c service_tier="fast"`) and
  `netmon/.codex/config.toml`.
- Not measured: how much faster it really is, and how much more allowance it uses.

---

## 19. Proposed round 4: ask an AI about what you see (not yet approved)

Raised by the owner on 2026-10-12: "making this project more agentic so that i can ask ai for
explaination", with the condition "it should not prosess sensitive data". This section records the
proposal. Nothing here is being built, and no running agent's brief includes it.

### Why it fits

The built-in explanations answer "what is this field?". They cannot answer a learner's follow-up
questions in context: "why did this connection get reset?", "is this normal?", "what should I look at
in this capture?". A model that can look things up in netmon's decoded data can.

### Shape

- **Tools, not a data dump.** The model gets a few read-only lookups over data netmon has already
  decoded and sanitised: list conversations, get one conversation's story, get one packet's fields and
  explanations, look up a glossary term, list alerts. It asks for what it needs.
- **Read-only, always.** The model can look, never act. It cannot start or stop a capture, write a
  file, change a filter, or run a command.
- **Answers cite packets.** Each answer names the packet and conversation numbers it relied on, so the
  reader can check it against the built-in explanation. AI answers are labelled as such on screen.
- **Built-in text stays the source of truth.** The model explains and connects; it does not replace
  the deterministic explanations.

### Keeping sensitive data out

Sensitive, for a packet capture, means: passwords and cookies; the sites and services the computer
talks to; its own addresses and those of its network; process names; and any unencrypted payload.

1. **Local model by default.** A model running on this computer (for example through Ollama, which
   speaks plain HTTP on localhost) means nothing leaves the machine. This also suits "small": plain
   HTTP to localhost needs no TLS library, so no new dependencies. The owner's account is in an
   `ollama` group; whether Ollama is installed and which models it has is **not yet checked**.
2. **No raw bytes, no payloads.** Only structured facts go to a model: protocol, flags, sizes, timings,
   counts, the plain-English sentence.
3. **Stand-ins for identities.** Addresses, hostnames and process names are replaced with stable
   placeholders (`your-computer`, `router`, `SERVER-A`) before anything reaches a model, keeping only
   the class (private, public, local). They are swapped back when the answer is shown.
4. **Secrets are already hidden** at decode time (task 01) and never appear in fields or sentences.
5. **Cloud model only by explicit opt-in**, off by default, per session, with a preview of exactly what
   would be sent and a log of what was sent.

### Risks to design for

- **Wrong answers.** A model can be confidently wrong, and a learner cannot always tell. Small local
  models are weaker here than large cloud ones. Mitigations: require cited packets, prefer "this capture
  does not show that" over guessing, keep the built-in text visible beside the answer.
- **Text written by strangers.** Packets carry attacker-chosen text (hostnames, headers). It could try
  to instruct the model. Read-only tools limit the worst case to a misleading answer. Mitigations: send
  placeholders instead of raw names where possible, mark packet-derived text as data, and never let a
  model's output trigger an action.
- **Size and scope.** Roughly one more round of work. A cloud option would need TLS, which means
  either a large dependency or calling the installed `curl`; that trade-off is open.

### Open decisions for the owner

1. Local model only, or local with an optional cloud model.
2. A question box inside the screen, a `netmon ask` command, or both.
3. Which local model, once it is known what this computer can run.

### When

After rounds 1 to 3. The model's input is the conversation tracking and stories that rounds 1 and 2 build.

---

## 20. Later idea: a Tauri desktop app (owner, 2026-10-13)

The owner said: eventually making this a Tauri app would be good, **on the condition that the web
view works**. Not approved for building yet.

- **Condition:** first confirm the web page works properly in a browser against a live `netmon web`.
  Only then consider wrapping it.
- **Why it fits:** Tauri puts a web page in a native window with a Rust backend, and netmon already
  has both halves: the React page in `web/` and the Rust engine. The page would be reused as it is.
- **What would change:** the page would talk to the Rust side through Tauri commands or keep using
  the local HTTP API; a window replaces "open this link in your browser".
- **Costs to weigh then:** Tauri needs system WebKitGTK development packages on Linux and a larger set
  of Rust dependencies, so the small-binary goal would apply only to the command-line build. Codex's
  sandbox has no network, so those dependencies must be installed beforehand.
