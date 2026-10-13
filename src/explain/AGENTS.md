# Wording — area guide

Applies to `src/explain.rs` and everything in `src/explain/`. Read the root `AGENTS.md` first.

The explanation text is the product. A user learns networking from these sentences, so they must be
correct, plain and specific.

## What lives where

| Path | Holds |
|---|---|
| `src/explain.rs` | The module root only: `mod` lines and re-exports. Other code writes `crate::explain::sentence`, `crate::explain::field_text`, `crate::explain::GLOSSARY` |
| `src/explain/sentence/` | The one-line sentence per packet, one file per protocol family |
| `src/explain/fields/` | The label and three-part text for every `FieldKey`, one file per protocol family; `meanings.rs` holds the shared "what this value implies" helpers |
| `src/explain/tables.rs` | Name tables: ports, IP protocols, EtherTypes, TLS and DNS names |
| `src/explain/values.rs` | Small value formatters: TCP flag names, checksum status, hidden HTTP header values |
| `src/explain/glossary.rs` | The glossary |
| `src/explain/cli.rs` | Command-line messages |
| `src/explain/flows.rs` | Sentences that use conversation context; story steps; conversation titles |
| `src/explain/alerts.rs` | Alert titles, what was seen, why it matters |
| `src/explain/log.rs`, `src/explain/pipeline.rs` | Wording of log lines and of the session summary |
| `src/explain/ui.rs` | Screen labels, key help, filter help, layer descriptions |

A new area gets a new file here, declared with one `pub mod name;` line in `src/explain.rs`.
Code outside this area must not contain user-facing sentences; it calls functions here.

Wording files grow fast. Keep each under the 500-line limit by splitting along the same lines as the
decoders: one file per protocol family (link, IP, ICMP, TCP, UDP, DNS, DHCP, HTTP, TLS, QUIC). New
text for a protocol goes in that protocol's file.

Explanation text is data, so it needs few code comments. What it does need: a file header, a doc
comment on each public function, and a comment wherever a statement rests on a specific RFC rule, so
the next person can check it.

## Writing standard

- Plain English, short sentences, present tense. Write for someone who has never read an RFC.
- Never use a technical term without saying what it means the first time it appears in that text.
- Say what the thing is **for**, not only what it is called. "TTL stops packets circling forever" beats
  "TTL is the time to live field".
- "Here" text must use the actual value and say what it implies for this packet.
- Prefer the concrete to the abstract: "the web server", "your computer", "the next router".
- Be accurate. If something is a likely guess, say "probably" or "usually". Never state a guess as fact.
- Do not say something that is true but useless ("64 remains"). Say what the reader can conclude.
- One idea per sentence. If a sentence needs a semicolon, split it.
- No jokes, no exclamation marks, no filler, no "simply" or "just".
- Numbers of bytes use thousands separators (`text::number`). Durations use the largest sensible unit
  (`412 µs`, `17 ms`, `2.4 s`).

## Rules for this area

- Field text is looked up with an exhaustive `match` on `FieldKey`, so the compiler refuses a missing
  entry. Keep it exhaustive; do not add a catch-all arm.
- `what` is required for every field. `here` is required wherever the value changes the meaning.
  `why` may be empty for purely structural fields.
- Text taken from packets is already sanitised by the decoders. Text from anywhere else (process names,
  file names) must be sanitised before it is put into a sentence.
- Never include a secret in a sentence.

## Golden files

`tests/golden/` holds the expected output. `NETMON_BLESS=1 cargo test --offline` rewrites them.
Bless only after reading the difference and confirming every changed line is an improvement.
Changing wording that another agent's golden file contains is a change to a file you do not own;
during parallel work, change only wording in your own files.
