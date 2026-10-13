# Task 09 — make the field explanations and glossary teach

Read the root `AGENTS.md` in full first, then `src/explain/AGENTS.md` (the writing standard is there),
`src/decode/AGENTS.md` and `tests/AGENTS.md`.

## Goal

The owner uses netmon to learn networking. The per-field explanations and the glossary are correct but
often read like a specification. Rewrite them so a beginner understands what each field is for and
what this packet's value tells them. **Accuracy comes first**: a clearer sentence that is wrong is
worse than a stiff one that is right.

## Parallel work

Two other agents are working at the same time, on the packets screen and on the pipeline. Their
branches contain golden files that quote the **one-line packet sentences**. So:

- **Do not change the one-line sentences** in `src/explain/sentence/` or `src/explain/flows.rs`, unless
  one states something false. If you find one, fix it and list it in your report.

**You own:** everything in `src/explain/fields/`, `src/explain/glossary.rs`, `src/explain/tables.rs`,
`src/explain/values.rs`, `tests/explain_golden.rs`, a new `tests/field_text.rs`, and the golden files
`tests/golden/packet-*.txt`.

**Also yours, for section 2 only:** `src/decode/ipv4.rs`, `src/decode/transport.rs` and any other
decoder file where a field is out of header order or shows a raw number.

Do not touch `src/explain.rs`, `src/main.rs`, or the `flow`, `names`, `procs`, `alerts`, `log`
modules and their tests.

## 1. What is wrong today (examples from real output)

| Today | Problem |
|---|---|
| Port: "A port is a number the operating system uses to deliver data to an application endpoint." | "Application endpoint" explains nothing. Say what a port is for: the IP address finds the computer, the port finds the program on it. |
| TTL here: "64 remains. It probably starts at 64, which suggests about 0 router hops; the starting value is not observed." | "64 remains" is not a conclusion. Say what the reader can conclude: most systems start at 64, 128 or 255, so this packet has probably not passed through any router. |
| Clear flag here: "The flag is clear. This flag does not request its action in this segment." | Says nothing. For a flag that is not set, write "Not set." and nothing more. |
| Glossary, handshake: "An exchange that establishes agreed settings before further communication." | Abstract. Describe the TCP three-packet handshake in plain words. |
| Glossary, window: "A TCP receiver's advertised limit on further unacknowledged bytes." | Jargon. Say it is how much more the receiver says it can take right now, and why that stops a fast sender overwhelming a slow receiver. |

These are examples of a pattern. Apply the fix to every field and glossary entry with the same fault.

## 2. Structure and values to fix in the decoders

A reader follows the field list alongside the header diagram, so order and form matter.

- **Fields appear in the order they occur in the header.** Today the TCP layer lists data offset and
  flags after the urgent pointer, and the IPv4 layer lists don't-fragment, more-fragments and fragment
  offset after the protocol. Put every layer's top-level fields in byte order.
- **Bits that belong to one field are its children.** IPv4 don't-fragment and more-fragments are
  children of Flags, as TCP's flag bits already are.
- **Flag sets show names, not a number.** IPv4 Flags shows `16384` today. Show it as TCP does:
  hex, then the names of the set bits, for example `0x4000 [DF]`.
- **Checksums and identifiers show as hex** (`0xfe31`), since that is how every other tool shows them.
  Counts, lengths and ports stay decimal.
- `num` keeps the numeric value in every case; only the display string changes.

Check every decoder for the same three faults, not only IPv4 and TCP.

## 3. How to write each piece

Follow `src/explain/AGENTS.md`. In addition:

- **`what`**: one or two sentences. First what the field is **for**, in words a beginner knows; the
  formal name may follow in brackets. Introduce at most one new term, and say what it means.
- **`here`**: one or two sentences about this packet's value: what it is, and what the reader can
  conclude. If nothing can be concluded, leave it empty rather than restating the value.
- **`why`**: at most two sentences: what going wrong looks like, or what to watch for. Empty when
  there is nothing worth watching.
- Prefer the concrete: "the web server", "your computer", "the next router", "the program that
  asked". Avoid "endpoint", "peer", "entity", "the sender's byte stream" unless you explain them.
- Use "packet" in explanations. The glossary explains once that a TCP packet is formally a segment,
  an Ethernet one a frame, and a UDP one a datagram.
- A comparison to everyday life is welcome where it truly clarifies (a port as a flat number in a
  building), and only once per idea. Do not stretch one.
- Each glossary entry: what it is in one plain sentence, then one sentence of how it shows up in
  netmon or why it matters. Add entries for terms the field text now uses and the glossary lacks.

## 4. Accuracy

- Check every statement against the RFC it rests on. Where a text states a protocol rule, add a code
  comment beside it citing the RFC section, as `AGENTS.md` requires.
- Say "usually" or "probably" where behaviour varies between systems (initial TTL, window scaling,
  temporary port ranges, checksum offload).
- In your report, list every statement you are not fully sure of, with the reason. Do not guess silently.

## 5. Tests

1. **`tests/field_text.rs`**, over every field of every packet in the three fixtures plus the built
   packets used by the decoder unit tests:
   - top-level fields of each layer are in non-decreasing byte order
   - every `what` is non-empty, ends with a full stop, and is at most 260 characters
   - no `here` text merely repeats the field's display value with nothing added
   - no text contains the phrases the examples in section 1 object to
     ("application endpoint", "does not request its action", "remains.")
   - a flag that is not set has `here` equal to `Not set.`
2. **Glossary**: sorted by term, no duplicates, every term from `tasks/01-engine.md` section 4.3 still
   present, every entry at most 320 characters.
3. **Golden**: regenerate `tests/golden/packet-*.txt` with `NETMON_BLESS=1`, then read every one of the
   seven files from top to bottom as a beginner would. Fix what is unclear and regenerate. The
   listing goldens (`loopback-list.txt`, `cooked-list.txt`, `flows-*`) must not change.
4. `tests/tshark_crosscheck.rs` and `tests/no_panic.rs` still pass: the decoded values are unchanged.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
git status --short tests/golden
./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng --packet 18
./target/release/netmon glossary
```

Expected: the size check prints nothing; `git status` shows only `packet-*.txt` changed; packet 18's
TCP fields are in header order with flags shown by name.

In the report, under "Built", paste the before and after text for five fields of your choice, so the
change can be judged at a glance.
