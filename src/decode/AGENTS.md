# Decoders — area guide

Applies to everything in `src/decode/`. Read the root `AGENTS.md` first; this adds to it.

## What this area does

`decode(link, data, orig_len, detail)` in `mod.rs` turns one packet's bytes into a `Decoded`:

- `layers` — one `Layer` per header, outermost first, each with its byte range and (in `Detail::Full`)
  a tree of `Field`s. Every field carries the byte range it occupies in the packet.
- `summary` — the facts other areas use: addresses, ports, TCP numbers, and `AppInfo` for what the
  application layer said.
- `truncated` — set when any header was cut short.

The chain is link (`link.rs`) → network (`ip.rs` dispatches to `ipv4.rs`, `ipv6.rs`, `icmp.rs`) →
transport (`transport.rs`) → application (`dns/`, `dhcp.rs`, `http.rs`, `tls/`, `quic.rs`). Each step
hands the rest of the bytes to the next.

Supporting files: `model.rs` (the result types: `Decoded`, `Layer`, `Field`, `Summary`, `TcpInfo`),
`app.rs` (`AppInfo` and its parts), `keys.rs` (`FieldKey`), `view.rs` (`View`), `context.rs`
(`Context`). `mod.rs` re-exports all of them, so other code writes `crate::decode::Summary`.

## The two helpers to use

- `View` — a checked window onto the packet. `get`, `u8`, `u16`, `u32`, `array`, `v4`, `v6` return
  `Option`; `tail` and `limit` never panic; `range(off, len)` gives the absolute byte range for a field.
- `Context` — builds the result. `layer(...)` starts a layer and marks truncation; `field`, `n` and
  `raw` add fields only in `Detail::Full`; `data(...)` records undecoded payload.

Read bytes only through `View`. Do not index slices directly.

## Rules for this area

- **`Summary` must be identical in `Detail::Summary` and `Detail::Full`.** Compute summary values
  outside the code that builds fields. `tests/fixtures_decode.rs` checks this.
- **Decoders hold no prose.** Labels, explanations and sentences are in `src/explain`. A decoder may
  build the short technical `Layer::line` (for example `51008 → 18080 [SYN] win=65495`).
- **Every field's range must lie inside the packet**, and must be the bytes that really hold the value.
  The screen highlights exactly those bytes.
- **A value that is missing is absent, not zero.** If a header is cut short, leave the field out or
  show `?`; never invent a 0.
- Text taken from a packet goes through `text::sanitise` before it is stored in a `String`.
- Mask secrets at decode time (HTTP `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`).

## Adding or changing a protocol: checklist

1. New protocol, new file. Start it with the RFC number and an RFC-style ASCII diagram of the header.
2. Add the `Proto` variant and its `name()`.
3. Add one `FieldKey` variant per field in `keys.rs`. The compiler will then refuse to build until
   `src/explain/fields/` has a label and a "what" text for each, in the file for that protocol family.
   Write them properly; do not stub.
4. If sentences or other areas need values from it, add or extend an `AppInfo` variant in `app.rs`.
5. Add the packet-list sentence in `src/explain/sentence/`, in the file for that protocol family.
6. Add a unit test with a hand-built packet beside the decoder, including a truncated version.
7. Run `tests/no_panic.rs`; it must still pass.

## Do not break other areas

Other code depends on the public names here (`Decoded`, `Layer`, `Field`, `FieldKey`, `Proto`, `Addr`,
`Summary`, `TcpInfo`, `AppInfo`, `ClientHello`, `tls::parse_client_hello`). Adding fields and variants
is fine. Renaming or removing them is not, unless your brief says so.
