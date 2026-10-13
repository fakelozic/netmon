//! Packet processing library. Start with `capture::Reader` for saved traffic.
//! `capture` or `live` → `decode` → `explain` → `flow`, `names`, `procs`, `alerts`, `log`.
//! `filter` selects traffic in `store`; `ui` draws it and `render` prints explained packets.
//! `text` sanitises outside text and formats values; `sys` supports local time and interfaces.
//! Each module owns its part of this flow; command-line dispatch belongs to `main.rs`.

/// Bounded alert rules that describe observed traffic problems.
pub mod alerts;
/// Saved capture readers that preserve packet timestamps and link types.
pub mod capture;
/// Checked protocol decoders with field byte ranges and packet summaries.
pub mod decode;
/// Plain-English packet sentences, field explanations and interface wording.
pub mod explain;
/// Display filter parsing and matching against packet summaries.
pub mod filter;
/// Bounded conversation tracking driven by packet timestamps.
pub mod flow;
/// Live capture supervision and interface discovery through dumpcap.
pub mod live;
/// Session events, readable reports and optional packet recordings.
pub mod log;
/// Bounded hostname learning from captured DNS and application facts.
pub mod names;
/// Local socket ownership lookup for associating traffic with programs.
pub mod pipeline;
pub mod procs;
/// Plain-text packet explanations for the explain command.
pub mod render;
/// Bounded packet storage with an incrementally rebuilt filtered view.
pub mod store;
/// Operating-system helpers for local time and interface addresses.
pub mod sys;
/// Shared text sanitisation, value formatting and hex dumps.
pub mod text;
/// Terminal-independent screen state and the interactive terminal runner.
pub mod ui;
/// Loopback HTTP serving with bounded parsing and authenticated API dispatch.
pub mod web;
