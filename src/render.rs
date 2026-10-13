//! Renders decoded packets as plain text for the explain command.
//! Protocol wording belongs to `explain`; byte decoding belongs to `decode`.
//! Start with `Renderer`.

use crate::capture::RawPacket;
use crate::decode::{self, Decoded, Detail, Field};
use crate::{explain, text};
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::time::Duration;

/// The explain command output format; `Packet(n)` selects a one-based packet number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One explained row per packet.
    Default,
    /// Tab-separated facts with Unix-epoch timestamps.
    Tsv,
    /// Packet rows followed by the decoded field tree.
    Fields,
    /// A one-based selected packet with explanations and a hex dump.
    Packet(u64),
}
/// Returns the column header for a mode, including its final newline.
pub fn header(mode: Mode) -> &'static str {
    if mode == Mode::Tsv {
        "#number\ttime_epoch\tsrc\tdst\tsrc_port\tdst_port\tip_proto\twire_len\ttcp_flags\ttcp_seq\ttcp_ack\tproto\tsentence\n"
    } else {
        "   No        Time  From                   To                     Proto    Bytes  What is happening\n"
    }
}
/// Formats seconds since the Unix epoch with exactly nine fractional decimal digits.
pub fn epoch(ts: Duration) -> String {
    format!("{}.{:09}", ts.as_secs(), ts.subsec_nanos())
}
fn relative(ts: Duration, first: Duration) -> String {
    let (sign, d) = if ts >= first {
        ("", ts.saturating_sub(first))
    } else {
        ("-", first.saturating_sub(ts))
    };
    format!("{sign}{}.{:06}", d.as_secs(), d.subsec_micros())
}
/// Formats one decoded packet; `first` is the first packet timestamp used as the relative-time origin.
pub fn packet(raw: &RawPacket, d: &Decoded, first: Duration, mode: Mode) -> String {
    let s = &d.summary;
    let mut out = String::new();
    if mode == Mode::Tsv {
        let cells = vec![
            raw.number.to_string(),
            epoch(raw.ts),
            s.src.as_ref().map(text::address).unwrap_or_default(),
            s.dst.as_ref().map(text::address).unwrap_or_default(),
            s.src_port.map(|n| n.to_string()).unwrap_or_default(),
            s.dst_port.map(|n| n.to_string()).unwrap_or_default(),
            s.ip_proto.map(|n| n.to_string()).unwrap_or_default(),
            s.wire_len.to_string(),
            s.tcp
                .as_ref()
                .map(|t| format!("0x{:04x}", t.flags))
                .unwrap_or_default(),
            s.tcp
                .as_ref()
                .map(|t| t.seq.to_string())
                .unwrap_or_default(),
            s.tcp
                .as_ref()
                .map(|t| t.ack.to_string())
                .unwrap_or_default(),
            s.proto.name().into(),
            explain::sentence(d),
        ];
        let _ = writeln!(out, "{}", cells.join("\t"));
        return out;
    }
    let _ = writeln!(
        out,
        "{:>5}  {:>10}  {:<21}  {:<21}  {:<7}  {:>6}  {}",
        raw.number,
        relative(raw.ts, first),
        text::endpoint(s.src.as_ref(), s.src_port),
        text::endpoint(s.dst.as_ref(), s.dst_port),
        s.proto.name(),
        s.wire_len,
        explain::sentence(d)
    );
    let full = matches!(mode, Mode::Packet(_));
    if mode == Mode::Fields || full {
        for l in &d.layers {
            let _ = writeln!(
                out,
                "      {}  [{}..{}]  {}",
                l.proto.name(),
                l.range.start,
                l.range.end,
                l.line
            );
            fields(&mut out, &l.fields, 4, d, full);
        }
    }
    if full {
        // Field masking alone is insufficient: a raw dump would reveal the same secret.
        let mut bytes = raw.data.clone();
        for range in decode::hidden_ranges(d, bytes.len()) {
            if let Some(hidden) = bytes.get_mut(range) {
                hidden.fill(0);
            }
        }
        out.push_str(&text::hex_dump(&bytes));
    }
    out
}
fn fields(out: &mut String, items: &[Field], level: usize, d: &Decoded, full: bool) {
    for f in items {
        let text = explain::field_text(f, d);
        let pad = "  ".repeat(level);
        let _ = writeln!(
            out,
            "{pad}{}  [{}..{}]  {}",
            text.label, f.range.start, f.range.end, f.value
        );
        if full {
            let _ = writeln!(out, "{pad}    What: {}", text.what);
            if !text.here.is_empty() {
                let _ = writeln!(out, "{pad}    Here: {}", text.here);
            }
            if !text.why.is_empty() {
                let _ = writeln!(out, "{pad}    Why:  {}", text.why);
            }
        }
        fields(out, &f.children, level.saturating_add(1), d, full);
    }
}

/// A streaming packet renderer that remembers the first packet timestamp for relative times.
pub struct Renderer<W: Write> {
    output: W,
    mode: Mode,
    first: Option<Duration>,
}
impl<W: Write> Renderer<W> {
    /// Writes the output header immediately; returns any error from the supplied writer.
    pub fn new(mut output: W, mode: Mode) -> io::Result<Self> {
        output.write_all(header(mode).as_bytes())?;
        Ok(Self {
            output,
            mode,
            first: None,
        })
    }
    /// Decodes and writes a packet at the detail required by the mode; the first input sets the time origin.
    pub fn write_packet(&mut self, raw: &RawPacket) -> io::Result<()> {
        let first = *self.first.get_or_insert(raw.ts);
        if matches!(self.mode,Mode::Packet(n) if n!=raw.number) {
            return Ok(());
        }
        let detail = if matches!(self.mode, Mode::Fields | Mode::Packet(_)) {
            Detail::Full
        } else {
            Detail::Summary
        };
        let d = decode::decode(raw.link, &raw.data, raw.orig_len, detail);
        self.output
            .write_all(packet(raw, &d, first, self.mode).as_bytes())
    }
    /// Flushes the output writer and returns its I/O error, if any.
    pub fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
    /// Returns the owned writer without flushing it; call `flush` first if buffering requires it.
    pub fn into_inner(self) -> W {
        self.output
    }
}
