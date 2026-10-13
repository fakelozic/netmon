//! Projects stored packet bytes into compact rows and field trees.
//! Filter indexes stay in `packets`; JSON escaping stays in `records` and `log`.
//! Read `State::packet` for lazy full decoding and captured-byte ranges.
//! HTTP headers can carry credentials in otherwise readable traffic.

use super::{
    records::{ResultJson, elapsed, opt, opt_num},
    state::State,
    store::Entry,
};
use crate::{
    decode::{self, Addr, Decoded, Detail, Field},
    explain::{self, web as words},
    log::{Json, JsonValue as V},
    sys, text,
};
use std::{net::IpAddr, ops::Range};

// The API contract caps the raw view at 65,536 bytes to bound response size.
const MAX_HEX_BYTES: usize = 65_536;

fn ip(addr: Option<&Addr>) -> Option<IpAddr> {
    match addr? {
        Addr::V4(a) => Some((*a).into()),
        Addr::V6(a) => Some((*a).into()),
        _ => None,
    }
}
/// Encodes every compact row field, looking up the current process owner.
pub(super) fn row(state: &State, e: &Entry) -> V {
    let row = &e.row;
    let names = state.pipeline.tracker().names();
    let dir = ip(row.summary.src.as_ref())
        .zip(ip(row.summary.dst.as_ref()))
        .and_then(
            |(src, dst)| match (names.is_local(&src), names.is_local(&dst)) {
                (true, false) => Some("out"),
                (false, true) => Some("in"),
                _ => None,
            },
        );
    Json::object()
        .num("no", row.number)
        .value("time", V::float(elapsed(row.ts, state.first)))
        .value("clock", opt(sys::local_time(row.ts).as_deref()))
        .value(
            "src",
            opt(row
                .summary
                .src
                .as_ref()
                .map(|_| text::endpoint(row.summary.src.as_ref(), row.summary.src_port))
                .as_deref()),
        )
        .value(
            "dst",
            opt(row
                .summary
                .dst
                .as_ref()
                .map(|_| text::endpoint(row.summary.dst.as_ref(), row.summary.dst_port))
                .as_deref()),
        )
        .value(
            "src_label",
            opt(row.summary.src.as_ref().map(|_| row.src_label.as_str())),
        )
        .value(
            "dst_label",
            opt(row.summary.dst.as_ref().map(|_| row.dst_label.as_str())),
        )
        .value(
            "app",
            opt(row
                .flow
                .and_then(|id| state.app(id))
                .map(|a| a.name.as_str())),
        )
        .str("proto", row.summary.proto.name())
        .num("bytes", u64::from(e.raw.orig_len))
        .str("info", &row.sentence)
        .bool("problem", row.problem)
        .num("alerts", u64::from(row.alerts))
        .value("flow", opt_num(row.flow.map(|id| u64::from(id.0))))
        .value("dir", opt(dir))
        .into_value()
}
impl State {
    /// Lazily decodes retained bytes; absent or unpublished packets return 404.
    /// Secret header lines become zeros in hex and half-open packet-byte ranges
    /// in `hidden`, clipped to the returned hex view's 65,536-byte limit.
    pub fn packet(&self, number: u64) -> ResultJson {
        let e = self
            .store
            .get(number)
            .filter(|_| number <= self.cutoff())
            .ok_or((404, words::PACKET_GONE))?;
        let bytes = &e.raw.data;
        let decoded = decode::decode(e.raw.link, bytes, e.raw.orig_len, Detail::Full);
        let hex_len = bytes.len().min(MAX_HEX_BYTES);
        let hidden = decode::hidden_ranges(&decoded, hex_len);
        let hex = masked_hex(bytes, &hidden);
        let layers = decoded.layers.iter().map(|layer| {
            Json::object()
                .str("proto", layer.proto.name())
                .value(
                    "range",
                    range(layer.range.start, layer.range.end, bytes.len()),
                )
                .str("line", &layer.line)
                .str(
                    "about",
                    explain::GLOSSARY
                        .iter()
                        .find(|(term, _)| term.eq_ignore_ascii_case(layer.proto.name()))
                        .map_or("", |(_, t)| *t),
                )
                .value(
                    "fields",
                    V::array(
                        layer
                            .fields
                            .iter()
                            .map(|f| field(f, &decoded, bytes.len(), 0)),
                    ),
                )
                .into_value()
        });
        Ok(Json::object()
            .num("no", number)
            .value("time", V::float(elapsed(e.raw.ts, self.first)))
            .value("clock", opt(sys::local_time(e.raw.ts).as_deref()))
            .str("info", &e.row.sentence)
            .num("wire_len", u64::from(e.raw.orig_len))
            .num("captured_len", bytes.len() as u64)
            .bool("truncated", decoded.truncated)
            .value("flow", opt_num(e.row.flow.map(|id| u64::from(id.0))))
            .str("hex", &hex)
            .value(
                "hidden",
                V::array(hidden.iter().map(|r| range(r.start, r.end, hex_len))),
            )
            .value("layers", V::array(layers))
            .finish())
    }
}
fn field(f: &Field, decoded: &Decoded, len: usize, depth: usize) -> V {
    let words = explain::field_text(f, decoded);
    // Decoders already bound nesting; keep the projection bounded independently.
    let children = f
        .children
        .iter()
        .take(if depth < 32 { usize::MAX } else { 0 })
        .map(|f| field(f, decoded, len, depth + 1));
    Json::object()
        .str("label", words.label)
        .str("value", &f.value)
        .value("range", range(f.range.start, f.range.end, len))
        .str("what", words.what)
        .str("here", &words.here)
        .str("why", words.why)
        .value("children", V::array(children))
        .into_value()
}
fn range(start: usize, end: usize, len: usize) -> V {
    V::array([
        V::number(start.min(len) as u64),
        V::number(end.min(len).max(start.min(len)) as u64),
    ])
}

fn masked_hex(bytes: &[u8], hidden: &[Range<usize>]) -> String {
    // Both outputs use these same ranges, so no masked byte can be returned as hex
    // without a corresponding marker for the page. Byte positions stay unchanged.
    bytes
        .iter()
        .take(MAX_HEX_BYTES)
        .enumerate()
        .map(|(offset, byte)| {
            if hidden.iter().any(|range| range.contains(&offset)) {
                "00".into()
            } else {
                format!("{byte:02x}")
            }
        })
        .collect()
}
