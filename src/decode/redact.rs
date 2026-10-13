//! Chooses byte ranges that must stay private in decoded packet views.
//! HTTP wording stays in `explain::values`; raw recordings stay in `log::record`.
//! Read `hidden_ranges` before exposing bytes through a terminal or the API.
//! TCP payloads may begin in the middle of a credential split across packets.

// RFC 9110, sections 11.6.2 and 11.7.2: HTTP credentials are private values.
// +------------------+----------------------+
// | Header name      | Credential bytes ... |
// +------------------+----------------------+

use super::{Decoded, FieldKey, Proto};
use crate::explain;
use std::ops::Range;

/// Returns ordered, nonoverlapping private ranges, clipped to captured bytes.
/// Unparsed TCP payload and HTTP bodies are private because packet-local decoding
/// cannot establish that a continuation or form body is free of credentials.
pub(crate) fn hidden_ranges(decoded: &Decoded, len: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let opaque_tcp = decoded.summary.ip_proto == Some(6)
        && !decoded.layers.iter().any(|l| l.proto == Proto::Tls);
    for layer in &decoded.layers {
        if opaque_tcp && layer.proto == Proto::Data {
            ranges.push(layer.range.clone());
        }
        for field in &layer.fields {
            if (field.key == FieldKey::HttpHeader
                && (field.value == explain::HIDDEN_HEADER
                    || field
                        .value
                        .split_once(':')
                        .is_some_and(|(name, _)| explain::http_sensitive_header(name))))
                || (field.key == FieldKey::HttpTarget && field.value == explain::HIDDEN_HEADER)
            {
                ranges.push(field.range.clone());
            }
        }
    }
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        let start = range.start.min(len);
        let end = range.end.min(len);
        if start >= end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && start <= last.end
        {
            last.end = last.end.max(end);
        } else {
            merged.push(start..end);
        }
    }
    merged
}
