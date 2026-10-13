//! Explains QUIC packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `message`.

use crate::text::number;

/// Formats the decoded message facts without reading packet bytes.
pub(super) fn message(long: &bool, version: &Option<u32>, packet_type: &u8, bytes: &u32) -> String {
    if *long && *version == Some(0) {
        "Negotiates a QUIC version (version negotiation is not encrypted)".into()
    } else if *long && *packet_type == 3 {
        "Asks the client to retry QUIC setup (Retry is not encrypted)".into()
    } else if *long && *packet_type == 0 {
        "Starts a QUIC connection (encrypted from the first packet)".into()
    } else {
        format!(
            "Sends {} bytes over QUIC (encrypted)",
            number(u64::from(*bytes))
        )
    }
}
