//! Explains TLS packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `client`.

use crate::decode::Proto;
use crate::explain::tls_version;
use crate::text::number;

/// Formats the decoded client facts without reading packet bytes.
pub(super) fn client(h: &crate::decode::ClientHello) -> String {
    format!(
        "Starts encryption (TLS Client Hello){}",
        h.server_name
            .as_ref()
            .map(|n| format!(" for {n}"))
            .unwrap_or_default()
    )
}

/// Formats the decoded server facts without reading packet bytes.
pub(super) fn server(version: &u16) -> String {
    format!(
        "Agrees on encryption settings (TLS Server Hello, {})",
        tls_version(*version)
    )
}

/// Formats the decoded records facts without reading packet bytes.
pub(super) fn records(
    d: &crate::decode::Decoded,
    content_types: &[u8],
    encrypted_bytes: &u32,
    handshake: &bool,
) -> String {
    if d.layers
        .iter()
        .any(|l| l.proto == Proto::Tls && l.range.len() < 5)
    {
        "TLS record header is incomplete".into()
    } else if *handshake || content_types.contains(&21) {
        "Continues the TLS handshake".into()
    } else if content_types.contains(&20) {
        "Switches to encrypted mode (TLS Change Cipher Spec)".into()
    } else {
        format!(
            "Sends {} bytes of encrypted data",
            number(u64::from(*encrypted_bytes))
        )
    }
}
