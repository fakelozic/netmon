//! Holds QUIC field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use crate::decode::{Decoded, Field};

/// Closed set of QUIC fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Form,
    Version,
    Type,
    DstLen,
    DstId,
    SrcLen,
    SrcId,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 9000, section 17.2–17.3.
        Kind::Form => (
            "Header form",
            "Tells the receiver whether this QUIC packet uses the long header used during setup or a short header for an established connection.",
            "",
        ),
        // RFC 9000, section 17.2.1.
        Kind::Version => (
            "Version",
            "Tells the receiver which QUIC rules to use. Zero marks a reply listing the versions the server supports.",
            "",
        ),
        // RFC 9000, section 17.2.
        Kind::Type => (
            "Packet type",
            "Identifies the setup step of a long-header QUIC packet, such as starting a connection or asking the client to try again.",
            "",
        ),
        // RFC 9000, section 17.2.
        Kind::DstLen => (
            "Destination identifier length",
            "Tells the receiver how many bytes to read for the destination connection's label.",
            "",
        ),
        // RFC 9000, section 5.1.
        Kind::DstId => (
            "Destination connection identifier",
            "Helps the receiving computer find the connection even if an IP address or port changes.",
            "",
        ),
        // RFC 9000, section 17.2.
        Kind::SrcLen => (
            "Source identifier length",
            "Tells the receiver how many bytes to read for the source connection's label.",
            "",
        ),
        // RFC 9000, section 5.1.
        Kind::SrcId => (
            "Source connection identifier",
            "Gives the other computer a connection label it can put in replies.",
            "",
        ),
    }
}

/// Interprets visible QUIC setup fields; identity bytes give no further conclusion.
pub(super) fn here(key: Kind, field: &Field, packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        // RFC 9000, section 17.2.1: version zero makes type bits meaningless.
        Kind::Type if matches!(packet.summary.app, Some(crate::decode::AppInfo::Quic { version: Some(0), .. })) => "Version zero marks version negotiation, so these type bits do not name a setup step.".into(),
        Kind::Type => match n {
            0 => "Initial starts encryption setup, though it can also carry a repeated setup message.",
            1 => "Early data carries application bytes before the current encryption setup finishes.",
            2 => "Handshake carries encryption setup messages.",
            3 => "Retry asks the client to try again with a token supplied by the server.",
            _ => "",
        }.into(),
        Kind::Form => if n == 0 { "The short header is used after setup. Port and header bits suggest QUIC, but this detection alone is not proof." } else { "The long header exposes version and connection labels used during setup." }.into(),
        Kind::Version if n == 0 => "Zero marks a server reply listing supported QUIC versions. This packet is not encrypted.".into(),
        Kind::Version if n == 1 => "Version 1 selects the original standard QUIC header rules.".into(),
        Kind::Version if n == 0x6b3343cf => "Version 2 changes the setup packet type assignments, among other rules.".into(),
        Kind::Version | Kind::DstLen | Kind::DstId | Kind::SrcLen | Kind::SrcId => String::new(),
    }
}
