//! Holds UDP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::port_meaning;
use super::meanings::transport_checksum;
use crate::decode::{Decoded, Field};
use crate::text::number;

/// Closed set of UDP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Src,
    Dst,
    Len,
    Checksum,
    Payload,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 768, Fields.
        Kind::Src => (
            "Source port",
            "Identifies the sending program's port. The IP address finds the computer, and the port helps find the program on it.",
            "",
        ),
        // RFC 768, Fields.
        Kind::Dst => (
            "Destination port",
            "Helps deliver data to the right program. The IP address finds the computer, and the port helps find the program on it.",
            "",
        ),
        // RFC 768, Fields.
        Kind::Len => (
            "Length",
            "Tells the receiver how many bytes belong to this UDP packet, including its eight-byte header.",
            "",
        ),
        // RFC 768, Fields.
        Kind::Checksum => (
            "Checksum",
            "Helps detect damaged UDP header or data bytes using a calculated check number, called a checksum. It also covers the IP addresses.",
            "A checksum can detect accidental damage, but it does not prove who sent the packet.",
        ),
        // RFC 768, Fields.
        Kind::Payload => (
            "Payload size",
            "Shows how many data bytes the UDP header declares. A cut-short capture may contain fewer bytes.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, _packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::Src | Kind::Dst => port_meaning(n as u16),
        Kind::Checksum if n == 0 => {
            // Zero means no UDP checksum in IPv4; IPv6 normally requires it (RFC 768; RFC 8200, section 8.1).
            // An ICMP quote can use a different IP version from the outer packet, so its summary cannot decide this.
            "Zero means no UDP checksum was supplied. IPv4 allows this, while IPv6 normally requires a nonzero checksum.".into()
        }
        Kind::Checksum => transport_checksum(&field.value),
        Kind::Len if n < 8 => format!(
            "{n} is too short to include the eight-byte UDP header. This is an invalid UDP length."
        ),
        Kind::Len => format!(
            "{} bytes: 8 header bytes and {} payload bytes.",
            number(n),
            number(n.saturating_sub(8))
        ),
        Kind::Payload => String::new(),
    }
}
