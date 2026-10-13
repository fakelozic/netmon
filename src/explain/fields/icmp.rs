//! Holds ICMP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::{address_meaning, mac_meaning};
use crate::decode::AppInfo;
use crate::decode::Proto;
use crate::decode::{Decoded, Field};
use crate::explain::tables::{icmp_type, unreachable};

/// Closed set of ICMP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Type,
    Code,
    Checksum,
    Id,
    Seq,
    Embedded,
    Target,
    LinkOption,
    OptionType,
    OptionLen,
    OptionData,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 792, Message Formats; RFC 4443, section 2.1.
        Kind::Type => (
            "Message type",
            "Tells the receiver what this network report is for, such as a ping or a delivery failure.",
            "",
        ),
        // RFC 792, Message Formats; RFC 4443, section 2.1.
        Kind::Code => (
            "Message code",
            "Gives the reason for a network report in more detail, such as which part of delivery failed.",
            "",
        ),
        // RFC 792, Message Formats; RFC 4443, section 2.3.
        Kind::Checksum => (
            "Checksum",
            "Helps detect damaged control-message bytes using a calculated check number, called a checksum.",
            "",
        ),
        // RFC 792, Echo or Echo Reply Message; RFC 4443, section 4.
        Kind::Id => (
            "Echo identifier",
            "Helps the ping program recognise replies to its own requests.",
            "",
        ),
        // RFC 792, Echo or Echo Reply Message; RFC 4443, section 4.
        Kind::Seq => (
            "Echo sequence",
            "Numbers ping requests so the program can match each reply to a request.",
            "",
        ),
        // RFC 792, Destination Unreachable Message.
        Kind::Embedded => (
            "Quoted packet",
            "Includes part of the packet that caused a delivery error, so the sending computer can recognise the failed traffic.",
            "",
        ),
        // RFC 4861, section 4.3–4.4.
        Kind::Target => (
            "Target address",
            "Names the IPv6 address being looked up or announced on the local network.",
            "",
        ),
        // RFC 4861, section 4.6.1.
        Kind::LinkOption => (
            "Link-layer address",
            "Supplies a local hardware address so devices can deliver packets on this network.",
            "",
        ),
        // RFC 4861, section 4.6.
        Kind::OptionType => (
            "Option type",
            "Tells the receiver what this extra neighbour-discovery information contains. Neighbour discovery finds devices on the local IPv6 network.",
            "",
        ),
        // RFC 4861, section 4.6.
        Kind::OptionLen => (
            "Option length",
            "Tells the receiver where this extra neighbour-discovery information ends, measured in bytes.",
            "",
        ),
        // RFC 4861, section 4.6.
        Kind::OptionData => (
            "Option contents",
            "Carries extra information about local IPv6 devices or routers as encoded bytes.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::LinkOption => mac_meaning(&field.value),
        Kind::Target => address_meaning(&field.value),
        Kind::Checksum => format!(
            "{} is shown without verification. Only the IPv4 header checksum is checked here.",
            field.value
        ),
        Kind::Type => format!(
            "{n} means {}.",
            icmp_type(packet.summary.proto == Proto::Icmpv6, n as u8)
        ),
        Kind::Code => match &packet.summary.app {
            Some(AppInfo::Icmp { v6, kind, .. })
                if matches!((*v6, *kind), (false, 3) | (true, 1)) =>
            {
                format!("{n}: {}.", unreachable(*v6, n as u8))
            }
            // Echo messages require code zero (RFC 792, Echo or Echo Reply Message; RFC 4443, section 4).
            Some(AppInfo::Icmp { v6, kind, .. })
                if n == 0 && matches!((*v6, *kind), (false, 0 | 8) | (true, 128 | 129)) =>
            {
                "Zero is the required code for a ping request or reply.".into()
            }
            _ => String::new(),
        },
        Kind::Id
        | Kind::Seq
        | Kind::Embedded
        | Kind::OptionType
        | Kind::OptionLen
        | Kind::OptionData => String::new(),
    }
}
