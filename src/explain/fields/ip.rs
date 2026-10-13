//! Holds IP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::{address_meaning, hop_meaning};
use crate::decode::{Decoded, Field};
use crate::explain::IP_PROTOCOLS;
use crate::text::number;

/// Closed set of IP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    IpVersion,
    IpHeaderLen,
    IpDscp,
    IpEcn,
    IpTotalLen,
    IpId,
    IpFlags,
    IpDf,
    IpMf,
    IpFragmentOffset,
    IpTtl,
    IpProtocol,
    IpChecksum,
    IpSrc,
    IpDst,
    IpOptions,
    V6Version,
    V6TrafficClass,
    V6FlowLabel,
    V6PayloadLen,
    V6NextHeader,
    V6HopLimit,
    V6Src,
    V6Dst,
    V6Extension,
    V6ExtNext,
    V6ExtLen,
    V6ExtData,
    V6FragmentOffset,
    V6MoreFragments,
    V6FragmentId,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 791, section 3.1.
        Kind::IpVersion => (
            "Version",
            "Tells the receiver which IP rules to use to read the packet.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpHeaderLen => (
            "Header length",
            "Tells the receiver where the IPv4 header ends and the carried data begins.",
            "",
        ),
        // RFC 2474, section 3.
        Kind::IpDscp => (
            "Differentiated services code point",
            "Asks routers to give this packet a particular priority or handling policy.",
            "",
        ),
        // RFC 3168, section 5.
        Kind::IpEcn => (
            "Explicit congestion notification",
            "Lets a router mark a packet when it is too busy, so the computers can slow down without losing that packet.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpTotalLen => (
            "Total length",
            "Tells the receiver how many bytes belong to this IPv4 packet, including its header.",
            "",
        ),
        // RFC 6864, section 4.1.
        Kind::IpId => (
            "Identification",
            "Helps the receiver join pieces of a split packet, called fragments, back together.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpFlags => (
            "Flags",
            "Controls whether routers may split this packet and whether more pieces follow.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpDf => (
            "Don't fragment",
            "Tells routers to drop the packet if it is too large for the next link, instead of splitting it.",
            "A rejection can reveal a path's size limit.",
        ),
        // RFC 791, section 3.1.
        Kind::IpMf => (
            "More fragments",
            "Tells the receiver that more pieces of this split IPv4 packet follow.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpFragmentOffset => (
            "Fragment offset",
            "Tells the receiver where these data bytes fit in the original packet, measured in bytes.",
            "",
        ),
        // RFC 1812, section 5.3.1.
        Kind::IpTtl => (
            "Time to live",
            "Stops packets circling forever. Each router lowers this counter and drops the packet if it reaches zero.",
            "A changed count from the same computer may suggest a route change. The starting count can also change.",
        ),
        // RFC 791, section 3.1.
        Kind::IpProtocol => (
            "Protocol",
            "Tells the receiver what kind of data follows the IPv4 header, such as TCP or UDP.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpChecksum => (
            "Header checksum",
            "Helps detect damaged IPv4 header bytes using a calculated check number, called a checksum.",
            "An incorrect result suggests damaged header bytes or a checksum filled after capture. It does not check the carried data or prove who sent the packet.",
        ),
        // RFC 791, section 3.1.
        Kind::IpSrc => (
            "Source IP address",
            "Gives the IP address the packet claims to come from, so a reply can be sent back.",
            "The address alone does not authenticate the sender.",
        ),
        // RFC 791, section 3.1.
        Kind::IpDst => (
            "Destination IP address",
            "Gives the IP address routers use to deliver this packet to its destination.",
            "",
        ),
        // RFC 791, section 3.1.
        Kind::IpOptions => (
            "Options",
            "Carries extra instructions in the IPv4 header, such as asking routers to record the route.",
            "",
        ),
        // RFC 8200, section 3.
        Kind::V6Version => (
            "Version",
            "Tells the receiver which IP rules to use to read the packet.",
            "",
        ),
        // RFC 8200, section 7.
        Kind::V6TrafficClass => (
            "Traffic class",
            "Asks routers for a handling policy and allows busy routers to mark congestion, meaning too much traffic.",
            "",
        ),
        // RFC 6437, section 3.
        Kind::V6FlowLabel => (
            "Flow label",
            "Labels related packets so routers can keep their handling consistent.",
            "",
        ),
        // RFC 8200, section 3.
        Kind::V6PayloadLen => (
            "Payload length",
            "Tells the receiver how many bytes follow the fixed IPv6 header, including any extra headers.",
            "",
        ),
        // RFC 8200, section 3.
        Kind::V6NextHeader => (
            "Next header",
            "Tells the receiver what to read next: an extra IPv6 header or data such as TCP or UDP.",
            "",
        ),
        // RFC 8200, section 3.
        Kind::V6HopLimit => (
            "Hop limit",
            "Stops packets circling forever. Each router lowers this counter and drops the packet if it reaches zero.",
            "The starting count is unknown, so any estimate of routers crossed is a guess.",
        ),
        // RFC 8200, section 3.
        Kind::V6Src => (
            "Source IP address",
            "Gives the IP address the packet claims to come from, so a reply can be sent back.",
            "The address alone does not authenticate the sender.",
        ),
        // RFC 8200, section 3.
        Kind::V6Dst => (
            "Destination IP address",
            "Gives the IP address routers use to deliver this packet to its destination.",
            "",
        ),
        // RFC 8200, section 4.
        Kind::V6Extension => (
            "Extension header",
            "Carries extra IPv6 instructions between the main header and the data, such as how to join a split packet.",
            "",
        ),
        // RFC 8200, section 4.
        Kind::V6ExtNext => (
            "Next header",
            "Tells the receiver which header or kind of data follows this extra IPv6 header.",
            "",
        ),
        // RFC 8200, section 4.
        Kind::V6ExtLen => (
            "Extension length",
            "Tells the receiver where this extra IPv6 header ends and the next header begins.",
            "",
        ),
        // RFC 8200, section 4.
        Kind::V6ExtData => (
            "Extension contents",
            "Carries the instructions inside this extra IPv6 header as encoded bytes.",
            "",
        ),
        // RFC 8200, section 4.5.
        Kind::V6FragmentOffset => (
            "Fragment offset",
            "Tells the receiver where these data bytes fit in the original packet, measured in bytes.",
            "",
        ),
        // RFC 8200, section 4.5.
        Kind::V6MoreFragments => (
            "More fragments",
            "Tells the receiver that more pieces of this split IPv6 packet follow.",
            "",
        ),
        // RFC 8200, section 4.5.
        Kind::V6FragmentId => (
            "Fragment identification",
            "Helps the receiver group pieces that belong to the same original IPv6 packet.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, _packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::IpHeaderLen => format!(
            "{} bytes: the fixed 20-byte header plus {} bytes of extra settings.",
            number(n),
            number(n.saturating_sub(20))
        ),
        Kind::IpTotalLen => format!(
            "{} bytes belong to this IPv4 packet. The Ethernet or capture header is extra.",
            number(n)
        ),
        Kind::IpDf => {
            "Set. A router must drop this packet if its next link needs smaller packets.".into()
        }
        Kind::IpMf | Kind::V6MoreFragments => {
            "Set. The receiver needs more pieces before it can rebuild the complete packet.".into()
        }
        Kind::IpFragmentOffset | Kind::V6FragmentOffset => {
            if n == 0 {
                "These data bytes start at the beginning of the original packet. This can be an unsplit packet or its first piece.".into()
            } else {
                format!(
                    "These data bytes start {} bytes into the original packet. The receiver also needs the earlier pieces.",
                    number(n)
                )
            }
        }
        Kind::IpTtl | Kind::V6HopLimit => hop_meaning(n),
        Kind::IpEcn => ecn_meaning(n).into(),
        Kind::IpProtocol | Kind::V6NextHeader | Kind::V6ExtNext => protocol_meaning(n),
        Kind::IpSrc | Kind::IpDst | Kind::V6Src | Kind::V6Dst => address_meaning(&field.value),
        Kind::IpChecksum => format!(
            "{}. netmon checks the IPv4 header bytes, including this checksum, but not the carried data.",
            field.value
        ),
        Kind::IpVersion | Kind::V6Version => format!("{n} selects IPv{n} header rules."),
        Kind::V6PayloadLen => {
            // Zero can signal a jumbo payload in a hop-by-hop option (RFC 2675, section 2).
            if n == 0 {
                "Zero can mean no carried data or a size supplied by an extra header for a very large packet.".into()
            } else {
                format!(
                    "{} bytes follow the fixed 40-byte IPv6 header. Any extra IPv6 headers count toward this size.",
                    number(n)
                )
            }
        }
        Kind::IpDscp
        | Kind::IpId
        | Kind::IpFlags
        | Kind::IpOptions
        | Kind::V6TrafficClass
        | Kind::V6FlowLabel
        | Kind::V6Extension
        | Kind::V6ExtLen
        | Kind::V6ExtData
        | Kind::V6FragmentId => String::new(),
    }
}

fn protocol_meaning(n: u64) -> String {
    let protocol = IP_PROTOCOLS
        .iter()
        .find_map(|(p, name)| (u64::from(*p) == n).then_some(*name))
        .unwrap_or(match n {
            0 => "hop-by-hop options",
            43 => "a routing header",
            44 => "a fragment header",
            60 => "destination options",
            59 => "no further header",
            _ => "a format netmon does not recognise",
        });
    format!("{n} tells the receiver to read {protocol} next.")
}

fn ecn_meaning(n: u64) -> &'static str {
    // RFC 3168, section 5: 00 is not capable, 01/10 are capable, 11 marks congestion.
    match n {
        0 => "This packet does not support a router marking it to report too much traffic.",
        1 | 2 => {
            "A busy router may mark this packet to report too much traffic instead of dropping it."
        }
        3 => {
            "A router marked this packet to report too much traffic. The receiving computer can pass that warning back to the sender."
        }
        _ => "",
    }
}
