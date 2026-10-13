//! Explains TRANSPORT packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `packet`.

use crate::decode::Proto;
use crate::explain::{IP_PROTOCOLS, service};
use crate::text::number;

/// Formats the decoded packet facts without reading packet bytes.
pub(super) fn packet(d: &crate::decode::Decoded) -> String {
    let s = &d.summary;
    if let Some(offset) = s.fragment_offset.filter(|n| *n != 0) {
        format!("Fragment of a larger packet (offset {offset})")
    } else if s.tcp.is_some()
        && d.layers
            .iter()
            .any(|l| l.proto == Proto::Tcp && l.range.len() < 14)
    {
        "TCP header is incomplete".into()
    } else if let Some(t) = &s.tcp {
        let n = number(u64::from(t.payload_len));
        if t.flags & 2 != 0 {
            if t.flags & 16 == 0 {
                "Opens a connection (SYN) — handshake 1 of 3".into()
            } else {
                "Accepts the connection (SYN+ACK) — handshake 2 of 3".into()
            }
        } else if t.flags & 4 != 0 {
            "Aborts or refuses the connection (RST)".into()
        } else if t.flags & 1 != 0 {
            if t.payload_len == 0 {
                "Finished sending, closing politely (FIN)".into()
            } else {
                format!("Sends {n} bytes of data and finishes (FIN)")
            }
        } else if t.payload_len > 0 {
            format!("Sends {n} bytes of data")
        } else if t.flags & 16 != 0 {
            "Acknowledges data received (ACK)".into()
        } else {
            "TCP segment with no data".into()
        }
    } else if s.proto == Proto::Udp && s.udp_payload_len.is_none() {
        "UDP header is incomplete".into()
    } else if s.proto == Proto::Arp {
        "ARP header is incomplete".into()
    } else if matches!(s.proto, Proto::Icmp | Proto::Icmpv6) {
        "ICMP header is incomplete".into()
    } else if s.proto == Proto::Udp {
        let known = s
            .dst_port
            .and_then(service)
            .or_else(|| s.src_port.and_then(service));
        format!(
            "Sends {} bytes over UDP{}",
            number(u64::from(s.udp_payload_len.unwrap_or(0))),
            known.map(|n| format!(" ({n})")).unwrap_or_default()
        )
    } else if let Some(n) = s.ip_proto {
        format!(
            "Carries IP protocol {n}{}",
            IP_PROTOCOLS
                .iter()
                .find_map(|(p, name)| (*p == n).then(|| format!(" ({name})")))
                .unwrap_or_default()
        )
    } else if let Some(n) = s.ether_type {
        format!("Unknown frame type 0x{n:04x}")
    } else {
        "Unrecognised packet data".into()
    }
}
