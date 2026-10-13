//! Detects an accepted public inbound TCP request.
//! Local addresses come from `Engine::set_local`; wording belongs to `crate::explain::alerts`.
//! Read `Engine::unexpected_inbound` first.
//! SYN proposes a TCP connection, and SYN+ACK accepts the proposal before the final ACK.

use super::{Alert, AlertKind, Connection, Engine, Severity};
use crate::capture::RawPacket;
use crate::decode::Decoded;
use crate::explain::alerts as wording;
use std::net::IpAddr;

/// Opening request retained until a matching acceptance, refusal or eviction.
pub(super) struct Pending {
    pub(super) first: u64,
    /// SYN sequence number, compared modulo 2^32 when its acknowledgement arrives.
    pub(super) sequence: u32,
}

impl Engine {
    /// Matches reversed connection tuples and the SYN acknowledgement before warning.
    /// Unknown local addresses disable this rule; reset/close packets remove pending history.
    pub(super) fn unexpected_inbound(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        c: Connection,
        alerts: &mut Vec<Alert>,
    ) {
        if self.local.is_empty() {
            return;
        }
        let Some(tcp) = &d.summary.tcp else {
            return;
        };
        if tcp.flags & 0x04 != 0 {
            self.inbound.remove(&c);
            self.inbound.remove(&c.reverse());
        } else if tcp.flags & 0x12 == 0x02
            && Self::is_public(&c.source.0)
            && self.local.contains(&c.destination.0)
        {
            let same = self
                .inbound
                .get_mut(&c)
                .is_some_and(|pending| pending.sequence == tcp.seq);
            if !same {
                self.inbound.insert(
                    c,
                    Pending {
                        first: raw.number,
                        sequence: tcp.seq,
                    },
                );
            }
        } else if tcp.flags & 0x12 == 0x12 && self.local.contains(&c.source.0) {
            let reverse = c.reverse();
            // SYN uses one sequence number, compared modulo 2^32 (RFC 9293, 3.4).
            let matches = self
                .inbound
                .get(&reverse)
                .is_some_and(|pending| pending.sequence.wrapping_add(1) == tcp.ack);
            if matches && let Some(pending) = self.inbound.remove(&reverse) {
                let text = wording::inbound(c.destination.0, c.source.0, c.source.1);
                alerts.extend(self.emit(
                    raw,
                    AlertKind::UnexpectedInbound,
                    Severity::Warning,
                    pending.first,
                    c.destination.0,
                    text,
                ));
            }
        } else if tcp.flags & 0x01 != 0 {
            self.inbound.remove(&c);
            self.inbound.remove(&c.reverse());
        }
    }
}

/// Public unicast classification shared by inbound matching and the engine's public helper.
/// IPv4-mapped IPv6 follows the IPv4 result; no address triggers a lookup.
pub(super) fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && matches!(b, 18 | 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(mapped));
            }
            let [a, b, c, ..] = ip.segments();
            // Use a built-in conservative global-unicast classification, not observed routing.
            // Exclude special-purpose protocol and documentation blocks (RFC 6890, 2.2.3).
            a & 0xe000 == 0x2000
                && !(a == 0x2001
                    && (b == 0xdb8 || b < 0x200 && !matches!(b, 3 | 4) && !(b == 1 && c == 0)))
                && !(a == 0x3fff && b & 0xf000 == 0)
        }
    }
}
