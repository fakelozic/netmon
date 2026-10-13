//! Detects attempts to reach many destination ports.
//! Packet decoding belongs to `crate::decode`; alert text belongs to `crate::explain::alerts`.
//! Read `Engine::port_scan` first.
//! TCP SYN requests open byte streams; UDP sends independent messages to service ports.

use super::{Alert, AlertKind, Connection, Engine, PORTS, Seen, Severity, in_window};
use crate::capture::RawPacket;
use crate::decode::{Decoded, Proto};
use crate::explain::alerts as wording;
use std::collections::VecDeque;

/// Last observation of one distinct port, retaining its original packet reference.
pub(super) struct PortSeen {
    pub(super) port: u16,
    /// Latest timestamp determines whether the port still lies inside the window.
    pub(super) seen: Seen,
    pub(super) first_packet: u64,
}

impl Engine {
    /// Counts SYN-without-ACK or UDP destinations by source/destination address pair.
    /// Retains at most 1,024 distinct ports; missing complete transport headers are ignored.
    pub(super) fn port_scan(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        c: Connection,
        alerts: &mut Vec<Alert>,
    ) {
        // SYN starts synchronization, while ACK also acknowledges an existing request
        // (RFC 9293, 3.1 and 3.5). Count opening requests, not SYN+ACK replies.
        let syn = d
            .layers
            .iter()
            .any(|layer| layer.proto == Proto::Tcp && layer.range.len() >= 20)
            && d.summary
                .tcp
                .as_ref()
                .is_some_and(|tcp| tcp.flags & 0x12 == 0x02);
        let udp = d.summary.ip_proto == Some(17)
            && d.layers
                .iter()
                .any(|l| l.proto == Proto::Udp && l.range.len() >= 8);
        if !syn && !udp {
            return;
        }
        let pair = (c.source.0, c.destination.0);
        if self.scans.get(&pair).is_none() {
            self.scans.insert(pair, VecDeque::new());
        }
        let Some(ports) = self.scans.get_mut(&pair) else {
            return;
        };
        let first_packet = ports
            .iter()
            .find(|p| {
                p.port == c.destination.1 && in_window(raw.ts, p.seen.ts, self.config.scan_window)
            })
            .map_or(raw.number, |p| p.first_packet);
        ports.retain(|p| {
            in_window(raw.ts, p.seen.ts, self.config.scan_window) && p.port != c.destination.1
        });
        // Keep the most recently used ports if a sender exhausts the per-pair budget.
        if ports.len() == PORTS {
            ports.pop_front();
        }
        ports.push_back(PortSeen {
            port: c.destination.1,
            seen: raw.into(),
            first_packet,
        });
        let count = ports.len();
        let first = ports
            .iter()
            .map(|p| p.first_packet)
            .min()
            .unwrap_or(raw.number);
        if count < self.config.scan_ports.max(1) {
            return;
        }
        let severity = if self.local.contains(&pair.0) && self.local.contains(&pair.1) {
            Severity::Notice
        } else {
            Severity::Warning
        };
        let text = wording::port_scan(pair.0, pair.1, count, self.config.scan_window);
        alerts.extend(self.emit(raw, AlertKind::PortScan, severity, first, pair.0, text));
    }
}
