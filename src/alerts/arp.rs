//! Detects changes in an ARP sender mapping.
//! ARP decoding belongs to `crate::decode::link`; wording belongs to `crate::explain::alerts`.
//! Read `Engine::arp_change` first.
//! ARP associates a local IPv4 address with the device MAC address used on that link.

use super::{Alert, AlertKind, Engine, Severity};
use crate::capture::RawPacket;
use crate::decode::{AppInfo, Decoded};
use crate::explain::alerts as wording;
use std::net::IpAddr;

/// Retained sender MAC for one IPv4 address; no network-provided text is stored.
pub(super) struct Mapping {
    pub(super) mac: [u8; 6],
    /// Packet that first established the current mapping, before any repeated announcement.
    pub(super) first: u64,
}

impl Engine {
    /// Compares ARP request/reply sender mappings, ignoring incomplete senders and probes.
    pub(super) fn arp_change(&mut self, raw: &RawPacket, d: &Decoded, alerts: &mut Vec<Alert>) {
        let Some(AppInfo::Arp {
            operation: 1 | 2,
            sender_mac: Some(mac),
            sender_ip: Some(ip),
            ..
        }) = &d.summary.app
        else {
            return;
        };
        // ARP probes intentionally use 0.0.0.0 while testing an address, so their
        // changing MACs are not reassignment evidence (RFC 5227, 2.1.1).
        if ip.is_unspecified() {
            return;
        }
        let ip = IpAddr::V4(*ip);
        let previous = self.arp.get_mut(&ip).map(|entry| (entry.mac, entry.first));
        if let Some((old, first)) = previous {
            if old == *mac {
                return;
            }
            self.arp.insert(
                ip,
                Mapping {
                    mac: *mac,
                    first: raw.number,
                },
            );
            let gateway = self.gateway == Some(ip);
            let text = wording::arp_change(ip, old, *mac, gateway);
            alerts.extend(self.emit(
                raw,
                AlertKind::ArpChange,
                if gateway {
                    Severity::Serious
                } else {
                    Severity::Warning
                },
                first,
                ip,
                text,
            ));
        } else {
            self.arp.insert(
                ip,
                Mapping {
                    mac: *mac,
                    first: raw.number,
                },
            );
        }
    }
}
