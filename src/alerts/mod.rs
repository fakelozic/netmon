//! Coordinates packet-time alert observations.
//! Protocol rules live in sibling modules; wording lives in `crate::explain::alerts`.
//! Read `Engine::observe` first.
//! A traffic pattern is evidence to inspect, not proof of an attacker.

mod arp;
mod credentials;
mod dns;
mod inbound;
mod scan;
mod table;

use crate::capture::RawPacket;
use crate::decode::{Addr, Decoded};
use crate::explain::alerts::{self as wording, Text};
use arp::Mapping;
use credentials::Telnet;
use inbound::Pending;
use scan::PortSeen;
use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;
use table::Table;

// These caps follow the alert brief: spoofed traffic must not grow history forever.
const PAIRS: usize = 4_096;
const PORTS: usize = 1_024;
const ARP_ENTRIES: usize = 8_192;
const DNS_CLIENTS: usize = 4_096;
const INBOUND: usize = 8_192;
// Suppression uses the same address budget as scan pairs and DNS clients.
const SUBJECTS: usize = 4_096;
// Bound caller-supplied local-address lists with the same address budget.
const LOCAL_ADDRESSES: usize = 4_096;

/// The five observed patterns. A kind identifies a rule, not a conclusion about intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AlertKind {
    PortScan,
    CleartextCredentials,
    ArpChange,
    SuspiciousDns,
    UnexpectedInbound,
}

/// How urgently an observation warrants inspection, independent of attack confidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Informational pattern, including scans confined to known local addresses.
    Notice,
    /// Pattern worth investigating, with plausible innocent explanations.
    Warning,
    /// Exposed credentials or a changed gateway mapping.
    Serious,
}

/// A secret-free observation with packet references and beginner explanations.
/// Formatting through `Display` prints severity, references, Seen, Why and Next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    /// Trigger packet time, unchanged from `RawPacket::ts` (capture-relative or epoch-based).
    pub ts: Duration,
    /// Capture packet number of the trigger, not an index into a retained packet buffer.
    pub packet: u64,
    /// Earliest retained evidence for this pattern, at or before the triggering packet.
    pub first_packet: u64,
    /// Source for scans/inbound, server for credentials, changed IP for ARP, client for DNS.
    /// Engine-generated alerts always contain `Some`; `None` means no address is supplied.
    pub subject: Option<IpAddr>,
    pub title: String,
    /// Observed facts and counts, without credential values or raw packet text.
    pub seen: String,
    pub why: &'static str,
    pub next: &'static str,
}

/// Packet-time thresholds; defaults are 20 ports/10 s, DNS 50/120 characters,
/// 20 missing-name replies/10 s and 60 s between repeats for a kind/subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Zero is treated as one. More than 1,024 ports cannot fit in the bounded history.
    pub scan_ports: usize,
    /// Inclusive look-back window measured from the current packet's timestamp.
    pub scan_window: Duration,
    /// Alert when a DNS wire label is strictly longer than this many characters.
    pub dns_label_len: usize,
    /// Alert when a DNS name including separating dots is strictly longer than this.
    pub dns_name_len: usize,
    /// Zero is treated as one. At most this many timestamps are retained per DNS client.
    pub nxdomain_count: usize,
    /// Inclusive packet-time look-back window for missing-name replies to one client.
    pub nxdomain_window: Duration,
    /// Minimum elapsed packet time between alerts of the same kind and subject.
    /// Zero disables interval suppression, but Telnet still fires once per conversation.
    pub repeat_after: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_ports: 20,
            scan_window: Duration::from_secs(10),
            dns_label_len: 50,
            dns_name_len: 120,
            nxdomain_count: 20,
            nxdomain_window: Duration::from_secs(10),
            repeat_after: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy)]
struct Seen {
    ts: Duration,
    packet: u64,
}
impl From<&RawPacket> for Seen {
    fn from(raw: &RawPacket) -> Self {
        Self {
            ts: raw.ts,
            packet: raw.number,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Connection {
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
}
impl Connection {
    fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
    fn canonical(self) -> Self {
        if self.source <= self.destination {
            self
        } else {
            self.reverse()
        }
    }
}

/// Owns bounded alert history, independent of flow tracking, logging and screens.
/// Full tables evict the least recently observed entry. Evicted history cannot be detected.
pub struct Engine {
    config: Config,
    local: Vec<IpAddr>,
    gateway: Option<IpAddr>,
    scans: Table<(IpAddr, IpAddr), VecDeque<PortSeen>>,
    arp: Table<IpAddr, Mapping>,
    dns: Table<IpAddr, VecDeque<Seen>>,
    inbound: Table<Connection, Pending>,
    telnet: Table<Connection, Telnet>,
    repeats: Table<(AlertKind, Option<IpAddr>), Duration>,
}

impl Engine {
    /// Starts empty history with caller-selected thresholds and no known local addresses.
    /// Inbound detection is off until `set_local` supplies addresses; the gateway is optional.
    pub fn new(config: Config) -> Engine {
        Self {
            config,
            local: Vec::new(),
            gateway: None,
            scans: Table::new(PAIRS),
            arp: Table::new(ARP_ENTRIES),
            dns: Table::new(DNS_CLIENTS),
            inbound: Table::new(INBOUND),
            telnet: Table::new(PAIRS),
            repeats: Table::new(SUBJECTS),
        }
    }

    /// Replaces this computer's addresses. An empty list turns inbound detection off.
    /// Retains the last 4,096 supplied addresses, deduplicated; removed locals lose pending SYNs.
    /// Supplying the same addresses again preserves pending inbound requests.
    pub fn set_local(&mut self, addrs: &[IpAddr]) {
        self.local.clear();
        // Configuration is bounded too. Retain the last addresses if an oversized list is supplied.
        for &addr in addrs.iter().rev().take(LOCAL_ADDRESSES) {
            if !self.local.contains(&addr) {
                self.local.push(addr);
            }
        }
        let invalid = self
            .inbound
            .values
            .keys()
            .copied()
            .filter(|connection| !self.local.contains(&connection.destination.0))
            .collect::<Vec<_>>();
        for connection in invalid {
            self.inbound.remove(&connection);
        }
    }

    /// Marks a gateway IP so a mapping change is Serious. `None` disables that escalation.
    pub fn set_gateway(&mut self, ip: Option<IpAddr>) {
        self.gateway = ip;
    }

    /// Feed each packet once, in capture order, with its corresponding `Detail::Summary` decode.
    /// Returns an empty list when no unsuppressed rule fires. Incomplete fields are ignored.
    /// Uses packet time only; a backward timestamp cannot advance the repeat interval.
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Vec<Alert> {
        let mut alerts = Vec::new();
        self.arp_change(raw, d, &mut alerts);
        self.suspicious_dns(raw, d, &mut alerts);
        if let Some(connection) = connection(d) {
            self.port_scan(raw, d, connection, &mut alerts);
            if d.summary.tcp.is_some() {
                self.credentials(raw, d, connection, &mut alerts);
                self.unexpected_inbound(raw, d, connection, &mut alerts);
            }
        }
        alerts
    }

    fn emit(
        &mut self,
        raw: &RawPacket,
        kind: AlertKind,
        severity: Severity,
        first_packet: u64,
        subject: IpAddr,
        text: Text,
    ) -> Option<Alert> {
        let key = (kind, Some(subject));
        if self
            .repeats
            .get(&key)
            .is_some_and(|last| raw.ts.saturating_sub(*last) < self.config.repeat_after)
        {
            return None;
        }
        self.repeats.insert(key, raw.ts);
        Some(Alert {
            kind,
            severity,
            ts: raw.ts,
            packet: raw.number,
            first_packet,
            subject: Some(subject),
            title: text.title,
            seen: text.seen,
            why: text.why,
            next: text.next,
        })
    }

    /// Classifies public unicast without a lookup; mapped IPv6 uses IPv4 classification.
    /// Private, loopback, multicast, documentation and reserved ranges return false.
    pub fn is_public(ip: &IpAddr) -> bool {
        inbound::is_public(ip)
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Notice => wording::NOTICE,
            Severity::Warning => wording::WARNING,
            Severity::Serious => wording::SERIOUS,
        };
        f.write_str(&wording::printed(
            severity,
            &self.title,
            (self.first_packet, self.packet),
            (&self.seen, self.why, self.next),
        ))
    }
}

fn ip_address(addr: Option<&Addr>) -> Option<IpAddr> {
    match addr {
        Some(Addr::V4(ip)) => Some((*ip).into()),
        Some(Addr::V6(ip)) => Some((*ip).into()),
        _ => None,
    }
}
fn connection(d: &Decoded) -> Option<Connection> {
    Some(Connection {
        source: (ip_address(d.summary.src.as_ref())?, d.summary.src_port?),
        destination: (ip_address(d.summary.dst.as_ref())?, d.summary.dst_port?),
    })
}
fn in_window(now: Duration, then: Duration, window: Duration) -> bool {
    now.checked_sub(then)
        .is_some_and(|elapsed| elapsed <= window)
}

#[cfg(test)]
#[path = "../../tests/alert_support/mod.rs"]
mod alert_support;
#[cfg(test)]
mod bounds;
