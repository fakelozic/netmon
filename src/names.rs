//! Bounded passive address labels.
//! Conversation-specific TLS/HTTP names stay on `flow::Flow`.
//! Read `Names::learn` for precedence, then `Names::label` for display order.
use crate::{explain::flows, text};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

// Match the brief's address cap; local labels use the same finite bound.
const MAX_NAMES: usize = 20_000;
// DNS names are short, but HTTP hints need an independent bound on stored text.
const MAX_NAME_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Address scope, not proof that a host is reachable. Public is the remaining class.
/// IPv6 has no broadcast class; IPv4-mapped IPv6 uses the IPv4 classification.
pub enum AddrClass {
    Unspecified,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Broadcast,
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Evidence source for an address alias. DNS/mDNS outrank TLS/HTTP hints.
pub enum NameSource {
    Dns,
    Mdns,
    Tls,
    Http,
}
impl NameSource {
    // Wire answers take precedence over names suggested by a single application.
    fn priority(self) -> u8 {
        match self {
            Self::Dns | Self::Mdns => 1,
            Self::Tls | Self::Http => 0,
        }
    }
}

struct Entry {
    name: String,
    source: NameSource,
    used: Cell<u64>,
}

/// Up to 20,000 sanitised address aliases, evicted by least recent lookup or learn.
/// Local addresses and the optional gateway have display priority over aliases.
pub struct Names {
    entries: HashMap<IpAddr, Entry>,
    clock: Cell<u64>,
    local: HashSet<IpAddr>,
    gateway: Option<IpAddr>,
}
impl Default for Names {
    fn default() -> Self {
        Self::new()
    }
}
impl Names {
    /// Create an empty table with no local addresses and no gateway.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            clock: Cell::new(0),
            local: HashSet::new(),
            gateway: None,
        }
    }

    /// Classify IPv4/IPv6 scope without network access or interface masks.
    /// Only 255.255.255.255 is classified as IPv4 broadcast; subnet masks are unavailable.
    pub fn classify(ip: &IpAddr) -> AddrClass {
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            return Self::classify(&IpAddr::V4(v4));
        }
        // IPv4 scopes follow RFC 1122, 3.2.1.3; IPv6 scopes follow RFC 4291, 2.4.
        if ip.is_unspecified() {
            AddrClass::Unspecified
        } else if ip.is_loopback() {
            AddrClass::Loopback
        } else if ip.is_multicast() {
            AddrClass::Multicast
        } else {
            match ip {
                IpAddr::V4(a) if a.is_broadcast() => AddrClass::Broadcast,
                IpAddr::V4(a) if a.is_private() => AddrClass::Private,
                IpAddr::V4(a) if a.is_link_local() => AddrClass::LinkLocal,
                IpAddr::V6(a) if a.is_unique_local() => AddrClass::Private,
                IpAddr::V6(a) if a.is_unicast_link_local() => AddrClass::LinkLocal,
                _ => AddrClass::Public,
            }
        }
    }

    fn stamp(&self) -> u64 {
        let stamp = self.clock.get().saturating_add(1);
        self.clock.set(stamp);
        stamp
    }

    /// Remember a name hint, sanitised and limited to 1,024 input bytes.
    /// Empty names do nothing. A full table drops the least recently used address.
    /// Newest hints win within an equal-priority source group.
    pub fn learn(&mut self, ip: IpAddr, name: &str, source: NameSource) {
        if name.is_empty() {
            return;
        }
        let used = self.stamp();
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.used.set(used);
            if source.priority() < entry.source.priority() {
                return;
            }
        } else if self.entries.len() >= MAX_NAMES {
            // The address breaks ties deterministically if the counter ever saturates.
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(ip, entry)| (entry.used.get(), **ip))
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                self.entries.remove(&ip);
            }
        }
        let bytes = name.as_bytes();
        let name = text::sanitise(
            bytes
                .get(..bytes.len().min(MAX_NAME_BYTES))
                .unwrap_or_default(),
        );
        self.entries.insert(
            ip,
            Entry {
                name,
                source,
                used: Cell::new(used),
            },
        );
    }

    /// Return the learned alias, or None if absent; a successful lookup refreshes LRU age.
    pub fn name_of(&self, ip: &IpAddr) -> Option<&str> {
        let entry = self.entries.get(ip)?;
        entry.used.set(self.stamp());
        Some(&entry.name)
    }

    /// Replace this computer's addresses, retaining at most 20,000 input entries.
    /// An empty list clears local labels; loopback is not implicitly considered local.
    pub fn set_local(&mut self, addrs: &[IpAddr]) {
        self.local = addrs.iter().take(MAX_NAMES).copied().collect();
    }

    /// Set the router address; None clears its special display label.
    pub fn set_gateway(&mut self, ip: Option<IpAddr>) {
        self.gateway = ip;
    }

    /// Test membership in the addresses supplied by `set_local`.
    pub fn is_local(&self, ip: &IpAddr) -> bool {
        self.local.contains(ip)
    }

    /// Return local label, router label, learned name, or the numeric address, in that order.
    pub fn label(&self, ip: &IpAddr) -> String {
        if self.is_local(ip) {
            flows::THIS_COMPUTER.into()
        } else if self.gateway.as_ref() == Some(ip) {
            flows::ROUTER.into()
        } else {
            self.name_of(ip)
                .map(str::to_owned)
                .unwrap_or_else(|| ip.to_string())
        }
    }
}
