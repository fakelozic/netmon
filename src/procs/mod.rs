//! Socket-owner lookup in the network namespace visible through `proc_root/net`.
//! Procfs traversal lives in scan.rs; snapshot scheduling lives in refresh.rs.
//! Read ProcTable::scan first for the partial-snapshot contract.
//! Use Refresher::start for polling, latest for snapshots, request_now for early scans.
//! Address labels come from local_addresses or default_gateway for the same root.
//! A socket is a kernel endpoint used for a TCP connection or UDP traffic.
//!
//! Sockets inside containers or other network namespaces do not appear in this
//! computer's `/proc/net`, so their traffic has no owner here.

mod addresses;
mod reader;
mod refresh;
mod scan;
mod sockets;

pub use addresses::{default_gateway, local_addresses};
pub use refresh::Refresher;

use sockets::{normalise_peer, normalise_socket, wildcard};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

/// Socket-table family. TCP uses IP protocol number 6; UDP uses number 17.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Transport {
    /// Connection-oriented sockets in `net/tcp` or `net/tcp6`.
    Tcp,
    /// Datagram sockets in `net/udp` or `net/udp6`.
    Udp,
}

/// Visible holder of a socket at scan time; this is not a lifetime guarantee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcInfo {
    /// Linux process identifier, in decimal when printed.
    pub pid: u32,
    /// `comm`, with its final newline removed and controls escaped by `text::sanitise`.
    /// At most 4 KiB of source bytes are read; escapes can expand the stored text.
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SocketKey {
    transport: Transport,
    local: SocketAddr,
    remote: SocketAddr,
}

/// Immutable ownership snapshot containing only endpoints with readable owners.
/// A fresh scan replaces the whole table, bounding growth across refreshes.
/// IPv4-mapped IPv6 endpoints are stored as IPv4 endpoints.
#[derive(Debug)]
pub struct ProcTable {
    owners: HashMap<SocketKey, Arc<ProcInfo>>,
    unreadable: usize,
}

impl ProcTable {
    /// An empty snapshot: zero owned sockets and zero observed access failures.
    pub fn empty() -> Self {
        Self {
            owners: HashMap::new(),
            unreadable: 0,
        }
    }

    /// Read a procfs root such as `/proc`; missing files never return an error.
    /// Malformed entries and vanished processes are skipped. Reaching the scan
    /// bounds returns a partial table: 200,000 table lines and 100,000 fd links.
    /// Shared sockets prefer the lowest readable PID other than 1.
    pub fn scan(proc_root: &Path) -> ProcTable {
        scan::scan(proc_root)
    }

    /// Find an owner by exact endpoints, then a bound any-peer socket, then a
    /// wildcard local address on the same port. `None` means no visible match.
    /// Connected sockets retain their peer. Address families stay separate after
    /// IPv4-mapped IPv6 normalisation; an IPv6 wildcard does not imply IPv4 support.
    pub fn lookup(
        &self,
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&ProcInfo> {
        let local = normalise_socket(local);
        let remote = normalise_peer(local, normalise_socket(remote));
        if local.is_ipv4() != remote.is_ipv4() {
            return None;
        }
        let any_remote = SocketAddr::new(wildcard(remote).ip(), 0);
        // A listener must not win over an established socket on its port.
        // Ignoring a connected socket's peer would assign unrelated traffic to it.
        for (local, remote) in [
            (local, remote),
            (local, any_remote),
            (wildcard(local), remote),
            (wildcard(local), any_remote),
        ] {
            if let Some(owner) = self.owners.get(&SocketKey {
                transport,
                local,
                remote,
            }) {
                return Some(owner.as_ref());
            }
        }
        None
    }

    /// Try the packet source as local before its destination. The returned bool
    /// is true for a source-side match (outgoing). Loopback can match both sides;
    /// source order resolves that ambiguity. Protocols other than 6 or 17, or
    /// packets with no visible socket owner, return `None`.
    pub fn lookup_packet(
        &self,
        ip_proto: u8,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<(&ProcInfo, bool)> {
        let transport = match ip_proto {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            _ => return None,
        };
        self.lookup(transport, src, dst)
            .map(|owner| (owner, true))
            .or_else(|| self.lookup(transport, dst, src).map(|owner| (owner, false)))
    }

    /// Count distinct normalised endpoint tuples with visible owners.
    /// Zero does not distinguish an empty namespace from an unreadable procfs root.
    pub fn sockets(&self) -> usize {
        self.owners.len()
    }

    /// Count processes with observed access failures, once per process.
    /// Vanished files and malformed non-link fd entries do not count. Zero means
    /// no such failure was observed among the bounded set of processes visited.
    pub fn unreadable(&self) -> usize {
        self.unreadable
    }

    /// Iterate owned endpoints for diagnostics; order is unspecified.
    /// Unowned sockets are absent, and an empty table yields no items.
    pub fn iter(&self) -> impl Iterator<Item = (Transport, SocketAddr, SocketAddr, &ProcInfo)> {
        self.owners
            .iter()
            .map(|(key, owner)| (key.transport, key.local, key.remote, owner.as_ref()))
    }
}
