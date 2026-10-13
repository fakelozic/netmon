//! Host address discovery from procfs routing information.
//! Socket ownership stays in scan.rs; no active address queries are sent.
//! Read local_addresses first for the source files and deduplication rule.
//! A default gateway is the router used when no more specific IPv4 route matches.

use super::reader::read_lines;
use super::sockets::{normalise_ip, parse_ipv4};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

// Large routing tables still need a finite traversal and output bound.
const MAX_ADDRESS_LINES: usize = 200_000;

/// Sorted, deduplicated addresses from IPv4 `/32 host LOCAL` routes and IPv6 interfaces.
/// Loopback is included when present. Missing or malformed files give a partial
/// list, possibly empty. Each source is capped at 200,000 lines.
/// An IPv4 address counts only when the immediately following line contains
/// both `/32` and `host LOCAL`; network prefix bases are excluded.
pub fn local_addresses(proc_root: &Path) -> Vec<IpAddr> {
    let mut addresses = BTreeSet::new();
    let mut candidate = None;
    let mut remaining = MAX_ADDRESS_LINES;
    read_lines(&proc_root.join("net/fib_trie"), &mut remaining, |bytes| {
        let Ok(line) = std::str::from_utf8(bytes) else {
            candidate = None;
            return;
        };
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let local =
            fields.contains(&"/32") && fields.windows(2).any(|pair| pair == ["host", "LOCAL"]);
        // Only a host route names one computer; a shorter prefix names a network.
        // Consume the candidate on every line so a later route cannot claim it.
        if local {
            if let Some(address) = candidate.take() {
                addresses.insert(IpAddr::V4(address));
            }
        } else {
            candidate = line
                .trim_start()
                .strip_prefix("|--")
                .and_then(|text| text.trim().parse::<Ipv4Addr>().ok());
        }
    });
    let mut remaining = MAX_ADDRESS_LINES;
    read_lines(&proc_root.join("net/if_inet6"), &mut remaining, |bytes| {
        if let Ok(line) = std::str::from_utf8(bytes)
            && let Some(hex) = line.split_ascii_whitespace().next()
            && hex.len() == 32
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            && let Ok(value) = u128::from_str_radix(hex, 16)
        {
            // Unlike tcp6, if_inet6 prints the address in network order.
            addresses.insert(normalise_ip(IpAddr::V6(Ipv6Addr::from(value))));
        }
    });
    addresses.into_iter().collect()
}

/// First IPv4 default route with the gateway flag set, in file order.
/// `None` means no eligible readable row was found within 200,000 lines.
pub fn default_gateway(proc_root: &Path) -> Option<Ipv4Addr> {
    let mut gateway = None;
    let mut remaining = MAX_ADDRESS_LINES;
    read_lines(&proc_root.join("net/route"), &mut remaining, |bytes| {
        if gateway.is_some() {
            return;
        }
        let Ok(line) = std::str::from_utf8(bytes) else {
            return;
        };
        let mut fields = line.split_ascii_whitespace();
        let Some((destination, address, flags)) = fields
            .next()
            .and_then(|_| fields.next())
            .zip(fields.next())
            .zip(fields.next())
            .map(|((destination, address), flags)| (destination, address, flags))
        else {
            return;
        };
        // A zero destination also occurs on direct routes; the gateway bit
        // distinguishes forwarding through a router from a directly attached link.
        if destination == "00000000"
            && u32::from_str_radix(flags, 16).is_ok_and(|flags| flags & 2 != 0)
        {
            gateway = parse_ipv4(address);
        }
    });
    gateway
}
