//! Interpretation of Linux socket-table rows.
//! Bounded I/O stays in reader.rs; ownership joins stay in scan.rs.
//! Read parse_socket first to see which columns identify an endpoint.
//! A socket inode is the kernel identifier shared by a table row and fd links.

use super::{SocketKey, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parse the endpoint columns and decimal inode; malformed rows return `None`.
pub(super) fn parse_socket(
    line: &[u8],
    transport: Transport,
    ipv6: bool,
) -> Option<(u64, SocketKey)> {
    let mut fields = std::str::from_utf8(line).ok()?.split_ascii_whitespace();
    parse_decimal(fields.next()?.strip_suffix(':')?)?;
    let local = parse_endpoint(fields.next()?, ipv6)?;
    let remote = normalise_peer(local, parse_endpoint(fields.next()?, ipv6)?);
    if !valid_hex(fields.next()?, 2)
        || !valid_hex_pair(fields.next()?, 8, 8)
        || !valid_hex_pair(fields.next()?, 2, 8)
        || !valid_hex(fields.next()?, 8)
    {
        return None;
    }
    parse_decimal(fields.next()?)?; // uid
    parse_decimal(fields.next()?)?; // timeout
    let inode = parse_decimal(fields.next()?)?;
    if inode == 0 {
        return None;
    }
    Some((
        inode,
        SocketKey {
            transport,
            local,
            remote,
        },
    ))
}

fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn valid_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_hex_pair(text: &str, first: usize, second: usize) -> bool {
    text.split_once(':')
        .is_some_and(|(a, b)| valid_hex(a, first) && valid_hex(b, second))
}

fn parse_endpoint(text: &str, ipv6: bool) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    if port.len() != 4 || !port.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if ipv6 {
        parse_ipv6(address).map(IpAddr::V6)?
    } else {
        parse_ipv4(address).map(IpAddr::V4)?
    };
    Some(normalise_socket(SocketAddr::new(address, port)))
}

/// Decode a Linux native-endian hexadecimal IPv4 word; invalid text returns `None`.
pub(super) fn parse_ipv4(text: &str) -> Option<Ipv4Addr> {
    if text.len() != 8 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    // Linux prints a native-endian u32, not the address's network-order value.
    Some(Ipv4Addr::from(
        u32::from_str_radix(text, 16).ok()?.to_ne_bytes(),
    ))
}

fn parse_ipv6(text: &str) -> Option<Ipv6Addr> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut octets = [0; 16];
    // Each of four native-endian 32-bit words is printed separately; reversing
    // the whole 128-bit address would reverse the word order incorrectly.
    let (hex_words, _) = text.as_bytes().as_chunks::<8>();
    let (octet_words, _) = octets.as_chunks_mut::<4>();
    for (hex, output) in hex_words.iter().zip(octet_words) {
        let word = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        output.copy_from_slice(&word.to_ne_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

/// Treat an IPv4-mapped IPv6 address as IPv4, preserving all other addresses.
pub(super) fn normalise_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

/// Normalise the IP and discard scope/flow identifiers absent from procfs rows.
pub(super) fn normalise_socket(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalise_ip(address.ip()), address.port())
}

/// Give an unspecified peer the local address family after mapped-address conversion.
pub(super) fn normalise_peer(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
    // A mapped IPv4 local endpoint can have an all-zero IPv6 remote in udp6.
    if remote.ip().is_unspecified() {
        SocketAddr::new(wildcard(local).ip(), remote.port())
    } else {
        remote
    }
}

/// Preserve the port but replace the IP with its family's unspecified address.
pub(super) fn wildcard(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(
        match address.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        address.port(),
    )
}
