//! Builds deterministic Ethernet packets for alert tests.
//! Decoder validation lives in `decodes.rs`; rule assertions live in `tests/alerts/`.
//! Read `tcp` first for the common packet construction path.
//! TCP carries a byte stream; UDP carries separate messages, both addressed to numbered ports.

use crate::{
    alerts::{Alert, Engine},
    capture::{LinkType, RawPacket},
    decode::{Detail, decode},
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Synthetic local client address. No packets are sent to it.
pub(crate) const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// Synthetic service address used by the DNS and HTTP builders.
pub(crate) const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
/// Ordinary public unicast classification example; never contacted.
pub(crate) const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
/// Synthetic login user name that must not appear in any alert field.
pub(crate) const USERNAME: &str = "learner-login";
/// Synthetic login password that must not appear in any alert field.
pub(crate) const PASSWORD: &str = "packet-secret";
/// Synthetic HTTP Basic value encoding the test user name and password.
pub(crate) const BASE64: &str = "bGVhcm5lci1sb2dpbjpwYWNrZXQtc2VjcmV0";

/// Feeds a summary decode of a synthetic packet to the engine once.
pub(crate) fn observe(engine: &mut Engine, raw: &RawPacket) -> Vec<Alert> {
    let d = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
    engine.observe(raw, &d)
}

fn raw(number: u64, milliseconds: u64, data: Vec<u8>) -> RawPacket {
    RawPacket {
        number,
        ts: Duration::from_millis(milliseconds),
        link: LinkType::Ethernet,
        iface: 0,
        orig_len: u32::try_from(data.len()).unwrap(),
        data,
    }
}

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1];
    bytes.extend_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn network(source: IpAddr, destination: IpAddr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(20 + payload.len()).unwrap();
            let mut bytes = vec![0x45, 0];
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
            bytes.extend_from_slice(&source.octets());
            bytes.extend_from_slice(&destination.octets());
            bytes.extend_from_slice(payload);
            ethernet(0x0800, &bytes)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u16::try_from(payload.len()).unwrap();
            let mut bytes = vec![0x60, 0, 0, 0];
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&[protocol, 64]);
            bytes.extend_from_slice(&source.octets());
            bytes.extend_from_slice(&destination.octets());
            bytes.extend_from_slice(payload);
            ethernet(0x86dd, &bytes)
        }
        _ => panic!("test endpoints must use the same IP version"),
    }
}

/// Builds Ethernet/IP/TCP bytes with timestamps in milliseconds from a synthetic origin.
/// Endpoints must use the same IP version; flags and payload are supplied literally.
pub(crate) fn tcp(
    number: u64,
    milliseconds: u64,
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
    flags: u8,
    payload: &[u8],
) -> RawPacket {
    let mut bytes = source.1.to_be_bytes().to_vec();
    bytes.extend_from_slice(&destination.1.to_be_bytes());
    // Fixed sequence numbers make SYN acknowledgement tests reproducible (RFC 9293, 3.4).
    bytes.extend_from_slice(&100u32.to_be_bytes());
    bytes.extend_from_slice(&101u32.to_be_bytes());
    bytes.extend_from_slice(&[0x50, flags, 0x10, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    raw(
        number,
        milliseconds,
        network(source.0, destination.0, 6, &bytes),
    )
}

/// Replaces sequence/ACK values in a complete packet produced by `tcp`.
/// Panics on an invalid test packet so builder mistakes fail the test immediately.
pub(crate) fn with_sequence(mut packet: RawPacket, sequence: u32, ack: u32) -> RawPacket {
    let d = decode(packet.link, &packet.data, packet.orig_len, Detail::Summary);
    let offset = d
        .layers
        .iter()
        .find(|l| l.proto == crate::decode::Proto::Tcp)
        .unwrap()
        .range
        .start;
    packet
        .data
        .get_mut(offset + 4..offset + 8)
        .unwrap()
        .copy_from_slice(&sequence.to_be_bytes());
    packet
        .data
        .get_mut(offset + 8..offset + 12)
        .unwrap()
        .copy_from_slice(&ack.to_be_bytes());
    packet
}

/// Builds Ethernet/IP/UDP bytes with a millisecond timestamp and same-version endpoints.
pub(crate) fn udp(
    number: u64,
    milliseconds: u64,
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
    payload: &[u8],
) -> RawPacket {
    let mut bytes = source.1.to_be_bytes().to_vec();
    bytes.extend_from_slice(&destination.1.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    raw(
        number,
        milliseconds,
        network(source.0, destination.0, 17, &bytes),
    )
}

/// Builds a complete HTTP request to the synthetic server. `None` adds no extra header.
pub(crate) fn http(number: u64, milliseconds: u64, header: Option<&str>) -> RawPacket {
    let mut request = "GET / HTTP/1.1\r\nHost: netmon.test\r\n".to_string();
    if let Some(header) = header {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tcp(
        number,
        milliseconds,
        (CLIENT, 40_000),
        (SERVER, 80),
        0x18,
        request.as_bytes(),
    )
}

/// Wraps arbitrary test bytes in an opaque TLS application-data record.
/// This tests decoder visibility, not cryptography or a real TLS exchange.
pub(crate) fn tls_record(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![23, 3, 3];
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    // The decoder treats application-data bytes as opaque ciphertext.
    bytes.extend_from_slice(payload);
    bytes
}

// DNS uses length-prefixed labels capped at 63 bytes (RFC 1035, 2.3.4).
fn question(labels: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in labels {
        assert!(label.len() <= 63);
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label);
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    bytes
}

/// Builds an IPv4 DNS query from literal wire labels, permitting nonprintable bytes.
/// Labels must be at most 63 bytes; timestamps are synthetic milliseconds.
pub(crate) fn dns_labels(
    number: u64,
    milliseconds: u64,
    client: IpAddr,
    labels: &[&[u8]],
) -> RawPacket {
    let mut bytes = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend(question(labels));
    udp(number, milliseconds, (client, 40_000), (SERVER, 53), &bytes)
}

/// Builds an IPv4 DNS question from dot-separated labels without sending a lookup.
pub(crate) fn dns_query(number: u64, milliseconds: u64, client: IpAddr, name: &str) -> RawPacket {
    let labels = name.as_bytes().split(|b| *b == b'.').collect::<Vec<_>>();
    dns_labels(number, milliseconds, client, &labels)
}

/// Builds a DNS query containing every supplied name to check later-question inspection.
pub(crate) fn dns_questions(
    number: u64,
    milliseconds: u64,
    client: IpAddr,
    names: &[&str],
) -> RawPacket {
    let mut bytes = vec![0, 1, 1, 0];
    bytes.extend_from_slice(&u16::try_from(names.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for name in names {
        bytes.extend(question(
            &name.as_bytes().split(|b| *b == b'.').collect::<Vec<_>>(),
        ));
    }
    udp(number, milliseconds, (client, 40_000), (SERVER, 53), &bytes)
}

/// Builds a DNS name-error reply to the supplied IPv4 client, using a readable question.
pub(crate) fn nxdomain(number: u64, milliseconds: u64, client: IpAddr) -> RawPacket {
    let mut bytes = vec![0, 1, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend(question(&[b"missing", b"test"]));
    udp(number, milliseconds, (SERVER, 53), (client, 40_000), &bytes)
}

/// Builds an Ethernet ARP reply advertising the supplied sender mapping.
pub(crate) fn arp(number: u64, milliseconds: u64, sender: Ipv4Addr, mac: [u8; 6]) -> RawPacket {
    let mut bytes = vec![0, 1, 8, 0, 6, 4, 0, 2];
    bytes.extend_from_slice(&mac);
    bytes.extend_from_slice(&sender.octets());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    raw(number, milliseconds, ethernet(0x0806, &bytes))
}

#[cfg(test)]
mod decodes;
