//! Checks teaching text against complete and cut-short synthetic packets.
//! Protocol parsing belongs to `netmon::decode`; reviewed rendering belongs to `explain_golden`.
//! Start with `fixtures_and_decoder_examples_have_teaching_text`.

use netmon::{
    capture::{LinkType, Reader},
    decode::{Decoded, Detail, Field, FieldKey as K, decode},
    explain::{GLOSSARY, field_text},
};
use std::path::Path;

#[test]
fn fixtures_and_decoder_examples_have_teaching_text() {
    for file in [
        "loopback-mixed.pcapng",
        "cooked-any.pcapng",
        "loopback-first20.pcap",
    ] {
        for raw in Reader::open(&Path::new("tests/fixtures").join(file)).unwrap() {
            let raw = raw.unwrap();
            review(&decode(raw.link, &raw.data, raw.orig_len, Detail::Full));
        }
    }
    for (link, bytes) in decoder_examples() {
        // Every capture boundary matters: a partial header must retain useful, honest text.
        for end in 0..=bytes.len() {
            review(&decode(
                link,
                &bytes[..end],
                bytes.len() as u32,
                Detail::Full,
            ));
        }
    }
}

fn review(packet: &Decoded) {
    for layer in &packet.layers {
        assert!(
            layer
                .fields
                .windows(2)
                .all(|p| p[0].range.start <= p[1].range.start),
            "{:?}: {:?}",
            layer.proto,
            layer.fields
        );
        for field in &layer.fields {
            review_field(field, packet);
        }
    }
}

fn review_field(field: &Field, packet: &Decoded) {
    let text = field_text(field, packet);
    assert!(
        !text.what.is_empty() && text.what.ends_with('.'),
        "{:?}: {}",
        field.key,
        text.what
    );
    assert!(
        text.what.chars().count() <= 260,
        "{:?}: {}",
        field.key,
        text.what
    );
    assert!(
        text.here.is_empty() || text.here.trim_end_matches('.') != field.value,
        "{:?} only repeats {}",
        field.key,
        field.value
    );
    for part in [text.what, &text.here, text.why] {
        for banned in [
            "application endpoint",
            "does not request its action",
            "remains.",
        ] {
            assert!(
                !part.to_lowercase().contains(banned),
                "{:?}: {part}",
                field.key
            );
        }
    }
    if field.num == Some(0) && is_flag(field.key) {
        assert_eq!(text.here, "Not set.", "{:?}", field.key);
    }
    review_display(field);
    for child in &field.children {
        review_field(child, packet);
    }
}

fn is_flag(key: K) -> bool {
    matches!(
        key,
        K::IpDf
            | K::IpMf
            | K::V6MoreFragments
            | K::VlanDrop
            | K::TcpCwr
            | K::TcpEce
            | K::TcpUrg
            | K::TcpAckFlag
            | K::TcpPsh
            | K::TcpRst
            | K::TcpSyn
            | K::TcpFin
            | K::DnsResponse
            | K::DnsAuthoritative
            | K::DnsTruncated
            | K::DnsRecursionDesired
            | K::DnsRecursionAvailable
            | K::DnsUnicast
            | K::DnsCacheFlush
            | K::DhcpFlags
            | K::DnsOptFlags
    )
}

#[test]
fn glossary_keeps_required_terms_and_teaches_briefly() {
    assert!(
        GLOSSARY
            .windows(2)
            .all(|p| p[0].0.to_lowercase() < p[1].0.to_lowercase())
    );
    for (term, text) in GLOSSARY {
        assert!(text.chars().count() <= 320, "{term}: {text}");
        assert!(text.ends_with('.'), "{term}");
    }
    // This is the required list in tasks/01-engine.md, section 4.3, including its original spelling.
    for term in [
        "ACK",
        "ARP",
        "checksum",
        "DHCP",
        "DNS",
        "Ethernet",
        "FIN",
        "frame",
        "fragment",
        "handshake",
        "hop",
        "ICMP",
        "IP address",
        "IPv4",
        "IPv6",
        "MAC address",
        "MSS",
        "MTU",
        "packet",
        "port",
        "protocol",
        "QUIC",
        "RST",
        "segment",
        "sequence number",
        "SYN",
        "TCP",
        "TLS",
        "TTL",
        "UDP",
        "window",
    ] {
        assert!(GLOSSARY.iter().any(|(t, _)| *t == term), "missing {term}");
    }
}

// These builders reproduce the examples beside the decoders through the public decode entry point.
fn decoder_examples() -> Vec<(LinkType, Vec<u8>)> {
    let mut cases = Vec::new();
    link_examples(&mut cases);
    ip_examples(&mut cases);
    for dns in dns_examples() {
        cases.push((LinkType::RawIp, ipv4(17, &udp(53, 1234, &dns))));
        cases.push((LinkType::RawIp, ipv4(17, &udp(5353, 5353, &dns))));
    }
    for message in [1, 2] {
        let mut dhcp = vec![0; 240];
        dhcp[0] = if message == 1 { 1 } else { 2 };
        dhcp[1] = 1;
        dhcp[2] = 6;
        dhcp[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        dhcp[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        dhcp[16..20].copy_from_slice(&[192, 168, 1, 20]);
        dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        dhcp.extend_from_slice(&[
            53, 1, message, 12, 3, b'p', b'c', b'1', 50, 4, 192, 168, 1, 20, 255,
        ]);
        cases.push((LinkType::RawIp, ipv4(17, &udp(67, 68, &dhcp))));
    }
    for http in [
        b"GET / HTTP/1.1\r\nHost: test\r\nAuthorization: Basic c2VjcmV0\r\nCookie: secret=1\r\nX-Test: \x1b[31m\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nAuthorization: Basic secret\r\n more-secret\r\n continuation: secret\r\nProxy-Authorization: Bearer proxy-secret\r\nSet-Cookie: secret-cookie\r\n\r\n",
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    ] { cases.push((LinkType::RawIp, ipv4(6, &tcp(http)))); }
    let hello = client_hello();
    let mut records = vec![23, 3, 3, 0, 3, 1, 2, 3, 22, 3, 3];
    records.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    records.extend_from_slice(&hello);
    cases.push((LinkType::RawIp, ipv4(6, &tcp(&records))));
    cases.push((
        LinkType::RawIp,
        ipv4(6, &tcp(&[23, 3, 3, 0, 2, 1, 2, 23, 3, 3, 0, 3, 3, 4, 5])),
    ));
    for quic in [
        vec![0xc0, 0, 0, 0, 1, 2, 1, 2, 1, 3, 0, 0],
        vec![0xc0, 0, 0, 0, 9, 0, 0],
        vec![0x40],
    ] {
        cases.push((LinkType::RawIp, ipv4(17, &udp(1234, 443, &quic))));
    }
    cases
}

fn link_examples(cases: &mut Vec<(LinkType, Vec<u8>)>) {
    for op in [1u16, 2] {
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&[
            2, 0, 0, 0, 0, 1, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
        ]);
        cases.push((LinkType::Ethernet, frame.clone()));
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        frame.splice(14..14, [0xa0, 7, 8, 6]);
        cases.push((LinkType::Ethernet, frame));
    }
    for (link, len, proto) in [(LinkType::LinuxSll, 16, 14), (LinkType::LinuxSll2, 20, 0)] {
        let mut bytes = vec![0; len];
        bytes[proto..proto + 2].copy_from_slice(&0x1234u16.to_be_bytes());
        cases.push((link, bytes));
    }
}

fn ip_examples(cases: &mut Vec<(LinkType, Vec<u8>)>) {
    let mut bytes = ipv4(17, &[4, 210, 4, 211, 0, 8, 0, 0]);
    bytes[0] = 0x46;
    bytes[2..4].copy_from_slice(&32u16.to_be_bytes());
    bytes.splice(20..20, [1, 1, 0, 0]);
    cases.push((LinkType::RawIp, bytes.clone()));
    bytes[6] = 0x20;
    cases.push((LinkType::RawIp, bytes.clone()));
    bytes[7] = 1;
    cases.push((LinkType::RawIp, bytes));
    let mut tcp = vec![0; 20];
    tcp[12] = 0xf0;
    tcp[13] = 2;
    tcp.extend_from_slice(&[
        2, 4, 5, 180, 3, 3, 7, 4, 2, 5, 10, 0, 0, 0, 1, 0, 0, 0, 9, 8, 10, 0, 0, 0, 2, 0, 0, 0, 1,
        1, 1, 0,
    ]);
    tcp.resize(60, 0);
    let mut bytes = ipv4(6, &tcp);
    bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
    cases.push((LinkType::RawIp, bytes));
    let quote = ipv4(17, &[0xcf, 0x84, 0, 9, 0, 8, 0, 0]);
    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&quote);
    cases.push((LinkType::RawIp, ipv4(1, &icmp)));
    let mut bytes = ipv6(
        0,
        &[
            44, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 1, 4, 210, 4, 211, 0, 8, 0, 0,
        ],
    );
    cases.push((LinkType::RawIp, bytes.clone()));
    bytes[51] = 8;
    cases.push((LinkType::RawIp, bytes));
    for kind in 133..=136 {
        let len = match kind {
            134 => 16,
            135 | 136 => 24,
            _ => 8,
        };
        let mut icmp = vec![0; len];
        icmp[0] = kind;
        if matches!(kind, 135 | 136) {
            icmp[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        }
        icmp.extend_from_slice(&[2, 1, 2, 0, 0, 0, 0, 1]);
        cases.push((LinkType::RawIp, ipv6(58, &icmp)));
    }
    for (protocol, payload) in [(6, vec![0, 1, 0]), (17, vec![0, 1, 0]), (1, vec![8, 0, 0])] {
        let mut bytes = ipv4(protocol, &payload);
        bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
        cases.push((LinkType::RawIp, bytes));
    }
}

fn dns_examples() -> Vec<Vec<u8>> {
    let mut looped = vec![0; 12];
    looped[5] = 1;
    looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    let mut chain = vec![0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
    chain.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    for (owner, ty, data) in [
        (12u16, 5u16, vec![1, b'b', 0]),
        (31, 5, vec![1, b'c', 0]),
        (46, 1, vec![1, 2, 3, 4]),
    ] {
        chain.extend_from_slice(&(0xc000 | owner).to_be_bytes());
        chain.extend_from_slice(&ty.to_be_bytes());
        chain.extend_from_slice(&[0x80, 1, 0, 0, 0, 60]);
        chain.extend_from_slice(&(data.len() as u16).to_be_bytes());
        chain.extend_from_slice(&data);
    }
    chain[34..36].copy_from_slice(&[0xc0, 31]);
    chain[49..51].copy_from_slice(&[0xc0, 46]);
    let mut cases = vec![looped, chain.clone(), vec![0, 1]];
    chain[13] = 0x1b;
    cases.push(chain);
    let named = vec![4, b'm', b'a', b'i', b'l', 0];
    let mut mx = vec![0, 10];
    mx.extend_from_slice(&named);
    let mut srv = vec![0, 1, 0, 2, 1, 187];
    srv.extend_from_slice(&named);
    let mut soa = named.clone();
    soa.extend_from_slice(&named);
    for n in [1u32, 2, 3, 4, 5] {
        soa.extend_from_slice(&n.to_be_bytes());
    }
    for (ty, data) in [
        (2u16, named.clone()),
        (12, named),
        (15, mx),
        (16, vec![2, b'h', b'i', 1, 0x1b]),
        (33, srv),
        (6, soa),
        (28, std::net::Ipv6Addr::LOCALHOST.octets().to_vec()),
        (41, vec![0, 12, 0, 1, 7]),
    ] {
        let mut dns = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        dns.extend_from_slice(&ty.to_be_bytes());
        dns.extend_from_slice(&1232u16.to_be_bytes());
        dns.extend_from_slice(&[0; 4]);
        dns.extend_from_slice(&(data.len() as u16).to_be_bytes());
        dns.extend_from_slice(&data);
        cases.push(dns);
    }
    cases
}

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, protocol, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !(sum as u16);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x60;
    bytes[6] = next;
    bytes[7] = 64;
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&src.to_be_bytes());
    bytes.extend_from_slice(&dst.to_be_bytes());
    bytes.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(payload);
    bytes
}

fn tcp(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0..2].copy_from_slice(&1234u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&80u16.to_be_bytes());
    bytes[12] = 0x50;
    bytes[13] = 16;
    bytes.extend_from_slice(payload);
    bytes
}

fn client_hello() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let mut ext = vec![0, 0, 0, 16, 0, 14, 0, 0, 11];
    ext.extend_from_slice(b"netmon.test");
    ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2', 0, 43, 0, 5, 4, 3, 4, 3, 3]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hello = vec![1, 0, 0, body.len() as u8];
    hello.extend_from_slice(&body);
    hello
}

#[test]
fn flags_are_nested_and_numeric_header_values_are_preserved() {
    let mut tcp = tcp(&[]);
    tcp[13] = 0x12;
    tcp[16..18].copy_from_slice(&0xfe31u16.to_be_bytes());
    let mut bytes = ipv4(6, &tcp);
    bytes[4..6].copy_from_slice(&0xfe31u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    let packet = decode(LinkType::RawIp, &bytes, bytes.len() as u32, Detail::Full);
    let fields = &packet.layers[0].fields;
    let flags = fields.iter().find(|f| f.key == K::IpFlags).unwrap();
    assert_eq!(flags.value, "0x4000 [DF]");
    assert_eq!(flags.num, Some(0x4000));
    assert_eq!(
        flags
            .children
            .iter()
            .map(|f| (f.key, f.num))
            .collect::<Vec<_>>(),
        vec![(K::IpDf, Some(1)), (K::IpMf, Some(0))]
    );
    assert!(!fields.iter().any(|f| matches!(f.key, K::IpDf | K::IpMf)));
    let fields = &packet.layers[1].fields;
    let flags = fields.iter().find(|f| f.key == K::TcpFlags).unwrap();
    assert_eq!(flags.value, "0x0012 [ACK, SYN]");
    assert_eq!(flags.num, Some(0x12));
    let checksum = fields.iter().find(|f| f.key == K::TcpChecksum).unwrap();
    assert_eq!(checksum.value, "0xfe31");
    assert_eq!(checksum.num, Some(0xfe31));
    review(&packet);
}

fn review_display(field: &Field) {
    if matches!(
        field.key,
        K::IpChecksum
            | K::TcpChecksum
            | K::UdpChecksum
            | K::IcmpChecksum
            | K::IpId
            | K::V6FragmentId
            | K::V6FlowLabel
            | K::IcmpId
            | K::DnsId
            | K::DhcpId
            | K::VlanId
            | K::ArpProtocol
            | K::SllProtocol
            | K::TlsCipher
            | K::TlsKeyShare
            | K::TlsRecordVersion
            | K::TlsHelloVersion
            | K::TlsVersions
            | K::TlsSupportedVersion
            | K::QuicVersion
    ) {
        let shown = field
            .value
            .split_whitespace()
            .next()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();
        assert_eq!(
            u64::from_str_radix(shown, 16).unwrap(),
            field.num.unwrap(),
            "{:?}",
            field.key
        );
    }
    if matches!(
        field.key,
        K::IpFlags | K::TcpFlags | K::DnsFlags | K::DhcpFlags | K::DnsOptFlags
    ) {
        assert!(
            field.value.starts_with("0x") && field.value.ends_with(']'),
            "{:?}",
            field.key
        );
        let shown = field
            .value
            .split_whitespace()
            .next()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();
        assert_eq!(u64::from_str_radix(shown, 16).unwrap(), field.num.unwrap());
    }
}
