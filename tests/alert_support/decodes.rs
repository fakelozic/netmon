//! Checks synthetic packet builders against the real decoder.
//! Byte construction lives in `mod.rs`; engine behavior lives in `tests/alerts/`.
//! Read `transport_helpers_produce_the_expected_decodes` first.
//! Both IP versions carry the same TCP or UDP service-port information.

use super::*;

#[test]
fn transport_helpers_produce_the_expected_decodes() {
    use crate::decode::{Addr, Proto};
    let v6_client: IpAddr = "fd00::2".parse().unwrap();
    let v6_server: IpAddr = "2606:4700::1111".parse().unwrap();
    for (source, destination) in [(CLIENT, SERVER), (v6_client, v6_server)] {
        for packet in [
            tcp(7, 123, (source, 40_000), (destination, 8080), 2, b"abc"),
            udp(7, 123, (source, 40_000), (destination, 8080), b"abc"),
        ] {
            let d = decode(packet.link, &packet.data, packet.orig_len, Detail::Full);
            assert!(!d.truncated);
            assert_eq!(packet.ts, Duration::from_millis(123));
            assert_eq!(d.summary.src_port, Some(40_000));
            assert_eq!(d.summary.dst_port, Some(8080));
            assert_eq!(
                d.summary.src.as_ref().map(|a| match a {
                    Addr::V4(ip) => IpAddr::V4(*ip),
                    Addr::V6(ip) => IpAddr::V6(*ip),
                    _ => panic!("expected IP"),
                }),
                Some(source)
            );
            assert!(
                d.layers
                    .iter()
                    .any(|l| matches!(l.proto, Proto::Ipv4 | Proto::Ipv6))
            );
            if let Some(tcp) = d.summary.tcp {
                assert_eq!(tcp.flags, 2);
                assert_eq!(tcp.seq, 100);
                assert_eq!(tcp.ack, 101);
                assert_eq!(tcp.payload_len, 3);
            } else {
                assert_eq!(d.summary.udp_payload_len, Some(3));
            }
        }
    }
}

#[test]
fn application_helpers_produce_the_expected_decodes() {
    use crate::decode::{AppInfo, FieldKey, Proto};
    let cases = [
        (dns_query(1, 0, CLIENT, "readable.test"), Proto::Dns),
        (nxdomain(1, 0, CLIENT), Proto::Dns),
        (
            arp(1, 0, Ipv4Addr::new(10, 0, 0, 1), [2, 0, 0, 0, 0, 1]),
            Proto::Arp,
        ),
        (
            http(1, 0, Some(&format!("Authorization: Basic {BASE64}"))),
            Proto::Http,
        ),
        (
            tcp(
                1,
                0,
                (CLIENT, 40_000),
                (SERVER, 443),
                0x18,
                &tls_record(b"opaque"),
            ),
            Proto::Tls,
        ),
    ];
    for (packet, proto) in cases {
        let summary = decode(packet.link, &packet.data, packet.orig_len, Detail::Summary);
        let full = decode(packet.link, &packet.data, packet.orig_len, Detail::Full);
        assert!(!full.truncated, "{proto:?}");
        assert_eq!(summary.summary, full.summary);
        assert_eq!(full.summary.proto, proto);
        match full.summary.app {
            Some(AppInfo::DnsQuery { name, .. }) => assert_eq!(name, "readable.test"),
            Some(AppInfo::DnsResponse { rcode, .. }) => assert_eq!(rcode, 3),
            Some(AppInfo::Arp { sender_mac, .. }) => {
                assert_eq!(sender_mac, Some([2, 0, 0, 0, 0, 1]))
            }
            Some(AppInfo::HttpRequest { .. }) => {
                assert!(
                    full.layers
                        .iter()
                        .flat_map(|l| &l.fields)
                        .any(|f| f.key == FieldKey::HttpHeader
                            && f.value == "Authorization: Basic [hidden]")
                );
                assert!(summary.layers.iter().all(|l| l.fields.is_empty()));
            }
            Some(AppInfo::TlsRecords {
                encrypted_bytes, ..
            }) => assert_eq!(encrypted_bytes, 6),
            app => panic!("unexpected helper decode: {app:?}"),
        }
    }
}

#[test]
fn auxiliary_helpers_preserve_questions_and_wrapped_sequences() {
    let multiple = dns_questions(1, 0, CLIENT, &["a.test", "b.test"]);
    assert!(
        !decode(
            multiple.link,
            &multiple.data,
            multiple.orig_len,
            Detail::Full
        )
        .truncated
    );
    let changed = with_sequence(tcp(1, 0, (PUBLIC, 5000), (CLIENT, 22), 2, &[]), u32::MAX, 0);
    assert_eq!(
        decode(
            changed.link,
            &changed.data,
            changed.orig_len,
            Detail::Summary
        )
        .summary
        .tcp
        .unwrap()
        .seq,
        u32::MAX
    );
    assert_ne!(USERNAME, PASSWORD);
}
