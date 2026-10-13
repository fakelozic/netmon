//! Deterministic names assertions for conversation evidence.
//! Packet construction stays in `flow_support`; production state stays in `netmon::flow`.
//! Read the test names for the packet condition each assertion exercises.
use super::*;
use netmon::decode::{self, AppInfo, Detail, DnsAnswer, Proto};
use netmon::flow::{Note, Tracker};
use netmon::names::{AddrClass, NameSource, Names};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn names_classification_precedence_labels_sanitising_and_lru() {
    for (address, class) in [
        ("0.0.0.0", AddrClass::Unspecified),
        ("::", AddrClass::Unspecified),
        ("127.0.0.2", AddrClass::Loopback),
        ("::1", AddrClass::Loopback),
        ("10.1.2.3", AddrClass::Private),
        ("172.16.0.1", AddrClass::Private),
        ("192.168.1.1", AddrClass::Private),
        ("fd12::1", AddrClass::Private),
        ("169.254.1.2", AddrClass::LinkLocal),
        ("fe80::1", AddrClass::LinkLocal),
        ("224.0.0.251", AddrClass::Multicast),
        ("ff02::fb", AddrClass::Multicast),
        ("255.255.255.255", AddrClass::Broadcast),
        ("8.8.8.8", AddrClass::Public),
        ("2001:4860:4860::8888", AddrClass::Public),
        ("::ffff:127.0.0.1", AddrClass::Loopback),
    ] {
        assert_eq!(
            Names::classify(&address.parse().unwrap()),
            class,
            "{address}"
        );
    }
    let mut names = Names::new();
    let address = "10.0.0.1".parse().unwrap();
    names.learn(address, "first", NameSource::Http);
    names.learn(address, "second", NameSource::Tls);
    names.learn(address, "dns", NameSource::Dns);
    names.learn(address, "ignored", NameSource::Tls);
    assert_eq!(names.name_of(&address), Some("dns"));
    names.learn(address, "mdns", NameSource::Mdns);
    names.learn(address, "newer", NameSource::Mdns);
    assert_eq!(names.name_of(&address), Some("newer"));
    names.learn(address, "bad\x1bname", NameSource::Dns);
    assert_eq!(names.name_of(&address), Some("bad\\x1Bname"));
    names.set_gateway(Some(address));
    assert_eq!(names.label(&address), "router");
    names.set_local(&[address]);
    assert!(names.is_local(&address));
    assert_eq!(names.label(&address), "this computer");
    names.set_local(&[]);
    names.set_gateway(None);
    assert_eq!(names.label(&address), "bad\\x1Bname");
    assert_eq!(names.label(&"8.8.8.8".parse().unwrap()), "8.8.8.8");
    let mut lru = Names::new();
    let ip = |n| IpAddr::V4(Ipv4Addr::from(n));
    for n in 1..=20_000u32 {
        lru.learn(ip(n), "name", NameSource::Dns);
    }
    assert_eq!(lru.name_of(&ip(1)), Some("name"));
    lru.learn(ip(20_001), "new", NameSource::Dns);
    assert!(lru.name_of(&ip(2)).is_none());
    assert_eq!(lru.name_of(&ip(1)), Some("name"));
    assert_eq!(
        (1..=20_001)
            .filter(|n| lru.name_of(&ip(*n)).is_some())
            .count(),
        20_000
    );
}

#[test]
fn mdns_cname_answers_use_asked_name_and_dns_ids_do_not_cross_flows() {
    let mut tracker = Tracker::new();
    let query = udp(1, 5353, 5353, false, &[]);
    let mut d = decode::decode(query.link, &query.data, query.orig_len, Detail::Summary);
    d.summary.proto = Proto::Mdns;
    d.summary.app = Some(AppInfo::DnsQuery {
        id: 7,
        name: "asked.local".into(),
        qtype: 1,
    });
    let flow = tracker.observe(&query, &d).flow;
    let unrelated = udp(2, 7000, 5353, false, &[]);
    let mut other = d.clone();
    other.summary.src_port = Some(7000);
    tracker.observe(&unrelated, &other);
    let response = udp(3, 5353, 5353, true, &[]);
    let mut answer = decode::decode(
        response.link,
        &response.data,
        response.orig_len,
        Detail::Summary,
    );
    answer.summary.proto = Proto::Mdns;
    answer.summary.app = Some(AppInfo::DnsResponse {
        id: 7,
        name: "canonical.local".into(),
        qtype: 1,
        rcode: 0,
        answers: vec![DnsAnswer {
            name: "canonical.local".into(),
            rr_type: 1,
            value: "10.9.8.7".into(),
            ttl: 60,
        }],
    });
    let obs = tracker.observe(&response, &answer);
    assert_eq!(obs.flow, flow);
    assert!(
        obs.notes
            .contains(&Note::DnsAnswerTime(Duration::from_millis(2)))
    );
    assert_eq!(
        tracker.names().name_of(&"10.9.8.7".parse().unwrap()),
        Some("asked.local")
    );
}
