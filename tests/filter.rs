//! Verifies the display-filter language with deterministic inputs.
//! Shared fixture reading belongs to ui_support; real capture is never started.
//! Read the fixture tests first for the observable acceptance requirements.
#[path = "ui_support/store.rs"]
mod store_tests;
mod ui_support;
use netmon::{
    decode::{self, Addr, Detail, Proto},
    filter::{self, Row},
    store::Store,
};
use std::net::{Ipv4Addr, Ipv6Addr};
#[test]
fn fixture_counts_and_problem_numbers() {
    let mut store = Store::new(200_000);
    for packet in ui_support::packets() {
        store.push(packet);
    }
    // Hand count: HTTP conversations contain 12 + 13 + 12 = 37 TCP
    // packets; TLS has 18, refused TCP has 2. Thus TCP=57 and excluding
    // port 18080 removes the 25 IPv4 HTTP packets: 57 - 25 = 32.
    // Four IPv4 + four IPv6 pings and the final port-unreachable = 9 ICMP.
    for (input, expected) in [
        ("dns", 8),
        ("tls", 9),
        ("http", 6),
        ("port 18443", 18),
        ("problem", 3),
        ("tcp and not port 18080", 32),
        ("icmp or arp", 9),
        ("tcp", 57),
        ("udp", 9),
        ("ipv6", 16),
        ("ip", 75),
    ] {
        store.set_filter(input.into(), filter::parse(input).unwrap());
        store.on_tick();
        assert_eq!(store.visible_len(), expected, "{input}");
        if input == "problem" {
            assert_eq!(
                (0..store.visible_len())
                    .map(|i| store.visible(i).unwrap().raw.number)
                    .collect::<Vec<_>>(),
                vec![16, 73, 75]
            );
        }
    }
}
#[test]
fn every_term_precedence_quotes_and_future_names() {
    let p = ui_support::packets().remove(19);
    let mut summary = decode::decode(p.link, &p.data, p.orig_len, Detail::Summary).summary;
    let sentence = "Requests GET / from the web server";
    let mut row = Row {
        summary: &summary,
        sentence,
        src_name: Some("My-CLIENT.local"),
        dst_name: Some("Web.Example.COM"),
        app: Some("Firefox"),
        problem: true,
    };
    for input in [
        "",
        "tcp",
        "http",
        "ip",
        "port 18080",
        "host 127.0.0",
        "host example",
        "host CLIENT",
        "app fireFOX",
        "problem",
        "requests",
        "'web server'",
        "\"GET /\"",
        "tcp http",
        "tcp and http",
        "udp or tcp and http",
        "not udp and tcp",
        "(udp or tcp) and http",
        "[tcp and not udp]",
        "not not tcp",
    ] {
        let f = filter::parse(input).unwrap();
        assert!(f.matches(&row), "{input}");
        assert_eq!(f.is_empty(), input.is_empty());
    }
    for input in [
        "udp",
        "dns",
        "app chrome",
        "port 443",
        "host missing",
        "'tcp'",
        "tcp and udp or dns",
        "not (tcp or udp)",
    ] {
        assert!(!filter::parse(input).unwrap().matches(&row), "{input}");
    }
    row.src_name = None;
    row.dst_name = None;
    row.app = None;
    assert!(
        !filter::parse("app firefox or host example")
            .unwrap()
            .matches(&row)
    );
    protocol_terms(&mut summary, sentence);
}
#[test]
fn errors_have_byte_positions_and_plain_expected_values() {
    for (input, position, message) in [
        ("tcp and", 7, "expected a protocol"),
        ("port", 4, "expected a value"),
        ("port 65536", 5, "expected a port number"),
        ("port x", 5, "expected a port number"),
        ("(tcp", 4, "expected a closing bracket"),
        ("tcp)", 3, "expected and"),
        ("\"hello", 0, "expected a closing quote"),
        ("not", 3, "expected a protocol"),
        ("host and", 5, "expected a value"),
        ("()", 1, "expected a protocol"),
    ] {
        let error = filter::parse(input).unwrap_err();
        assert_eq!(error.position, position, "{input}");
        assert!(error.message.starts_with(message), "{input}: {error:?}");
    }
    assert!(filter::parse(&"not ".repeat(100)).is_err());
    assert!(filter::parse(&"x ".repeat(300)).is_err());
    assert!(filter::parse(&"x".repeat(4097)).is_err());
    assert!(filter::parse("\"web \\\"server\\\"\"").is_ok());
}
#[test]
fn exact_conversation_matches_reverse_but_not_another_socket() {
    let p = ui_support::packets().remove(19);
    let summary = decode::decode(p.link, &p.data, p.orig_len, Detail::Summary).summary;
    let filter = filter::Filter::conversation(&summary).unwrap();
    let mut other = summary.clone();
    std::mem::swap(&mut other.src, &mut other.dst);
    std::mem::swap(&mut other.src_port, &mut other.dst_port);
    fn row(s: &netmon::decode::Summary) -> Row<'_> {
        Row {
            summary: s,
            sentence: "",
            src_name: None,
            dst_name: None,
            app: None,
            problem: false,
        }
    }
    assert!(filter.matches(&row(&other)));
    other.src = Some(Addr::V4(Ipv4Addr::new(127, 0, 0, 20)));
    assert!(!filter.matches(&row(&other)));
    other = summary.clone();
    other.src_port = Some(123);
    assert!(!filter.matches(&row(&other)));
}

fn protocol_terms(summary: &mut netmon::decode::Summary, sentence: &str) {
    for (word, proto, ip_proto) in [
        ("udp", Proto::Udp, Some(17)),
        ("icmp", Proto::Icmp, Some(1)),
        ("arp", Proto::Arp, None),
        ("dns", Proto::Dns, Some(17)),
        ("mdns", Proto::Mdns, Some(17)),
        ("dhcp", Proto::Dhcp, Some(17)),
        ("tls", Proto::Tls, Some(6)),
        ("quic", Proto::Quic, Some(17)),
        ("ipv6", Proto::Ipv6, Some(58)),
    ] {
        summary.proto = proto;
        summary.ip_proto = ip_proto;
        summary.tcp = None;
        summary.ether_type = if proto == Proto::Arp {
            Some(0x0806)
        } else {
            Some(0x0800)
        };
        if word == "ipv6" {
            summary.src = Some(Addr::V6(Ipv6Addr::LOCALHOST));
        }
        let row = Row {
            summary,
            sentence,
            src_name: None,
            dst_name: None,
            app: None,
            problem: false,
        };
        assert!(filter::parse(word).unwrap().matches(&row), "{word}");
        if proto == Proto::Arp {
            assert!(!filter::parse("ip").unwrap().matches(&row));
        }
    }
}
