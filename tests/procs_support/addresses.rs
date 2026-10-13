//! Checks for procfs addresses behavior.
//! Fake-tree construction stays in mod.rs.
//! Read local_addresses_are_deduplicated_and_gateway_requires_a_default_route_and_flag first.
//! Routing entries identify the addresses treated as local in a namespace.

use super::{FakeProc, encode_v4};
use netmon::procs::{default_gateway, local_addresses};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn only_immediately_following_host_routes_count_as_own_addresses() {
    let fake = FakeProc::new("host-routes");
    fake.net("fib_trie", b"Main:\n |-- 127.0.0.0\n    /8 host LOCAL\n |-- 127.0.0.1\n    /32 host LOCAL\n |-- 10.0.0.1\n    /32 link UNICAST\n    /32 host LOCAL\n |-- 10.0.0.2\n\n    /32 host LOCAL\n |-- 10.0.0.3\n    /320 host LOCAL\n |-- 10.0.0.4\n    /32 host LOCAL\n");
    assert_eq!(
        local_addresses(fake.root()),
        vec![
            "10.0.0.4".parse::<IpAddr>().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ]
    );
}

#[test]
fn local_addresses_are_deduplicated_and_gateway_requires_a_default_route_and_flag() {
    let fake = FakeProc::new("addresses");
    fake.net("fib_trie", b"Main:\n  +-- 127.0.0.0/8 2 0 2\n     |-- 127.0.0.1\n        /32 host LOCAL\n     |-- 192.168.1.42\n        /32 host LOCAL\n     |-- 192.168.1.255\n        /32 link BROADCAST\nLocal:\n     |-- 127.0.0.1\n        /32 host LOCAL\n     |-- 192.168.1.42\n        /32 host LOCAL\n     |-- 999.999.999.999\n        /32 host LOCAL\n");
    fake.net("if_inet6", b"00000000000000000000000000000001 01 80 10 80 lo\n20010db8123456789abcdef012345678 02 40 00 80 eth0\n00000000000000000000ffffc0a8012a 02 80 00 80 eth0\n00000000000000000000000000000001 01 80 10 80 lo\nmalformed\n\xff\n");
    assert_eq!(
        local_addresses(fake.root()),
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.1.42".parse().unwrap(),
            "::1".parse().unwrap(),
            "2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap(),
        ]
    );
    let gateway = Ipv4Addr::new(192, 168, 1, 1);
    fake.net("route", format!("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 00000000 0001 0 0 0 00000000 0 0 0\neth0 0001A8C0 {} 0003 0 0 0 00FFFFFF 0 0 0\ninvalid\neth0 00000000 {} 0003 0 0 100 00000000 0 0 0\n", encode_v4(gateway), encode_v4(gateway)));
    assert_eq!(default_gateway(fake.root()), Some(gateway));
    fake.net(
        "route",
        b"eth0 00000000 0101A8C0 0001\neth0 00000001 0101A8C0 0003\neth0 00000000 INVALID 0003\n",
    );
    assert_eq!(default_gateway(fake.root()), None);
    fake.net("fib_trie", b"\xff\n");
    fake.net("if_inet6", b"\xff\n");
    fake.net("route", b"\xff\n");
    assert!(local_addresses(fake.root()).is_empty());
    assert_eq!(default_gateway(fake.root()), None);
}
