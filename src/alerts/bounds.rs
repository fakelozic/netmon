//! Verifies bounded alert state under spoofed traffic.
//! Packet construction lives in `tests/alert_support`; public behavior tests live in `tests/alerts`.
//! Read `one_hundred_thousand_distinct_spoofed_sources_keep_all_tables_bounded` first.
//! Spoofed addresses can fill tracking tables even when there are few real devices.

use super::alert_support::*;
use super::*;
use std::hash::Hash;
use std::net::Ipv4Addr;

fn table_bounded<K: Clone + Eq + Hash, V>(table: &Table<K, V>, expected: usize) {
    assert!(table.values.len() <= table.cap);
    assert_eq!(table.values.len(), expected);
    assert_eq!(table.order.len(), table.values.len());
    for (key, (_, stamp)) in &table.values {
        assert!(table.order.get(stamp).is_some_and(|ordered| ordered == key));
    }
}

#[test]
fn one_hundred_thousand_distinct_spoofed_sources_keep_all_tables_bounded() {
    let mut engine = Engine::new(Config {
        scan_ports: 1,
        nxdomain_count: 1,
        ..Config::default()
    });
    engine.set_local(&[CLIENT]);
    for n in 0..100_000u32 {
        let octets = n.to_be_bytes();
        let ip = Ipv4Addr::new(8, octets[1], octets[2], octets[3]);
        let number = u64::from(n) + 1;
        let raw = match n % 4 {
            // SYN with data fills scans, Telnet, inbound and suppression state.
            0 => tcp(
                number,
                u64::from(n),
                (ip.into(), 50_000),
                (CLIENT, 23),
                2,
                b"login",
            ),
            1 => arp(
                number,
                u64::from(n),
                ip,
                [2, 0, 0, octets[1], octets[2], octets[3]],
            ),
            2 => nxdomain(number, u64::from(n), ip.into()),
            _ => udp(
                number,
                u64::from(n),
                (ip.into(), 50_000),
                (CLIENT, 999),
                &[],
            ),
        };
        observe(&mut engine, &raw);
        assert!(engine.scans.values.len() <= PAIRS);
        assert!(engine.arp.values.len() <= ARP_ENTRIES);
        assert!(engine.dns.values.len() <= DNS_CLIENTS);
        assert!(engine.inbound.values.len() <= INBOUND);
        assert!(engine.telnet.values.len() <= PAIRS);
        assert!(engine.repeats.values.len() <= SUBJECTS);
    }
    table_bounded(&engine.scans, PAIRS);
    table_bounded(&engine.arp, ARP_ENTRIES);
    table_bounded(&engine.dns, DNS_CLIENTS);
    table_bounded(&engine.inbound, INBOUND);
    table_bounded(&engine.telnet, PAIRS);
    table_bounded(&engine.repeats, SUBJECTS);
    assert!(
        engine
            .scans
            .values
            .values()
            .all(|(ports, _)| ports.len() <= PORTS)
    );
    assert!(
        engine
            .dns
            .values
            .values()
            .all(|(replies, _)| replies.len() <= engine.config.nxdomain_count)
    );
    assert!(engine.local.len() <= LOCAL_ADDRESSES);
}

#[test]
fn ports_replies_local_addresses_and_eviction_bookkeeping_are_bounded() {
    let mut engine = Engine::new(Config {
        scan_ports: usize::MAX,
        scan_window: Duration::MAX,
        ..Config::default()
    });
    for n in 0..5000u16 {
        observe(
            &mut engine,
            &tcp(u64::from(n), 0, (PUBLIC, 50_000), (CLIENT, n), 2, &[]),
        );
        observe(&mut engine, &nxdomain(u64::from(n), 0, CLIENT));
    }
    let ports = engine.scans.get(&(PUBLIC, CLIENT)).unwrap();
    assert_eq!(ports.len(), PORTS);
    assert_eq!(ports.front().unwrap().port, 5000 - PORTS as u16);
    assert_eq!(ports.back().unwrap().port, 4999);
    assert_eq!(engine.dns.get(&CLIENT).unwrap().len(), 20);
    let locals = (0..LOCAL_ADDRESSES + 10)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n as u32)))
        .collect::<Vec<_>>();
    engine.set_local(&locals);
    assert_eq!(engine.local.len(), LOCAL_ADDRESSES);
    assert_eq!(engine.local.first(), locals.last());

    let mut table = Table::new(2);
    table.insert(1, "first");
    table.insert(2, "second");
    assert_eq!(table.get_mut(&1), Some(&mut "first"));
    table.insert(3, "third");
    assert!(table.get(&2).is_none());
    assert_eq!(table.get(&1), Some(&"first"));
    for n in 0..10_000 {
        table.insert(n, "value");
        assert_eq!(table.remove(&n), Some("value"));
        assert_eq!(table.order.len(), table.values.len());
    }
    table.serial = u64::MAX;
    table.insert(4, "after counter reset");
    table_bounded(&table, 1);
}
