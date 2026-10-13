//! Checks cached matching at the production packet-count limit.
//! Retention lives in store; JSON schema assertions live in tests/web_api.
//! Read `polling_reuses_matched_cursor_at_two_hundred_thousand_packets` first.

use super::{Options, state::State};
use crate::{
    capture::{LinkType, RawPacket},
    live::Message,
    pipeline,
};
use std::time::Duration;

#[test]
fn polling_reuses_matched_cursor_at_two_hundred_thousand_packets() {
    let mut state = State::new(Options::file(
        "test".into(),
        Duration::ZERO,
        pipeline::Options {
            log: None,
            record: false,
            proc_root: None,
            alerts: Default::default(),
        },
    ));
    let mut raw = RawPacket {
        number: 1,
        ts: Duration::ZERO,
        link: LinkType::RawIp,
        iface: 0,
        orig_len: 0,
        data: Vec::new(),
    };
    state.message(Message::Packet(raw.clone()));
    let mut row = state.store.get(1).unwrap().row.clone();
    for number in 2..=200_000 {
        raw.number = number;
        row.number = number;
        state.store.push(raw.clone(), row.clone());
    }
    state.total = 200_000;
    state.last_number = 200_000;
    let query = vec![("filter".into(), "dns".into())];
    while state.packets(&query).is_none() {}
    assert_eq!(state.caches.back().unwrap().evaluated, 200_000);
    assert!(state.packets(&query).is_some());
    assert_eq!(state.caches.back().unwrap().evaluated, 200_000);
    raw.number = 200_001;
    row.number = 200_001;
    state.store.push(raw, row);
    state.total = 200_001;
    state.last_number = 200_001;
    assert!(state.packets(&query).is_some());
    assert_eq!(state.caches.back().unwrap().evaluated, 200_001);
    assert_eq!(state.store.entries.len(), 200_000);
    assert_eq!(state.store.dropped, 1);
    for text in ["tcp", "udp", "http", "arp", "icmp"] {
        let query = vec![("filter".into(), text.into())];
        while state.packets(&query).is_none() {}
        assert!(state.caches.len() <= 4);
    }
}
