//! Verifies bounded packet retention.
//! Fixture loading belongs to ui_support; filter grammar tests stay in filter.rs.
//! Read arrivals_and_evictions_during_sliced_rebuild_stay_ordered for rebuild edges.
use crate::ui_support;
use netmon::{filter, store::Store};
#[test]
fn store_drops_oldest_for_count_and_byte_limits() {
    let packets = ui_support::packets();
    let mut store = Store::with_limits(2, 200);
    for p in packets.iter().take(3).cloned() {
        store.push(p);
    }
    assert_eq!(store.len(), 2);
    assert_eq!(store.dropped(), 1);
    assert_eq!(store.bytes(), 196);
    assert_eq!(store.visible(0).unwrap().raw.number, 2);
    store.push(packets[4].clone()); // 118 bytes: both 98-byte entries must fall off.
    assert_eq!(store.len(), 1);
    assert_eq!(store.dropped(), 3);
    assert_eq!(store.visible(0).unwrap().raw.number, 5);
    let mut too_large = packets[0].clone();
    too_large.data.resize(201, 0);
    store.push(too_large);
    assert_eq!(store.dropped(), 4);
    assert_eq!(store.total(), 5);
    assert_eq!(store.len(), 1);
    let mut zero = Store::new(0);
    zero.push(packets[0].clone());
    assert!(zero.is_empty());
    assert_eq!(zero.dropped(), 1);
}
#[test]
fn arrivals_and_evictions_during_sliced_rebuild_stay_ordered() {
    let packets = ui_support::packets();
    let mut store = Store::with_limits(40_004, 10_000_000);
    for number in 0..40_004 {
        let mut p = packets[if number % 2 == 0 { 8 } else { 16 }].clone();
        p.number = number + 1;
        store.push(p);
    }
    store.set_filter("dns".into(), filter::parse("dns").unwrap());
    store.on_tick();
    assert!(store.rebuilding());
    assert_eq!(store.visible_len(), 10_000);
    for number in 40_004..40_014 {
        let mut p = packets[8].clone();
        p.number = number + 1;
        store.push(p);
    }
    store.on_tick();
    assert!(store.rebuilding());
    store.on_tick();
    assert!(!store.rebuilding());
    // Five historical DNS packets were evicted; ten new DNS packets arrived.
    assert_eq!(store.visible_len(), 20_007);
    let mut p = packets[8].clone();
    p.number = 40_015;
    store.push(p);
    let numbers: Vec<_> = (0..store.visible_len())
        .map(|i| store.visible(i).unwrap().raw.number)
        .collect();
    assert!(numbers.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(numbers.last(), Some(&40_015));
    store.set_filter("tcp".into(), filter::parse("tcp").unwrap());
    while store.rebuilding() {
        store.on_tick();
    }
    assert!(
        (0..store.visible_len()).all(|i| store.visible(i).unwrap().summary.ip_proto == Some(6))
    );
}
