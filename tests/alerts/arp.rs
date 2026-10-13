//! Verifies changes in ARP sender mappings.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! ARP probes use the unspecified sender address while testing whether an address is free.

use super::*;

#[test]
fn arp_changes_warn_and_gateway_changes_are_serious() {
    let address = Ipv4Addr::new(10, 0, 0, 1);
    for gateway in [false, true] {
        let mut engine = engine();
        if gateway {
            engine.set_gateway(Some(address.into()));
        }
        assert!(observe(&mut engine, &arp(10, 0, address, [2, 0, 0, 0, 0, 1])).is_empty());
        assert!(observe(&mut engine, &arp(11, 10, address, [2, 0, 0, 0, 0, 1])).is_empty());
        let alerts = observe(&mut engine, &arp(12, 20, address, [2, 0, 0, 0, 0, 2]));
        one(
            &alerts,
            AlertKind::ArpChange,
            if gateway {
                Severity::Serious
            } else {
                Severity::Warning
            },
            10,
            12,
        );
        assert_eq!(alerts[0].subject, Some(address.into()));
        assert!(alerts[0].why.contains("innocently"));
        assert!(alerts[0].seen.contains("02:00:00:00:00:01"));
        assert!(alerts[0].seen.contains("02:00:00:00:00:02"));
        assert!(observe(&mut engine, &arp(13, 60_020, address, [2, 0, 0, 0, 0, 2])).is_empty());
    }
}

#[test]
fn arp_probes_and_repeated_mappings_stay_quiet() {
    let mut engine = engine();
    for n in 0..50 {
        assert!(
            observe(
                &mut engine,
                &arp(n, n * 1000, Ipv4Addr::UNSPECIFIED, [2, 0, 0, 0, 0, n as u8])
            )
            .is_empty()
        );
        assert!(
            observe(
                &mut engine,
                &arp(n, n * 1000, Ipv4Addr::new(10, 0, 0, 1), [2, 0, 0, 0, 0, 1])
            )
            .is_empty()
        );
    }
}
