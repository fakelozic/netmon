//! Runs deterministic acceptance tests for alert observations.
//! Packet builders live in `alert_support`; focused rule tests live in `alerts/`.
//! Read `one` for the shared alert assertion first.
//! An alert records observed packets and preserves uncertainty about their cause.

use alerts::{Alert, AlertKind, Config, Engine, Severity};
use capture::Reader;
use netmon::{alerts, capture, decode};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    time::Duration,
};

mod alert_support;
use alert_support::*;

fn engine() -> Engine {
    Engine::new(Config::default())
}

fn printed(alert: &Alert) -> String {
    alert.to_string()
}

fn scan(engine: &mut Engine, count: u16, spacing_ms: u64, udp_scan: bool) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for port in 1..=count {
        let time = u64::from(port - 1) * spacing_ms;
        let packet = if udp_scan {
            udp(u64::from(port), time, (PUBLIC, 40_000), (CLIENT, port), &[])
        } else {
            tcp(
                u64::from(port),
                time,
                (PUBLIC, 40_000),
                (CLIENT, port),
                2,
                &[],
            )
        };
        alerts.extend(observe(engine, &packet));
    }
    alerts
}

fn one(alerts: &[Alert], kind: AlertKind, severity: Severity, first: u64, packet: u64) {
    assert_eq!(alerts.len(), 1, "{alerts:#?}");
    assert_eq!(alerts[0].kind, kind);
    assert_eq!(alerts[0].severity, severity);
    assert_eq!(alerts[0].first_packet, first);
    assert_eq!(alerts[0].packet, packet);
    assert!(!alerts[0].why.is_empty());
    assert!(!alerts[0].next.is_empty());
}

fn no_secrets(alert: &Alert) {
    let all = format!("{alert:?}\n{}", printed(alert));
    for secret in [USERNAME, PASSWORD, BASE64, "bearer-secret", "proxy-secret"] {
        assert!(!all.contains(secret), "secret {secret} in alert: {all}");
    }
    for value in [
        &alert.title,
        &alert.seen,
        &alert.why.to_string(),
        &alert.next.to_string(),
    ] {
        assert!(value.chars().all(|c| !c.is_control()), "{value:?}");
    }
}

#[test]
fn same_subject_suppression_covers_arp_dns_and_credentials_without_cross_kind_suppression() {
    let mut engine = engine();
    let header = format!("Authorization: Basic {BASE64}");
    assert_eq!(observe(&mut engine, &http(1, 0, Some(&header))).len(), 1);
    assert!(observe(&mut engine, &http(2, 59_999, Some(&header))).is_empty());
    assert_eq!(
        observe(&mut engine, &http(3, 60_000, Some(&header))).len(),
        1
    );
    let long = format!("{}.test", "a".repeat(60));
    // Same IP, different kind: credentials must not suppress suspicious DNS.
    assert_eq!(
        observe(&mut engine, &dns_query(4, 60_000, SERVER, &long)).len(),
        1
    );
    assert!(observe(&mut engine, &dns_query(5, 60_001, SERVER, &long)).is_empty());
    assert_eq!(
        observe(&mut engine, &dns_query(6, 120_000, SERVER, &long)).len(),
        1
    );
    let address = Ipv4Addr::new(10, 0, 0, 53);
    assert!(observe(&mut engine, &arp(7, 120_001, address, [2, 0, 0, 0, 0, 1])).is_empty());
    assert_eq!(
        observe(&mut engine, &arp(8, 120_002, address, [2, 0, 0, 0, 0, 2])).len(),
        1
    );
    assert!(observe(&mut engine, &arp(9, 120_003, address, [2, 0, 0, 0, 0, 3])).is_empty());
    let alerts = observe(&mut engine, &arp(10, 180_002, address, [2, 0, 0, 0, 0, 4]));
    one(&alerts, AlertKind::ArpChange, Severity::Warning, 9, 10);
}

#[path = "alerts/scan.rs"]
mod scan_tests;

#[path = "alerts/credentials.rs"]
mod credentials_tests;

#[path = "alerts/arp.rs"]
mod arp_tests;

#[path = "alerts/dns.rs"]
mod dns_tests;

#[path = "alerts/inbound.rs"]
mod inbound_tests;

#[path = "alerts/robustness.rs"]
mod robustness_tests;

#[path = "alerts/golden.rs"]
mod golden_tests;
