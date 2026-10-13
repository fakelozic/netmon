//! Verifies distinct-port scan windows.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! Repeated packets to one port must not count as distinct services.

use super::*;

#[test]
fn tcp_and_udp_scans_fire_at_twenty_distinct_ports() {
    for udp_scan in [false, true] {
        let alerts = scan(&mut engine(), 25, 100, udp_scan);
        one(&alerts, AlertKind::PortScan, Severity::Warning, 1, 20);
        assert_eq!(alerts[0].ts, Duration::from_millis(1900));
        assert_eq!(alerts[0].subject, Some(PUBLIC));
        assert!(alerts[0].seen.contains("20 different ports"));
    }
}

#[test]
fn sparse_small_repeated_and_split_destination_scans_stay_quiet() {
    for udp_scan in [false, true] {
        assert!(scan(&mut engine(), 19, 100, udp_scan).is_empty());
        assert!(scan(&mut engine(), 25, 2500, udp_scan).is_empty());
    }
    let mut engine = engine();
    for n in 1..=100 {
        assert!(
            observe(
                &mut engine,
                &tcp(n, n * 10, (PUBLIC, 40_000), (CLIENT, 22), 2, &[])
            )
            .is_empty()
        );
        // SYN+ACK and ordinary data are not scan probes.
        assert!(
            observe(
                &mut engine,
                &tcp(
                    n,
                    n * 10,
                    (PUBLIC, 40_000),
                    (CLIENT, n as u16 + 100),
                    0x12,
                    &[]
                )
            )
            .is_empty()
        );
        assert!(
            observe(
                &mut engine,
                &tcp(
                    n,
                    n * 10,
                    (PUBLIC, 40_000),
                    (CLIENT, n as u16 + 100),
                    0x18,
                    b"data"
                )
            )
            .is_empty()
        );
    }
    let mut engine = Engine::new(Config::default());
    for port in 1..=25 {
        let destination = if port <= 13 { CLIENT } else { SERVER };
        assert!(
            observe(
                &mut engine,
                &tcp(
                    u64::from(port),
                    0,
                    (PUBLIC, 40_000),
                    (destination, port),
                    2,
                    &[]
                )
            )
            .is_empty()
        );
    }
}

#[test]
fn local_scan_is_notice_and_both_transport_types_contribute() {
    let mut engine = engine();
    engine.set_local(&[CLIENT, PUBLIC]);
    let alerts = scan(&mut engine, 25, 100, false);
    one(&alerts, AlertKind::PortScan, Severity::Notice, 1, 20);
    let mut engine = Engine::new(Config {
        scan_ports: 2,
        ..Config::default()
    });
    assert!(
        observe(
            &mut engine,
            &tcp(1, 0, (PUBLIC, 1000), (CLIENT, 100), 2, &[])
        )
        .is_empty()
    );
    let alerts = observe(&mut engine, &udp(2, 0, (PUBLIC, 1000), (CLIENT, 101), &[]));
    one(&alerts, AlertKind::PortScan, Severity::Warning, 1, 2);
}

#[test]
fn scan_window_slides_and_includes_its_boundary() {
    let config = Config {
        scan_ports: 2,
        repeat_after: Duration::ZERO,
        ..Config::default()
    };
    let mut engine = Engine::new(config.clone());
    assert!(
        observe(
            &mut engine,
            &tcp(1, 0, (PUBLIC, 1000), (CLIENT, 100), 2, &[])
        )
        .is_empty()
    );
    let alerts = observe(
        &mut engine,
        &tcp(2, 10_000, (PUBLIC, 1000), (CLIENT, 101), 2, &[]),
    );
    one(&alerts, AlertKind::PortScan, Severity::Warning, 1, 2);
    let mut engine = Engine::new(config);
    assert!(
        observe(
            &mut engine,
            &tcp(1, 0, (PUBLIC, 1000), (CLIENT, 100), 2, &[])
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(2, 10_001, (PUBLIC, 1000), (CLIENT, 101), 2, &[])
        )
        .is_empty()
    );
    let alerts = observe(
        &mut engine,
        &tcp(3, 10_002, (PUBLIC, 1000), (CLIENT, 102), 2, &[]),
    );
    one(&alerts, AlertKind::PortScan, Severity::Warning, 2, 3);
}

#[test]
fn repeated_scan_probes_preserve_the_original_packet_reference() {
    let mut engine = Engine::new(Config {
        scan_ports: 2,
        ..Config::default()
    });
    for (number, port) in [(1, 100), (2, 100)] {
        assert!(
            observe(
                &mut engine,
                &tcp(number, number * 100, (PUBLIC, 1000), (CLIENT, port), 2, &[])
            )
            .is_empty()
        );
    }
    let alerts = observe(
        &mut engine,
        &tcp(3, 300, (PUBLIC, 1000), (CLIENT, 101), 2, &[]),
    );
    one(&alerts, AlertKind::PortScan, Severity::Warning, 1, 3);
}

#[test]
fn scan_repeats_only_after_sixty_seconds_from_the_last_alert() {
    let mut engine = engine();
    let mut alerts = Vec::new();
    for n in 0..=620 {
        alerts.extend(observe(
            &mut engine,
            &tcp(
                n + 1,
                n * 100,
                (PUBLIC, 1000),
                (CLIENT, (n % 25 + 1) as u16),
                2,
                &[],
            ),
        ));
    }
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].ts, Duration::from_millis(1900));
    assert_eq!(alerts[1].ts, Duration::from_millis(61_900));
}
