//! Verifies suspicious DNS query shapes.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! Long random names also occur in legitimate traffic.

use super::*;

#[test]
fn long_labels_random_labels_and_long_total_names_raise_notices() {
    for name in [
        format!("{}.test", "a".repeat(60)),
        "abcdefghijklmnopqrstuvwxyz012345.test".into(),
        format!(
            "{}.{}.{}.test",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40)
        ),
    ] {
        let alerts = observe(&mut engine(), &dns_query(8, 500, CLIENT, &name));
        one(&alerts, AlertKind::SuspiciousDns, Severity::Notice, 8, 8);
        assert_eq!(alerts[0].subject, Some(CLIENT));
        assert!(alerts[0].why.contains("DNS tunnelling"));
        assert!(alerts[0].why.contains("Name-guessing malware"));
        assert!(
            alerts[0]
                .why
                .contains("Content networks also use long random names")
        );
    }
    let alerts = observe(
        &mut engine(),
        &dns_query(1, 0, CLIENT, "abcdefghijklmnopqrstuvwxyz012345.test"),
    );
    assert!(alerts[0].seen.contains("32-character label has 5.00 bits"));
}

#[test]
fn readable_names_and_lengths_at_threshold_stay_quiet() {
    let readable = "thisisreadablenameaboutnetworkmonitoring";
    assert_eq!(readable.len(), 40);
    for name in [
        readable.to_string(),
        "a".repeat(50),
        format!("{}.{}.{}", "a".repeat(40), "b".repeat(40), "c".repeat(38)),
    ] {
        assert!(
            observe(&mut engine(), &dns_query(1, 0, CLIENT, &name)).is_empty(),
            "{name}"
        );
    }
    // A highly varied label shorter than 24 characters does not meet the entropy rule.
    assert!(
        observe(
            &mut engine(),
            &dns_query(1, 0, CLIENT, "abcdefghijklmnopqrstuvw.test")
        )
        .is_empty()
    );
    // Escaping these bytes in the decoder must not inflate the measured name.
    assert!(
        observe(
            &mut engine(),
            &dns_labels(1, 0, CLIENT, &[&[0x1b; 20], b"test"])
        )
        .is_empty()
    );
}

#[test]
fn every_dns_question_is_checked_and_no_controls_reach_alert_text() {
    let suspicious = format!("{}.test", "a".repeat(60));
    let alerts = observe(
        &mut engine(),
        &dns_questions(1, 0, CLIENT, &["readable.test", &suspicious]),
    );
    one(&alerts, AlertKind::SuspiciousDns, Severity::Notice, 1, 1);
    let alerts = observe(
        &mut engine(),
        &dns_labels(1, 0, CLIENT, &[&[0x1b; 60], b"test"]),
    );
    one(&alerts, AlertKind::SuspiciousDns, Severity::Notice, 1, 1);
    no_secrets(&alerts[0]);
}

#[test]
fn nxdomain_burst_warns_but_slow_replies_and_separate_clients_stay_quiet() {
    let mut engine = engine();
    let mut alerts = Vec::new();
    for n in 1..=25 {
        alerts.extend(observe(&mut engine, &nxdomain(n, (n - 1) * 200, CLIENT)));
    }
    one(&alerts, AlertKind::SuspiciousDns, Severity::Warning, 1, 20);
    assert!(alerts[0].seen.contains("at least 20 NXDOMAIN"));
    let mut engine = Engine::new(Config::default());
    for n in 1..=25 {
        assert!(observe(&mut engine, &nxdomain(n, (n - 1) * 12_500, CLIENT)).is_empty());
    }
    let mut engine = Engine::new(Config::default());
    for n in 1..=25 {
        let client = if n <= 13 { CLIENT } else { PUBLIC };
        assert!(observe(&mut engine, &nxdomain(n, n * 100, client)).is_empty());
    }
}

#[test]
fn nxdomain_window_slides_with_exact_packet_numbers() {
    let mut engine = Engine::new(Config {
        nxdomain_count: 2,
        ..Config::default()
    });
    assert!(observe(&mut engine, &nxdomain(1, 0, CLIENT)).is_empty());
    assert!(observe(&mut engine, &nxdomain(2, 10_001, CLIENT)).is_empty());
    let alerts = observe(&mut engine, &nxdomain(3, 10_002, CLIENT));
    one(&alerts, AlertKind::SuspiciousDns, Severity::Warning, 2, 3);
}

#[test]
fn dns_compression_loops_and_truncated_questions_are_quiet() {
    let mut engine = Engine::new(Config::default());
    for question in [
        vec![0xc0, 12, 0, 1, 0, 1],
        vec![0xff, 0xff, 0, 1, 0, 1],
        vec![60, b'a'],
    ] {
        let mut bytes = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend(question);
        assert!(
            observe(
                &mut engine,
                &udp(1, 0, (CLIENT, 40_000), (SERVER, 53), &bytes)
            )
            .is_empty()
        );
    }
    let mut bytes = vec![0, 1, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 60];
    bytes.extend_from_slice(&[b'a'; 60]);
    bytes.extend_from_slice(&[0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1]);
    let alerts = observe(
        &mut engine,
        &udp(1, 0, (CLIENT, 40_000), (SERVER, 53), &bytes),
    );
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, AlertKind::SuspiciousDns);
}
