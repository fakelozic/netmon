//! Verifies accepted inbound TCP requests.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! A SYN+ACK is acceptance of a request, not proof the complete handshake finished.

use super::*;

fn accepted(engine: &mut Engine, remote: IpAddr, local: IpAddr) -> Vec<Alert> {
    assert!(observe(engine, &tcp(1, 0, (remote, 50_000), (local, 22), 2, &[])).is_empty());
    observe(
        engine,
        &tcp(2, 25, (local, 22), (remote, 50_000), 0x12, &[]),
    )
}

#[test]
fn accepted_public_inbound_connections_warn_on_ipv4_and_ipv6() {
    for (remote, local) in [
        (PUBLIC, CLIENT),
        (
            "2606:4700::1111".parse().unwrap(),
            "fd00::2".parse().unwrap(),
        ),
    ] {
        let mut engine = engine();
        engine.set_local(&[local]);
        let alerts = accepted(&mut engine, remote, local);
        one(
            &alerts,
            AlertKind::UnexpectedInbound,
            Severity::Warning,
            1,
            2,
        );
        assert_eq!(alerts[0].subject, Some(remote));
        assert_eq!(alerts[0].ts, Duration::from_millis(25));
        assert!(alerts[0].seen.contains("port 22 (usually SSH)"));
    }
}

#[test]
fn unknown_local_refused_private_and_outbound_connections_stay_quiet() {
    assert!(accepted(&mut engine(), PUBLIC, CLIENT).is_empty());
    let mut engine = engine();
    engine.set_local(&[CLIENT]);
    assert!(accepted(&mut engine, SERVER, CLIENT).is_empty());
    assert!(
        observe(
            &mut engine,
            &tcp(1, 0, (PUBLIC, 50_000), (CLIENT, 22), 2, &[])
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(2, 25, (CLIENT, 22), (PUBLIC, 50_000), 0x14, &[])
        )
        .is_empty()
    );
    // A later SYN+ACK must not resurrect a refused request.
    assert!(
        observe(
            &mut engine,
            &tcp(3, 30, (CLIENT, 22), (PUBLIC, 50_000), 0x12, &[])
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(4, 40, (CLIENT, 40_000), (PUBLIC, 22), 2, &[])
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(5, 50, (PUBLIC, 22), (CLIENT, 40_000), 0x12, &[])
        )
        .is_empty()
    );
}

#[test]
fn inbound_acknowledgement_and_full_connection_tuple_must_match() {
    let mut engine = engine();
    engine.set_local(&[CLIENT]);
    let syn = with_sequence(
        tcp(1, 0, (PUBLIC, 50_000), (CLIENT, 22), 2, &[]),
        u32::MAX,
        0,
    );
    assert!(observe(&mut engine, &syn).is_empty());
    let wrong_ack = with_sequence(
        tcp(2, 10, (CLIENT, 22), (PUBLIC, 50_000), 0x12, &[]),
        100,
        1,
    );
    assert!(observe(&mut engine, &wrong_ack).is_empty());
    let wrong_port = with_sequence(
        tcp(3, 20, (CLIENT, 23), (PUBLIC, 50_000), 0x12, &[]),
        100,
        0,
    );
    assert!(observe(&mut engine, &wrong_port).is_empty());
    let ack = with_sequence(
        tcp(4, 30, (CLIENT, 22), (PUBLIC, 50_000), 0x12, &[]),
        100,
        0,
    );
    engine.set_local(&[CLIENT]);
    let alerts = observe(&mut engine, &ack);
    one(
        &alerts,
        AlertKind::UnexpectedInbound,
        Severity::Warning,
        1,
        4,
    );
    assert!(observe(&mut engine, &ack).is_empty());
    engine.set_local(&[]);
    assert!(accepted(&mut engine, PUBLIC, CLIENT).is_empty());
}

#[test]
fn public_address_classification_excludes_local_and_special_ranges() {
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "192.0.0.9",
        "192.0.0.10",
        "2606:4700::1111",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",
    ] {
        assert!(Engine::is_public(&address.parse().unwrap()), "{address}");
    }
    for address in [
        "0.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2001:db8::1",
        "2001:2::1",
        "2001:10::1",
        "2001:20::1",
        "3fff::1",
        "::ffff:10.0.0.1",
    ] {
        assert!(!Engine::is_public(&address.parse().unwrap()), "{address}");
    }
}
