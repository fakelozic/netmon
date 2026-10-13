//! Verifies cleartext credential detection.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! TLS records are opaque even when their synthetic test bytes contain readable text.

use super::*;

#[test]
fn http_authorization_and_proxy_authorization_fire_without_any_secret() {
    for header in [
        format!("Authorization: Basic {BASE64}"),
        "aUtHoRiZaTiOn: Bearer bearer-secret".into(),
        "Proxy-Authorization: Bearer proxy-secret".into(),
        "Authorization: packet-secret".into(),
    ] {
        let alerts = observe(&mut engine(), &http(9, 2000, Some(&header)));
        one(
            &alerts,
            AlertKind::CleartextCredentials,
            Severity::Serious,
            9,
            9,
        );
        assert_eq!(alerts[0].subject, Some(SERVER));
        assert!(alerts[0].seen.contains("HTTP"));
        no_secrets(&alerts[0]);
    }
    // A plaintext request remains plaintext even if sent to the usual HTTPS port.
    let payload = format!("GET / HTTP/1.1\r\nAuthorization: Basic {BASE64}\r\n\r\n");
    let alerts = observe(
        &mut engine(),
        &tcp(
            1,
            0,
            (CLIENT, 40_000),
            (SERVER, 443),
            0x18,
            payload.as_bytes(),
        ),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        1,
        1,
    );
}

#[test]
fn ftp_user_and_pass_fire_without_any_secret() {
    let mut engine = engine();
    let user = format!("USER {USERNAME}\r\n");
    let pass = format!("PASS {PASSWORD}\r\n");
    let alerts = observe(
        &mut engine,
        &tcp(
            3,
            1000,
            (CLIENT, 40_000),
            (SERVER, 21),
            0x18,
            user.as_bytes(),
        ),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        3,
        3,
    );
    no_secrets(&alerts[0]);
    assert!(
        observe(
            &mut engine,
            &tcp(
                4,
                2000,
                (CLIENT, 40_000),
                (SERVER, 21),
                0x18,
                pass.as_bytes()
            )
        )
        .is_empty()
    );
    let alerts = observe(
        &mut Engine::new(Config::default()),
        &tcp(
            4,
            2000,
            (CLIENT, 40_000),
            (SERVER, 21),
            0x18,
            pass.as_bytes(),
        ),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        4,
        4,
    );
    no_secrets(&alerts[0]);
}

#[test]
fn telnet_fires_once_without_any_secret() {
    let user = format!("USER {USERNAME}\r\n");
    let pass = format!("PASS {PASSWORD}\r\n");
    let mut engine = engine();
    assert!(
        observe(
            &mut engine,
            &tcp(5, 0, (CLIENT, 40_000), (SERVER, 23), 2, &[])
        )
        .is_empty()
    );
    let alerts = observe(
        &mut engine,
        &tcp(
            6,
            1000,
            (CLIENT, 40_000),
            (SERVER, 23),
            0x18,
            pass.as_bytes(),
        ),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        5,
        6,
    );
    no_secrets(&alerts[0]);
    assert!(
        observe(
            &mut engine,
            &tcp(
                7,
                120_000,
                (SERVER, 23),
                (CLIENT, 40_000),
                0x18,
                user.as_bytes()
            )
        )
        .is_empty()
    );
}

#[test]
fn telnet_reopens_after_close_and_can_be_detected_in_either_direction() {
    let mut engine = engine();
    let reply = tcp(1, 0, (SERVER, 23), (CLIENT, 40_000), 0x18, b"Login: ");
    let alerts = observe(&mut engine, &reply);
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        1,
        1,
    );
    assert_eq!(alerts[0].subject, Some(SERVER));
    assert!(
        observe(
            &mut engine,
            &tcp(2, 10, (SERVER, 23), (CLIENT, 40_000), 4, &[])
        )
        .is_empty()
    );
    let alerts = observe(
        &mut engine,
        &tcp(3, 60_000, (SERVER, 23), (CLIENT, 40_000), 0x18, b"Login: "),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        3,
        3,
    );
}

#[test]
fn telnet_half_close_does_not_repeat_and_new_syn_starts_a_new_conversation() {
    let mut engine = engine();
    assert!(
        observe(
            &mut engine,
            &tcp(1, 0, (CLIENT, 40_000), (SERVER, 23), 2, &[])
        )
        .is_empty()
    );
    assert_eq!(
        observe(
            &mut engine,
            &tcp(2, 10, (CLIENT, 40_000), (SERVER, 23), 0x18, b"login")
        )
        .len(),
        1
    );
    assert!(
        observe(
            &mut engine,
            &tcp(3, 20, (CLIENT, 40_000), (SERVER, 23), 0x11, &[])
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(
                4,
                70_000,
                (SERVER, 23),
                (CLIENT, 40_000),
                0x18,
                b"last reply"
            )
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine,
            &tcp(5, 80_000, (CLIENT, 40_000), (SERVER, 23), 2, &[])
        )
        .is_empty()
    );
    let alerts = observe(
        &mut engine,
        &tcp(6, 80_010, (CLIENT, 40_000), (SERVER, 23), 0x18, b"login"),
    );
    one(
        &alerts,
        AlertKind::CleartextCredentials,
        Severity::Serious,
        5,
        6,
    );
}

#[test]
fn requests_without_credentials_and_opaque_tls_stay_quiet() {
    assert!(observe(&mut engine(), &http(1, 0, None)).is_empty());
    assert!(observe(&mut engine(), &http(1, 0, Some("Cookie: packet-secret"))).is_empty());
    let hidden = format!("GET / HTTP/1.1\r\nAuthorization: Basic {BASE64}\r\n\r\n");
    for port in [21, 23, 443] {
        assert!(
            observe(
                &mut engine(),
                &tcp(
                    1,
                    0,
                    (CLIENT, 40_000),
                    (SERVER, port),
                    0x18,
                    &tls_record(hidden.as_bytes())
                )
            )
            .is_empty()
        );
    }
    assert!(
        observe(
            &mut engine(),
            &tcp(1, 0, (CLIENT, 40_000), (SERVER, 21), 0x18, b"NOOP\r\n")
        )
        .is_empty()
    );
    assert!(
        observe(
            &mut engine(),
            &tcp(
                1,
                0,
                (SERVER, 21),
                (CLIENT, 40_000),
                0x18,
                b"USER not-a-command-from-client\r\n"
            )
        )
        .is_empty()
    );
}
