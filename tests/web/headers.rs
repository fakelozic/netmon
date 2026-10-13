//! Checks required headers on routed replies and hand-built wire responses.
//! Access checks belong to `rules.rs`; these tests examine browser-facing bytes.
//! Read `routed_success_and_errors_have_safety_headers` first.

use super::support::{Stub, config, request};
use netmon::web::{Method, Response, respond, write_response};

const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn check_headers(response: &Response) {
    for (key, value) in [
        ("Content-Security-Policy", POLICY),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        ("Connection", "close"),
    ] {
        let found: Vec<_> = response
            .headers
            .iter()
            .filter(|(name, _)| *name == key)
            .collect();
        assert_eq!(found.len(), 1, "{key}");
        assert_eq!(found[0].1, value);
    }
    assert!(
        response
            .headers
            .iter()
            .any(|(key, _)| *key == "Content-Length")
    );
    assert!(
        !response
            .headers
            .iter()
            .any(|(key, _)| key.to_ascii_lowercase().starts_with("access-control-"))
    );
    check_wire(response);
}

fn check_wire(response: &Response) -> String {
    let mut out = Vec::new();
    write_response(response, &mut out);
    let wire = String::from_utf8(out).expect("UTF-8 test responses");
    let (headers, _) = wire.split_once("\r\n\r\n").expect("HTTP header terminator");
    for (key, value) in [
        ("Content-Security-Policy", POLICY),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        ("Connection", "close"),
        ("Content-Type", response.content_type),
    ] {
        assert_eq!(
            headers
                .lines()
                .filter(|line| *line == format!("{key}: {value}"))
                .count(),
            1,
            "{key}"
        );
    }
    assert_eq!(
        headers
            .lines()
            .filter(|line| line.starts_with("Content-Length:"))
            .count(),
        1
    );
    assert!(!headers.to_ascii_lowercase().contains("access-control-"));
    wire
}

#[test]
fn routed_success_and_errors_have_safety_headers() {
    let cfg = config();
    let mut req = request("/");
    for (path, method, expected) in [
        ("/", Method::Get, 200),
        ("/", Method::Head, 200),
        ("/missing", Method::Get, 404),
        ("/api/session", Method::Get, 401),
        ("/", Method::Post, 400),
        ("/a..b", Method::Get, 400),
    ] {
        req.path = path.into();
        req.method = method;
        let reply = respond(&req, &cfg, &Stub);
        assert_eq!(reply.status, expected);
        check_headers(&reply);
    }
    req.headers.clear();
    let reply = respond(&req, &cfg, &Stub);
    assert_eq!(reply.status, 403);
    check_headers(&reply);
    req = request("/api/session");
    req.headers
        .push(("X-Netmon-Token".into(), cfg.token.to_string()));
    check_headers(&respond(&req, &cfg, &Stub));
    req.body.resize(4097, b'x');
    let oversized = respond(&req, &cfg, &Stub);
    assert_eq!(oversized.status, 400);
    check_headers(&oversized);
}

#[test]
fn serializer_enforces_headers_on_all_error_statuses() {
    for status in [400, 401, 403, 404, 400, 408, 413, 431, 500, 503] {
        let reply = Response {
            status,
            content_type: "application/json",
            headers: vec![],
            body: format!("{{\"error\": \"{}\"}}", netmon::explain::web::error(status))
                .into_bytes(),
        };
        let wire = check_wire(&reply);
        assert!(wire.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(wire.contains(&format!("Content-Length: {}\r\n", reply.body.len())));
        assert!(wire.ends_with(std::str::from_utf8(&reply.body).expect("JSON")));
    }
}

#[test]
fn caller_cannot_override_safety_or_inject_headers() {
    let reply = Response {
        status: 200,
        content_type: "application/json",
        body: b"{}".to_vec(),
        headers: vec![
            ("Content-Security-Policy", "unsafe".into()),
            ("Connection", "keep-alive".into()),
            ("Content-Length", "999".into()),
            ("aCcEsS-CoNtRoL-Allow-Origin", "*".into()),
            ("Bad\r\nHeader", "x".into()),
            ("X-Test", "ok\r\nInjected: yes".into()),
        ],
    };
    let wire = check_wire(&reply);
    assert!(wire.contains("Content-Length: 2\r\n"));
    assert!(!wire.contains("Injected"));
    assert!(!wire.contains("Bad"));
}

#[test]
fn head_preserves_length_without_sending_a_body() {
    let cfg = config();
    let mut req = request("/");
    let get = respond(&req, &cfg, &Stub);
    req.method = Method::Head;
    let head = respond(&req, &cfg, &Stub);
    assert_eq!(head.headers, get.headers);
    let wire = check_wire(&head);
    assert!(wire.contains(&format!("Content-Length: {}\r\n", get.body.len())));
    assert!(wire.ends_with("\r\n\r\n"));
}
