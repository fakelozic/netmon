//! Checks that access rules run before API dispatch or embedded file lookup.
//! Framing belongs to `parser.rs`; wire safety headers belong to `headers.rs`.
//! Read `token_is_required_only_for_api` first. A Host header names the requested server.

use super::support::{Stub, complete, config, request};
use netmon::web::{Api, ApiReply, Method, respond};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn token_is_required_only_for_api() {
    let cfg = config();
    let mut req = request("/api/session");
    assert_eq!(respond(&req, &cfg, &Stub).status, 401);
    req.headers.push(("X-Netmon-Token".into(), "wrong".into()));
    assert_eq!(respond(&req, &cfg, &Stub).status, 401);
    req.headers.pop();
    req.headers
        .push(("x-NeTmOn-ToKeN".into(), cfg.token.to_string()));
    assert_eq!(respond(&req, &cfg, &Stub).status, 200);
    req.headers
        .push(("X-Netmon-Token".into(), cfg.token.to_string()));
    assert_eq!(respond(&req, &cfg, &Stub).status, 401);
    assert_eq!(respond(&request("/"), &cfg, &Stub).status, 200);
}

#[test]
fn host_requires_exact_loopback_name_and_port() {
    let cfg = config();
    for (host, status) in [
        ("127.0.0.1:7979", 200),
        ("localhost:7979", 200),
        ("localhost:7980", 403),
        ("127.0.0.1:7980", 403),
        ("attacker.test:7979", 403),
        ("127.0.0.1", 403),
        ("", 403),
        ("127.0.0.1:7979.attacker.test", 403),
    ] {
        let mut req = request("/");
        req.headers = vec![("hOsT".into(), host.into())];
        assert_eq!(respond(&req, &cfg, &Stub).status, status, "{host}");
    }
    let mut req = request("/");
    req.headers.clear();
    assert_eq!(respond(&req, &cfg, &Stub).status, 403);
    req.headers = vec![("Host".into(), "localhost:7979".into()); 2];
    assert_eq!(respond(&req, &cfg, &Stub).status, 403);
}

#[test]
fn origin_must_match_the_requested_server_origin() {
    let cfg = config();
    for host in ["127.0.0.1:7979", "localhost:7979"] {
        for (origin, status) in [
            (format!("http://{host}"), 200),
            ("http://attacker.test".into(), 403),
            ("null".into(), 403),
            (format!("https://{host}"), 403),
            ("http://localhost:7980".into(), 403),
            (format!("http://{host}/"), 403),
        ] {
            let mut req = request("/");
            req.headers = vec![
                ("Host".into(), host.into()),
                ("oRiGiN".into(), origin.clone()),
            ];
            assert_eq!(respond(&req, &cfg, &Stub).status, status, "{origin}");
        }
    }
    let mut req = request("/");
    req.headers
        .extend(vec![("Origin".into(), "http://127.0.0.1:7979".into()); 2]);
    assert_eq!(respond(&req, &cfg, &Stub).status, 403);
}

#[test]
fn methods_are_limited_at_each_route() {
    let cfg = config();
    for (method, file_status, api_status) in [
        (Method::Get, 200, 200),
        (Method::Head, 200, 400),
        (Method::Post, 400, 404),
        (Method::Options, 400, 400),
        (Method::Other, 400, 400),
    ] {
        let mut req = request("/");
        req.method = method;
        assert_eq!(respond(&req, &cfg, &Stub).status, file_status);
        req.path = "/api/session".into();
        req.headers
            .push(("X-Netmon-Token".into(), cfg.token.to_string()));
        assert_eq!(respond(&req, &cfg, &Stub).status, api_status);
    }
    let mut preflight = request("/api/session");
    preflight.method = Method::Options;
    assert_eq!(respond(&preflight, &cfg, &Stub).status, 400);
}

struct CheckingApi(AtomicUsize);
impl Api for CheckingApi {
    fn handle(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
    ) -> ApiReply {
        assert_eq!(method, Method::Post);
        assert_eq!(path, "control");
        assert_eq!(query, [("filter".into(), "dns and tls".into())]);
        assert_eq!(body, b"{}!");
        self.0.fetch_add(1, Ordering::Relaxed);
        ApiReply {
            status: 200,
            json: "{\"ok\":true}".into(),
        }
    }
}

#[test]
fn dispatch_preserves_method_path_query_and_body() {
    let cfg = config();
    let bytes = format!(
        "POST /api/control?filter=dns+and+tls HTTP/1.1\r\nHOST: 127.0.0.1:7979\r\nX-Netmon-Token: {}\r\nContent-Length: 3\r\n\r\n{{}}!",
        cfg.token
    );
    let (mut req, _) = complete(bytes.as_bytes());
    let api = CheckingApi(AtomicUsize::new(0));
    assert_eq!(respond(&req, &cfg, &api).body, b"{\"ok\":true}");
    req.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("x-netmon-token"));
    assert_eq!(respond(&req, &cfg, &api).status, 401);
    assert_eq!(api.0.load(Ordering::Relaxed), 1);
}

#[test]
fn static_lookup_cannot_read_other_paths() {
    let cfg = config();
    for path in [
        "/assets/../Cargo.toml",
        "/assets/%2e%2e/x",
        "//etc/passwd",
        "/assets/unknown.js",
        "/Cargo.toml",
        "/index.html",
        "/api",
        "/assets/",
    ] {
        let reply = respond(&request(path), &cfg, &Stub);
        assert!(matches!(reply.status, 400 | 404), "{path}");
        assert!(reply.body.starts_with(b"{\"error\":"));
    }
}

struct InvalidStatus;
impl Api for InvalidStatus {
    fn handle(&self, _: Method, _: &str, _: &[(String, String)], _: &[u8]) -> ApiReply {
        ApiReply {
            status: 0,
            json: "ignored".into(),
        }
    }
}

#[test]
fn invalid_api_status_becomes_a_safe_error() {
    let cfg = config();
    let mut req = request("/api/session");
    req.headers
        .push(("X-Netmon-Token".into(), cfg.token.to_string()));
    let response = respond(&req, &cfg, &InvalidStatus);
    assert_eq!(response.status, 500);
    assert_eq!(
        response.body,
        format!("{{\"error\": \"{}\"}}", netmon::explain::web::error(500)).as_bytes()
    );
}
