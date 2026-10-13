//! Supplies fixed API replies and request helpers for web tests.
//! Individual assertions belong to the focused files beside this module.
//! Read `request` first; it sets a valid loopback Host but no authentication token.

use netmon::web::{Api, ApiReply, Config, Method, Parsed, Request, Token, parse_request};

/// An endpoint provider with no traffic state, for routing and socket checks.
pub(super) struct Stub;

impl Api for Stub {
    fn handle(&self, method: Method, path: &str, _: &[(String, String)], _: &[u8]) -> ApiReply {
        let status = if method == Method::Get && path == "session" {
            200
        } else {
            404
        };
        ApiReply {
            status,
            json: if status == 200 {
                "{\"state\":\"ended\"}".into()
            } else {
                format!("{{\"error\": \"{}\"}}", netmon::explain::web::error(status))
            },
        }
    }
}

/// Uses the specified contract port and a freshly generated session token.
pub(super) fn config() -> Config {
    Config {
        port: 7979,
        token: Token::generate().expect("read OS token"),
    }
}

/// Makes a GET request with a valid Host and no query, body or token.
pub(super) fn request(path: &str) -> Request {
    Request {
        method: Method::Get,
        path: path.into(),
        query: vec![],
        headers: vec![("Host".into(), "127.0.0.1:7979".into())],
        body: vec![],
    }
}

/// Requires one complete parse, returning the request and exact consumed count.
pub(super) fn complete(bytes: &[u8]) -> (Request, usize) {
    match parse_request(bytes) {
        Parsed::Complete(req, count) => (req, count),
        other => panic!("expected complete request, got {other:?}"),
    }
}

/// Requires the parser's specific HTTP rejection status.
pub(super) fn bad(bytes: &[u8], expected: u16) {
    match parse_request(bytes) {
        Parsed::Bad(status) => assert_eq!(status, expected),
        other => panic!("expected status {expected}, got {other:?}"),
    }
}
