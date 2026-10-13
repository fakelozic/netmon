//! Checks framing, decoding, limits and rejection of unsafe request targets.
//! Mutation tests belong to `robustness.rs`; access policy belongs to `rules.rs`.
//! Read `get_and_post` first. Content-Length counts body bytes, not characters.

use super::support::{bad, complete};
use netmon::web::{Method, Parsed, parse_request};

#[test]
fn get_and_post() {
    for version in ["HTTP/1.0", "HTTP/1.1"] {
        let bytes = format!("GET / {version}\r\nHost: localhost:7979\r\n\r\n");
        let (req, count) = complete(bytes.as_bytes());
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.path, "/");
        assert!(req.body.is_empty());
        assert_eq!(count, bytes.len());
    }
    let bytes =
        b"POST /api/control HTTP/1.1\r\ncOnTeNt-LeNgTh: 3\r\nHoSt: localhost:7979\r\n\r\n\0xyEXTRA";
    let (req, count) = complete(bytes);
    assert_eq!(req.method, Method::Post);
    assert_eq!(
        req.headers,
        [
            ("content-length".into(), "3".into()),
            ("host".into(), "localhost:7979".into())
        ]
    );
    assert_eq!(req.body, b"\0xy");
    assert_eq!(count, bytes.len() - 5);
}

#[test]
fn percent_encoded_query_and_path() {
    let (req, _) = complete(b"GET /api/%73ession?filter=dns+and+port+53&name=a%26b%3Dc&empty=&bare&plus=%2B&utf=%C2%B5 HTTP/1.1\r\n\r\n");
    assert_eq!(req.path, "/api/session");
    assert_eq!(
        req.query,
        [
            ("filter".into(), "dns and port 53".into()),
            ("name".into(), "a&b=c".into()),
            ("empty".into(), "".into()),
            ("bare".into(), "".into()),
            ("plus".into(), "+".into()),
            ("utf".into(), "µ".into()),
        ]
    );
    assert_eq!(
        complete(b"GET /assets/a+b.js HTTP/1.1\r\n\r\n").0.path,
        "/assets/a+b.js"
    );
}

#[test]
fn split_reads_need_more_bytes() {
    let valid = b"POST /api/control HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
    for length in 0..valid.len() {
        assert!(
            matches!(parse_request(&valid[..length]), Parsed::Incomplete),
            "prefix {length}"
        );
    }
    assert_eq!(complete(valid).0.body, b"body");
}

#[test]
fn method_names_are_case_sensitive_tokens() {
    for (name, method) in [
        ("GET", Method::Get),
        ("HEAD", Method::Head),
        ("POST", Method::Post),
        ("OPTIONS", Method::Options),
        ("DELETE", Method::Other),
        ("get", Method::Other),
    ] {
        assert_eq!(
            complete(format!("{name} / HTTP/1.1\r\n\r\n").as_bytes())
                .0
                .method,
            method
        );
    }
}

#[test]
fn header_and_body_limits_are_inclusive() {
    let start = "GET / HTTP/1.1\r\nX-Pad: ";
    let request = format!("{start}{}\r\n\r\n", "x".repeat(8192 - start.len() - 4));
    assert_eq!(complete(request.as_bytes()).1, 8192);
    let oversized = request.replacen("X-Pad: ", "X-Pad: x", 1);
    bad(oversized.as_bytes(), 431);
    bad(&vec![b'X'; 8192], 431);
    for length in [4096, 4097] {
        let mut request =
            format!("POST /api/control HTTP/1.1\r\nContent-Length: {length}\r\n\r\n").into_bytes();
        request.resize(request.len() + length, b'x');
        if length == 4096 {
            assert_eq!(complete(&request).0.body.len(), length);
        } else {
            bad(&request, 413);
        }
    }
    bad(
        b"POST / HTTP/1.1\r\nContent-Length: 999999999999999999999999999\r\n\r\n",
        413,
    );
}

#[test]
fn malformed_framing_and_lines_are_rejected() {
    for bytes in [
        &b"GET / HTTP/2.0\r\n\r\n"[..],
        b"GET / HTTP/0.9\r\n\r\n",
        b"GET /\r\n\r\n",
        b"GET  / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1 extra\r\n\r\n",
        b" / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nNoColon\r\n\r\n",
        b"GET / HTTP/1.1\r\nX: x\0\r\n\r\n",
        b"GET / HTTP/1.1\r\nX: x\rbroken\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: \r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 1,1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: identity\r\n\r\n",
        b"GET / HTTP/1.1\r\n X: folded\r\n\r\n",
    ] {
        bad(bytes, 400);
    }
}

#[test]
fn unsafe_and_malformed_targets_are_rejected() {
    for path in [
        "/assets/../Cargo.toml",
        "/assets/%2e%2e/x",
        "/assets/%2E./x",
        "/a..b",
        "/%00",
        "/a\0b",
        "/a\\b",
        "/%5c",
        "//etc/passwd",
        "/%2fetc/passwd",
        "http://localhost/",
        "*",
        "/#fragment",
        "/%",
        "/%1",
        "/%zz",
        "/%ff",
        "/?x=%00",
    ] {
        bad(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes(), 400);
    }
}
