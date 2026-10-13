//! Writes HTTP responses with one consistent set of browser safety headers.
//! Reply routing belongs to `routing`; error sentences belong to `explain::web`.
//! Read `write_response` first. Connection close marks the end of each HTTP exchange.

use super::{Response, parser::token_byte};
use crate::explain::web;
use std::io::Write;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub(super) fn standard_headers(length: usize) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Security-Policy", CSP.into()),
        ("X-Content-Type-Options", "nosniff".into()),
        ("Referrer-Policy", "no-referrer".into()),
        ("Cache-Control", "no-store".into()),
        ("Content-Length", length.to_string()),
        ("Connection", "close".into()),
    ]
}

pub(super) fn reply(status: u16, content_type: &'static str, body: Vec<u8>) -> Response {
    Response {
        status,
        content_type,
        headers: standard_headers(body.len()),
        body,
    }
}

pub(super) fn error(status: u16) -> Response {
    // These fixed sentences contain no quotes, backslashes, or outside text.
    reply(
        match status {
            401 | 403 | 404 => status,
            500..=599 => 500,
            _ => 400,
        },
        "application/json",
        format!("{{\"error\": \"{}\"}}", web::error(status)).into_bytes(),
    )
}

/// Appends one HTTP/1.1 reply. Safety headers are enforced even for hand-built replies.
/// HEAD replies may keep the original length in headers while carrying an empty body.
/// CORS headers and invalid header text are discarded, preventing header injection.
pub fn write_response(r: &Response, out: &mut Vec<u8>) {
    let status = if (200..=599).contains(&r.status) {
        r.status
    } else {
        500
    };
    let _ = write!(out, "HTTP/1.1 {status} {}\r\n", web::reason(status));
    let content_type = if valid_value(r.content_type) {
        r.content_type
    } else {
        "application/octet-stream"
    };
    let _ = write!(out, "Content-Type: {content_type}\r\n");
    let length = if r.body.is_empty() {
        r.headers
            .iter()
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("Content-Length")
                    .then(|| value.parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    } else {
        r.body.len()
    };
    let required = standard_headers(length);
    for (name, value) in &required {
        let _ = write!(out, "{name}: {value}\r\n");
    }
    for (name, value) in &r.headers {
        if !name.is_empty()
            && name.bytes().all(token_byte)
            && valid_value(value)
            && !name.to_ascii_lowercase().starts_with("access-control-")
            && !name.eq_ignore_ascii_case("content-type")
            && !required
                .iter()
                .any(|(key, _)| name.eq_ignore_ascii_case(key))
        {
            let _ = write!(out, "{name}: {value}\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
}

fn valid_value(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}
