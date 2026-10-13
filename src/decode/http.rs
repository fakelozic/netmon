//! Reads the HTTP message present in one TCP payload.
//! TCP framing belongs to `transport`; secret-masking wording belongs to `crate::explain`.
//! Start with `http`.

// RFC 9112 HTTP/1.1 message syntax; RFC 9110 semantics.
// +------------------------------------------------------+
// | method SP request-target SP HTTP-version CRLF         |
// | or: HTTP-version SP status-code SP reason CRLF         |
// +------------------------------------------------------+
// | field-name ':' OWS field-value OWS CRLF (repeat)       |
// +------------------------------------------------------+
// | CRLF | optional message body ...                      |
// +------------------------------------------------------+
use super::{AppInfo, Context, FieldKey as K, Proto, View};
use crate::text;

fn line(v: View<'_>, off: usize) -> (&[u8], usize, bool) {
    let rest = v.tail(off);
    if let Some(n) = rest.bytes.windows(2).position(|b| b == b"\r\n") {
        (
            rest.get(0, n).unwrap_or_default(),
            off.saturating_add(n).saturating_add(2),
            true,
        )
    } else {
        (rest.bytes, v.bytes.len(), false)
    }
}

/// Recognises an HTTP/1 message, hides credential and cookie headers, and returns false for unrecognised payloads.
pub(super) fn http(c: &mut Context, v: View<'_>) -> bool {
    let (first, off, complete) = line(v, 0);
    let request = [
        b"GET ".as_slice(),
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"CONNECT ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
    ]
    .iter()
    .any(|prefix| first.starts_with(prefix));
    let response = first.starts_with(b"HTTP/1.");
    if !request && !response {
        return false;
    }
    // HTTP/1 separates a start line, named headers and a body with CRLF boundaries (RFC 9112, section 2.1).
    let mut parts = first.splitn(3, |b| *b == b' ');
    let a = parts.next().unwrap_or_default();
    let b = parts.next().unwrap_or_default();
    let d = parts.next().unwrap_or_default();
    let shown = start_line(request, first, (a, b, d));
    let mut l = c.layer(Proto::Http, v, off, shown);
    if !complete {
        c.decoded.truncated = true;
    }
    start_fields(c, &mut l.fields, v, request, first, (a, b, d));
    let (off, host) = headers(c, &mut l.fields, v, off);
    l.range = v.range(0, off);
    let body = v.bytes.len().saturating_sub(off);
    c.n(&mut l.fields, K::HttpBody, v, off, body, Some(body as u64));
    c.decoded.summary.app = if request {
        Some(AppInfo::HttpRequest {
            method: text::sanitise(a),
            target: target(b),
            host,
        })
    } else {
        text::sanitise(b)
            .parse()
            .ok()
            .map(|status| AppInfo::HttpResponse {
                status,
                reason: text::sanitise(d),
            })
    };
    c.decoded.layers.push(l);
    c.data(v.tail(off));
    true
}

fn start_line(request: bool, first: &[u8], parts: (&[u8], &[u8], &[u8])) -> String {
    if request {
        let (method, path, version) = parts;
        format!(
            "{} {} {}",
            text::sanitise(method),
            target(path),
            text::sanitise(version)
        )
    } else {
        text::sanitise(first)
    }
}

fn target(bytes: &[u8]) -> String {
    // Queries and URI userinfo can contain passwords or tokens (RFC 9110, 4.2.4).
    // Hide the whole target rather than guessing which parameter names are private.
    if bytes.contains(&b'?') || bytes.contains(&b'@') {
        crate::explain::HIDDEN_HEADER.into()
    } else {
        text::sanitise(bytes)
    }
}

fn start_fields(
    c: &Context,
    fields: &mut Vec<super::Field>,
    v: View<'_>,
    request: bool,
    first: &[u8],
    parts: (&[u8], &[u8], &[u8]),
) {
    let (a, b, d) = parts;
    c.field(
        fields,
        if request {
            K::HttpRequestLine
        } else {
            K::HttpStatusLine
        },
        v,
        (0, first.len()),
        || start_line(request, first, (a, b, d)),
        None,
    );
    if request {
        for (key, pos, bytes) in [
            (K::HttpMethod, 0, a),
            (K::HttpTarget, a.len().saturating_add(1), b),
            (
                K::HttpVersion,
                a.len().saturating_add(b.len()).saturating_add(2),
                d,
            ),
        ] {
            c.field(
                fields,
                key,
                v,
                (pos, bytes.len()),
                || {
                    if key == K::HttpTarget {
                        target(bytes)
                    } else {
                        text::sanitise(bytes)
                    }
                },
                None,
            );
        }
    } else {
        c.field(
            fields,
            K::HttpVersion,
            v,
            (0, a.len()),
            || text::sanitise(a),
            None,
        );
        c.field(
            fields,
            K::HttpStatus,
            v,
            (a.len().saturating_add(1), b.len()),
            || text::sanitise(b),
            text::sanitise(b).parse::<u64>().ok(),
        );
        c.field(
            fields,
            K::HttpReason,
            v,
            (a.len().saturating_add(b.len()).saturating_add(2), d.len()),
            || text::sanitise(d),
            None,
        );
    }
}

fn headers(
    c: &mut Context,
    fields: &mut Vec<super::Field>,
    v: View<'_>,
    mut off: usize,
) -> (usize, Option<String>) {
    let mut host = None;
    let mut terminated = false;
    // A 256-header cap limits field allocation in an attacker-supplied HTTP payload.
    for _ in 0..256 {
        if off >= v.bytes.len() {
            break;
        }
        let start = off;
        let (header, next, complete) = line(v, off);
        off = next;
        if header.is_empty() && complete {
            terminated = true;
            break;
        }
        header_value(c, fields, v, start, header, &mut host);
        if !complete {
            c.decoded.truncated = true;
            break;
        }
    }
    if !terminated {
        c.decoded.truncated = true;
    }
    (off, host)
}

fn header_value(
    c: &Context,
    fields: &mut Vec<super::Field>,
    v: View<'_>,
    start: usize,
    header: &[u8],
    host: &mut Option<String>,
) {
    // Obsolete folded lines can carry a split credential; hide them even when the previous name was cut short (RFC 9112, section 5.2).
    if header.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        c.field(
            fields,
            K::HttpHeader,
            v,
            (start, header.len()),
            || crate::explain::HIDDEN_HEADER.into(),
            None,
        );
    } else if let Some(colon) = header.iter().position(|b| *b == b':') {
        let name = text::sanitise(header.get(..colon).unwrap_or_default().trim_ascii())
            .trim()
            .to_string();
        let raw = header.get(colon.saturating_add(1)..).unwrap_or_default();
        let value = text::sanitise(raw).trim().to_string();
        if name.eq_ignore_ascii_case("Host") {
            *host = Some(value.clone());
        }
        let shown = crate::explain::http_header_value(&name, &value);
        c.field(
            fields,
            K::HttpHeader,
            v,
            (start, header.len()),
            || format!("{name}: {shown}"),
            None,
        );
    } else {
        // A malformed or cut-off name cannot establish a harmless header value.
        c.field(
            fields,
            K::HttpHeader,
            v,
            (start, header.len()),
            || crate::explain::HIDDEN_HEADER.into(),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn masks_secrets_and_escapes_headers() {
        let b=b"GET / HTTP/1.1\r\nHost: test\r\nAuthorization: Basic c2VjcmV0\r\nCookie: secret=1\r\nX-Test: \x1b[31m\r\n\r\n";
        let mut c = Context::new(b.len() as u32, super::super::Detail::Full);
        assert!(http(&mut c, View { bytes: b, base: 0 }));
        assert!(!c.decoded.truncated);
        let shown = c.decoded.layers[0]
            .fields
            .iter()
            .map(|f| f.value.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!shown.contains("c2VjcmV0"));
        assert!(!shown.contains("secret=1"));
        assert!(shown.contains("Basic [hidden]"));
        assert!(shown.contains("\\x1B"));
        assert!(shown.chars().all(|ch| !ch.is_control() || ch == '\n'));
    }
    #[test]
    fn folded_and_proxy_credentials_are_masked() {
        let b=b"GET / HTTP/1.1\r\nAuthorization: Basic secret\r\n more-secret\r\n continuation: secret\r\nProxy-Authorization: Bearer proxy-secret\r\nSet-Cookie: secret-cookie\r\n\r\n";
        let mut c = Context::new(b.len() as u32, super::super::Detail::Full);
        http(&mut c, View { bytes: b, base: 0 });
        assert!(
            !c.decoded
                .layers
                .iter()
                .flat_map(|l| &l.fields)
                .any(|f| f.value.contains("secret"))
        );
    }
}
