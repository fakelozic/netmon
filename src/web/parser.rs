//! Parses one bounded HTTP request without sockets or retained state.
//! Target decoding belongs to `target`; authentication belongs to `routing`.
//! Read `parse_request` first. HTTP separates headers from its body with an empty line.

use super::{BODY_LIMIT, HEADER_LIMIT, Method, Parsed, Request, target};

/// Parses at most 8 KiB of request line/headers and 4 KiB of body.
/// Returns the exact consumed byte count, leaving pipelined bytes untouched.
/// Invalid framing is rejected rather than guessing a message boundary.
pub fn parse_request(bytes: &[u8]) -> Parsed {
    let prefix = bytes.get(..HEADER_LIMIT).unwrap_or(bytes);
    let Some(end) = prefix.windows(4).position(|part| part == b"\r\n\r\n") else {
        return if bytes.len() >= HEADER_LIMIT {
            Parsed::Bad(431)
        } else {
            Parsed::Incomplete
        };
    };
    let header_end = end.saturating_add(4);
    let Some(head) = bytes.get(..end.saturating_add(2)) else {
        return Parsed::Bad(400);
    };
    let (mut request, body_len) = match parse_head(head) {
        Ok(parts) => parts,
        Err(status) => return Parsed::Bad(status),
    };
    let Some(consumed) = header_end.checked_add(body_len) else {
        return Parsed::Bad(413);
    };
    let Some(body) = bytes.get(header_end..consumed) else {
        return Parsed::Incomplete;
    };
    request.body = body.to_vec();
    Parsed::Complete(request, consumed)
}

fn parse_head(head: &[u8]) -> Result<(Request, usize), u16> {
    let text = std::str::from_utf8(head).map_err(|_| 400_u16)?;
    let mut lines = text.split("\r\n");
    let (method, target) = request_line(lines.next().ok_or(400_u16)?)?;
    let mut headers = Vec::new();
    let mut body_len = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = header(line)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // No chunked reader exists here. Reject ambiguous framing (RFC 9112, 6.3).
            return Err(400);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if body_len.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(400);
            }
            let length = value.parse::<usize>().map_err(|_| 413_u16)?;
            if length > BODY_LIMIT {
                return Err(413);
            }
            body_len = Some(length);
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    let (path, query) = target::parse(target)?;
    Ok((
        Request {
            method,
            path,
            query,
            headers,
            body: Vec::new(),
        },
        body_len.unwrap_or(0),
    ))
}

fn request_line(line: &str) -> Result<(Method, &str), u16> {
    let mut words = line.split(' ');
    let method = words.next().ok_or(400_u16)?;
    let target = words.next().ok_or(400_u16)?;
    let version = words.next().ok_or(400_u16)?;
    if words.next().is_some()
        || method.is_empty()
        || !method.bytes().all(token_byte)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || target.is_empty()
        || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(400);
    }
    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "OPTIONS" => Method::Options,
        _ => Method::Other,
    };
    Ok((method, target))
}

fn header(line: &str) -> Result<(&str, &str), u16> {
    let (name, value) = line.split_once(':').ok_or(400_u16)?;
    if name.is_empty()
        || !name.bytes().all(token_byte)
        || !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(400);
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}

pub(super) fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
