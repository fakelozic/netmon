//! Decodes bounded request paths and query pairs.
//! HTTP framing belongs to `parser`; embedded file lookup belongs to `assets`.
//! Read `parse` first. A URL query uses percent escapes to carry characters in a path.

type Query = Vec<(String, String)>;

pub(super) fn parse(target: &str) -> Result<(String, Query), u16> {
    // Accept only origin-form, never a proxy URL or an authority (RFC 9112, 3.2.1).
    if !target.starts_with('/') || target.starts_with("//") || target.contains('#') {
        return Err(400);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = decode(path, false)?;
    if forbidden_path(&path) || path.starts_with("//") {
        return Err(400);
    }
    let mut pairs = Vec::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        pairs.push((decode(key, true)?, decode(value, true)?));
    }
    Ok((path, pairs))
}

pub(super) fn forbidden_path(path: &str) -> bool {
    path.contains("..") || path.contains(['\0', '\\']) || !path.starts_with('/')
}

fn decode(value: &str, plus_is_space: bool) -> Result<String, u16> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        let byte = match byte {
            b'%' => {
                let high = hex(bytes.next().ok_or(400_u16)?)?;
                let low = hex(bytes.next().ok_or(400_u16)?)?;
                (high << 4) | low
            }
            b'+' if plus_is_space => b' ',
            other => other,
        };
        if byte == 0 || byte < 0x20 || byte == 0x7f {
            return Err(400);
        }
        out.push(byte);
    }
    String::from_utf8(out).map_err(|_| 400)
}

fn hex(byte: u8) -> Result<u8, u16> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(400),
    }
}
