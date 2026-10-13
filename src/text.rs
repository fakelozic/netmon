//! Makes packet-derived text safe to display and formats scalar values.
//! Protocol explanations belong to `explain`; packet layout belongs to `render`.
//! Start with `sanitise`.

use crate::decode::Addr;
use std::fmt::Write;

/// Keeps printable ASCII bytes unchanged and escapes every other byte as uppercase `\xNN`.
/// Empty input gives an empty string; the output cannot contain terminal control bytes.
pub fn sanitise(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        if (0x20..=0x7e).contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
    out
}

/// Formats bytes as lowercase hexadecimal pairs separated by spaces; empty input gives an empty string.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Formats a six-byte link address as lowercase hexadecimal pairs separated by colons.
pub fn mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Formats a link or IP address without adding a port.
pub fn address(addr: &Addr) -> String {
    match addr {
        Addr::Mac(m) => mac(m),
        Addr::V4(a) => a.to_string(),
        Addr::V6(a) => a.to_string(),
    }
}

/// Formats an address with an optional port; brackets IPv6 and returns an empty string when the address is absent.
pub fn endpoint(addr: Option<&Addr>, port: Option<u16>) -> String {
    match (addr, port) {
        (Some(Addr::V6(a)), Some(p)) => format!("[{a}]:{p}"),
        (Some(a), Some(p)) => format!("{}:{p}", address(a)),
        (Some(a), None) => address(a),
        _ => String::new(),
    }
}

/// Formats an unsigned count in base ten with commas separating thousands.
pub fn number(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats 16 bytes per row with byte offsets from the start of the supplied slice; empty input gives no rows.
pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, row) in bytes.chunks(16).enumerate() {
        let ascii: String = row
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    char::from(b)
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(
            out,
            "{offset:04x}  {hex:<47}  {ascii}",
            offset = i.saturating_mul(16),
            hex = hex(row)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn controls_are_escaped() {
        assert_eq!(sanitise(b"a\x1b\n\xff"), "a\\x1B\\x0A\\xFF");
        assert_eq!(number(1234567), "1,234,567");
    }
}
