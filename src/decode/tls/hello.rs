//! Reads the fixed TLS hello layout and its offered parameters.
//! Optional extension parsing belongs to `super::extensions`; records belong to `super::records`.
//! Start with `hello`.

// RFC 5246, section 7.4.1; RFC 8446, section 4.1: hellos offer or select encryption settings.
// +------------+------------+------------+-------------------+
// | Version 16 | Random 32B | ID len 8   | Session ID ...    |
// +------------+------------+------------+-------------------+
// | Client suites / server suite | Compression | Extensions |
// +--------------------------------------------------------+
use super::extensions::extensions;
use crate::decode::{ClientHello, Context, Field, FieldKey as K, View};

/// Reads a client or server hello body without its handshake header; incomplete parameters mark the context truncated.
pub(super) fn hello(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    server: bool,
) -> (ClientHello, u16, u16) {
    // TLS hellos retain an older version field for compatibility; extensions can negotiate a newer version (RFC 8446, section 4.1.2).
    let legacy = v.u16(0).unwrap_or(0);
    let mut chosen = legacy;
    let mut cipher = 0;
    if let Some(n) = v.u16(0) {
        c.field(
            fields,
            K::TlsHelloVersion,
            v,
            (0, 2),
            || format!("0x{n:04x} ({})", crate::explain::tls_version(n)),
            Some(u64::from(n)),
        );
    }
    c.raw(fields, K::TlsRandom, v, 2, 32);
    if v.bytes.len() < 35 {
        c.decoded.truncated = true;
        return (ClientHello::default(), chosen, cipher);
    }
    let sid_len = usize::from(v.u8(34).unwrap_or(0));
    c.raw(fields, K::TlsSession, v, 35, sid_len);
    let mut off = 35usize.saturating_add(sid_len);
    if off > v.bytes.len() {
        c.decoded.truncated = true;
        return (ClientHello::default(), chosen, cipher);
    }
    if server {
        cipher = v.u16(off).unwrap_or(0);
        if let Some(n) = v.u16(off) {
            c.field(
                fields,
                K::TlsCipher,
                v,
                (off, 2),
                || format!("0x{n:04x}"),
                Some(u64::from(n)),
            );
        }
        off = off.saturating_add(2);
        c.n(fields, K::TlsCompression, v, off, 1, v.num(off, 1));
        off = off.saturating_add(1);
    } else if let Some(next) = client_parameters(c, fields, v, off) {
        off = next;
    } else {
        return (ClientHello::default(), chosen, cipher);
    }
    let mut result = ClientHello {
        versions: vec![legacy],
        ..ClientHello::default()
    };
    if off > v.bytes.len() {
        c.decoded.truncated = true;
        return (result, chosen, cipher);
    }
    if off == v.bytes.len() {
        result.complete = true;
        return (result, chosen, cipher);
    }
    if !extensions(c, fields, v, off, server, &mut result, &mut chosen) {
        return (result, chosen, cipher);
    }
    result.complete = !c.decoded.truncated;
    (result, chosen, cipher)
}

fn client_parameters(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    mut off: usize,
) -> Option<usize> {
    let Some(len) = v.u16(off) else {
        c.decoded.truncated = true;
        return None;
    };
    let len = usize::from(len);
    c.n(fields, K::TlsCipherCount, v, off, 2, Some((len / 2) as u64));
    off = off.saturating_add(2);
    c.raw(fields, K::TlsCiphers, v, off, len);
    off = off.saturating_add(len);
    let Some(compression_len) = v.u8(off) else {
        c.decoded.truncated = true;
        return None;
    };
    off = off.saturating_add(1);
    c.raw(
        fields,
        K::TlsCompression,
        v,
        off,
        usize::from(compression_len),
    );
    off = off.saturating_add(usize::from(compression_len));
    Some(off)
}
