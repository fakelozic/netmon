//! Reads the bounded extension lists inside TLS hellos.
//! Fixed hello layouts belong to `super::hello`; record boundaries belong to `super::records`.
//! Start with `extensions`.

// RFC 8446, section 4.2: extensions carry optional encryption capabilities.
// +---------+-----------+------------------+
// | Type 16 | Length 16 | Data ...         |
// +---------+-----------+------------------+
use crate::decode::{ClientHello, Context, Detail, Field, FieldKey as K, View};
use crate::text;

/// Parses optional hello extensions inside their declared length boundary.
pub(super) fn extensions(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    mut off: usize,
    server: bool,
    result: &mut ClientHello,
    chosen: &mut u16,
) -> bool {
    let Some(ext_len) = v.u16(off) else {
        c.decoded.truncated = true;
        return false;
    };
    let ext_start = off.saturating_add(2);
    let ext_end = ext_start.saturating_add(usize::from(ext_len));
    let extensions = v.limit(ext_end);
    let mut extension_fields = Vec::new();
    off = ext_start;
    if ext_end > v.bytes.len() {
        c.decoded.truncated = true;
    }
    // A 256-extension cap bounds field allocation; every extension advances by its four-byte header plus declared data.
    for _ in 0..256 {
        if off >= ext_end {
            break;
        }
        let Some(ty) = extensions.u16(off) else {
            c.decoded.truncated = true;
            break;
        };
        let Some(len) = extensions.u16(off.saturating_add(2)) else {
            c.decoded.truncated = true;
            break;
        };
        let len = usize::from(len);
        let data_start = off.saturating_add(4);
        let ext = extensions.tail(data_start).limit(len);
        let mut children = Vec::new();
        if len > ext.bytes.len() {
            c.decoded.truncated = true;
        }
        match ty {
            0 => server_names(c, &mut children, ext, result),
            16 => application_protocols(c, &mut children, ext, result),
            43 => supported_versions(c, &mut children, ext, server, result, chosen),
            51 => key_shares(c, &mut children, ext, server),
            _ => {}
        }
        c.field(
            &mut extension_fields,
            K::TlsExtension,
            extensions,
            (off, len.saturating_add(4)),
            || {
                format!(
                    "{} (type={ty}), {}",
                    crate::explain::tls_extension(ty),
                    crate::explain::byte_count(len)
                )
            },
            Some(u64::from(ty)),
        );
        if c.detail == Detail::Full
            && let Some(f) = extension_fields.last_mut()
        {
            f.children = children;
        }
        off = data_start.saturating_add(len);
    }
    if off < ext_end {
        c.decoded.truncated = true;
    }
    extension_list_field(c, fields, v, ext_start, ext_len, extension_fields);
    true
}

fn server_names(
    c: &mut Context,
    children: &mut Vec<Field>,
    ext: View<'_>,
    result: &mut ClientHello,
) {
    let end = 2usize.saturating_add(usize::from(ext.u16(0).unwrap_or(0)));
    let list = ext.limit(end);
    let mut p = 2usize;
    if end > ext.bytes.len() {
        c.decoded.truncated = true;
    }
    // A 64-name cap bounds an SNI list; even an empty name consumes a three-byte entry header.
    for _ in 0..64 {
        if p >= end {
            break;
        }
        let name_type = list.u8(p);
        let Some(size) = list.u16(p.saturating_add(1)) else {
            c.decoded.truncated = true;
            break;
        };
        p = p.saturating_add(3);
        let size = usize::from(size);
        let name = list.tail(p).limit(size);
        // RFC 6066, section 3: the length describes the entire host name.
        // A prefix must never become a learned identity for this connection.
        if size > name.bytes.len() {
            c.decoded.truncated = true;
            break;
        }
        if name_type == Some(0) {
            let s = text::sanitise(name.bytes);
            if result.server_name.is_none() {
                result.server_name = Some(s.clone());
            }
            c.field(children, K::TlsServerName, list, (p, size), || s, None);
        }
        p = p.saturating_add(size);
    }
}

fn application_protocols(
    c: &mut Context,
    children: &mut Vec<Field>,
    ext: View<'_>,
    result: &mut ClientHello,
) {
    let end = 2usize.saturating_add(usize::from(ext.u16(0).unwrap_or(0)));
    let list = ext.limit(end);
    let mut p = 2usize;
    if end > ext.bytes.len() {
        c.decoded.truncated = true;
    }
    // A 64-entry cap bounds the ALPN list; every entry consumes at least its length byte.
    for _ in 0..64 {
        if p >= end {
            break;
        }
        let Some(size) = list.u8(p) else {
            c.decoded.truncated = true;
            break;
        };
        p = p.saturating_add(1);
        let size = usize::from(size);
        let bytes = list.tail(p).limit(size).bytes;
        if bytes.len() < size {
            c.decoded.truncated = true;
        }
        let s = text::sanitise(bytes);
        result.alpn.push(s.clone());
        c.field(children, K::TlsAlpn, list, (p, size), || s, None);
        p = p.saturating_add(size);
    }
}

fn supported_versions(
    c: &mut Context,
    children: &mut Vec<Field>,
    ext: View<'_>,
    server: bool,
    result: &mut ClientHello,
    chosen: &mut u16,
) {
    if server {
        *chosen = ext.u16(0).unwrap_or(*chosen);
        if let Some(n) = ext.u16(0) {
            c.field(
                children,
                K::TlsSupportedVersion,
                ext,
                (0, 2),
                || format!("0x{n:04x} ({})", crate::explain::tls_version(n)),
                Some(u64::from(n)),
            );
        }
    } else {
        result.versions.clear();
        let len = usize::from(ext.u8(0).unwrap_or(0));
        let list = ext.tail(1).limit(len);
        if len > list.bytes.len() {
            c.decoded.truncated = true;
        }
        // The one-byte version-list length can hold at most 127 two-byte versions (RFC 8446, section 4.2.1).
        for i in 0..128usize {
            let p = i.saturating_mul(2);
            if p >= len {
                break;
            }
            if let Some(version) = list.u16(p) {
                result.versions.push(version);
                c.field(
                    children,
                    K::TlsVersions,
                    list,
                    (p, 2),
                    || format!("0x{version:04x} ({})", crate::explain::tls_version(version)),
                    Some(u64::from(version)),
                );
            } else {
                c.decoded.truncated = true;
                break;
            }
        }
    }
}

fn key_shares(c: &mut Context, children: &mut Vec<Field>, ext: View<'_>, server: bool) {
    let mut p = if server { 0 } else { 2 };
    let end = if server {
        ext.bytes.len()
    } else {
        2usize.saturating_add(usize::from(ext.u16(0).unwrap_or(0)))
    };
    let shares = ext.limit(end);
    if end > ext.bytes.len() {
        c.decoded.truncated = true;
    }
    // A 128-share cap bounds key-share fields; each normal entry advances by its four-byte header and key bytes.
    for _ in 0..128 {
        if p >= end {
            break;
        }
        if let Some(n) = shares.u16(p) {
            c.field(
                children,
                K::TlsKeyShare,
                shares,
                (p, 2),
                || format!("0x{n:04x}"),
                Some(u64::from(n)),
            );
        }
        // HelloRetryRequest carries only the selected group in key_share (RFC 8446, section 4.2.8).
        if server && end == 2 {
            break;
        }
        let Some(size) = shares.u16(p.saturating_add(2)) else {
            c.decoded.truncated = true;
            break;
        };
        p = p.saturating_add(4).saturating_add(usize::from(size));
        if p > end {
            c.decoded.truncated = true;
            break;
        }
    }
}

fn extension_list_field(
    c: &Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    ext_start: usize,
    ext_len: u16,
    extension_fields: Vec<Field>,
) {
    c.field(
        fields,
        K::TlsExtensions,
        v,
        (ext_start, usize::from(ext_len)),
        || crate::explain::byte_count(usize::from(ext_len)),
        Some(u64::from(ext_len)),
    );
    if c.detail == Detail::Full
        && let Some(f) = fields.last_mut()
    {
        f.children = extension_fields;
    }
}
