//! Decodes the TLS records present in one captured TCP payload.
//! Hello bodies belong to `super::hello`; joining TCP segments belongs to `crate::flow`.
//! Start with `tls`.

// RFC 5246, section 6.2; RFC 8446, section 5: TLS records frame handshake or protected data.
// +--------+------------+-----------+------------------+
// | Type 8 | Version 16 | Length 16 | Fragment ...     |
// +--------+------------+-----------+------------------+
// | Handshake type 8 | Length 24 | Body ...            |
// +---------------------------------------------------+
use super::hello::hello;
use crate::decode::{AppInfo, Context, Detail, Field, FieldKey as K, Proto, View};

/// Recognises TLS record framing and returns false for unrecognised payloads; decoding is limited to captured records.
pub(in crate::decode) fn tls(c: &mut Context, v: View<'_>) -> bool {
    if !matches!(v.u8(0), Some(20..=24)) || v.u8(1) != Some(3) {
        return false;
    }
    let mut off = 0usize;
    let mut content_types = Vec::new();
    let mut encrypted_bytes = 0u32;
    let mut handshake = false;
    let mut selected: Option<(u8, AppInfo)> = None;
    // A 128-record cap bounds work in a payload; each iteration advances past its five-byte header.
    for _ in 0..128 {
        if off >= v.bytes.len() {
            break;
        }
        let record = v.tail(off);
        let kind = record.u8(0).unwrap_or(0);
        let len = usize::from(record.u16(3).unwrap_or(0));
        let total = 5usize.saturating_add(len);
        let mut l = c.layer(
            Proto::Tls,
            record,
            total.max(5),
            format!(
                "type={kind} version={} len={}",
                record
                    .u16(1)
                    .map(|n| format!("0x{n:04x}"))
                    .unwrap_or_else(|| "?".into()),
                record.display_num(3, 2)
            ),
        );
        record_fields(c, &mut l.fields, record);
        content_types.push(kind);
        let body = record.tail(5).limit(len);
        if kind == 23 && record.u16(3).is_some() {
            encrypted_bytes = encrypted_bytes.saturating_add(len as u32);
            c.field(
                &mut l.fields,
                K::TlsEncrypted,
                body,
                (0, len),
                || crate::explain::encrypted(len),
                Some(len as u64),
            );
        }
        if kind == 22 {
            handshake = true;
            handshakes(c, &mut l.fields, body, &mut selected);
        }
        c.decoded.layers.push(l);
        off = off.saturating_add(total);
        if total > record.bytes.len() {
            break;
        }
    }
    if off < v.bytes.len() {
        c.decoded.truncated = true;
    }
    c.decoded.summary.app = Some(selected.map(|(_, app)| app).unwrap_or(AppInfo::TlsRecords {
        content_types,
        encrypted_bytes,
        handshake,
    }));
    true
}

fn handshakes(
    c: &mut Context,
    fields: &mut Vec<Field>,
    body: View<'_>,
    selected: &mut Option<(u8, AppInfo)>,
) {
    let mut p = 0usize;
    // A 128-message cap bounds handshake work; each message advances past its four-byte header.
    for _ in 0..128 {
        if p >= body.bytes.len() {
            break;
        }
        let msg = body.tail(p);
        let ty = msg.u8(0).unwrap_or(0);
        let Some(size) = msg.num(1, 3) else {
            c.decoded.truncated = true;
            break;
        };
        let size = size as usize;
        let mut children = Vec::new();
        c.n(&mut children, K::TlsHandshakeType, msg, 0, 1, msg.num(0, 1));
        c.n(
            &mut children,
            K::TlsHandshakeLen,
            msg,
            1,
            3,
            Some(size as u64),
        );
        if size > msg.bytes.len().saturating_sub(4) {
            c.decoded.truncated = true;
        }
        let message = msg.tail(4).limit(size);
        let candidate = handshake_app(c, &mut children, message, ty);
        // Prefer a Client Hello over a Server Hello, and either over generic records, so a name offer is retained.
        if let Some(candidate) = candidate
            && selected.as_ref().is_none_or(|s| candidate.0 < s.0)
        {
            *selected = Some(candidate);
        }
        c.field(
            fields,
            K::TlsHandshake,
            msg,
            (0, size.saturating_add(4)),
            || format!("type={ty} len={size}"),
            Some(u64::from(ty)),
        );
        if c.detail == Detail::Full
            && let Some(f) = fields.last_mut()
        {
            f.children = children;
        }
        p = p.saturating_add(4).saturating_add(size);
    }
}

fn handshake_app(
    c: &mut Context,
    children: &mut Vec<Field>,
    message: View<'_>,
    ty: u8,
) -> Option<(u8, AppInfo)> {
    if ty == 1 {
        let (h, _, _) = hello(c, children, message, false);
        Some((0, AppInfo::TlsClientHello(h)))
    } else if ty == 2 {
        let (_, version, cipher_suite) = hello(c, children, message, true);
        Some((
            1,
            AppInfo::TlsServerHello {
                version,
                cipher_suite,
            },
        ))
    } else {
        None
    }
}

fn record_fields(c: &Context, fields: &mut Vec<Field>, record: View<'_>) {
    for (key, p, n) in [
        (K::TlsContentType, 0, 1),
        (K::TlsRecordVersion, 1, 2),
        (K::TlsRecordLen, 3, 2),
    ] {
        if let Some(value) = record.num(p, n) {
            c.field(
                fields,
                key,
                record,
                (p, n),
                || {
                    if key == K::TlsRecordVersion {
                        format!(
                            "0x{value:04x} ({})",
                            crate::explain::tls_version(value as u16)
                        )
                    } else {
                        value.to_string()
                    }
                },
                Some(value),
            );
        }
    }
}
