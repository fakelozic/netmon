//! Reads the values stored in DNS resource records.
//! Name decompression belongs to `super::name`; message layout belongs to `super`.
//! Start with `record_data`.

// RFC 1035, section 4.1.3; RFC 3596, RFC 2782 and RFC 6891 add record formats.
// A record type selects how its data bytes are interpreted.
// +--------+----------+-----------+------------+-------------+
// | TYPE16 | CLASS16  | TTL32     | RDLENGTH16 | RDATA ...   |
// +--------+----------+-----------+------------+-------------+
use super::name::{name, name_field};
use crate::decode::{Context, Field, FieldKey as K, View};
use crate::text;

/// Reads one record value; offsets are relative to the whole DNS message so compression pointers can refer backward.
pub(super) fn record_data(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    off: usize,
    len: usize,
    metadata: (u16, u16, u32),
) -> String {
    let (ty, _, _) = metadata;
    let data = v.tail(off).limit(len);
    let value = match ty {
        1 => data
            .v4(0)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| text::hex(data.bytes)),
        28 => data
            .v6(0)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| text::hex(data.bytes)),
        2 | 5 | 12 => {
            let n = name(v, off);
            if !n.complete || n.end > off.saturating_add(len) {
                c.decoded.truncated = true;
            }
            n.text
        }
        15 => {
            c.n(fields, K::DnsMxPreference, data, 0, 2, data.num(0, 2));
            let n = name_field(c, fields, K::DnsMxExchange, v, off.saturating_add(2));
            format!("{} {}", data.u16(0).unwrap_or(0), n.text)
        }
        16 => txt_strings(c, data),
        6 => authority(c, fields, v, off, len),
        33 => {
            for (key, p) in [
                (K::DnsSrvPriority, 0),
                (K::DnsSrvWeight, 2),
                (K::DnsSrvPort, 4),
            ] {
                c.n(fields, key, data, p, 2, data.num(p, 2));
            }
            let n = name_field(c, fields, K::DnsSrvTarget, v, off.saturating_add(6));
            format!(
                "{} {} {} {}",
                data.u16(0).unwrap_or(0),
                data.u16(2).unwrap_or(0),
                data.u16(4).unwrap_or(0),
                n.text
            )
        }
        41 => opt(c, fields, v, off, len, metadata),
        _ => text::hex(data.bytes),
    };
    if ty == 41 {
        c.raw(fields, K::DnsData, v, off, len);
    } else {
        c.field(fields, K::DnsData, v, (off, len), || value.clone(), None);
    }
    value
}

fn txt_strings(c: &mut Context, data: View<'_>) -> String {
    let mut p = 0usize;
    let mut strings = Vec::new();
    // A 256-string cap also bounds zero-length TXT strings, each of which consumes one length byte.
    for _ in 0..256 {
        let Some(size) = data.u8(p) else {
            break;
        };
        p = p.saturating_add(1);
        let size = usize::from(size);
        let bytes = data.tail(p).limit(size).bytes;
        strings.push(text::sanitise(bytes));
        if bytes.len() < size {
            c.decoded.truncated = true;
            break;
        }
        p = p.saturating_add(size);
    }
    strings.join("; ")
}

fn authority(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    off: usize,
    len: usize,
) -> String {
    let primary = name_field(c, fields, K::DnsSoaPrimary, v, off);
    let mailbox = name_field(c, fields, K::DnsSoaMailbox, v, primary.end);
    let mut p = mailbox.end;
    let mut numbers = Vec::new();
    for key in [
        K::DnsSoaSerial,
        K::DnsSoaRefresh,
        K::DnsSoaRetry,
        K::DnsSoaExpire,
        K::DnsSoaMinimum,
    ] {
        c.n(fields, key, v, p, 4, v.num(p, 4));
        numbers.push(v.u32(p).unwrap_or(0).to_string());
        p = p.saturating_add(4);
    }
    if p > off.saturating_add(len) {
        c.decoded.truncated = true;
    }
    format!("{} {} {}", primary.text, mailbox.text, numbers.join(" "))
}

fn opt(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    off: usize,
    len: usize,
    metadata: (u16, u16, u32),
) -> String {
    let (_, class, ttl) = metadata;
    let data = v.tail(off).limit(len);
    // OPT overloads CLASS and TTL instead of describing a cached answer (RFC 6891, section 6.1.2).
    c.n(
        fields,
        K::DnsOptSize,
        v,
        off.saturating_sub(8),
        2,
        Some(u64::from(class)),
    );
    for (key, shift, mask) in [
        (K::DnsOptRcode, 24, 255),
        (K::DnsOptVersion, 16, 255),
        (K::DnsOptFlags, 0, 65535),
    ] {
        let n = u64::from((ttl >> shift) & mask);
        c.field(
            fields,
            key,
            v,
            (off.saturating_sub(6), 4),
            || {
                if key == K::DnsOptFlags {
                    format!("0x{n:04x} [{}]", if n & 0x8000 != 0 { "DO" } else { "" })
                } else {
                    n.to_string()
                }
            },
            Some(n),
        );
    }
    let mut p = 0usize;
    // A 64-option cap bounds extended DNS fields; every option consumes its four-byte header.
    for _ in 0..64 {
        if p >= len {
            break;
        }
        let Some(size) = data.u16(p.saturating_add(2)) else {
            c.decoded.truncated = true;
            break;
        };
        c.n(fields, K::DnsOptCode, data, p, 2, data.num(p, 2));
        c.raw(
            fields,
            K::DnsOptData,
            data,
            p.saturating_add(4),
            usize::from(size),
        );
        p = p.saturating_add(4).saturating_add(usize::from(size));
        if p > data.bytes.len() {
            c.decoded.truncated = true;
            break;
        }
    }
    format!(
        "udp={class} version={} flags=0x{:04x}",
        (ttl >> 16) & 255,
        ttl & 65535
    )
}
