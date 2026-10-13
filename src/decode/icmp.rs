//! Decodes IP control messages, including quoted packet facts.
//! Quoted IP headers belong to `ipv4` and `ipv6`; wording belongs to `crate::explain`.
//! Start with `icmp`.

// RFC 792, RFC 4443 and RFC 4861: ICMP reports delivery problems and probes peers.
// +--------+--------+----------------+--------------------------+
// | Type 8 | Code 8 | Checksum 16    | Message-specific body ... |
// +--------+--------+----------------+--------------------------+
use super::{
    AppInfo, Context, Detail, EmbeddedPacket, Field, FieldKey as K, Proto, View,
    ip::{ipv4, ipv6},
};

/// Reads IPv4 or IPv6 control messages, selected by `v6`, keeping quoted-packet truncation separate from the outer packet.
pub(super) fn icmp(c: &mut Context, v: View<'_>, v6: bool) {
    let kind = v.u8(0).unwrap_or(0);
    let code = v.u8(1).unwrap_or(0);
    let echo = if v6 {
        matches!(kind, 128 | 129)
    } else {
        matches!(kind, 0 | 8)
    };
    let error = if v6 {
        kind < 128
    } else {
        matches!(kind, 3 | 5 | 11 | 12)
    };
    let hlen = if v6 && matches!(kind, 135 | 136) {
        24
    } else if v6 && kind == 134 {
        16
    } else {
        8
    };
    let proto = if v6 { Proto::Icmpv6 } else { Proto::Icmp };
    let mut l = c.layer(
        proto,
        v,
        hlen,
        format!("type={} code={}", v.display_num(0, 1), v.display_num(1, 1)),
    );
    fixed_fields(c, &mut l.fields, v);
    let (id, sequence) = if echo {
        (v.u16(4), v.u16(6))
    } else {
        (None, None)
    };
    if echo {
        if let Some(n) = id {
            c.field(
                &mut l.fields,
                K::IcmpId,
                v,
                (4, 2),
                || format!("0x{n:04x}"),
                Some(u64::from(n)),
            );
        }
        c.n(&mut l.fields, K::IcmpSeq, v, 6, 2, sequence.map(u64::from));
    }
    let embedded = quoted_packet(c, &mut l.fields, v, error);
    let target = if v6 && matches!(kind, 135 | 136) {
        v.v6(8)
    } else {
        None
    };
    if let Some(target) = target {
        c.field(
            &mut l.fields,
            K::IcmpTarget,
            v,
            (8, 16),
            || target.to_string(),
            None,
        );
    }
    let mac = neighbour_options(c, &mut l.fields, v, v6, kind, hlen);
    c.decoded.summary.app = v.u8(0).map(|_| AppInfo::Icmp {
        v6,
        kind,
        code,
        id,
        sequence,
        embedded,
        target,
        mac,
    });
    c.decoded.layers.push(l);
    if echo {
        c.data(v.tail(8));
    }
}

fn quoted_packet(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    error: bool,
) -> Option<EmbeddedPacket> {
    let mut embedded = None;
    if error && v.bytes.len() > 8 {
        let quote = v.tail(8);
        let version = quote.u8(0).map(|b| b >> 4);
        let header_len = if version == Some(4) {
            usize::from(quote.u8(0).unwrap_or(0) & 15)
                .saturating_mul(4)
                .max(20)
        } else {
            40
        };
        // IPv4 ICMP errors may quote only the IP header and eight payload bytes (RFC 792).
        // A separate context prevents that intentional limit from truncating the outer packet.
        let mut nested = Context::new(quote.bytes.len() as u32, c.detail);
        match version {
            Some(4) => ipv4(&mut nested, quote.limit(header_len.saturating_add(8))),
            Some(6) => ipv6(&mut nested, quote.limit(header_len.saturating_add(8))),
            _ => nested.data(quote),
        }
        let s = &nested.decoded.summary;
        embedded = Some(EmbeddedPacket {
            protocol: s.ip_proto,
            src_port: s.src_port,
            dst_port: s.dst_port,
        });
        if c.detail == Detail::Full {
            fields.push(Field {
                key: K::IcmpEmbedded,
                value: format!("{} bytes", quote.bytes.len()),
                num: None,
                range: quote.range(0, quote.bytes.len()),
                children: nested
                    .decoded
                    .layers
                    .into_iter()
                    .map(|l| Field {
                        key: K::IcmpEmbedded,
                        value: format!("{} {}", l.proto.name(), l.line),
                        num: None,
                        range: l.range,
                        children: l.fields,
                    })
                    .collect(),
            });
        }
    }
    embedded
}

fn neighbour_options(
    c: &mut Context,
    fields: &mut Vec<Field>,
    v: View<'_>,
    v6: bool,
    kind: u8,
    hlen: usize,
) -> Option<[u8; 6]> {
    let mut mac = None;
    if v6 && (133..=136).contains(&kind) {
        let mut off = hlen;
        // Sixty-four options keeps neighbour-discovery work bounded for malformed or oversized messages.
        for _ in 0..64 {
            if off >= v.bytes.len() {
                break;
            }
            let opt = v.tail(off);
            let Some(units) = opt.u8(1) else {
                c.decoded.truncated = true;
                break;
            };
            let len = usize::from(units).saturating_mul(8);
            if len == 0 {
                c.decoded.truncated = true;
                break;
            }
            let ty = opt.u8(0).unwrap_or(0);
            c.n(fields, K::IcmpOptionType, opt, 0, 1, Some(u64::from(ty)));
            c.n(fields, K::IcmpOptionLen, opt, 1, 1, Some(len as u64));
            if matches!(ty, 1 | 2) {
                if let Some(m) = opt.array::<6>(2) {
                    mac = Some(m);
                    c.field(
                        fields,
                        K::IcmpLinkOption,
                        opt,
                        (2, 6),
                        || crate::text::mac(&m),
                        None,
                    );
                }
            } else {
                c.raw(fields, K::IcmpOptionData, opt, 2, len.saturating_sub(2));
            }
            off = off.saturating_add(len);
            if len > opt.bytes.len() {
                c.decoded.truncated = true;
                break;
            }
        }
    }
    mac
}

fn fixed_fields(c: &Context, fields: &mut Vec<Field>, v: View<'_>) {
    for (key, off, n) in [(K::IcmpType, 0, 1), (K::IcmpCode, 1, 1)] {
        c.n(fields, key, v, off, n, v.num(off, n));
    }
    if let Some(n) = v.u16(2) {
        c.field(
            fields,
            K::IcmpChecksum,
            v,
            (2, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
}
