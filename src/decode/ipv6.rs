//! Decodes IPv6 through its bounded extension-header chain.
//! Transport parsing belongs to `transport`; control messages belong to `icmp`.
//! Start with `ipv6`.

// RFC 8200, sections 3 and 4: extensions sit between the IP header and payload.
// +----+---------------+----------------------------+
// |Ver |Traffic class 8| Flow label 20              |
// +--------------------+-------------+-------------+
// | Payload length 16  | Next hdr 8  | Hop limit 8 |
// +------------------------------------------------+
// | Source 128 | Destination 128 | Extensions ...   |
// +------------------------------------------------+
use super::{Addr, Context, FieldKey as K, Proto, View};

/// Reads the 40-byte IPv6 header and up to sixteen supported extensions before dispatching its payload.
pub(super) fn ipv6(c: &mut Context, v: View<'_>) {
    c.decoded.summary.src = None;
    c.decoded.summary.dst = None;
    let mut l = c.layer(Proto::Ipv6, v, 40, String::new());
    header_fields(c, &mut l.fields, v);
    let plen = u32::from(v.u16(4).unwrap_or(0));
    l.line = format!(
        "{} → {}, hops={} len={}",
        c.decoded
            .summary
            .src
            .as_ref()
            .map(crate::text::address)
            .unwrap_or_default(),
        c.decoded
            .summary
            .dst
            .as_ref()
            .map(crate::text::address)
            .unwrap_or_default(),
        v.display_num(7, 1),
        v.display_num(4, 2)
    );
    c.decoded.layers.push(l);
    if v.bytes.len() < 40 {
        return;
    }
    let total = 40usize.saturating_add(plen as usize);
    if total > v.bytes.len() {
        c.decoded.truncated = true;
    }
    let packet = v.limit(total);
    let Some((next, off, wire, later_fragment)) = extensions(c, v, packet, plen) else {
        return;
    };
    c.decoded.summary.ip_proto = Some(next);
    if later_fragment || matches!(next, 0 | 43 | 44 | 60 | 59) {
        c.data(packet.tail(off));
    } else {
        c.transport(next, packet.tail(off), wire);
    }
}

fn extensions(
    c: &mut Context,
    v: View<'_>,
    packet: View<'_>,
    plen: u32,
) -> Option<(u8, usize, u32, bool)> {
    let mut next = v.u8(6).unwrap_or(59);
    let mut off = 40usize;
    let mut wire = plen;
    let mut later_fragment = false;
    // Sixteen extensions is a local work limit, not a protocol limit; stop before a hostile chain grows costly.
    for _ in 0..16 {
        if !matches!(next, 0 | 43 | 44 | 60) {
            break;
        }
        let ext = packet.tail(off);
        // Fragment headers are eight bytes; other supported extensions count eight-byte units after the first unit (RFC 8200, section 4).
        let len = if next == 44 {
            8
        } else {
            usize::from(ext.u8(1).unwrap_or(0))
                .saturating_add(1)
                .saturating_mul(8)
        };
        let mut l = c.layer(Proto::Ipv6, ext, len, format!("extension={next}"));
        c.n(&mut l.fields, K::V6ExtNext, ext, 0, 1, ext.num(0, 1));
        c.n(&mut l.fields, K::V6ExtLen, ext, 1, 1, Some(len as u64));
        c.raw(&mut l.fields, K::V6ExtData, ext, 2, len.saturating_sub(2));
        if next == 44 {
            let bits = ext.u16(2);
            let offset = bits.map(|b| u32::from(b & 0xfff8)).unwrap_or(0);
            later_fragment = offset != 0;
            c.decoded.summary.fragment_offset = Some(offset);
            c.n(
                &mut l.fields,
                K::V6FragmentOffset,
                ext,
                2,
                2,
                bits.map(|_| u64::from(offset)),
            );
            c.n(
                &mut l.fields,
                K::V6MoreFragments,
                ext,
                2,
                2,
                bits.map(|b| u64::from(b & 1)),
            );
            if let Some(n) = ext.u32(4) {
                c.field(
                    &mut l.fields,
                    K::V6FragmentId,
                    ext,
                    (4, 4),
                    || format!("0x{n:08x}"),
                    Some(u64::from(n)),
                );
            }
        }
        c.decoded.layers.push(l);
        let n = ext.u8(0)?;
        next = n;
        off = off.saturating_add(len);
        wire = wire.saturating_sub(len as u32);
        if len > ext.bytes.len() {
            c.decoded.summary.ip_proto = Some(next);
            return None;
        }
    }
    Some((next, off, wire, later_fragment))
}

fn header_fields(c: &mut Context, fields: &mut Vec<super::Field>, v: View<'_>) {
    let word = v.u32(0);
    c.n(
        fields,
        K::V6Version,
        v,
        0,
        1,
        word.map(|n| u64::from(n >> 28)),
    );
    c.n(
        fields,
        K::V6TrafficClass,
        v,
        0,
        2,
        word.map(|n| u64::from((n >> 20) & 255)),
    );
    if let Some(word) = word {
        let n = word & 0xfffff;
        c.field(
            fields,
            K::V6FlowLabel,
            v,
            (1, 3),
            || format!("0x{n:05x}"),
            Some(u64::from(n)),
        );
    }
    for (key, off, n) in [
        (K::V6PayloadLen, 4, 2),
        (K::V6NextHeader, 6, 1),
        (K::V6HopLimit, 7, 1),
    ] {
        c.n(fields, key, v, off, n, v.num(off, n));
    }
    for (key, off) in [(K::V6Src, 8), (K::V6Dst, 24)] {
        if let Some(ip) = v.v6(off) {
            c.field(fields, key, v, (off, 16), || ip.to_string(), None);
            if off == 8 {
                c.decoded.summary.src = Some(Addr::V6(ip));
            } else {
                c.decoded.summary.dst = Some(Addr::V6(ip));
            }
        }
    }
}
