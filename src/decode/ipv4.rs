//! Decodes the IPv4 header and determines its payload boundary.
//! Transport parsing belongs to `transport`; ICMP parsing belongs to `icmp`.
//! Start with `ipv4`.

// RFC 791, section 3.1: IPv4 carries addresses and a forwarding hop counter.
// +----+----+----------+------------+----------------+
// |Ver |IHL |DSCP / ECN| Length 16  | ID 16          |
// +---------+---------+------------+----------------+
// |Flags / Offset 16  | TTL 8 | Protocol 8 | Sum 16 |
// +-------------------+----------------------------+
// | Source 32 | Destination 32 | Options ...       |
// +------------------------------------------------+
use super::{Addr, Context, FieldKey as K, Proto, View};

/// Reads IPv4 header fields and dispatches only the initial fragment; declared lengths use bytes.
pub(super) fn ipv4(c: &mut Context, v: View<'_>) {
    c.decoded.summary.src = None;
    c.decoded.summary.dst = None;
    let first = v.u8(0).unwrap_or(0);
    // IHL counts four-byte words, with at least 20 bytes in an IPv4 header (RFC 791, section 3.1).
    let hlen = usize::from(first & 15).saturating_mul(4).max(20);
    let total = u32::from(v.u16(2).unwrap_or(0));
    let mut l = c.layer(Proto::Ipv4, v, hlen, String::new());
    let offset = header_numbers(c, &mut l.fields, v);
    if let Some(n) = v.u16(10) {
        let status = match v.get(0, hlen) {
            Some(header) => crate::explain::checksum_status(checksum(header) == 0),
            None => crate::explain::CHECKSUM_INCOMPLETE,
        };
        c.field(
            &mut l.fields,
            K::IpChecksum,
            v,
            (10, 2),
            || format!("0x{n:04x} ({status})"),
            Some(u64::from(n)),
        );
    }
    for (key, off) in [(K::IpSrc, 12), (K::IpDst, 16)] {
        if let Some(ip) = v.v4(off) {
            c.field(&mut l.fields, key, v, (off, 4), || ip.to_string(), None);
            if off == 12 {
                c.decoded.summary.src = Some(Addr::V4(ip));
            } else {
                c.decoded.summary.dst = Some(Addr::V4(ip));
            }
        }
    }
    if hlen > 20 {
        c.raw(&mut l.fields, K::IpOptions, v, 20, hlen.saturating_sub(20));
    }
    l.line = format!(
        "{} → {}, ttl={} len={}",
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
        v.display_num(8, 1),
        v.display_num(2, 2)
    );
    c.decoded.layers.push(l);
    if total as usize > v.bytes.len() {
        c.decoded.truncated = true;
    }
    if hlen > v.bytes.len() || total < hlen as u32 {
        return;
    }
    let payload = v.limit(total as usize).tail(hlen);
    // Only offset zero contains the start of the transport header (RFC 791, section 3.2).
    if offset != 0 {
        c.decoded.summary.ip_proto = v.u8(9);
        c.data(payload);
    } else if let Some(proto) = v.u8(9) {
        c.transport(proto, payload, total.saturating_sub(hlen as u32));
    }
}

/// Computes the IPv4 ones-complement header checksum; a correct header including its checksum produces zero.
pub(super) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let high = u32::from(pair.first().copied().unwrap_or(0));
        let low = u32::from(pair.get(1).copied().unwrap_or(0));
        sum = sum.saturating_add((high << 8) | low);
    }
    // Folding twice accounts for the carry from a 16-bit sum of a maximum-size IPv4 header.
    for _ in 0..2 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn header_numbers(c: &mut Context, fields: &mut Vec<super::Field>, v: View<'_>) -> u32 {
    c.n(
        fields,
        K::IpVersion,
        v,
        0,
        1,
        v.u8(0).map(|b| u64::from(b >> 4)),
    );
    c.n(
        fields,
        K::IpHeaderLen,
        v,
        0,
        1,
        v.u8(0).map(|b| u64::from(b & 15) * 4),
    );
    c.n(
        fields,
        K::IpDscp,
        v,
        1,
        1,
        v.u8(1).map(|b| u64::from(b >> 2)),
    );
    c.n(fields, K::IpEcn, v, 1, 1, v.u8(1).map(|b| u64::from(b & 3)));
    c.n(fields, K::IpTotalLen, v, 2, 2, v.num(2, 2));
    if let Some(n) = v.u16(4) {
        c.field(
            fields,
            K::IpId,
            v,
            (4, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
    let offset = fragment_fields(c, fields, v);
    for (key, off) in [(K::IpTtl, 8), (K::IpProtocol, 9)] {
        c.n(fields, key, v, off, 1, v.num(off, 1));
    }
    c.decoded.summary.fragment_offset = Some(offset);
    offset
}

fn fragment_fields(c: &Context, fields: &mut Vec<super::Field>, v: View<'_>) -> u32 {
    let mut bits = Vec::new();
    let flags = v.u16(6).unwrap_or(0);
    c.n(
        &mut bits,
        K::IpDf,
        v,
        6,
        2,
        v.u16(6).map(|n| u64::from((n >> 14) & 1)),
    );
    c.n(
        &mut bits,
        K::IpMf,
        v,
        6,
        2,
        v.u16(6).map(|n| u64::from((n >> 13) & 1)),
    );
    let offset = u32::from(flags & 0x1fff).saturating_mul(8);
    // DF and MF are bits of Flags, not separate header fields (RFC 791, section 3.1).
    if let Some(n) = v.u16(6) {
        let names = [(0x8000, "reserved"), (0x4000, "DF"), (0x2000, "MF")]
            .into_iter()
            .filter_map(|(bit, name)| (n & bit != 0).then_some(name))
            .collect::<Vec<_>>()
            .join(", ");
        c.field(
            fields,
            K::IpFlags,
            v,
            (6, 2),
            || format!("0x{n:04x} [{names}]"),
            Some(u64::from(n)),
        );
        if let Some(field) = fields.last_mut().filter(|f| f.key == K::IpFlags) {
            field.children = bits;
        }
    }
    c.n(
        fields,
        K::IpFragmentOffset,
        v,
        6,
        2,
        v.u16(6).map(|_| u64::from(offset)),
    );
    offset
}
