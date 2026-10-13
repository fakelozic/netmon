//! Reads transport headers to locate their application payload.
//! Application parsing belongs to the protocol modules; wording belongs to `crate::explain`.
//! Start with `tcp`.

// RFC 9293 TCP, RFC 768 UDP; TCP options: RFC 7323, RFC 2018.
// TCP: +------------------------+------------------------+
//      | Source port 16         | Destination port 16    |
//      +------------------------+------------------------+
//      | Sequence number 32                              |
//      | Acknowledgment number 32                        |
//      +--------+-------+---------+----------------------+
//      |Offset 4|Res. 3 |Flags 9  | Window 16            |
//      +------------------------+------------------------+
//      | Checksum 16            | Urgent pointer 16      |
//      +------------------------+------------------------+
//      | Options ...            | Payload ...            |
// UDP: | Source 16 | Destination 16 | Length 16 | Checksum 16 |
use super::{Context, Detail, FieldKey as K, Proto, TcpInfo, View};

/// Reads a TCP segment; `wire_len` is its declared IP payload size in bytes, even when capture data is shorter.
pub(super) fn tcp(c: &mut Context, v: View<'_>, wire_len: u32) {
    // TCP data offset counts four-byte words, including a 20-byte fixed header (RFC 9293, section 3.1).
    let hlen = usize::from(v.u8(12).unwrap_or(0) >> 4)
        .saturating_mul(4)
        .max(20);
    let flags = u16::from(v.u8(13).unwrap_or(0)) | (u16::from(v.u8(12).unwrap_or(0) & 1) << 8);
    // TCP sequence numbers count bytes; SYN and FIN also consume one position (RFC 9293, section 3.4).
    let mut info = TcpInfo {
        seq: v.u32(4).unwrap_or(0),
        ack: v.u32(8).unwrap_or(0),
        flags,
        window: v.u16(14).unwrap_or(0),
        payload_len: wire_len.saturating_sub(hlen as u32),
        mss: None,
        window_scale: None,
    };
    let mut l = c.layer(Proto::Tcp, v, hlen, String::new());
    tcp_fields(c, &mut l.fields, v, flags);
    let fields = tcp_options(c, v, hlen, &mut info);
    if hlen > 20 && c.detail == Detail::Full {
        c.raw(&mut l.fields, K::TcpOptions, v, 20, hlen.saturating_sub(20));
        if let Some(f) = l.fields.last_mut() {
            f.children = fields;
        }
    }
    if v.u8(12).is_some() {
        c.n(
            &mut l.fields,
            K::TcpPayload,
            v,
            hlen,
            v.bytes.len().saturating_sub(hlen),
            Some(u64::from(info.payload_len)),
        );
    }
    c.decoded.summary.src_port = v.u16(0);
    c.decoded.summary.dst_port = v.u16(2);
    l.line = format!(
        "{} → {} [{}] seq={} ack={} win={}",
        v.display_num(0, 2),
        v.display_num(2, 2),
        if v.u16(12).is_some() {
            crate::explain::tcp_flags(flags)
        } else {
            "?".into()
        },
        v.display_num(4, 4),
        v.display_num(8, 4),
        v.display_num(14, 2)
    );
    c.decoded.summary.tcp = Some(info);
    c.decoded.layers.push(l);
    if hlen > v.bytes.len() {
        return;
    }
    let payload = v.tail(hlen);
    if payload.bytes.is_empty() {
        return;
    }
    let dns_port = matches!(v.u16(0), Some(53)) || matches!(v.u16(2), Some(53));
    // DNS over TCP prefixes each message with its two-byte byte count (RFC 1035, section 4.2.2).
    if dns_port && payload.u16(0).is_some() {
        let len = usize::from(payload.u16(0).unwrap_or(0));
        if len.saturating_add(2) > payload.bytes.len() {
            c.decoded.truncated = true;
        }
        super::dns::dns(c, payload.tail(2).limit(len), false);
    } else if !super::http::http(c, payload) && !super::tls::tls(c, payload) {
        c.data(payload);
    }
}

/// Reads UDP ports and its declared payload length in bytes, then dispatches recognised application ports.
pub(super) fn udp(c: &mut Context, v: View<'_>) {
    let len = u32::from(v.u16(4).unwrap_or(0));
    let mut l = c.layer(
        Proto::Udp,
        v,
        8,
        format!(
            "{} → {}, len={}",
            v.display_num(0, 2),
            v.display_num(2, 2),
            v.display_num(4, 2)
        ),
    );
    for (key, off) in [(K::UdpSrc, 0), (K::UdpDst, 2), (K::UdpLen, 4)] {
        c.n(&mut l.fields, key, v, off, 2, v.num(off, 2));
    }
    if let Some(n) = v.u16(6) {
        c.field(
            &mut l.fields,
            K::UdpChecksum,
            v,
            (6, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
    let payload_len = len.saturating_sub(8);
    c.n(
        &mut l.fields,
        K::UdpPayload,
        v,
        8,
        v.bytes.len().saturating_sub(8),
        v.u16(4).map(|_| u64::from(payload_len)),
    );
    c.decoded.summary.src_port = v.u16(0);
    c.decoded.summary.dst_port = v.u16(2);
    c.decoded.summary.udp_payload_len = v.u16(4).map(|_| payload_len);
    c.decoded.layers.push(l);
    if len as usize > v.bytes.len() {
        c.decoded.truncated = true;
    }
    if len < 8 || v.bytes.len() < 8 {
        return;
    }
    let payload = v.limit(len as usize).tail(8);
    let ports = [v.u16(0).unwrap_or(0), v.u16(2).unwrap_or(0)];
    if ports.contains(&5353) {
        super::dns::dns(c, payload, true);
    } else if ports.contains(&53) {
        super::dns::dns(c, payload, false);
    } else if ports.iter().any(|p| matches!(p, 67 | 68)) {
        super::dhcp::dhcp(c, payload);
    } else if !super::quic::quic(c, payload, ports.contains(&443)) {
        c.data(payload);
    }
}

fn tcp_fields(c: &mut Context, fields: &mut Vec<super::Field>, v: View<'_>, flags: u16) {
    for (key, off, n) in [
        (K::TcpSrc, 0, 2),
        (K::TcpDst, 2, 2),
        (K::TcpSeq, 4, 4),
        (K::TcpAck, 8, 4),
    ] {
        c.n(fields, key, v, off, n, v.num(off, n));
    }
    c.n(
        fields,
        K::TcpOffset,
        v,
        12,
        1,
        v.u8(12).map(|b| u64::from(b >> 4) * 4),
    );
    if v.u16(12).is_some() {
        c.field(
            fields,
            K::TcpFlags,
            v,
            (12, 2),
            || format!("0x{flags:04x} [{}]", crate::explain::tcp_flags(flags)),
            Some(u64::from(flags)),
        );
    }
    if c.detail == Detail::Full
        && let Some(field) = fields.last_mut()
        && field.key == K::TcpFlags
    {
        for (key, bit) in [
            (K::TcpCwr, 128),
            (K::TcpEce, 64),
            (K::TcpUrg, 32),
            (K::TcpAckFlag, 16),
            (K::TcpPsh, 8),
            (K::TcpRst, 4),
            (K::TcpSyn, 2),
            (K::TcpFin, 1),
        ] {
            c.n(
                &mut field.children,
                key,
                v,
                13,
                1,
                Some(u64::from((flags & bit) != 0)),
            );
        }
    }
    // The fixed header continues after data offset and flags (RFC 9293, section 3.1).
    c.n(fields, K::TcpWindow, v, 14, 2, v.num(14, 2));
    if let Some(n) = v.u16(16) {
        c.field(
            fields,
            K::TcpChecksum,
            v,
            (16, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
    c.n(fields, K::TcpUrgent, v, 18, 2, v.num(18, 2));
}

fn tcp_options(c: &mut Context, v: View<'_>, hlen: usize, info: &mut TcpInfo) -> Vec<super::Field> {
    let options = v.limit(hlen);
    let mut off = 20usize;
    let mut fields = Vec::new();
    // A TCP header has at most 40 option bytes; even one-byte padding must advance the cursor (RFC 9293, section 3.1).
    for _ in 0..40 {
        if off >= hlen {
            break;
        }
        let Some(kind) = options.u8(off) else {
            c.decoded.truncated = true;
            break;
        };
        if kind <= 1 {
            c.n(
                &mut fields,
                if kind == 0 { K::TcpEnd } else { K::TcpNop },
                options,
                off,
                1,
                Some(u64::from(kind)),
            );
            off = off.saturating_add(1);
            if kind == 0 {
                break;
            }
            continue;
        }
        let Some(len) = options.u8(off.saturating_add(1)) else {
            c.decoded.truncated = true;
            break;
        };
        let len = usize::from(len);
        if len < 2 {
            c.decoded.truncated = true;
            break;
        }
        let opt = options.tail(off).limit(len);
        if opt.bytes.len() < len {
            c.decoded.truncated = true;
        }
        tcp_option(c, &mut fields, opt, kind, len, info);
        off = off.saturating_add(len);
    }
    fields
}

fn tcp_option(
    c: &mut Context,
    fields: &mut Vec<super::Field>,
    opt: View<'_>,
    kind: u8,
    len: usize,
    info: &mut TcpInfo,
) {
    match (kind, len) {
        (2, 4) => {
            info.mss = opt.u16(2);
            c.n(fields, K::TcpMss, opt, 2, 2, opt.num(2, 2));
        }
        (3, 3) => {
            info.window_scale = opt.u8(2);
            c.n(fields, K::TcpScale, opt, 2, 1, opt.num(2, 1));
        }
        (4, 2) => c.n(fields, K::TcpSackPermitted, opt, 0, 2, Some(1)),
        (5, _) => {
            sack(c, fields, opt, len);
        }
        (8, 10) => {
            timestamps(c, fields, opt, len);
        }
        _ => c.field(
            fields,
            K::TcpUnknownOption,
            opt,
            (0, len),
            || format!("kind={kind} {}", crate::text::hex(opt.bytes)),
            Some(u64::from(kind)),
        ),
    }
}

fn sack(c: &Context, fields: &mut Vec<super::Field>, opt: View<'_>, len: usize) {
    c.raw(fields, K::TcpSack, opt, 0, len);
    if c.detail == Detail::Full
        && let Some(f) = fields.last_mut()
    {
        // At most four eight-byte SACK blocks fit after the option header (RFC 2018, section 3).
        for i in 0..4usize {
            let p = 2usize.saturating_add(i.saturating_mul(8));
            if p.saturating_add(8) > len {
                break;
            }
            c.n(&mut f.children, K::TcpSackLeft, opt, p, 4, opt.num(p, 4));
            c.n(
                &mut f.children,
                K::TcpSackRight,
                opt,
                p.saturating_add(4),
                4,
                opt.num(p.saturating_add(4), 4),
            );
        }
    }
}

fn timestamps(c: &Context, fields: &mut Vec<super::Field>, opt: View<'_>, len: usize) {
    c.raw(fields, K::TcpTimestamp, opt, 0, len);
    if c.detail == Detail::Full
        && let Some(f) = fields.last_mut()
    {
        c.n(
            &mut f.children,
            K::TcpTimestampValue,
            opt,
            2,
            4,
            opt.num(2, 4),
        );
        c.n(
            &mut f.children,
            K::TcpTimestampEcho,
            opt,
            6,
            4,
            opt.num(6, 4),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capture::LinkType,
        decode::{decode, ip::tests::packet},
    };
    #[test]
    fn all_common_options_and_declared_payload() {
        let mut tcp = vec![0; 20];
        tcp[12] = 0xf0;
        tcp[13] = 2;
        tcp.extend_from_slice(&[
            2, 4, 5, 180, 3, 3, 7, 4, 2, 5, 10, 0, 0, 0, 1, 0, 0, 0, 9, 8, 10, 0, 0, 0, 2, 0, 0, 0,
            1, 1, 1, 0,
        ]);
        tcp.resize(60, 0);
        let mut b = packet(6, &tcp);
        b[2..4].copy_from_slice(&100u16.to_be_bytes());
        let d = decode(LinkType::RawIp, &b, 100, Detail::Full);
        let t = d.summary.tcp.as_ref().unwrap();
        assert_eq!(t.mss, Some(1460));
        assert_eq!(t.window_scale, Some(7));
        assert_eq!(t.payload_len, 20);
        assert!(d.truncated);
        let options = d.layers[1]
            .fields
            .iter()
            .find(|f| f.key == K::TcpOptions)
            .unwrap();
        assert!(options.children.iter().any(|f| f.key == K::TcpSack));
        assert!(options.children.iter().any(|f| f.key == K::TcpTimestamp));
    }
}
