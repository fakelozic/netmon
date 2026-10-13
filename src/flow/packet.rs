//! Checked access to packet values needed by conversation lookup.
//! Field trees stay in `decode`; sequence inference stays in `tcp`.
//! Read `conversation` to see which decoded packets have a conversation key.
use super::*;
use crate::capture::RawPacket;
use crate::decode::{Addr, AppInfo, Decoded, TcpInfo};

/// Extract an IP address; link-layer addresses and missing addresses return None.
pub(super) fn ip(addr: Option<&Addr>) -> Option<IpAddr> {
    match addr? {
        Addr::V4(a) => Some(IpAddr::V4(*a)),
        Addr::V6(a) => Some(IpAddr::V6(*a)),
        Addr::Mac(_) => None,
    }
}

/// Choose the base protocol label before any application layer is observed.
pub(super) fn transport_proto(protocol: u8) -> Proto {
    match protocol {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        58 => Proto::Icmpv6,
        _ => Proto::Icmp,
    }
}

/// Identify an IPv4 or IPv6 echo request, rather than an echo reply.
pub(super) fn echo_request(d: &Decoded) -> bool {
    matches!(
        d.summary.app,
        Some(
            AppInfo::Icmp {
                v6: false,
                kind: 8,
                ..
            } | AppInfo::Icmp {
                v6: true,
                kind: 128,
                ..
            }
        )
    )
}

/// Build a direction-independent key; echo ids distinguish concurrent ping sessions.
/// No key is returned for DHCP, unsupported protocols, or missing identifying fields.
pub(super) fn conversation(
    d: &Decoded,
    source: IpAddr,
    destination: IpAddr,
) -> Option<(Key, Endpoint, Endpoint)> {
    if matches!(d.summary.app, Some(AppInfo::Dhcp { .. })) || d.summary.proto == Proto::Dhcp {
        return None;
    }
    let protocol = d.summary.ip_proto?;
    // Echo replies repeat the request identifier (RFC 792; RFC 4443, 4.1–4.2).
    let (ports, echo_id) = match protocol {
        6 | 17 => ([Some(d.summary.src_port?), Some(d.summary.dst_port?)], None),
        1 | 58 => {
            let Some(AppInfo::Icmp {
                v6,
                kind,
                id: Some(id),
                sequence: Some(_),
                ..
            }) = &d.summary.app
            else {
                return None;
            };
            if !matches!((*v6, *kind), (false, 0 | 8) | (true, 128 | 129)) {
                return None;
            }
            ([None, None], Some(*id))
        }
        _ => return None,
    };
    let a = Endpoint {
        addr: source,
        port: ports[0],
    };
    let b = Endpoint {
        addr: destination,
        port: ports[1],
    };
    Some((Key::new(protocol, a, b, echo_id), a, b))
}

/// Return TCP numbers only if the full captured header exists; otherwise None.
pub(super) fn complete_tcp<'a>(raw: &RawPacket, d: &'a Decoded) -> Option<&'a TcpInfo> {
    let layer = d.layers.iter().find(|l| l.proto == Proto::Tcp)?;
    let offset = *raw.data.get(layer.range.start.saturating_add(12))?;
    let header_len = usize::from(offset >> 4).saturating_mul(4);
    // A shortened TCP header has placeholder numbers in Summary. They are not evidence.
    if header_len < 20
        || layer.range.len() < header_len
        || raw.data.get(layer.range.clone()).is_none()
    {
        return None;
    }
    d.summary.tcp.as_ref()
}

/// Borrow captured payload bytes, bounded by the TCP wire length and raw buffer.
pub(super) fn tcp_payload<'a>(raw: &'a RawPacket, d: &Decoded, tcp: &TcpInfo) -> &'a [u8] {
    let Some(header) = d.layers.iter().find(|l| l.proto == Proto::Tcp) else {
        return &[];
    };
    let start = header.range.end;
    let end = start
        .saturating_add(tcp.payload_len as usize)
        .min(raw.data.len());
    raw.data.get(start..end).unwrap_or_default()
}

/// Count declared transport payload bytes; incomplete TCP headers contribute zero.
pub(super) fn payload_bytes(raw: &RawPacket, d: &Decoded) -> u64 {
    if let Some(t) = complete_tcp(raw, d) {
        return u64::from(t.payload_len);
    }
    if let Some(n) = d.summary.udp_payload_len {
        return u64::from(n);
    }
    d.layers
        .iter()
        .find(|l| matches!(l.proto, Proto::Icmp | Proto::Icmpv6))
        .map(|l| {
            raw.orig_len
                .saturating_sub(l.range.start as u32)
                .saturating_sub(8) as u64
        })
        .unwrap_or(0)
}
