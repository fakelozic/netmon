//! Reads link headers to locate their network payload.
//! Network parsing belongs to `ip`; explanatory wording belongs to `crate::explain`.
//! Start with `ethernet`.

// IEEE 802.3 / 802.1Q Ethernet; RFC 826 ARP; Linux SLL/SLL2 link headers.
// Ethernet: +----------------+----------------+----------+----------------+
//           | Destination 6B | Source MAC 6B  | Type 2B  | Payload ...    |
//           +----------------+----------------+----------+----------------+
// VLAN:     | TCI 2B (PCP:3 DEI:1 VID:12) | Inner type 2B | Payload ... |
// ARP:      +--------+--------+----+----+--------+-----------------------+
//           | HTYPE  | PTYPE  |HLEN|PLEN| OPER   | SHA SPA THA TPA ...   |
//           +--------+--------+----+----+--------+-----------------------+
// SLL:      | Type 2 | Hardware 2 | Addr len 2 | Address 8 | Protocol 2 |
// SLL2:     | Proto 2 | Reserved 2 | Ifindex 4 | HW 2 | Type 1 | Len 1 |
//           | Address 8                                               |
use super::{Addr, AppInfo, Context, FieldKey as K, Proto, View};
use crate::text;

/// Reads Ethernet and up to eight VLAN tags, then dispatches the captured network payload.
pub(super) fn ethernet(c: &mut Context, v: View<'_>) {
    let mut l = c.layer(Proto::Ethernet, v, 14, String::new());
    for (key, off) in [(K::EthDst, 0), (K::EthSrc, 6)] {
        if let Some(mac) = v.array::<6>(off) {
            c.field(&mut l.fields, key, v, (off, 6), || text::mac(&mac), None);
            if off == 0 {
                c.decoded.summary.dst = Some(Addr::Mac(mac));
            } else {
                c.decoded.summary.src = Some(Addr::Mac(mac));
            }
        }
    }
    let (ether_type, off) = ethernet_tags(c, &mut l.fields, v);
    l.range = v.range(0, off);
    l.line = format!(
        "{} → {}, type=0x{:04x}",
        c.decoded
            .summary
            .src
            .as_ref()
            .map(text::address)
            .unwrap_or_default(),
        c.decoded
            .summary
            .dst
            .as_ref()
            .map(text::address)
            .unwrap_or_default(),
        ether_type.unwrap_or(0)
    );
    c.decoded.layers.push(l);
    if let Some(n) = ether_type {
        if !matches!(n, 0x8100 | 0x88a8) {
            c.network(n, v.tail(off));
        } else {
            c.data(v.tail(off));
        }
    }
}

/// Reads Linux SLL or SLL2 metadata, selected by `v2`, and dispatches the captured network payload.
pub(super) fn cooked(c: &mut Context, v: View<'_>, v2: bool) {
    let len = if v2 { 20 } else { 16 };
    let mut l = c.layer(
        Proto::LinuxCooked,
        v,
        len,
        if v2 { "SLL2".into() } else { "SLL".into() },
    );
    let (packet_type, hardware, address_len, address, protocol) = if v2 {
        (10, 8, 11, 12, 0)
    } else {
        (0, 2, 4, 6, 14)
    };
    for (key, off, n) in [
        (K::SllPacketType, packet_type, if v2 { 1 } else { 2 }),
        (K::SllHardware, hardware, 2),
        (K::SllAddrLen, address_len, if v2 { 1 } else { 2 }),
        (K::SllProtocol, protocol, 2),
    ] {
        if key == K::SllProtocol {
            if let Some(value) = v.u16(off) {
                c.field(
                    &mut l.fields,
                    key,
                    v,
                    (off, n),
                    || format!("0x{value:04x}"),
                    Some(u64::from(value)),
                );
            }
        } else {
            c.n(&mut l.fields, key, v, off, n, v.num(off, n));
        }
    }
    if v2 {
        c.n(&mut l.fields, K::SllInterface, v, 4, 4, v.num(4, 4));
    }
    let addr_len = v
        .num(address_len, if v2 { 1 } else { 2 })
        .unwrap_or(0)
        .min(8) as usize;
    c.raw(&mut l.fields, K::SllAddr, v, address, addr_len);
    // SLL2 moves Protocol to the front; both formats still follow their wire layout.
    l.fields.sort_by_key(|field| field.range.start);
    if addr_len == 6 {
        c.decoded.summary.src = v.array(address).map(Addr::Mac);
    }
    c.decoded.layers.push(l);
    if let Some(n) = v.u16(protocol) {
        c.network(n, v.tail(len));
    }
}

/// Reads variable-length ARP addresses; unsupported formats remain raw fields and missing values stay absent.
pub(super) fn arp(c: &mut Context, v: View<'_>) {
    let hlen = usize::from(v.u8(4).unwrap_or(0));
    let plen = usize::from(v.u8(5).unwrap_or(0));
    let len = 8usize.saturating_add(hlen.saturating_add(plen).saturating_mul(2));
    let mut l = c.layer(Proto::Arp, v, len.max(8), String::new());
    for (key, off, n) in [
        (K::ArpHardware, 0, 2),
        (K::ArpProtocol, 2, 2),
        (K::ArpHardwareSize, 4, 1),
        (K::ArpProtocolSize, 5, 1),
        (K::ArpOperation, 6, 2),
    ] {
        if key == K::ArpProtocol {
            if let Some(value) = v.u16(off) {
                c.field(
                    &mut l.fields,
                    key,
                    v,
                    (off, n),
                    || format!("0x{value:04x}"),
                    Some(u64::from(value)),
                );
            }
        } else {
            c.n(&mut l.fields, key, v, off, n, v.num(off, n));
        }
    }
    let spa = 8usize.saturating_add(hlen);
    let tha = spa.saturating_add(plen);
    let tpa = tha.saturating_add(hlen);
    // ARP declares address sizes; only six-byte hardware and IPv4 addresses get typed values (RFC 826).
    let sender_mac = if hlen == 6 { v.array::<6>(8) } else { None };
    let target_mac = if hlen == 6 { v.array::<6>(tha) } else { None };
    let sender_ip = if plen == 4 && v.u16(2) == Some(0x0800) {
        v.v4(spa)
    } else {
        None
    };
    let target_ip = if plen == 4 && v.u16(2) == Some(0x0800) {
        v.v4(tpa)
    } else {
        None
    };
    for (key, off, mac) in [
        (K::ArpSenderMac, 8, sender_mac),
        (K::ArpTargetMac, tha, target_mac),
    ] {
        if let Some(mac) = mac {
            c.field(&mut l.fields, key, v, (off, hlen), || text::mac(&mac), None);
        } else {
            c.raw(&mut l.fields, key, v, off, hlen);
        }
    }
    for (key, off, ip) in [
        (K::ArpSenderIp, spa, sender_ip),
        (K::ArpTargetIp, tpa, target_ip),
    ] {
        if let Some(ip) = ip {
            c.field(&mut l.fields, key, v, (off, plen), || ip.to_string(), None);
        } else {
            c.raw(&mut l.fields, key, v, off, plen);
        }
    }
    let operation = v.u16(6).unwrap_or(0);
    // ARP interleaves hardware and protocol addresses for each device (RFC 826, Packet format).
    l.fields.sort_by_key(|field| field.range.start);
    l.line = format!("op={}", v.display_num(6, 2));
    c.decoded.summary.app = v.u16(6).map(|_| AppInfo::Arp {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    });
    c.decoded.layers.push(l);
    c.data(v.tail(len));
}

fn ethernet_tags(
    c: &mut Context,
    fields: &mut Vec<super::Field>,
    v: View<'_>,
) -> (Option<u16>, usize) {
    let mut ether_type = v.u16(12);
    if let Some(n) = ether_type {
        c.field(
            fields,
            K::EtherType,
            v,
            (12, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
    let mut off: usize = 14;
    // Eight VLAN tags is a local work limit; each tag advances four bytes even in a nested chain.
    for _ in 0..8 {
        if !matches!(ether_type, Some(0x8100 | 0x88a8)) {
            break;
        }
        let Some(tci) = v.u16(off) else {
            c.decoded.truncated = true;
            break;
        };
        c.n(
            fields,
            K::VlanPriority,
            v,
            off,
            2,
            Some(u64::from(tci >> 13)),
        );
        c.n(
            fields,
            K::VlanDrop,
            v,
            off,
            2,
            Some(u64::from((tci >> 12) & 1)),
        );
        let id = tci & 0xfff;
        c.field(
            fields,
            K::VlanId,
            v,
            (off, 2),
            || format!("0x{id:03x}"),
            Some(u64::from(id)),
        );
        ether_type = v.u16(off.saturating_add(2));
        if let Some(n) = ether_type {
            c.field(
                fields,
                K::EtherType,
                v,
                (off.saturating_add(2), 2),
                || format!("0x{n:04x}"),
                Some(u64::from(n)),
            );
        } else {
            c.decoded.truncated = true;
        }
        off = off.saturating_add(4);
    }
    (ether_type, off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capture::LinkType,
        decode::{Detail, decode},
    };
    #[test]
    fn arp_request_reply_and_vlan() {
        for op in [1u16, 2] {
            let mut frame = vec![0; 14];
            frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
            frame.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
            frame.extend_from_slice(&op.to_be_bytes());
            frame.extend_from_slice(&[
                2, 0, 0, 0, 0, 1, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1,
            ]);
            let d = decode(LinkType::Ethernet, &frame, 42, Detail::Full);
            assert!(!d.truncated);
            assert!(matches!(d.summary.app,Some(AppInfo::Arp {operation,..}) if operation == op));
            let mut tagged = frame.clone();
            tagged[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            tagged.splice(14..14, [0xa0, 7, 8, 6]);
            let d = decode(LinkType::Ethernet, &tagged, 46, Detail::Full);
            assert!(
                d.layers[0]
                    .fields
                    .iter()
                    .any(|f| f.key == K::VlanId && f.num == Some(7))
            );
            assert_eq!(d.summary.proto, Proto::Arp);
        }
    }
    #[test]
    fn both_cooked_versions() {
        for (link, len, proto) in [(LinkType::LinuxSll, 16, 14), (LinkType::LinuxSll2, 20, 0)] {
            let mut b = vec![0; len];
            b[proto..proto + 2].copy_from_slice(&0x1234u16.to_be_bytes());
            let d = decode(link, &b, len as u32, Detail::Full);
            assert!(!d.truncated);
            assert_eq!(d.layers[0].range, 0..len);
        }
    }
}
