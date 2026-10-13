//! Keeps the shared IP decoder entry points at their established paths.
//! Header parsing belongs to `ipv4`, `ipv6` and `icmp`.
//! Start with `ipv4`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
pub(super) use super::{icmp::icmp, ipv4::ipv4, ipv6::ipv6};

/// Deterministic byte-array tests; shared builders keep their established internal paths.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::decode::{AppInfo, Context, Detail, EmbeddedPacket, Proto, View, ipv4::checksum};
    use crate::{capture::LinkType, decode::decode};
    /// Builds a synthetic IPv4 packet with the supplied protocol number and payload bytes.
    pub(crate) fn packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![
            0x45, 0, 0, 0, 0, 1, 0, 0, 64, protocol, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let len = (20 + payload.len()) as u16;
        b[2..4].copy_from_slice(&len.to_be_bytes());
        let sum = checksum(&b);
        b[10..12].copy_from_slice(&sum.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }
    #[test]
    fn options_and_fragments() {
        let mut b = packet(17, &[4, 210, 4, 211, 0, 8, 0, 0]);
        b[0] = 0x46;
        b[2..4].copy_from_slice(&32u16.to_be_bytes());
        b.splice(20..20, [1, 1, 0, 0]);
        let d = decode(LinkType::RawIp, &b, 32, Detail::Full);
        assert!(!d.truncated);
        assert_eq!(d.summary.src_port, Some(1234));
        assert_eq!(d.layers[0].range, 0..24);
        b[6] = 0x20;
        assert_eq!(
            decode(LinkType::RawIp, &b, 32, Detail::Full).summary.proto,
            Proto::Udp
        );
        b[7] = 1;
        let d = decode(LinkType::RawIp, &b, 32, Detail::Full);
        assert_eq!(d.summary.proto, Proto::Ipv4);
        assert_eq!(d.summary.fragment_offset, Some(8));
    }
    #[test]
    fn ipv6_extensions_and_fragment() {
        let mut b = vec![0; 40];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&24u16.to_be_bytes());
        b[6] = 0;
        b[7] = 64;
        b.extend_from_slice(&[
            44, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 1, 4, 210, 4, 211, 0, 8, 0, 0,
        ]);
        let d = decode(LinkType::RawIp, &b, 64, Detail::Full);
        assert!(!d.truncated);
        assert_eq!(d.summary.ip_proto, Some(17));
        assert_eq!(d.summary.src_port, Some(1234));
        b[50] = 0;
        b[51] = 8;
        let d = decode(LinkType::RawIp, &b, 64, Detail::Full);
        assert_eq!(d.summary.src_port, None);
        assert_eq!(d.summary.fragment_offset, Some(8));
    }
    #[test]
    fn unreachable_quotes_udp() {
        let quote = packet(17, &[0xcf, 0x84, 0, 9, 0, 8, 0, 0]);
        let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quote);
        let b = packet(1, &icmp);
        let d = decode(LinkType::RawIp, &b, b.len() as u32, Detail::Full);
        assert_eq!(d.summary.src_port, None);
        assert!(matches!(
            d.summary.app,
            Some(AppInfo::Icmp {
                embedded: Some(EmbeddedPacket {
                    dst_port: Some(9),
                    ..
                }),
                ..
            })
        ));
        assert!(!d.truncated);
    }
    #[test]
    fn neighbour_and_router_discovery() {
        for kind in 133..=136 {
            let len = match kind {
                134 => 16,
                135 | 136 => 24,
                _ => 8,
            };
            let mut b = vec![0; len];
            b[0] = kind;
            if matches!(kind, 135 | 136) {
                b[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            }
            b.extend_from_slice(&[2, 1, 2, 0, 0, 0, 0, 1]);
            let mut c = Context::new(b.len() as u32, Detail::Full);
            icmp(&mut c, View { bytes: &b, base: 0 }, true);
            assert!(!c.decoded.truncated);
            assert!(
                matches!(c.decoded.summary.app,Some(AppInfo::Icmp {mac:Some([2,0,0,0,0,1]),target,..}) if target.is_some()==matches!(kind,135|136))
            );
        }
    }
}
