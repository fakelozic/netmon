//! Decodes a packet from its link header through its application payload.
//! Protocol modules do the parsing; `crate::explain` supplies explanatory wording.
//! Start with `decode`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
/// Exposes DHCPv4 decoding.
pub mod dhcp;
/// Exposes DNS decoding.
pub mod dns;
/// Exposes HTTP/1 decoding.
pub mod http;
/// Exposes shared IP decoder paths.
pub mod ip;
/// Exposes link-header decoding.
pub mod link;
/// Exposes QUIC recognition.
pub mod quic;
/// Exposes TLS hello parsing.
pub mod tls;
/// Exposes TCP and UDP decoding.
pub mod transport;

mod app;
mod context;
mod icmp;
mod ipv4;
mod ipv6;
mod keys;
mod model;
mod redact;
mod view;

pub(crate) use redact::hidden_ranges;

pub use app::{AppInfo, ClientHello};
pub(super) use context::Context;
pub use keys::FieldKey;
pub use model::{
    Addr, Decoded, Detail, DnsAnswer, EmbeddedPacket, Field, Layer, Proto, Summary, TcpInfo,
};
pub(super) use view::View;

use crate::capture::LinkType;

/// Decodes captured bytes through link, IP, transport and application layers without requiring complete headers.
// Each parser stores its layer before dispatching the payload, preserving outer-to-inner order.
// Detail::Summary skips field trees; all byte ranges remain absolute in the captured packet.
pub fn decode(link: LinkType, data: &[u8], orig_len: u32, detail: Detail) -> Decoded {
    let mut c = Context::new(orig_len, detail);
    let v = View {
        bytes: data,
        base: 0,
    };
    match link {
        LinkType::Ethernet => link::ethernet(&mut c, v),
        LinkType::LinuxSll => link::cooked(&mut c, v, false),
        LinkType::LinuxSll2 => link::cooked(&mut c, v, true),
        LinkType::RawIp => match v.u8(0).map(|b| b >> 4) {
            Some(4) => ip::ipv4(&mut c, v),
            Some(6) => ip::ipv6(&mut c, v),
            _ => {
                c.decoded.truncated = data.is_empty();
                c.data(v);
            }
        },
        LinkType::Other(_) => c.data(v),
    }
    c.decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_header_values_are_not_presented_as_zero() {
        for (protocol, payload, expected) in [
            (6, vec![0, 1, 0], "TCP header is incomplete [cut short]"),
            (17, vec![0, 1, 0], "UDP header is incomplete [cut short]"),
            (1, vec![8, 0, 0], "Ping request (seq ?) [cut short]"),
        ] {
            let mut bytes = vec![
                0x45, 0, 0, 40, 0, 0, 0, 0, 64, protocol, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            ];
            bytes.extend(payload);
            let d = decode(LinkType::RawIp, &bytes, 40, Detail::Full);
            assert_eq!(crate::explain::sentence(&d), expected);
            assert!(
                d.layers
                    .iter()
                    .all(|l| !l.fields.iter().any(|f| f.key == FieldKey::TcpFlags))
            );
        }
        let mut bytes = vec![
            0x45, 0, 0, 34, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        bytes.extend_from_slice(&[0, 53, 4, 210, 0, 14, 0, 0, 0, 1]);
        let d = decode(LinkType::RawIp, &bytes, 34, Detail::Full);
        assert!(d.summary.app.is_none());
        let id = d
            .layers
            .iter()
            .flat_map(|l| &l.fields)
            .find(|f| f.key == FieldKey::DnsId)
            .unwrap();
        assert!(id.children.is_empty());
        let truncated = decode(LinkType::RawIp, &[0x45], 40, Detail::Full);
        assert!(truncated.layers[0].line.contains("ttl=? len=?"));
    }
}
