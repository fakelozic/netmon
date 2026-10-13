//! Checks that packet text cannot inject terminal controls into output.
//! Synthetic packet parsing belongs to `netmon::decode`; output belongs to `netmon::render`.
//! Start with `dns_and_http_controls_never_reach_printed_output`.

use netmon::{
    capture::{LinkType, RawPacket},
    decode::{Detail, decode},
    render::{self, Mode},
};
use std::time::Duration;

#[test]
fn dns_and_http_controls_never_reach_printed_output() {
    let mut dns = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x1b, 0, 0, 1, 0, 1];
    let mut udp = vec![4, 210, 0, 53, 0, 0, 0, 0];
    udp[4..6].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp.append(&mut dns);
    let mut tcp = vec![0; 20];
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    tcp.extend_from_slice(b"GET / HTTP/1.1\r\nHost: test\r\nX-Test: \x1b[31m\r\n\r\n");
    for (protocol, payload) in [(17, udp), (6, tcp)] {
        let mut bytes = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2,
        ];
        bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        bytes.extend(payload);
        let raw = RawPacket {
            number: 1,
            ts: Duration::ZERO,
            link: LinkType::RawIp,
            iface: 0,
            orig_len: bytes.len() as u32,
            data: bytes,
        };
        let d = decode(raw.link, &raw.data, raw.orig_len, Detail::Full);
        for mode in [Mode::Default, Mode::Fields, Mode::Packet(1)] {
            let out = render::packet(&raw, &d, Duration::ZERO, mode);
            assert!(out.chars().all(|c| !c.is_control() || c == '\n'), "{out:?}");
            if protocol == 17 || mode != Mode::Default {
                assert!(out.contains("\\x1B"));
            }
        }
    }
}
