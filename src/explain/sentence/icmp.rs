//! Explains ICMP packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `message`.

use crate::explain::tables::{icmp_type, unreachable};
use crate::text::mac;

/// Formats the decoded message facts without reading packet bytes.
pub(super) fn message(
    v6: &bool,
    kind: &u8,
    code: &u8,
    sequence: &Option<u16>,
    embedded: &Option<crate::decode::EmbeddedPacket>,
    target: &Option<std::net::Ipv6Addr>,
    hardware: &Option<[u8; 6]>,
) -> String {
    match (*v6, *kind) {
        (false, 8) | (true, 128) => format!(
            "Ping request (seq {})",
            sequence
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into())
        ),
        (false, 0) | (true, 129) => format!(
            "Ping reply (seq {})",
            sequence
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into())
        ),
        (false, 3) | (true, 1) => {
            let mut text = format!("Cannot deliver: {}", unreachable(*v6, *code));
            if let Some(e) = embedded
                && let (Some(p @ (6 | 17)), Some(port)) = (e.protocol, e.dst_port)
            {
                text.push_str(&format!(
                    " — about a {} packet to port {port}",
                    if p == 6 { "TCP" } else { "UDP" }
                ));
            }
            text
        }
        (false, 11) | (true, 3) => "Packet expired on the way (its hop counter reached 0)".into(),
        (true, 135) => format!(
            "Who has {}? (IPv6 neighbour discovery)",
            target
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown address".into())
        ),
        (true, 136) => format!(
            "{} is at {}",
            target
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown address".into()),
            hardware
                .as_ref()
                .map(mac)
                .unwrap_or_else(|| "an unreported hardware address".into())
        ),
        (true, 133) => "Asks: is there a router here?".into(),
        (true, 134) => "A router announces itself".into(),
        _ => format!("ICMP {}", icmp_type(*v6, *kind)),
    }
}
