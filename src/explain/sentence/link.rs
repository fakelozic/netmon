//! Explains LINK packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `arp`.

use crate::text::mac;

/// Formats the decoded arp facts without reading packet bytes.
pub(super) fn arp(
    operation: &u16,
    sender_mac: &Option<[u8; 6]>,
    sender_ip: &Option<std::net::Ipv4Addr>,
    target_ip: &Option<std::net::Ipv4Addr>,
) -> String {
    let sender = sender_ip
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown address".into());
    let target = target_ip
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown address".into());
    let m = sender_mac
        .as_ref()
        .map(mac)
        .unwrap_or_else(|| "unknown hardware address".into());
    if sender_ip.is_some() && sender_ip == target_ip {
        format!("Announces: {sender} is at {m}")
    } else if *operation == 1 && sender_ip.is_some_and(|a| a.is_unspecified()) {
        format!("Is anyone using {target}?")
    } else if *operation == 1 {
        format!("Who has {target}? Tell {sender}")
    } else if *operation == 2 {
        format!("{sender} is at {m}")
    } else {
        format!("ARP operation {operation}")
    }
}
