//! Explains DHCP packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `message`.

use crate::explain::tables::dhcp_type;

/// Formats the decoded message facts without reading packet bytes.
pub(super) fn message(
    message_type: &u8,
    offered: &Option<std::net::Ipv4Addr>,
    requested: &Option<std::net::Ipv4Addr>,
) -> String {
    let address = requested
        .or(*offered)
        .map(|a| a.to_string())
        .unwrap_or_else(|| "an unreported address".into());
    match message_type {
        1 => "Asks the network for an IP address (DHCP Discover)".into(),
        2 => format!("Offers the address {address} (DHCP Offer)"),
        3 => format!("Requests the address {address} (DHCP Request)"),
        5 => format!("Confirms: use {address} (DHCP ACK)"),
        _ => format!("DHCP {}", dhcp_type(*message_type)),
    }
}
