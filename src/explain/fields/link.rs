//! Holds LINK field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::{address_meaning, mac_meaning};
use crate::decode::{Decoded, Field};
use crate::explain::ETHERTYPES;

/// Closed set of LINK fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    EthDst,
    EthSrc,
    EtherType,
    VlanPriority,
    VlanDrop,
    VlanId,
    SllPacketType,
    SllHardware,
    SllAddrLen,
    SllAddr,
    SllProtocol,
    SllInterface,
    ArpHardware,
    ArpProtocol,
    ArpHardwareSize,
    ArpProtocolSize,
    ArpOperation,
    ArpSenderMac,
    ArpSenderIp,
    ArpTargetMac,
    ArpTargetIp,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    // RFC 826, Packet format: hardware and protocol types define the addresses in an ARP exchange.
    // Ethernet and VLAN fields follow IEEE 802.3 and 802.1Q, rather than an RFC.
    match key {
        Kind::EthDst => (
            "Destination MAC",
            "Helps deliver this packet to a device or listening group on the local network, using its hardware address (MAC address).",
            "",
        ),
        Kind::EthSrc => (
            "Source MAC",
            "Gives the sending device's hardware address (MAC address) on this local network, so local replies can find it.",
            "",
        ),
        Kind::EtherType => (
            "EtherType",
            "Tells the receiver which kind of packet is inside this Ethernet packet, such as IPv4 or ARP.",
            "",
        ),
        Kind::VlanPriority => (
            "VLAN priority",
            "Asks switches to give this packet a particular handling priority on the local network.",
            "",
        ),
        Kind::VlanDrop => (
            "Drop eligible",
            "Marks this packet as a candidate to drop first when a switch has too much traffic waiting.",
            "",
        ),
        Kind::VlanId => (
            "VLAN identifier",
            "Keeps traffic in a chosen logical network, called a VLAN, even when several networks share the same cables.",
            "",
        ),
        Kind::SllPacketType => (
            "Packet type",
            "Records how this packet relates to the capturing computer, such as outgoing or addressed to all local devices.",
            "",
        ),
        Kind::SllHardware => (
            "Hardware type",
            "The capture system records which kind of link hardware carries the packet.",
            "",
        ),
        Kind::SllAddrLen => (
            "Address length",
            "This byte count tells how much of the captured link address is meaningful.",
            "",
        ),
        Kind::SllAddr => (
            "Link address",
            "The capture system supplies the link address available at its capture point.",
            "",
        ),
        Kind::SllProtocol => (
            "Protocol",
            "Tells netmon what kind of packet follows the Linux capture information, such as IPv4 or ARP.",
            "",
        ),
        Kind::SllInterface => (
            "Interface index",
            "This number identifies the operating system interface where the packet is captured.",
            "",
        ),
        Kind::ArpHardware => (
            "Hardware type",
            "Tells the receiver what kind of hardware address this local address lookup uses, usually Ethernet.",
            "",
        ),
        Kind::ArpProtocol => (
            "Protocol type",
            "Tells the receiver what kind of network address is being matched to a hardware address, usually IPv4.",
            "",
        ),
        Kind::ArpHardwareSize => (
            "Hardware address size",
            "This byte count determines the size of each link address in the message.",
            "",
        ),
        Kind::ArpProtocolSize => (
            "Protocol address size",
            "This byte count determines the size of each network address in the message.",
            "",
        ),
        Kind::ArpOperation => (
            "Operation",
            "Distinguishes asking for a local hardware address from replying with that address.",
            "",
        ),
        Kind::ArpSenderMac => (
            "Sender MAC",
            "Gives the hardware address the sender claims to use on this local network.",
            "",
        ),
        Kind::ArpSenderIp => (
            "Sender IP",
            "Gives the IP address the sender claims belongs to its hardware address.",
            "",
        ),
        Kind::ArpTargetMac => (
            "Target MAC",
            "Names the hardware address the lookup concerns. A request usually leaves it unknown because it is asking for that address.",
            "",
        ),
        Kind::ArpTargetIp => (
            "Target IP",
            "Names the IP address whose hardware address is being requested or supplied.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, _packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::EthDst | Kind::EthSrc | Kind::ArpSenderMac | Kind::ArpTargetMac => {
            mac_meaning(&field.value)
        }
        Kind::EtherType | Kind::SllProtocol | Kind::ArpProtocol => {
            let payload = ETHERTYPES
                .iter()
                .find_map(|(v, name)| (*v == n as u16).then_some(*name))
                .unwrap_or("an unrecognised payload format");
            format!("{} selects {payload}.", field.value)
        }
        Kind::ArpSenderIp | Kind::ArpTargetIp => address_meaning(&field.value),
        Kind::VlanDrop => {
            "Set. A busy switch may choose this packet for dropping before other traffic.".into()
        }
        Kind::ArpOperation => match n {
            1 => "This asks for the hardware address belonging to the target IP address.",
            2 => "This supplies a hardware address for the sender's IP address.",
            _ => "",
        }
        .into(),
        Kind::SllPacketType => match n {
            0 => "This packet was addressed to the capturing computer.",
            1 => "This packet was addressed to every device on the local network.",
            2 => "This packet was addressed to a listening group on the local network.",
            3 => "This packet was addressed to another device but was captured here.",
            4 => "This packet was sent by the capturing computer.",
            _ => "",
        }
        .into(),
        Kind::ArpHardware | Kind::SllHardware if n == 1 => {
            "Type 1 identifies Ethernet hardware addresses.".into()
        }
        Kind::VlanPriority
        | Kind::VlanId
        | Kind::SllHardware
        | Kind::SllAddrLen
        | Kind::SllAddr
        | Kind::SllInterface
        | Kind::ArpHardware
        | Kind::ArpHardwareSize
        | Kind::ArpProtocolSize => String::new(),
    }
}
