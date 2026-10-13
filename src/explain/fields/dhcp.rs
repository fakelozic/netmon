//! Holds DHCP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::{address_meaning, duration, mac_meaning};
use crate::decode::{Decoded, Field};
use crate::text::number;

/// Closed set of DHCP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Op,
    Hardware,
    HardwareLen,
    Hops,
    Id,
    Seconds,
    Flags,
    ClientIp,
    YourIp,
    ServerIp,
    RelayIp,
    Mac,
    Options,
    Subnet,
    Routers,
    Dns,
    Hostname,
    Requested,
    Lease,
    Message,
    Server,
    Parameters,
    ClientId,
    Unknown,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 2131, section 2.
        Kind::Op => (
            "Operation",
            "Tells the receiver whether this address-setup message comes from a client or a server.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::Hardware => (
            "Hardware type",
            "Tells the server what kind of hardware address the client uses, usually Ethernet.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::HardwareLen => (
            "Hardware address length",
            "Tells the server how many bytes of the client's hardware address to read.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::Hops => (
            "Relay hops",
            "Counts the forwarding helpers, called relays, that this address request passed through.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::Id => (
            "Transaction identifier",
            "Labels this address-setup exchange so the client can recognise replies to its request.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::Seconds => (
            "Seconds elapsed",
            "Tells the server how long the client has been trying to obtain or renew an address.",
            "",
        ),
        // RFC 2131, section 4.1.
        Kind::Flags => (
            "Flags",
            "Lets a client ask for a reply sent to all devices on its local network when it cannot yet receive an individually addressed reply.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::ClientIp => (
            "Client address",
            "Gives the client's current IPv4 address when it already has one and can use it.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::YourIp => (
            "Offered address",
            "Gives the IPv4 address the server offers or assigns to the client.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::ServerIp => (
            "Next server address",
            "Names the next server to contact for boot files. It may differ from the server assigning the address.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::RelayIp => (
            "Relay address",
            "Tells the address server which forwarding helper to send replies through to reach the client's network.",
            "",
        ),
        // RFC 2131, section 2.
        Kind::Mac => (
            "Client MAC",
            "Gives the client's hardware address so a reply can reach it on the local network.",
            "",
        ),
        // RFC 2132, section 2.
        Kind::Options => (
            "Options",
            "Carries network settings, the address's allowed lifetime, and the kind of address-setup message.",
            "",
        ),
        // RFC 2132, section 3.3.
        Kind::Subnet => (
            "Subnet mask",
            "Helps the client decide which IPv4 addresses are on its own network and which need a router.",
            "",
        ),
        // RFC 2132, section 3.5.
        Kind::Routers => (
            "Routers",
            "Lists routers the client can use to reach other networks, in order of preference.",
            "",
        ),
        // RFC 2132, section 3.8.
        Kind::Dns => (
            "DNS servers",
            "Lists servers the client can ask to turn names into IP addresses.",
            "",
        ),
        // RFC 2132, section 3.14.
        Kind::Hostname => (
            "Hostname",
            "Gives the name the client uses to identify itself on the network.",
            "",
        ),
        // RFC 2132, section 9.1.
        Kind::Requested => (
            "Requested address",
            "Tells the server which IPv4 address the client would like to use.",
            "",
        ),
        // RFC 2132, section 9.2.
        Kind::Lease => (
            "Lease time",
            "Tells the client how long it may use the assigned address before it must renew or stop using it.",
            "",
        ),
        // RFC 2132, section 9.6.
        Kind::Message => (
            "Message type",
            "Identifies the address-setup step, such as looking for a server, offering an address, or accepting it.",
            "",
        ),
        // RFC 2132, section 9.7.
        Kind::Server => (
            "Server identifier",
            "Identifies the address server so the client can choose it or send later requests to it.",
            "",
        ),
        // RFC 2132, section 9.8.
        Kind::Parameters => (
            "Parameter request list",
            "Lists the network settings the client would like the server to supply.",
            "",
        ),
        // RFC 2132, section 9.14.
        Kind::ClientId => (
            "Client identifier",
            "Gives the server a label for this client, so it can recognise it even before it has an IP address.",
            "",
        ),
        // RFC 2132, section 2.
        Kind::Unknown => (
            "Unknown option",
            "Carries an address-setup setting netmon does not recognise. Its type and length let the receiver skip it.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, _packet: &Decoded) -> String {
    match key {
        Kind::Mac => mac_meaning(&field.value),
        Kind::ClientIp | Kind::YourIp | Kind::ServerIp | Kind::RelayIp | Kind::Requested => {
            address_meaning(&field.value)
        }
        // RFC 2131, sections 2 and 3: op identifies BOOTP direction; option 53 identifies the DHCP step.
        Kind::Op => match field.num {
            Some(1) => "This message travels from the client toward an address server.",
            Some(2) => "This message travels from the server toward the client.",
            _ => "",
        }
        .into(),
        Kind::Flags => {
            if field.num.is_some_and(|n| n & 0x8000 != 0) {
                "BROADCAST is set. The client asks for a reply sent to all devices on its local network.".into()
            } else {
                "Not set.".into()
            }
        }
        Kind::Lease => {
            let n = field.num.unwrap_or(0);
            // All ones represents an infinite lease (RFC 2131, section 3.3).
            if n == u64::from(u32::MAX) {
                "The server offers an address lease with no time limit.".into()
            } else {
                format!(
                    "The address may be used for {} before renewal or expiry.",
                    duration(n)
                )
            }
        }
        Kind::Seconds => format!(
            "The client reports {} seconds spent obtaining or renewing an address.",
            number(field.num.unwrap_or(0))
        ),
        Kind::Message => message_meaning(field.num.unwrap_or(0)).into(),
        Kind::Hardware
        | Kind::HardwareLen
        | Kind::Hops
        | Kind::Id
        | Kind::Options
        | Kind::Subnet
        | Kind::Routers
        | Kind::Dns
        | Kind::Hostname
        | Kind::Server
        | Kind::Parameters
        | Kind::ClientId
        | Kind::Unknown => String::new(),
    }
}

fn message_meaning(n: u64) -> &'static str {
    // RFC 2131, section 3.1 and table 2: each message has a different role in address setup.
    match n {
        1 => "Discover looks for address servers willing to configure this client.",
        2 => "Offer proposes an address and network settings for the client.",
        3 => {
            "Request asks to accept, confirm, or renew an address, depending on the client's state."
        }
        4 => "Decline reports that the offered address appears to be in use already.",
        5 => "ACK confirms the client's address or network settings.",
        6 => "NAK refuses the request because the address or settings are unsuitable.",
        7 => "Release tells the server the client no longer needs the address.",
        8 => "Inform asks for network settings when the client already has an address.",
        _ => "",
    }
}
