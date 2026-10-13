//! Holds short definitions for networking terms.
//! Packet-specific explanations belong to `fields`; sentences belong to `sentence`.
//! Start with `GLOSSARY`.

/// Case-insensitively sorted terms; each definition introduces the idea and its use in netmon.
pub const GLOSSARY: &[(&str, &str)] = &[
    // RFC 9293, section 3.1.
    (
        "ACK",
        "A TCP flag marking the acknowledgment number as valid, normally confirming earlier bytes arrived and naming the next expected byte. netmon also shows ACK on resets, where it helps identify refused or aborted traffic.",
    ),
    // RFC 7301, section 3.
    (
        "ALPN",
        "A TLS setting that offers or selects how the application will communicate, such as HTTP/2. netmon reads it when it is visible in an encryption setup message.",
    ),
    // RFC 826, Packet format.
    (
        "ARP",
        "A request and reply that find the local hardware address for an IPv4 address. Devices need that address to send Ethernet packets on the local network.",
    ),
    // RFC 1035, section 4.1.3.
    (
        "cache",
        "A saved copy of information that can be reused instead of asking again. DNS record TTL tells you how long an answer may stay in a cache.",
    ),
    // RFC 791, section 3.1.
    (
        "checksum",
        "A calculated number that helps detect accidentally damaged bytes. netmon checks the IPv4 header checksum, but a checksum does not prove who sent the packet.",
    ),
    // RFC 8446, section 4.1.
    (
        "cipher suite",
        "A named choice of encryption and related protection methods. A TLS client offers choices and the server selects one they both support.",
    ),
    // RFC 3168, sections 5–6.
    (
        "congestion",
        "More traffic arriving than a router or network path can handle comfortably. Packets may be delayed, dropped, or marked so sending computers can slow down.",
    ),
    // RFC 768, Introduction.
    (
        "datagram",
        "One independently delivered message. UDP sends these without guaranteeing that they arrive or arrive in order.",
    ),
    // RFC 2131, section 3.
    (
        "DHCP",
        "A protocol that gives a device an IP address and network settings for an allowed time. netmon shows the request, offer, and acceptance so you can follow address setup.",
    ),
    // RFC 1035, section 4.
    (
        "DNS",
        "The system that looks up information about names, including their IP addresses. netmon shows questions and replies, including names that cannot be found.",
    ),
    // RFC 2474, section 3.
    (
        "DSCP",
        "An IP marking that asks routers for a particular way of handling traffic. It is a request for a policy, so it does not guarantee faster delivery.",
    ),
    // RFC 3168, sections 5–6.
    (
        "ECN",
        "A way for a busy router to mark a packet instead of dropping it to report congestion. TCP can pass that warning back and slow the sender down.",
    ),
    // RFC 894, Frame Format.
    (
        "Ethernet",
        "A protocol for sending packets between hardware addresses on a local network. netmon shows its source and destination MAC addresses before the IP header.",
    ),
    // RFC 9293, section 3.6.
    (
        "FIN",
        "A TCP flag saying the sender has finished sending data. netmon may still show traffic in the other direction while that computer finishes its reply.",
    ),
    // RFC 791, section 3.1; RFC 8200, section 4.5.
    (
        "fragment",
        "One piece of an IP packet split to fit a network link. The fragment offset tells the receiver where to put that piece when rebuilding the original packet.",
    ),
    // RFC 894, Frame Format.
    (
        "frame",
        "A packet as carried on a local link, with its own delivery header. In netmon, Ethernet fields tell you about local delivery before IP fields tell you about the destination.",
    ),
    // RFC 9293, section 3.4.
    (
        "handshake",
        "TCP usually opens a connection with three packets: SYN asks to connect, SYN+ACK accepts and replies, and ACK confirms that reply. netmon's connection story helps you follow these steps.",
    ),
    (
        "header",
        "The instructions and addresses before a packet's carried data. netmon lists header fields in byte order so you can follow them alongside the highlighted bytes.",
    ),
    // RFC 1812, section 5.3.1; RFC 8200, section 3.
    (
        "hop",
        "One forwarding step through a router toward the destination. Each router reduces the IP hop counter, preventing a packet from circulating forever.",
    ),
    // RFC 8200, section 3.
    (
        "hop limit",
        "IPv6's counter limiting how many routers may forward a packet. netmon can estimate routers crossed only by guessing the starting count.",
    ),
    // RFC 9110, section 1.
    (
        "HTTP",
        "The request-and-reply protocol used by web clients and servers. netmon reads visible HTTP/1 requests and results, while encrypted web contents need the encryption keys.",
    ),
    // RFC 792, Message Formats.
    (
        "ICMP",
        "A protocol for network reports such as delivery failures and ping replies. netmon can show the failed packet quoted inside an error report.",
    ),
    // RFC 791, section 3.1.
    (
        "IP address",
        "An address routers use to deliver traffic to a device's network connection. netmon shows the claimed sender and intended destination, but these addresses do not prove identity.",
    ),
    // RFC 791, section 3.1.
    (
        "IPv4",
        "The IP version using 32-bit addresses written like 192.168.1.2. netmon shows a header checksum and TTL in its fields.",
    ),
    // RFC 8200, section 3.
    (
        "IPv6",
        "The IP version using 128-bit addresses written like 2001:db8::1. netmon shows a hop limit and may show extra headers after its fixed header.",
    ),
    // RFC 826, Packet format.
    (
        "MAC address",
        "A hardware address for an interface or group on the local network. netmon shows it in Ethernet and ARP, where it helps explain delivery to the next local device.",
    ),
    // RFC 9293, section 3.7.1.
    (
        "MSS",
        "The most TCP data a computer offers to receive in one packet, excluding IP and TCP headers. netmon shows this offer in the opening packets' options.",
    ),
    // RFC 1191, section 2.
    (
        "MTU",
        "The largest IP packet a network link can carry in one piece. A packet too large for the next link may need splitting or trigger a size error.",
    ),
    // RFC 6762, section 3.
    (
        "multicast",
        "Delivery to a group of devices that listen to the same address. Local name discovery can use it to ask several devices without knowing their individual addresses.",
    ),
    // RFC 9293, section 3.1.
    (
        "option",
        "An extra protocol setting beyond the fixed header fields. netmon expands TCP options to show size limits, timing counters, and reports of received byte ranges.",
    ),
    (
        "packet",
        "A unit of data sent over a network. netmon uses this everyday word for what TCP formally calls a segment, Ethernet a frame, and UDP a datagram.",
    ),
    (
        "payload",
        "The data carried after a protocol's header. It may be another protocol's packet or application data, and netmon shows its size even when the contents are encrypted.",
    ),
    // RFC 9293, section 3.1.
    (
        "port",
        "A number that helps a computer deliver traffic to the right program. The IP address finds the computer, while the port helps find the program on it.",
    ),
    // RFC 1918, section 3.
    (
        "private address",
        "An IP address reserved for use inside private networks. Seeing one in netmon does not prove that the device or traffic is safe.",
    ),
    (
        "protocol",
        "Rules computers agree to use to read and exchange messages. netmon's layers show which rules apply at each step, such as Ethernet, IP, and TCP.",
    ),
    // RFC 9000, section 17.
    (
        "QUIC",
        "A transport protocol over UDP that protects application traffic with encryption and can carry several independent conversations. netmon recognises visible headers, including unencrypted Retry and version-negotiation packets.",
    ),
    // RFC 1035, section 4.1.1.
    (
        "recursion",
        "A DNS server contacting other name servers to find an answer for a client. netmon shows whether the client asks for this and whether the server supports it.",
    ),
    // RFC 2131, section 2.
    (
        "relay",
        "A helper that forwards DHCP requests between a client's network and an address server. netmon shows its address so you can see how a reply gets back to the client.",
    ),
    // RFC 1812, section 5.3.1.
    (
        "router",
        "A device that forwards IP packets between networks. A packet's TTL or hop limit decreases as routers forward it.",
    ),
    // RFC 9293, section 3.5.2.
    (
        "RST",
        "A TCP flag that stops or refuses a connection immediately. netmon shows who sent the reset, but that packet alone may not reveal why.",
    ),
    // RFC 2018, section 3.
    (
        "SACK",
        "A TCP report listing byte ranges that arrived beyond a gap. netmon shows each range so you can see what the sender may still need to resend.",
    ),
    // RFC 9293, section 3.1.
    (
        "segment",
        "One TCP packet with byte numbers, control flags, and optional data. netmon uses its sequence number to follow ordered delivery.",
    ),
    // RFC 9293, section 3.4.
    (
        "sequence number",
        "A TCP number locating data bytes within a connection. netmon uses it to show order, gaps, or repeated data, and SYN and FIN each use one number too.",
    ),
    // RFC 2132, section 3.3.
    (
        "subnet",
        "A group of IP addresses treated as belonging to one network. A DHCP subnet mask helps a computer decide which destinations need a router.",
    ),
    // RFC 9293, section 3.4.
    (
        "SYN",
        "A TCP flag sharing a starting byte number when opening a connection. netmon shows it in the first packet and in the SYN+ACK reply.",
    ),
    // RFC 9293, section 2.2.
    (
        "TCP",
        "A protocol that delivers data bytes in order and resends missing bytes. netmon follows its opening handshake, byte numbers, receive windows, and closing flags.",
    ),
    // RFC 8446, section 1.
    (
        "TLS",
        "A protocol that sets up keys to protect data and can check a server's identity. netmon can read visible setup fields, but encrypted contents require the keys.",
    ),
    // RFC 1812, section 5.3.1; RFC 1035, section 4.1.3.
    (
        "TTL",
        "IPv4's counter preventing packets from circling forever. Each router lowers it, while the similarly named DNS record TTL limits how long a saved answer can be reused.",
    ),
    // RFC 768, Introduction.
    (
        "UDP",
        "A protocol that sends separate messages to numbered ports without promising delivery or order. netmon shows its ports and lengths, while the application must handle any missing messages.",
    ),
    (
        "VLAN",
        "A way to divide one physical local network into separate logical networks. netmon shows the VLAN label in tagged Ethernet packets.",
    ),
    // RFC 9293, section 3.8.6.
    (
        "window",
        "How much more data a TCP receiver says it can take right now. It keeps a fast sender from overwhelming a slow receiver, and zero asks the sender to pause ordinary data.",
    ),
    // RFC 7323, section 2.
    (
        "window scale",
        "A multiplier agreed during TCP setup so a window can represent more receive space. Opening packets always use the window without this multiplier.",
    ),
    // RFC 1035, section 3.3.13.
    (
        "zone",
        "A group of DNS names managed together by a responsible name server. netmon shows zone update counters and timing rules in start-of-authority records.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explain::sentence;
    use crate::{
        capture::LinkType,
        decode::{Detail, decode},
    };
    #[test]
    fn glossary_is_sorted_and_quic_unencrypted_controls_are_explicit() {
        assert!(
            GLOSSARY
                .windows(2)
                .all(|pair| pair[0].0.to_lowercase() < pair[1].0.to_lowercase())
        );
        for (first, version, expected) in [
            (0xc0, 0u32, "version negotiation is not encrypted"),
            (0xf0, 1, "Retry is not encrypted"),
            (0xc0, 0x6b3343cf, "Retry is not encrypted"),
        ] {
            let mut quic = vec![first];
            quic.extend_from_slice(&version.to_be_bytes());
            quic.extend_from_slice(&[0, 0]);
            let mut udp = vec![4, 210, 1, 187, 0, 15, 0, 0];
            udp.extend_from_slice(&quic);
            let mut ip = vec![
                0x45, 0, 0, 35, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            ];
            ip.extend_from_slice(&udp);
            let d = decode(LinkType::RawIp, &ip, 35, Detail::Full);
            assert!(sentence(&d).contains(expected));
        }
    }
}
