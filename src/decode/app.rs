//! Defines the application facts carried in a packet summary.
//! Decoding belongs to the protocol modules; prose belongs to `crate::explain`.
//! Start with `AppInfo`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
use super::DnsAnswer;
use super::EmbeddedPacket;
use std::net::{Ipv4Addr, Ipv6Addr};

/// TLS client offers; an incomplete message can retain complete individual values.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// First fully captured host-name entry, sanitised; None means absent or an incomplete name.
    pub server_name: Option<String>,
    /// Sanitised application-protocol offers; empty means none were decoded.
    pub alpn: Vec<String>,
    /// Offered wire-version numbers; empty means none decoded. The legacy version remains when no supported-version extension was decoded.
    pub versions: Vec<u16>,
    /// True only when the declared handshake and its parsed parameters are complete.
    pub complete: bool,
}
/// Sanitised application facts, independent of field-tree detail; `None` fields mean absent, unsupported or cut-short values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppInfo {
    /// Address Resolution Protocol maps IPv4 addresses to local hardware addresses.
    Arp {
        /// ARP operation number; 1 is request and 2 is reply.
        operation: u16,
        /// Sender hardware address; None means absent or not the supported six-byte format.
        sender_mac: Option<[u8; 6]>,
        /// Sender IPv4 address; None means absent or an unsupported protocol-address format.
        sender_ip: Option<Ipv4Addr>,
        /// Target hardware address; None means absent or not the supported six-byte format.
        target_mac: Option<[u8; 6]>,
        /// Target IPv4 address; None means absent or an unsupported protocol-address format.
        target_ip: Option<Ipv4Addr>,
    },
    /// IP control messages report delivery problems, probe peers or discover neighbours.
    Icmp {
        /// Selects ICMPv6 rather than ICMP for IPv4.
        v6: bool,
        /// Message type number; a present type is required before these facts are stored.
        kind: u8,
        /// Message-specific reason number; zero also represents an absent code byte.
        code: u8,
        /// Ping identifier; None means absent or not an echo message.
        id: Option<u16>,
        /// Ping request/reply sequence number; None means absent or not an echo message.
        sequence: Option<u16>,
        /// Facts from the quoted failing packet; None means no supported quote was present.
        embedded: Option<EmbeddedPacket>,
        /// Neighbour-discovery target IPv6 address; None means absent or not applicable.
        target: Option<Ipv6Addr>,
        /// Hardware address from a neighbour-discovery option; None means absent or incomplete.
        mac: Option<[u8; 6]>,
    },
    /// The first DNS question decoded from a message.
    DnsQuery {
        /// DNS transaction identifier in host byte order; absent bytes leave zero.
        id: u16,
        /// Sanitised first question name; empty means no question name was decoded.
        name: String,
        /// First question resource-record type number; zero means unavailable.
        qtype: u16,
    },
    /// DNS response facts and the bounded answer-section records.
    DnsResponse {
        /// DNS transaction identifier in host byte order; absent bytes leave zero.
        id: u16,
        /// Sanitised first question name; empty means no question name was decoded.
        name: String,
        /// First question resource-record type number; zero means unavailable.
        qtype: u16,
        /// Low four DNS response-code bits; extension bits remain in fields.
        rcode: u8,
        /// At most 256 answer records; empty means none were decoded.
        answers: Vec<DnsAnswer>,
    },
    /// DHCPv4 configuration settings offered or requested by a device.
    Dhcp {
        /// DHCP option 53 value; zero means no message type was decoded.
        message_type: u8,
        /// Nonzero offered IPv4 address; None means absent or unspecified.
        offered: Option<Ipv4Addr>,
        /// IPv4 address from option 50; None means no complete address option.
        requested: Option<Ipv4Addr>,
        /// Sanitised hostname from option 12; None means no hostname option was read.
        hostname: Option<String>,
    },
    /// An HTTP/1 request line and optional Host header.
    HttpRequest {
        /// Sanitised HTTP request method.
        method: String,
        /// Sanitised request target from this message.
        target: String,
        /// Sanitised Host header value; None means no Host header was decoded.
        host: Option<String>,
    },
    /// An HTTP/1 response status and reason phrase.
    HttpResponse {
        /// Numeric HTTP response status code.
        status: u16,
        /// Sanitised reason phrase; can be empty.
        reason: String,
    },
    /// Client encryption offers; individual values can be useful before the full hello is available.
    TlsClientHello(ClientHello),
    /// The server-selected TLS settings decoded from a hello.
    TlsServerHello {
        /// Selected TLS wire version, or legacy hello version when no selection extension was decoded.
        version: u16,
        /// Selected cipher-suite number; zero can mean incomplete hello bytes.
        cipher_suite: u16,
    },
    /// TLS record facts when no hello is selected for the summary.
    TlsRecords {
        /// Record content-type numbers in captured order, bounded to 128 records.
        content_types: Vec<u8>,
        /// Declared application-data record lengths summed in bytes with saturation.
        encrypted_bytes: u32,
        /// True when at least one handshake record is present.
        handshake: bool,
    },
    /// Visible QUIC header facts without decryption.
    Quic {
        /// True for a long header, false for a short protected header.
        long: bool,
        /// QUIC wire version for long headers; None for short headers.
        version: Option<u32>,
        /// Normalised type: 0 Initial, 1 early data, 2 Handshake, 3 Retry, 4 short header.
        packet_type: u8,
        /// Captured QUIC payload size in bytes, including its visible header.
        bytes: u32,
    },
}
