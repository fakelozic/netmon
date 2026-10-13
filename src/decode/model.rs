//! Defines the packet facts shared by all consumers.
//! Byte reading belongs to `view`; application facts belong to `app`.
//! Start with `Decoded`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
use super::{AppInfo, FieldKey};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

/// Controls field-tree construction; both modes compute the same summary and layer boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    /// Compute summary facts and layer ranges without allocating field trees or formatting field values.
    Summary,
    /// Compute the same summary facts plus every available decoded field.
    Full,
}
/// The bounded result for one packet; byte ranges are absolute within its captured data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Headers in outer-to-inner order; field trees are empty in summary detail.
    pub layers: Vec<Layer>,
    /// Facts for higher-level consumers, independent of detail mode.
    pub summary: Summary,
    /// A header, declared payload or bounded parse was incomplete; captured length alone does not set this flag.
    pub truncated: bool,
}
/// One outer-to-inner protocol header or undecoded payload with a captured-byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// Protocol represented by this header or payload.
    pub proto: Proto,
    /// Half-open byte range from the start of the captured packet, clamped to available bytes.
    pub range: Range<usize>,
    /// Short technical summary; all outside text is already sanitised.
    pub line: String,
    /// Field tree in full detail; empty in summary detail.
    pub fields: Vec<Field>,
}
/// One decoded field; values are sanitised and secrets are masked before storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Selects the exhaustive explanatory wording.
    pub key: FieldKey,
    /// Display value with packet text sanitised and sensitive headers masked.
    pub value: String,
    /// Numeric interpretation when applicable; None means unavailable or nonnumeric.
    pub num: Option<u64>,
    /// Half-open absolute captured-byte range; bit fields can share their containing byte range.
    pub range: Range<usize>,
    /// Subfields such as flag bits, options or quoted headers; empty for a leaf.
    pub children: Vec<Field>,
}

/// The recognised protocol at a header or the most specific decoded layer of a summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Ethernet,
    LinuxCooked,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Dns,
    Mdns,
    Dhcp,
    Http,
    Tls,
    Quic,
    Data,
}
impl Proto {
    /// Returns the stable display name of a recognised protocol.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::LinuxCooked => "Linux cooked",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::Mdns => "mDNS",
            Self::Dhcp => "DHCP",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Quic => "QUIC",
            Self::Data => "Data",
        }
    }
}
/// A link-layer hardware address or an IPv4/IPv6 network address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    /// Six-byte link hardware address.
    Mac([u8; 6]),
    /// 32-bit IPv4 network address.
    V4(Ipv4Addr),
    /// 128-bit IPv6 network address.
    V6(Ipv6Addr),
}
/// Packet facts shared by every consumer, identical in both detail modes; absent optional facts are `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Most specific recognised protocol; raw Data layers do not replace a recognised protocol.
    pub proto: Proto,
    /// Source IP address, or link address before IP decoding; None means unavailable.
    pub src: Option<Addr>,
    /// Destination IP address, or link address before IP decoding; None means unavailable.
    pub dst: Option<Addr>,
    /// IP protocol or final IPv6 next-header number; None means not decoded.
    pub ip_proto: Option<u8>,
    /// Source transport port, in host byte order; None means unavailable or not a transport packet.
    pub src_port: Option<u16>,
    /// Destination transport port, in host byte order; None means unavailable or not a transport packet.
    pub dst_port: Option<u16>,
    /// TCP header facts when a TCP layer is reached; absent header bytes can leave scalar facts at zero.
    pub tcp: Option<TcpInfo>,
    /// Original complete packet length in bytes reported by the capture, including its link header.
    pub wire_len: u32,
    /// Recognised application or control-message facts; None means no supported message was decoded.
    pub app: Option<AppInfo>,
    /// Link payload type, in host byte order; None means no link type field was decoded.
    pub ether_type: Option<u16>,
    /// Position in bytes within the original IP payload; zero identifies an initial fragment and None means no offset was recorded.
    pub fragment_offset: Option<u32>,
    /// Declared UDP length minus its eight-byte header, saturating at zero; None means no UDP length was available.
    pub udp_payload_len: Option<u32>,
}
/// TCP facts from one header; byte positions wrap modulo 2³² and lengths are bytes, not bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpInfo {
    /// Raw sender byte position, modulo 2³²; zero can also mean the header was cut short.
    pub seq: u32,
    /// Raw next expected peer byte position, modulo 2³²; meaningful only with ACK set, and zero can mean absent bytes.
    pub ack: u32,
    /// The low nine TCP control bits; unavailable captured bits remain clear.
    pub flags: u16,
    /// Unscaled advertised receive window in bytes; zero can also mean absent header bytes.
    pub window: u16,
    /// Declared TCP data length in bytes from the enclosing IP length, even if fewer bytes were captured.
    pub payload_len: u32,
    /// Maximum segment size offered by this header, in data bytes; None means no complete option.
    pub mss: Option<u16>,
    /// Power-of-two window exponent offered in this header; None means no complete option, not a negotiated scale of zero.
    pub window_scale: Option<u8>,
}
/// Transport facts recovered from the packet quoted by an ICMP error; missing quote bytes leave options absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedPacket {
    /// Quoted IP protocol number; None means not recovered from the quote.
    pub protocol: Option<u8>,
    /// Quoted source transport port in host byte order; None means absent or not applicable.
    pub src_port: Option<u16>,
    /// Quoted destination transport port in host byte order; None means absent or not applicable.
    pub dst_port: Option<u16>,
}
/// An answer-section resource record with sanitised owner and value strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Sanitised owner name in dotted form.
    pub name: String,
    /// DNS resource-record type number in host byte order.
    pub rr_type: u16,
    /// Sanitised decoded record data, or hexadecimal when unsupported.
    pub value: String,
    /// Permitted cache lifetime in seconds; for OPT this retains the overloaded raw TTL word.
    pub ttl: u32,
}
