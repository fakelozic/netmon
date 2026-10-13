//! Builds the three-part explanation for every decoded field.
//! Protocol wording belongs to the family modules; byte parsing belongs to `crate::decode`.
//! Start with `field_text`.

use crate::decode::{Decoded, Field, FieldKey as K};

mod data;
mod dhcp;
mod dns;
mod http;
mod icmp;
mod ip;
mod link;
mod meanings;
mod quic;
mod tcp;
#[cfg(test)]
mod tests;
mod tls;
mod udp;

/// The label, definition, packet-specific interpretation and significance of one field.
pub struct FieldText {
    /// Short display label for the field.
    pub label: &'static str,
    /// Required definition of the field and its purpose.
    pub what: &'static str,
    /// Interpretation of this packet value; empty when no additional interpretation applies.
    pub here: String,
    /// Significance of the field; empty when the field needs no additional guidance.
    pub why: &'static str,
}
/// Returns wording for every field key, using already sanitised decoded values.
pub fn field_text(field: &Field, packet: &Decoded) -> FieldText {
    let (label, what, mut why) = description(field.key);
    // A reset offers no receive capacity (RFC 9293, section 3.5.2).
    if field.key == K::TcpWindow
        && packet
            .summary
            .tcp
            .as_ref()
            .is_some_and(|t| t.flags & 4 != 0)
    {
        why = "";
    }
    let mut here = match family(field.key) {
        Family::Link(key) => link::here(key, field, packet),
        Family::Ip(key) => ip::here(key, field, packet),
        Family::Icmp(key) => icmp::here(key, field, packet),
        Family::Tcp(key) => tcp::here(key, field, packet),
        Family::Udp(key) => udp::here(key, field, packet),
        Family::Dns(key) => dns::here(key, field, packet),
        Family::Dhcp(key) => dhcp::here(key, field, packet),
        Family::Http(key) => http::here(key, field, packet),
        Family::Tls(key) => tls::here(key, field, packet),
        Family::Quic(key) => quic::here(key, field, packet),
        Family::Data(key) => data::here(key, field, packet),
    };
    // Boolean control bits use one consistent explanation when clear; numeric codes are not flags.
    if field.num == Some(0)
        && matches!(
            field.key,
            K::IpDf
                | K::IpMf
                | K::V6MoreFragments
                | K::VlanDrop
                | K::TcpCwr
                | K::TcpEce
                | K::TcpUrg
                | K::TcpAckFlag
                | K::TcpPsh
                | K::TcpRst
                | K::TcpSyn
                | K::TcpFin
                | K::DnsResponse
                | K::DnsAuthoritative
                | K::DnsTruncated
                | K::DnsRecursionDesired
                | K::DnsRecursionAvailable
                | K::DnsUnicast
                | K::DnsCacheFlush
        )
    {
        here = "Not set.".into();
    }
    FieldText {
        label,
        what,
        here,
        why,
    }
}

/// Returns the required definition for every key through exhaustive family dispatch.
pub(super) fn description(key: K) -> (&'static str, &'static str, &'static str) {
    match family(key) {
        Family::Link(key) => link::description(key),
        Family::Ip(key) => ip::description(key),
        Family::Icmp(key) => icmp::description(key),
        Family::Tcp(key) => tcp::description(key),
        Family::Udp(key) => udp::description(key),
        Family::Dns(key) => dns::description(key),
        Family::Dhcp(key) => dhcp::description(key),
        Family::Http(key) => http::description(key),
        Family::Tls(key) => tls::description(key),
        Family::Quic(key) => quic::description(key),
        Family::Data(key) => data::description(key),
    }
}

// The variants carry only keys from their own family, so family text stays exhaustive.
enum Family {
    Link(link::Kind),
    Ip(ip::Kind),
    Icmp(icmp::Kind),
    Tcp(tcp::Kind),
    Udp(udp::Kind),
    Dns(dns::Kind),
    Dhcp(dhcp::Kind),
    Http(http::Kind),
    Tls(tls::Kind),
    Quic(quic::Kind),
    Data(data::Kind),
}

fn family(key: K) -> Family {
    // This dispatch stays exhaustive: adding a FieldKey must supply its wording.
    match key {
        K::EthDst => Family::Link(link::Kind::EthDst),
        K::EthSrc => Family::Link(link::Kind::EthSrc),
        K::EtherType => Family::Link(link::Kind::EtherType),
        K::VlanPriority => Family::Link(link::Kind::VlanPriority),
        K::VlanDrop => Family::Link(link::Kind::VlanDrop),
        K::VlanId => Family::Link(link::Kind::VlanId),
        K::SllPacketType => Family::Link(link::Kind::SllPacketType),
        K::SllHardware => Family::Link(link::Kind::SllHardware),
        K::SllAddrLen => Family::Link(link::Kind::SllAddrLen),
        K::SllAddr => Family::Link(link::Kind::SllAddr),
        K::SllProtocol => Family::Link(link::Kind::SllProtocol),
        K::SllInterface => Family::Link(link::Kind::SllInterface),
        K::ArpHardware => Family::Link(link::Kind::ArpHardware),
        K::ArpProtocol => Family::Link(link::Kind::ArpProtocol),
        K::ArpHardwareSize => Family::Link(link::Kind::ArpHardwareSize),
        K::ArpProtocolSize => Family::Link(link::Kind::ArpProtocolSize),
        K::ArpOperation => Family::Link(link::Kind::ArpOperation),
        K::ArpSenderMac => Family::Link(link::Kind::ArpSenderMac),
        K::ArpSenderIp => Family::Link(link::Kind::ArpSenderIp),
        K::ArpTargetMac => Family::Link(link::Kind::ArpTargetMac),
        K::ArpTargetIp => Family::Link(link::Kind::ArpTargetIp),
        K::IpVersion => Family::Ip(ip::Kind::IpVersion),
        K::IpHeaderLen => Family::Ip(ip::Kind::IpHeaderLen),
        K::IpDscp => Family::Ip(ip::Kind::IpDscp),
        K::IpEcn => Family::Ip(ip::Kind::IpEcn),
        K::IpTotalLen => Family::Ip(ip::Kind::IpTotalLen),
        K::IpId => Family::Ip(ip::Kind::IpId),
        K::IpFlags => Family::Ip(ip::Kind::IpFlags),
        K::IpDf => Family::Ip(ip::Kind::IpDf),
        K::IpMf => Family::Ip(ip::Kind::IpMf),
        K::IpFragmentOffset => Family::Ip(ip::Kind::IpFragmentOffset),
        K::IpTtl => Family::Ip(ip::Kind::IpTtl),
        K::IpProtocol => Family::Ip(ip::Kind::IpProtocol),
        K::IpChecksum => Family::Ip(ip::Kind::IpChecksum),
        K::IpSrc => Family::Ip(ip::Kind::IpSrc),
        K::IpDst => Family::Ip(ip::Kind::IpDst),
        K::IpOptions => Family::Ip(ip::Kind::IpOptions),
        K::V6Version => Family::Ip(ip::Kind::V6Version),
        K::V6TrafficClass => Family::Ip(ip::Kind::V6TrafficClass),
        K::V6FlowLabel => Family::Ip(ip::Kind::V6FlowLabel),
        K::V6PayloadLen => Family::Ip(ip::Kind::V6PayloadLen),
        K::V6NextHeader => Family::Ip(ip::Kind::V6NextHeader),
        K::V6HopLimit => Family::Ip(ip::Kind::V6HopLimit),
        K::V6Src => Family::Ip(ip::Kind::V6Src),
        K::V6Dst => Family::Ip(ip::Kind::V6Dst),
        K::V6Extension => Family::Ip(ip::Kind::V6Extension),
        K::V6ExtNext => Family::Ip(ip::Kind::V6ExtNext),
        K::V6ExtLen => Family::Ip(ip::Kind::V6ExtLen),
        K::V6ExtData => Family::Ip(ip::Kind::V6ExtData),
        K::V6FragmentOffset => Family::Ip(ip::Kind::V6FragmentOffset),
        K::V6MoreFragments => Family::Ip(ip::Kind::V6MoreFragments),
        K::V6FragmentId => Family::Ip(ip::Kind::V6FragmentId),
        K::IcmpType => Family::Icmp(icmp::Kind::Type),
        K::IcmpCode => Family::Icmp(icmp::Kind::Code),
        K::IcmpChecksum => Family::Icmp(icmp::Kind::Checksum),
        K::IcmpId => Family::Icmp(icmp::Kind::Id),
        K::IcmpSeq => Family::Icmp(icmp::Kind::Seq),
        K::IcmpEmbedded => Family::Icmp(icmp::Kind::Embedded),
        K::IcmpTarget => Family::Icmp(icmp::Kind::Target),
        K::IcmpLinkOption => Family::Icmp(icmp::Kind::LinkOption),
        K::IcmpOptionType => Family::Icmp(icmp::Kind::OptionType),
        K::IcmpOptionLen => Family::Icmp(icmp::Kind::OptionLen),
        K::IcmpOptionData => Family::Icmp(icmp::Kind::OptionData),
        K::TcpSrc => Family::Tcp(tcp::Kind::Src),
        K::TcpDst => Family::Tcp(tcp::Kind::Dst),
        K::TcpSeq => Family::Tcp(tcp::Kind::Seq),
        K::TcpAck => Family::Tcp(tcp::Kind::Ack),
        K::TcpOffset => Family::Tcp(tcp::Kind::Offset),
        K::TcpFlags => Family::Tcp(tcp::Kind::Flags),
        K::TcpCwr => Family::Tcp(tcp::Kind::Cwr),
        K::TcpEce => Family::Tcp(tcp::Kind::Ece),
        K::TcpUrg => Family::Tcp(tcp::Kind::Urg),
        K::TcpAckFlag => Family::Tcp(tcp::Kind::AckFlag),
        K::TcpPsh => Family::Tcp(tcp::Kind::Psh),
        K::TcpRst => Family::Tcp(tcp::Kind::Rst),
        K::TcpSyn => Family::Tcp(tcp::Kind::Syn),
        K::TcpFin => Family::Tcp(tcp::Kind::Fin),
        K::TcpWindow => Family::Tcp(tcp::Kind::Window),
        K::TcpChecksum => Family::Tcp(tcp::Kind::Checksum),
        K::TcpUrgent => Family::Tcp(tcp::Kind::Urgent),
        K::TcpOptions => Family::Tcp(tcp::Kind::Options),
        K::TcpMss => Family::Tcp(tcp::Kind::Mss),
        K::TcpScale => Family::Tcp(tcp::Kind::Scale),
        K::TcpSackPermitted => Family::Tcp(tcp::Kind::SackPermitted),
        K::TcpSack => Family::Tcp(tcp::Kind::Sack),
        K::TcpSackLeft => Family::Tcp(tcp::Kind::SackLeft),
        K::TcpSackRight => Family::Tcp(tcp::Kind::SackRight),
        K::TcpTimestamp => Family::Tcp(tcp::Kind::Timestamp),
        K::TcpTimestampValue => Family::Tcp(tcp::Kind::TimestampValue),
        K::TcpTimestampEcho => Family::Tcp(tcp::Kind::TimestampEcho),
        K::TcpNop => Family::Tcp(tcp::Kind::Nop),
        K::TcpEnd => Family::Tcp(tcp::Kind::End),
        K::TcpUnknownOption => Family::Tcp(tcp::Kind::UnknownOption),
        K::TcpPayload => Family::Tcp(tcp::Kind::Payload),
        K::UdpSrc => Family::Udp(udp::Kind::Src),
        K::UdpDst => Family::Udp(udp::Kind::Dst),
        K::UdpLen => Family::Udp(udp::Kind::Len),
        K::UdpChecksum => Family::Udp(udp::Kind::Checksum),
        K::UdpPayload => Family::Udp(udp::Kind::Payload),
        K::DnsId => Family::Dns(dns::Kind::Id),
        K::DnsFlags => Family::Dns(dns::Kind::Flags),
        K::DnsResponse => Family::Dns(dns::Kind::Response),
        K::DnsOpcode => Family::Dns(dns::Kind::Opcode),
        K::DnsAuthoritative => Family::Dns(dns::Kind::Authoritative),
        K::DnsTruncated => Family::Dns(dns::Kind::Truncated),
        K::DnsRecursionDesired => Family::Dns(dns::Kind::RecursionDesired),
        K::DnsRecursionAvailable => Family::Dns(dns::Kind::RecursionAvailable),
        K::DnsRcode => Family::Dns(dns::Kind::Rcode),
        K::DnsQuestions => Family::Dns(dns::Kind::Questions),
        K::DnsAnswers => Family::Dns(dns::Kind::Answers),
        K::DnsAuthorities => Family::Dns(dns::Kind::Authorities),
        K::DnsAdditionals => Family::Dns(dns::Kind::Additionals),
        K::DnsQuestion => Family::Dns(dns::Kind::Question),
        K::DnsName => Family::Dns(dns::Kind::Name),
        K::DnsType => Family::Dns(dns::Kind::Type),
        K::DnsClass => Family::Dns(dns::Kind::Class),
        K::DnsUnicast => Family::Dns(dns::Kind::Unicast),
        K::DnsRecord => Family::Dns(dns::Kind::Record),
        K::DnsTtl => Family::Dns(dns::Kind::Ttl),
        K::DnsData => Family::Dns(dns::Kind::Data),
        K::DnsCacheFlush => Family::Dns(dns::Kind::CacheFlush),
        K::DnsMxPreference => Family::Dns(dns::Kind::MxPreference),
        K::DnsMxExchange => Family::Dns(dns::Kind::MxExchange),
        K::DnsSoaPrimary => Family::Dns(dns::Kind::SoaPrimary),
        K::DnsSoaMailbox => Family::Dns(dns::Kind::SoaMailbox),
        K::DnsSoaSerial => Family::Dns(dns::Kind::SoaSerial),
        K::DnsSoaRefresh => Family::Dns(dns::Kind::SoaRefresh),
        K::DnsSoaRetry => Family::Dns(dns::Kind::SoaRetry),
        K::DnsSoaExpire => Family::Dns(dns::Kind::SoaExpire),
        K::DnsSoaMinimum => Family::Dns(dns::Kind::SoaMinimum),
        K::DnsSrvPriority => Family::Dns(dns::Kind::SrvPriority),
        K::DnsSrvWeight => Family::Dns(dns::Kind::SrvWeight),
        K::DnsSrvPort => Family::Dns(dns::Kind::SrvPort),
        K::DnsSrvTarget => Family::Dns(dns::Kind::SrvTarget),
        K::DnsOptSize => Family::Dns(dns::Kind::OptSize),
        K::DnsOptRcode => Family::Dns(dns::Kind::OptRcode),
        K::DnsOptVersion => Family::Dns(dns::Kind::OptVersion),
        K::DnsOptFlags => Family::Dns(dns::Kind::OptFlags),
        K::DnsOptCode => Family::Dns(dns::Kind::OptCode),
        K::DnsOptData => Family::Dns(dns::Kind::OptData),
        K::DhcpOp => Family::Dhcp(dhcp::Kind::Op),
        K::DhcpHardware => Family::Dhcp(dhcp::Kind::Hardware),
        K::DhcpHardwareLen => Family::Dhcp(dhcp::Kind::HardwareLen),
        K::DhcpHops => Family::Dhcp(dhcp::Kind::Hops),
        K::DhcpId => Family::Dhcp(dhcp::Kind::Id),
        K::DhcpSeconds => Family::Dhcp(dhcp::Kind::Seconds),
        K::DhcpFlags => Family::Dhcp(dhcp::Kind::Flags),
        K::DhcpClientIp => Family::Dhcp(dhcp::Kind::ClientIp),
        K::DhcpYourIp => Family::Dhcp(dhcp::Kind::YourIp),
        K::DhcpServerIp => Family::Dhcp(dhcp::Kind::ServerIp),
        K::DhcpRelayIp => Family::Dhcp(dhcp::Kind::RelayIp),
        K::DhcpMac => Family::Dhcp(dhcp::Kind::Mac),
        K::DhcpOptions => Family::Dhcp(dhcp::Kind::Options),
        K::DhcpSubnet => Family::Dhcp(dhcp::Kind::Subnet),
        K::DhcpRouters => Family::Dhcp(dhcp::Kind::Routers),
        K::DhcpDns => Family::Dhcp(dhcp::Kind::Dns),
        K::DhcpHostname => Family::Dhcp(dhcp::Kind::Hostname),
        K::DhcpRequested => Family::Dhcp(dhcp::Kind::Requested),
        K::DhcpLease => Family::Dhcp(dhcp::Kind::Lease),
        K::DhcpMessage => Family::Dhcp(dhcp::Kind::Message),
        K::DhcpServer => Family::Dhcp(dhcp::Kind::Server),
        K::DhcpParameters => Family::Dhcp(dhcp::Kind::Parameters),
        K::DhcpClientId => Family::Dhcp(dhcp::Kind::ClientId),
        K::DhcpUnknown => Family::Dhcp(dhcp::Kind::Unknown),
        K::HttpRequestLine => Family::Http(http::Kind::RequestLine),
        K::HttpMethod => Family::Http(http::Kind::Method),
        K::HttpTarget => Family::Http(http::Kind::Target),
        K::HttpVersion => Family::Http(http::Kind::Version),
        K::HttpStatusLine => Family::Http(http::Kind::StatusLine),
        K::HttpStatus => Family::Http(http::Kind::Status),
        K::HttpReason => Family::Http(http::Kind::Reason),
        K::HttpHeader => Family::Http(http::Kind::Header),
        K::HttpBody => Family::Http(http::Kind::Body),
        K::TlsRecord => Family::Tls(tls::Kind::Record),
        K::TlsContentType => Family::Tls(tls::Kind::ContentType),
        K::TlsRecordVersion => Family::Tls(tls::Kind::RecordVersion),
        K::TlsRecordLen => Family::Tls(tls::Kind::RecordLen),
        K::TlsHandshake => Family::Tls(tls::Kind::Handshake),
        K::TlsHandshakeType => Family::Tls(tls::Kind::HandshakeType),
        K::TlsHandshakeLen => Family::Tls(tls::Kind::HandshakeLen),
        K::TlsHelloVersion => Family::Tls(tls::Kind::HelloVersion),
        K::TlsRandom => Family::Tls(tls::Kind::Random),
        K::TlsSession => Family::Tls(tls::Kind::Session),
        K::TlsCipherCount => Family::Tls(tls::Kind::CipherCount),
        K::TlsCiphers => Family::Tls(tls::Kind::Ciphers),
        K::TlsCipher => Family::Tls(tls::Kind::Cipher),
        K::TlsCompression => Family::Tls(tls::Kind::Compression),
        K::TlsExtensions => Family::Tls(tls::Kind::Extensions),
        K::TlsExtension => Family::Tls(tls::Kind::Extension),
        K::TlsServerName => Family::Tls(tls::Kind::ServerName),
        K::TlsAlpn => Family::Tls(tls::Kind::Alpn),
        K::TlsVersions => Family::Tls(tls::Kind::Versions),
        K::TlsKeyShare => Family::Tls(tls::Kind::KeyShare),
        K::TlsSupportedVersion => Family::Tls(tls::Kind::SupportedVersion),
        K::TlsEncrypted => Family::Tls(tls::Kind::Encrypted),
        K::QuicForm => Family::Quic(quic::Kind::Form),
        K::QuicVersion => Family::Quic(quic::Kind::Version),
        K::QuicType => Family::Quic(quic::Kind::Type),
        K::QuicDstLen => Family::Quic(quic::Kind::DstLen),
        K::QuicDstId => Family::Quic(quic::Kind::DstId),
        K::QuicSrcLen => Family::Quic(quic::Kind::SrcLen),
        K::QuicSrcId => Family::Quic(quic::Kind::SrcId),
        K::DataSize => Family::Data(data::Kind::DataSize),
    }
}
