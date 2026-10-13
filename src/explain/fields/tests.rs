//! Checks field definitions even when no fixture exercises their protocol value.
//! Packet examples belong to `tests/field_text.rs`; family dispatch belongs to `super`.
//! Start with `every_key_has_a_brief_definition`.

use super::*;
use crate::{
    capture::LinkType,
    decode::{Detail, decode},
};

const KEYS: &[K] = &[
    K::EthDst,
    K::EthSrc,
    K::EtherType,
    K::VlanPriority,
    K::VlanDrop,
    K::VlanId,
    K::SllPacketType,
    K::SllHardware,
    K::SllAddrLen,
    K::SllAddr,
    K::SllProtocol,
    K::SllInterface,
    K::ArpHardware,
    K::ArpProtocol,
    K::ArpHardwareSize,
    K::ArpProtocolSize,
    K::ArpOperation,
    K::ArpSenderMac,
    K::ArpSenderIp,
    K::ArpTargetMac,
    K::ArpTargetIp,
    K::IpVersion,
    K::IpHeaderLen,
    K::IpDscp,
    K::IpEcn,
    K::IpTotalLen,
    K::IpId,
    K::IpFlags,
    K::IpDf,
    K::IpMf,
    K::IpFragmentOffset,
    K::IpTtl,
    K::IpProtocol,
    K::IpChecksum,
    K::IpSrc,
    K::IpDst,
    K::IpOptions,
    K::V6Version,
    K::V6TrafficClass,
    K::V6FlowLabel,
    K::V6PayloadLen,
    K::V6NextHeader,
    K::V6HopLimit,
    K::V6Src,
    K::V6Dst,
    K::V6Extension,
    K::V6ExtNext,
    K::V6ExtLen,
    K::V6ExtData,
    K::V6FragmentOffset,
    K::V6MoreFragments,
    K::V6FragmentId,
    K::IcmpType,
    K::IcmpCode,
    K::IcmpChecksum,
    K::IcmpId,
    K::IcmpSeq,
    K::IcmpEmbedded,
    K::IcmpTarget,
    K::IcmpLinkOption,
    K::IcmpOptionType,
    K::IcmpOptionLen,
    K::IcmpOptionData,
    K::TcpSrc,
    K::TcpDst,
    K::TcpSeq,
    K::TcpAck,
    K::TcpOffset,
    K::TcpFlags,
    K::TcpCwr,
    K::TcpEce,
    K::TcpUrg,
    K::TcpAckFlag,
    K::TcpPsh,
    K::TcpRst,
    K::TcpSyn,
    K::TcpFin,
    K::TcpWindow,
    K::TcpChecksum,
    K::TcpUrgent,
    K::TcpOptions,
    K::TcpMss,
    K::TcpScale,
    K::TcpSackPermitted,
    K::TcpSack,
    K::TcpSackLeft,
    K::TcpSackRight,
    K::TcpTimestamp,
    K::TcpTimestampValue,
    K::TcpTimestampEcho,
    K::TcpNop,
    K::TcpEnd,
    K::TcpUnknownOption,
    K::TcpPayload,
    K::UdpSrc,
    K::UdpDst,
    K::UdpLen,
    K::UdpChecksum,
    K::UdpPayload,
    K::DnsId,
    K::DnsFlags,
    K::DnsResponse,
    K::DnsOpcode,
    K::DnsAuthoritative,
    K::DnsTruncated,
    K::DnsRecursionDesired,
    K::DnsRecursionAvailable,
    K::DnsRcode,
    K::DnsQuestions,
    K::DnsAnswers,
    K::DnsAuthorities,
    K::DnsAdditionals,
    K::DnsQuestion,
    K::DnsName,
    K::DnsType,
    K::DnsClass,
    K::DnsUnicast,
    K::DnsRecord,
    K::DnsTtl,
    K::DnsData,
    K::DnsCacheFlush,
    K::DnsMxPreference,
    K::DnsMxExchange,
    K::DnsSoaPrimary,
    K::DnsSoaMailbox,
    K::DnsSoaSerial,
    K::DnsSoaRefresh,
    K::DnsSoaRetry,
    K::DnsSoaExpire,
    K::DnsSoaMinimum,
    K::DnsSrvPriority,
    K::DnsSrvWeight,
    K::DnsSrvPort,
    K::DnsSrvTarget,
    K::DnsOptSize,
    K::DnsOptRcode,
    K::DnsOptVersion,
    K::DnsOptFlags,
    K::DnsOptCode,
    K::DnsOptData,
    K::DhcpOp,
    K::DhcpHardware,
    K::DhcpHardwareLen,
    K::DhcpHops,
    K::DhcpId,
    K::DhcpSeconds,
    K::DhcpFlags,
    K::DhcpClientIp,
    K::DhcpYourIp,
    K::DhcpServerIp,
    K::DhcpRelayIp,
    K::DhcpMac,
    K::DhcpOptions,
    K::DhcpSubnet,
    K::DhcpRouters,
    K::DhcpDns,
    K::DhcpHostname,
    K::DhcpRequested,
    K::DhcpLease,
    K::DhcpMessage,
    K::DhcpServer,
    K::DhcpParameters,
    K::DhcpClientId,
    K::DhcpUnknown,
    K::HttpRequestLine,
    K::HttpMethod,
    K::HttpTarget,
    K::HttpVersion,
    K::HttpStatusLine,
    K::HttpStatus,
    K::HttpReason,
    K::HttpHeader,
    K::HttpBody,
    K::TlsRecord,
    K::TlsContentType,
    K::TlsRecordVersion,
    K::TlsRecordLen,
    K::TlsHandshake,
    K::TlsHandshakeType,
    K::TlsHandshakeLen,
    K::TlsHelloVersion,
    K::TlsRandom,
    K::TlsSession,
    K::TlsCipherCount,
    K::TlsCiphers,
    K::TlsCipher,
    K::TlsCompression,
    K::TlsExtensions,
    K::TlsExtension,
    K::TlsServerName,
    K::TlsAlpn,
    K::TlsVersions,
    K::TlsKeyShare,
    K::TlsSupportedVersion,
    K::TlsEncrypted,
    K::QuicForm,
    K::QuicVersion,
    K::QuicType,
    K::QuicDstLen,
    K::QuicDstId,
    K::QuicSrcLen,
    K::QuicSrcId,
    K::DataSize,
];

#[test]
fn every_key_has_a_brief_definition() {
    let packet = decode(LinkType::RawIp, &[], 0, Detail::Full);
    for &key in KEYS {
        let field = Field {
            key,
            value: "0".into(),
            num: Some(0),
            range: 0..0,
            children: Vec::new(),
        };
        let text = field_text(&field, &packet);
        assert!(!text.what.is_empty() && text.what.ends_with('.'), "{key:?}");
        assert!(text.what.chars().count() <= 260, "{key:?}: {}", text.what);
        assert!(text.what.split(". ").count() <= 2, "{key:?}: {}", text.what);
        for part in [text.what, &text.here, text.why] {
            for banned in [
                "application endpoint",
                "does not request its action",
                "remains.",
            ] {
                assert!(!part.to_lowercase().contains(banned), "{key:?}: {part}");
            }
        }
    }
}

#[test]
fn estimates_do_not_turn_clues_into_proof() {
    let hops = meanings::hop_meaning(64);
    assert!(hops.contains("probably"));
    assert!(meanings::hop_meaning(57).contains("If it started"));
    assert!(meanings::hop_meaning(1).contains("deliberately small"));
    assert!(meanings::port_meaning(443).contains("clue"));
    assert!(meanings::address_meaning("8.8.8.8").contains("does not prove reachability"));
    assert!(meanings::transport_checksum("0xfe31").contains("has not been checked"));
}

#[test]
fn opening_and_reset_packets_do_not_promise_scaled_receive_space() {
    let mut packet = decode(LinkType::RawIp, &[], 0, Detail::Full);
    let mut tcp = crate::decode::TcpInfo {
        seq: 0,
        ack: 0,
        flags: 2,
        window: 64,
        payload_len: 0,
        mss: None,
        window_scale: Some(10),
    };
    assert!(meanings::window_meaning(64, Some(&tcp)).contains("64 data bytes"));
    tcp.flags = 16;
    tcp.window_scale = None;
    assert!(meanings::window_meaning(64, Some(&tcp)).contains("cannot show the receive space"));
    assert!(meanings::window_meaning(0, Some(&tcp)).contains("zero space"));
    tcp.flags = 20;
    packet.summary.tcp = Some(tcp);
    let field = Field {
        key: K::TcpAck,
        value: "123".into(),
        num: Some(123),
        range: 0..4,
        children: Vec::new(),
    };
    assert!(
        field_text(&field, &packet)
            .here
            .contains("without promising that data was accepted")
    );
    assert!(meanings::window_meaning(0, packet.summary.tcp.as_ref()).contains("not an offer"));
}
