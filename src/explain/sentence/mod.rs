//! Chooses the one-line explanation from decoded packet facts.
//! Field definitions belong to `fields`; name tables belong to `tables`.
//! Start with `sentence`.

use crate::decode::{AppInfo, Decoded};

mod dhcp;
mod dns;
mod http;
mod icmp;
mod link;
mod quic;
mod tls;
mod transport;

/// Returns one sentence; truncated packets have a final cut-short marker.
pub fn sentence(d: &Decoded) -> String {
    let s = &d.summary;
    let mut result = match &s.app {
        Some(AppInfo::Arp {
            operation,
            sender_mac,
            sender_ip,
            target_ip,
            ..
        }) => link::arp(operation, sender_mac, sender_ip, target_ip),
        Some(AppInfo::Icmp {
            v6,
            kind,
            code,
            sequence,
            embedded,
            target,
            mac: hardware,
            ..
        }) => icmp::message(v6, kind, code, sequence, embedded, target, hardware),
        Some(AppInfo::DnsQuery { name, .. }) if name.is_empty() && d.truncated => {
            "DNS question is incomplete".into()
        }
        Some(AppInfo::DnsQuery { name, .. }) if name.is_empty() => {
            "DNS query has no decoded question".into()
        }
        Some(AppInfo::DnsQuery { name, qtype, .. }) => dns::query(d, name, qtype),
        Some(AppInfo::DnsResponse {
            name,
            qtype,
            rcode,
            answers,
            ..
        }) => dns::response(d, name, qtype, rcode, answers),
        Some(AppInfo::Dhcp {
            message_type,
            offered,
            requested,
            ..
        }) => dhcp::message(message_type, offered, requested),
        Some(AppInfo::HttpRequest {
            method,
            target,
            host,
        }) => http::request(method, target, host),
        Some(AppInfo::HttpResponse { status, reason }) => http::response(status, reason),
        Some(AppInfo::TlsClientHello(h)) => tls::client(h),
        Some(AppInfo::TlsServerHello { version: 0, .. }) if d.truncated => {
            "TLS Server Hello is incomplete".into()
        }
        Some(AppInfo::TlsServerHello { version, .. }) => tls::server(version),
        Some(AppInfo::TlsRecords {
            content_types,
            encrypted_bytes,
            handshake,
        }) => tls::records(d, content_types, encrypted_bytes, handshake),
        Some(AppInfo::Quic {
            long,
            version,
            packet_type,
            bytes,
        }) => quic::message(long, version, packet_type, bytes),
        None => transport::packet(d),
    };
    if d.truncated {
        result.push_str(" [cut short]");
    }
    result
}
