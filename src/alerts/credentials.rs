//! Detects packet-local cleartext credential patterns.
//! Packet decoding belongs to `crate::decode`; wording belongs to `crate::explain::alerts`.
//! Read `Engine::credentials` first.
//! Encryption hides payload contents; a port number alone does not establish encryption.
//! This packet-local rule does not reassemble TCP streams.

use super::{Alert, AlertKind, Connection, Engine, Severity};
use crate::capture::RawPacket;
use crate::decode::{self, AppInfo, Decoded, Detail, FieldKey, Proto, TcpInfo};
use crate::explain::alerts::{self as wording, CredentialProtocol};

/// Per-conversation Telnet suppression, including traffic after a one-sided close.
pub(super) struct Telnet {
    /// Packet beginning the retained conversation, or its first captured payload.
    pub(super) first: u64,
    /// Opening SYN sequence number; None means capture began after the handshake.
    pub(super) sequence: Option<u32>,
    /// True after the first data observation, even if subject suppression hides its alert.
    pub(super) alerted: bool,
    /// True after a FIN; a later opening SYN may begin another conversation on this tuple.
    pub(super) closing: bool,
}

impl Engine {
    /// Checks credentials using a full decode only for an eligible payload.
    /// Telnet fires once per conversation; packet text and login values never reach wording.
    pub(super) fn credentials(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        c: Connection,
        alerts: &mut Vec<Alert>,
    ) {
        let Some(tcp) = &d.summary.tcp else {
            return;
        };
        let telnet = c.source.1 == 23 || c.destination.1 == 23;
        if telnet {
            self.start_telnet(raw, c, tcp);
        }
        if let Some(protocol) = credential_protocol(raw, d, c) {
            let (server, port) = if protocol == CredentialProtocol::Telnet && c.source.1 == 23 {
                c.source
            } else {
                c.destination
            };
            let first = if protocol == CredentialProtocol::Telnet {
                self.telnet_first(raw, c)
            } else {
                Some(raw.number)
            };
            if let Some(first) = first {
                let text = wording::credentials(protocol, server, port);
                alerts.extend(self.emit(
                    raw,
                    AlertKind::CleartextCredentials,
                    Severity::Serious,
                    first,
                    server,
                    text,
                ));
            }
        }
        if telnet {
            self.close_telnet(c, tcp);
        }
    }

    fn start_telnet(&mut self, raw: &RawPacket, c: Connection, tcp: &TcpInfo) {
        // A retransmitted SYN is still the same opening attempt (RFC 9293, 3.5).
        // Do not discard once-per-conversation suppression when its sequence repeats.
        if tcp.flags & 0x12 != 0x02 {
            return;
        }
        let canonical = c.canonical();
        let same = self
            .telnet
            .get(&canonical)
            .is_some_and(|state| state.sequence == Some(tcp.seq) && !state.closing);
        if !same {
            self.telnet.insert(
                canonical,
                Telnet {
                    first: raw.number,
                    sequence: Some(tcp.seq),
                    alerted: false,
                    closing: false,
                },
            );
        }
    }

    fn telnet_first(&mut self, raw: &RawPacket, c: Connection) -> Option<u64> {
        let canonical = c.canonical();
        if self.telnet.get(&canonical).is_none() {
            self.telnet.insert(
                canonical,
                Telnet {
                    first: raw.number,
                    sequence: None,
                    alerted: false,
                    closing: false,
                },
            );
        }
        let state = self.telnet.get_mut(&canonical)?;
        if state.alerted {
            return None;
        }
        state.alerted = true;
        Some(state.first)
    }

    fn close_telnet(&mut self, c: Connection, tcp: &TcpInfo) {
        let canonical = c.canonical();
        if tcp.flags & 0x04 != 0 {
            self.telnet.remove(&canonical);
        } else if tcp.flags & 0x01 != 0
            && let Some(state) = self.telnet.get_mut(&canonical)
        {
            // FIN closes only one direction (RFC 9293, 3.6.1).
            // Preserve suppression for replies while permitting a later opening SYN.
            state.closing = true;
        }
    }
}

fn credential_protocol(raw: &RawPacket, d: &Decoded, c: Connection) -> Option<CredentialProtocol> {
    let http = matches!(d.summary.app, Some(AppInfo::HttpRequest { .. }));
    let ftp = c.destination.1 == 21;
    let telnet = c.source.1 == 23 || c.destination.1 == 23;
    if !d
        .summary
        .tcp
        .as_ref()
        .is_some_and(|tcp| tcp.payload_len > 0)
        || !(http || ftp || telnet)
    {
        return None;
    }
    let full = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Full);
    // TLS application records carry opaque protected data (RFC 8446, 5.2).
    // Port 443 alone is not encryption evidence; plaintext HTTP there still qualifies.
    if full.layers.iter().any(|layer| layer.proto == Proto::Tls) {
        return None;
    }
    let payload = full
        .layers
        .iter()
        .filter(|layer| layer.proto == Proto::Tcp)
        .flat_map(|layer| &layer.fields)
        .find(|field| field.key == FieldKey::TcpPayload)
        .and_then(|field| raw.data.get(field.range.clone()))
        .unwrap_or_default();
    // Check header names only. Authentication schemes or values can contain secrets
    // even when a decoder redacts most of the field (RFC 9110, 11.6.2 and 11.7.2).
    if http
        && full
            .layers
            .iter()
            .filter(|layer| layer.proto == Proto::Http)
            .flat_map(|layer| &layer.fields)
            .any(|field| {
                field.key == FieldKey::HttpHeader
                    && field.value.split_once(':').is_some_and(|(name, _)| {
                        name.trim().eq_ignore_ascii_case("Authorization")
                            || name.trim().eq_ignore_ascii_case("Proxy-Authorization")
                    })
            })
    {
        Some(CredentialProtocol::Http)
    } else if ftp && (payload.starts_with(b"USER ") || payload.starts_with(b"PASS ")) {
        // These are client-to-server login commands, not server replies (RFC 959, 4.1.1).
        Some(CredentialProtocol::Ftp)
    } else if telnet && !payload.is_empty() {
        Some(CredentialProtocol::Telnet)
    } else {
        None
    }
}
