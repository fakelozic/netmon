//! Bounded in-order assembly of the starter's TLS Client Hello.
//! TLS field decoding stays in `decode::tls`; the learned name stays on `Flow`.
//! Read `Tracked::client_hello` before the record and SNI boundary checks.
use super::packet::tcp_payload;
use super::*;
use crate::capture::RawPacket;
use crate::decode::{self, Decoded, TcpInfo};

impl Tracked {
    /// Append only contiguous starter payload, ignoring already assembled bytes.
    /// Stop at a complete hello, a fully captured server name, or the 16 KiB cap.
    pub(super) fn client_hello(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        tcp: &TcpInfo,
        direction: Direction,
        notes: &mut Vec<Note>,
    ) {
        if direction != Direction::Forward || tcp.payload_len == 0 {
            return;
        }
        let Some(buffer) = &mut self.hello else {
            return;
        };
        let seq = tcp.seq.wrapping_add(u32::from(tcp.flags & SYN != 0));
        let next = self.hello_next.unwrap_or(seq);
        let distance = seq.wrapping_sub(next) as i32;
        if distance > 0 {
            return;
        } // Wait for the missing in-order bytes; no out-of-order storage.
        let payload = tcp_payload(raw, d, tcp);
        let skip = distance.unsigned_abs() as usize;
        let Some(payload) = payload.get(skip..) else {
            return;
        };
        let available = MAX_HELLO.saturating_sub(buffer.len());
        let part = payload
            .get(..payload.len().min(available))
            .unwrap_or_default();
        buffer.extend_from_slice(part);
        self.hello_next = Some(next.wrapping_add(part.len() as u32));
        if buffer.first().is_some_and(|b| *b != 22) || buffer.get(1).is_some_and(|b| *b != 3) {
            self.hello = None;
            return;
        }
        let handshake = hello_handshake(buffer);
        let parsed = decode::tls::parse_client_hello(&handshake);
        // The existing parser can return a cut-short SNI. Use it only when the
        // advertised SNI bytes are all present, even if later extensions are absent.
        let name = parsed.server_name.filter(|_| full_sni(&handshake));
        let stop = parsed.complete || name.is_some() || buffer.len() >= MAX_HELLO;
        if let Some(name) = name {
            self.flow.proto = Proto::Tls;
            self.server_name(&name, notes);
        }
        if stop {
            self.hello = None;
        }
    }
}

fn hello_handshake(buffer: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    for _ in 0..128 {
        let Some(header) = buffer.get(offset..offset.saturating_add(5)) else {
            break;
        };
        let (Some(&kind), Some(&major), Some(length)) =
            (header.first(), header.get(1), header.get(3..5))
        else {
            break;
        };
        if kind != 22 || major != 3 {
            break;
        }
        let Some(length) = length.try_into().ok().map(u16::from_be_bytes) else {
            break;
        };
        let start = offset.saturating_add(5);
        let end = start.saturating_add(usize::from(length)).min(buffer.len());
        if let Some(body) = buffer.get(start..end) {
            result.extend_from_slice(body);
        }
        offset = start.saturating_add(usize::from(length));
        if offset >= buffer.len() {
            break;
        }
    }
    result
}

fn be16(bytes: &[u8], offset: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    )))
}

// SNI carries explicit list/name lengths (RFC 6066, 3). A truncated name
// is not an alias, even when the existing parser returns its captured prefix.
fn full_sni(handshake: &[u8]) -> bool {
    let Some(&session_len) = handshake.get(38) else {
        return false;
    };
    let mut offset = 39usize.saturating_add(usize::from(session_len));
    let Some(ciphers) = be16(handshake, offset) else {
        return false;
    };
    offset = offset.saturating_add(2).saturating_add(ciphers);
    let Some(&compression) = handshake.get(offset) else {
        return false;
    };
    offset = offset
        .saturating_add(1)
        .saturating_add(usize::from(compression));
    let Some(extensions) = be16(handshake, offset) else {
        return false;
    };
    offset = offset.saturating_add(2);
    let end = offset.saturating_add(extensions);
    for _ in 0..256 {
        if offset >= end {
            break;
        }
        let (Some(kind), Some(length)) = (
            be16(handshake, offset),
            be16(handshake, offset.saturating_add(2)),
        ) else {
            break;
        };
        let start = offset.saturating_add(4);
        let stop = start.saturating_add(length);
        if stop > end {
            return false;
        }
        if kind == 0 {
            let Some(extension) = handshake.get(start..stop) else {
                return false;
            };
            let (Some(list), Some(name)) = (be16(extension, 0), be16(extension, 3)) else {
                return false;
            };
            return extension.get(2) == Some(&0)
                && list.saturating_add(2) <= extension.len()
                && name.saturating_add(5) <= list.saturating_add(2);
        }
        offset = stop;
    }
    false
}
