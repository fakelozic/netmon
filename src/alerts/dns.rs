//! Detects unusual DNS query shapes or bursts of missing names.
//! General DNS decoding belongs to `crate::decode::dns`; wording belongs to `crate::explain::alerts`.
//! Read `Engine::suspicious_dns` first.
//! DNS resolves names; NXDOMAIN tells a client that its requested name does not exist.

// RFC 1035, 4.1.2: the question whose wire labels we measure.
// +---------------------------+-------------+-------------+
// | Name: labels or pointers  | Type: 16    | Class: 16   |
// +---------------------------+-------------+-------------+

use super::{Alert, AlertKind, Config, Engine, Severity, in_window, ip_address};
use crate::capture::RawPacket;
use crate::decode::{AppInfo, Decoded, Proto};
use crate::explain::alerts::{self as wording, DnsShape};
use std::collections::VecDeque;

impl Engine {
    /// Checks complete wire question names or missing-name replies addressed to one client.
    /// Timestamp queues retain only the configured threshold needed to establish a burst.
    pub(super) fn suspicious_dns(&mut self, raw: &RawPacket, d: &Decoded, alerts: &mut Vec<Alert>) {
        match &d.summary.app {
            Some(AppInfo::DnsQuery { .. }) => {
                let Some(client) = ip_address(d.summary.src.as_ref()) else {
                    return;
                };
                if let Some(shape) = dns_shape(raw, d, &self.config) {
                    let text = wording::dns_name(client, &shape);
                    alerts.extend(self.emit(
                        raw,
                        AlertKind::SuspiciousDns,
                        Severity::Notice,
                        raw.number,
                        client,
                        text,
                    ));
                }
            }
            // RCODE 3 means name error; the response destination is the client
            // receiving that result (RFC 1035, 4.1.1).
            Some(AppInfo::DnsResponse { rcode: 3, .. }) => {
                let Some(client) = ip_address(d.summary.dst.as_ref()) else {
                    return;
                };
                if self.dns.get(&client).is_none() {
                    self.dns.insert(client, VecDeque::new());
                }
                let Some(replies) = self.dns.get_mut(&client) else {
                    return;
                };
                replies.retain(|reply| in_window(raw.ts, reply.ts, self.config.nxdomain_window));
                // Only the latest threshold replies are needed to establish the burst.
                // The configurable threshold bounds each client's timestamp queue.
                let threshold = self.config.nxdomain_count.max(1);
                if replies.len() >= threshold {
                    replies.pop_front();
                }
                replies.push_back(raw.into());
                if replies.len() >= threshold {
                    let first = replies.front().map_or(raw.number, |reply| reply.packet);
                    let text =
                        wording::dns_failures(client, replies.len(), self.config.nxdomain_window);
                    alerts.extend(self.emit(
                        raw,
                        AlertKind::SuspiciousDns,
                        Severity::Warning,
                        first,
                        client,
                        text,
                    ));
                }
            }
            _ => {}
        }
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Measure wire labels rather than the escaped display name: escaping a control byte
/// must not make a short label appear long or artificially increase its entropy.
fn dns_shape(raw: &RawPacket, d: &Decoded, config: &Config) -> Option<DnsShape> {
    let layer = d
        .layers
        .iter()
        .find(|l| matches!(l.proto, Proto::Dns | Proto::Mdns))?;
    let bytes = raw.data.get(layer.range.clone())?;
    // Match the decoder's question budget rather than trust an attacker-supplied count.
    let questions = u16_at(bytes, 4)?.min(256);
    // The DNS header is six 16-bit words before the questions (RFC 1035, 4.1.1).
    let mut offset = 12usize;
    for _ in 0..questions {
        let (shape, end) = name_shape(bytes, offset)?;
        u16_at(bytes, end.checked_add(2)?)?;
        let next = end.checked_add(4)?;
        if next <= offset {
            return None;
        }
        offset = next;
        if shape.longest_label > config.dns_label_len
            || shape.name_len > config.dns_name_len
            || shape.random_label_len > 0
        {
            return Some(shape);
        }
    }
    None
}

fn name_shape(bytes: &[u8], start: usize) -> Option<(DnsShape, usize)> {
    let mut shape = DnsShape {
        name_len: 0,
        longest_label: 0,
        random_label_len: 0,
        entropy: 0.0,
    };
    let mut offset = start;
    let mut end = None;
    let mut labels = 0usize;
    // Names have at most 255 wire bytes and 63 per label (RFC 1035, 2.3.4).
    // 128 steps cover the maximum 127 one-byte labels plus termination, with a hard pointer budget.
    for _ in 0..128 {
        let length = *bytes.get(offset)?;
        if length == 0 {
            return Some((shape, end.unwrap_or(offset.checked_add(1)?)));
        }
        if length & 0xc0 == 0xc0 {
            let pointer = usize::from(u16_at(bytes, offset)? & 0x3fff);
            // Compression references a prior occurrence (RFC 1035, 4.1.4).
            // Reject forward pointers; the step budget also stops cycles through earlier labels.
            if pointer >= offset {
                return None;
            }
            end.get_or_insert(offset.checked_add(2)?);
            offset = pointer;
            continue;
        }
        if length > 63 {
            return None;
        }
        let length = usize::from(length);
        offset = offset.checked_add(1)?;
        let next = offset.checked_add(length)?;
        let label = bytes.get(offset..next)?;
        if labels > 0 {
            shape.name_len = shape.name_len.checked_add(1)?;
        }
        shape.name_len = shape.name_len.checked_add(length)?;
        // With dots between labels, the name count is wire length minus the initial
        // label-length byte and terminating root byte: at most 253 (RFC 1035, 2.3.4).
        if shape.name_len > 253 {
            return None;
        }
        shape.longest_label = shape.longest_label.max(length);
        // Short labels can have varied characters by chance. The brief requires
        // both 24 characters and Shannon entropy >= 4 bits per character.
        if length >= 24 {
            let mut counts = [0u8; 256];
            for &byte in label {
                if let Some(count) = counts.get_mut(usize::from(byte)) {
                    *count = count.saturating_add(1);
                }
            }
            let entropy = counts
                .iter()
                .filter(|&&n| n != 0)
                .map(|&n| {
                    let probability = f64::from(n) / length as f64;
                    -probability * probability.log2()
                })
                .sum::<f64>();
            if entropy >= 4.0 && entropy > shape.entropy {
                shape.random_label_len = length;
                shape.entropy = entropy;
            }
        }
        labels = labels.saturating_add(1);
        offset = next;
    }
    None
}
