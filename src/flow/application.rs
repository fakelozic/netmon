//! Application timing from requests and their replies.
//! TLS byte assembly stays in `tls`; packet decoding stays in `decode`.
//! Read `Tracked::application` to see how response times are matched.
use super::packet::echo_request;
use super::*;
use crate::decode::{AppInfo, Decoded};
use crate::names::{NameSource, Names};
use crate::text;
use std::net::SocketAddr;

fn bounded_text(value: &str) -> String {
    let bytes = value.as_bytes();
    // Bound even caller-constructed Decoded values, not only decoder-limited names.
    text::sanitise(bytes.get(..bytes.len().min(1_024)).unwrap_or_default())
}

fn http_host_name(host: &str) -> String {
    if let Ok(address) = host.parse::<SocketAddr>() {
        return address.ip().to_string();
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && !name.contains(':')
        && port.parse::<u16>().is_ok()
    {
        return name.to_owned();
    }
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
}

fn application_rank(proto: Proto) -> u8 {
    match proto {
        Proto::Tls | Proto::Quic => 3,
        Proto::Http => 2,
        Proto::Dns | Proto::Mdns => 1,
        _ => 0,
    }
}

/// Learn all captured A/AAAA answer addresses with the matched asked name.
/// `asked` is None for an unmatched response; failed DNS responses teach no names.
pub(super) fn learn_dns(names: &mut Names, d: &Decoded, asked: Option<&str>) {
    if let Some(AppInfo::DnsResponse {
        name,
        answers,
        rcode: 0,
        ..
    }) = &d.summary.app
    {
        let source = if d.summary.proto == Proto::Mdns {
            NameSource::Mdns
        } else {
            NameSource::Dns
        };
        for answer in answers.iter().take(MAX_PENDING) {
            if matches!(answer.rr_type, 1 | 28)
                && let Ok(ip) = answer.value.parse::<IpAddr>()
            {
                // A CNAME points elsewhere, but the address answers the original
                // question (RFC 1035, 3.3.1). Keep the requested alias.
                let name = asked
                    .filter(|n| !n.is_empty())
                    .unwrap_or(if name.is_empty() { &answer.name } else { name });
                names.learn(ip, name, source);
            }
        }
    }
}

impl Tracked {
    /// Reorient retained evidence when an opening SYN identifies the actual starter.
    pub(super) fn reverse(&mut self) {
        self.flow.endpoints.swap(0, 1);
        self.flow.packets.swap(0, 1);
        self.flow.payload_bytes.swap(0, 1);
        self.flow.acked_bytes.swap(0, 1);
        self.sides.swap(0, 1);
        for step in &mut self.flow.story {
            step.direction = step.direction.opposite();
        }
        for query in &mut self.queries {
            query.direction = query.direction.opposite();
        }
        for ping in &mut self.pings {
            ping.direction = ping.direction.opposite();
        }
        if let Some((direction, _)) = &mut self.http_request {
            *direction = direction.opposite();
        }
        self.hello = None;
        self.hello_next = None;
    }

    /// Drop request/hello buffers once a conversation ends; retained public facts survive.
    pub(super) fn release(&mut self) {
        self.hello = None;
        self.queries.clear();
        self.pings.clear();
        self.http_request = None;
    }

    /// Remember a bounded sanitised conversation name; empty values teach nothing.
    pub(super) fn server_name(&mut self, name: &str, notes: &mut Vec<Note>) {
        if name.is_empty() {
            return;
        }
        let name = bounded_text(name);
        // Host and SNI identify this conversation's intended server. They do not
        // identify every service on this address (PLAN section 8: per connection).
        if self.flow.server_name.as_ref() != Some(&name) {
            self.flow.server_name = Some(name.clone());
            notes.push(Note::ServerName(name));
        }
    }

    /// Update request/reply timings using packet time; generic data preserves the app label.
    pub(super) fn application(
        &mut self,
        d: &Decoded,
        direction: Direction,
        time: Duration,
        names: &mut Names,
        notes: &mut Vec<Note>,
    ) {
        if application_rank(d.summary.proto) > 0
            && application_rank(d.summary.proto) >= application_rank(self.flow.proto)
        {
            // A later generic transport/data packet must not erase application knowledge.
            self.flow.proto = d.summary.proto;
        }
        // DNS transaction ids are meaningful within the matched conversation
        // (RFC 1035, 4.1.1); unrelated sockets must not share response clocks.
        match &d.summary.app {
            Some(AppInfo::DnsQuery { id, name, .. }) => {
                self.queries
                    .retain(|q| q.id != *id || q.direction != direction);
                if self.queries.len() >= MAX_PENDING {
                    self.queries.pop_front();
                }
                self.queries.push_back(Query {
                    id: *id,
                    direction,
                    time,
                    name: bounded_text(name),
                });
            }
            Some(AppInfo::DnsResponse { id, .. }) => {
                let query = self
                    .queries
                    .iter()
                    .position(|q| q.id == *id && q.direction != direction)
                    .and_then(|i| self.queries.remove(i));
                if let Some(query) = &query {
                    notes.push(Note::DnsAnswerTime(time.saturating_sub(query.time)));
                }
                learn_dns(names, d, query.as_ref().map(|q| q.name.as_str()));
            }
            Some(AppInfo::Icmp {
                sequence: Some(sequence),
                ..
            }) => {
                self.ping(*sequence, direction, time, echo_request(d), notes);
            }
            Some(AppInfo::HttpRequest { host, .. }) => {
                if !notes.contains(&Note::Retransmission) {
                    self.http_request = Some((direction, time));
                }
                if let Some(host) = host {
                    self.server_name(&http_host_name(host), notes);
                }
            }
            Some(AppInfo::HttpResponse { .. }) => {
                if let Some((request_direction, start)) = self.http_request
                    && direction != request_direction
                    && !notes.contains(&Note::Retransmission)
                {
                    notes.push(Note::HttpResponseTime(time.saturating_sub(start)));
                    self.http_request = None;
                }
            }
            Some(AppInfo::TlsServerHello { version, .. }) if *version != 0 => {
                self.flow.tls_version = Some(*version);
            }
            _ => {}
        }
    }
    fn ping(
        &mut self,
        sequence: u16,
        direction: Direction,
        time: Duration,
        request: bool,
        notes: &mut Vec<Note>,
    ) {
        if request {
            self.pings
                .retain(|p| p.sequence != sequence || p.direction != direction);
            if self.pings.len() >= MAX_PENDING {
                self.pings.pop_front();
            }
            self.pings.push_back(Ping {
                sequence,
                direction,
                time,
            });
        } else if let Some(i) = self
            .pings
            .iter()
            .position(|p| p.sequence == sequence && p.direction != direction)
            && let Some(ping) = self.pings.remove(i)
        {
            notes.push(Note::PingTime(time.saturating_sub(ping.time)));
        }
    }
}
