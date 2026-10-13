//! Bounded ladder steps for a conversation.
//! User-facing sentences stay in `explain::flows`; TCP inference stays in `tcp`.
//! Read `Tracked::add_step` for data runs and the ACKs folded into them.
use super::packet::echo_request;
use super::*;
use crate::capture::RawPacket;
use crate::decode::{AppInfo, Decoded};
use crate::explain;
use crate::names::Names;

impl Tracked {
    /// Append or group a ladder event; byte counts include captured transport payload.
    /// ACKs fold into their confirmed data; after 400 steps only data accumulators grow.
    pub(super) fn add_step(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        direction: Direction,
        bytes: u64,
        obs: &Observation,
        names: &Names,
    ) {
        let icmp_error = matches!(
            d.summary.app,
            Some(AppInfo::Icmp {
                embedded: Some(_),
                ..
            })
        );
        // Failure/close evidence outranks an application label on the same packet.
        let mut kind = step_kind(d, obs, icmp_error);
        if self.flow.proto == Proto::Tls
            && matches!(kind, StepKind::Data | StepKind::TlsClientHello)
            && obs.notes.iter().any(|n| matches!(n, Note::ServerName(_)))
        {
            kind = StepKind::TlsClientHello;
        }
        if kind == StepKind::Data && bytes == 0 {
            self.fold_ack(raw.number, direction, obs);
            return;
        }
        if matches!(kind, StepKind::Data | StepKind::TlsClientHello)
            && let Some(last) = self.flow.story.last_mut()
            && last.kind == kind
            && last.direction == direction
        {
            absorb(last, raw.number, bytes);
            return;
        }
        let duration = obs.notes.iter().find_map(|n| match n {
            Note::HandshakeTime(t)
            | Note::DnsAnswerTime(t)
            | Note::PingTime(t)
            | Note::HttpResponseTime(t) => Some(*t),
            _ => None,
        });
        let description = matches!(
            kind,
            StepKind::HttpRequest
                | StepKind::HttpResponse
                | StepKind::DnsQuery
                | StepKind::DnsResponse
                | StepKind::PingRequest
                | StepKind::PingReply
                | StepKind::IcmpError
        )
        .then(|| explain::flows::sentence(d, obs, Some(&self.flow), names));
        let step = Step {
            kind,
            direction,
            first_packet: raw.number,
            last_packet: raw.number,
            time: raw.ts,
            packets: 1,
            payload_bytes: bytes,
            duration,
            text: description.map(|s| s.chars().take(1_024).collect()),
            encrypted: matches!(self.flow.proto, Proto::Tls | Proto::Quic)
                && kind == StepKind::Data,
        };
        self.store_step(step);
    }
    fn fold_ack(&mut self, number: u64, direction: Direction, obs: &Observation) {
        // An ACK belongs to the data exchange it confirms, not a new zero-byte run.
        let target = direction.opposite();
        if obs.notes.iter().any(|n| matches!(n, Note::AckedBytes(_)))
            && let Some(step) = self
                .flow
                .story
                .iter_mut()
                .rev()
                .take_while(|s| {
                    !matches!(
                        s.kind,
                        StepKind::Syn
                            | StepKind::SynAck
                            | StepKind::HandshakeAck
                            | StepKind::Fin
                            | StepKind::CloseAck
                    )
                })
                .find(|s| s.direction == target && s.payload_bytes > 0)
        {
            absorb(step, number, 0);
        }
    }

    fn store_step(&mut self, mut step: Step) {
        let direction = step.direction;
        if self.flow.story.len() < MAX_STEPS {
            self.flow.story.push(step);
        } else {
            self.flow.story_omitted = self.flow.story_omitted.saturating_add(1);
            if let Some(last) = self
                .flow
                .story
                .iter_mut()
                .rev()
                .find(|s| s.kind == StepKind::Data && s.direction == direction)
            {
                absorb(last, step.last_packet, step.payload_bytes);
            } else if let Some(last) = self
                .flow
                .story
                .iter_mut()
                .rev()
                .find(|s| s.direction == direction)
            {
                // A story made entirely of control events still needs an accumulator.
                last.kind = StepKind::Data;
                last.text = None;
                last.encrypted = step.encrypted;
                absorb(last, step.last_packet, step.payload_bytes);
            } else {
                // All earlier steps went the other way. Fold the old tail into
                // its own direction before reserving a slot for the new direction.
                step.kind = StepKind::Data;
                step.text = None;
                if let Some(old) = self.flow.story.pop() {
                    if let Some(previous) = self.flow.story.last_mut() {
                        previous.kind = StepKind::Data;
                        previous.text = None;
                        previous.last_packet = old.last_packet;
                        previous.packets = previous.packets.saturating_add(old.packets);
                        previous.payload_bytes =
                            previous.payload_bytes.saturating_add(old.payload_bytes);
                    }
                    self.flow.story.push(step);
                }
            }
        }
    }
}

fn absorb(step: &mut Step, number: u64, bytes: u64) {
    step.last_packet = number;
    step.packets = step.packets.saturating_add(1);
    step.payload_bytes = step.payload_bytes.saturating_add(bytes);
}

fn step_kind(d: &Decoded, obs: &Observation, icmp_error: bool) -> StepKind {
    if icmp_error {
        return StepKind::IcmpError;
    }
    // Preserve this priority: a final close ACK must not become a generic data ACK.
    for (note, kind) in [
        (Note::Refused, StepKind::Refused),
        (Note::Reset, StepKind::Reset),
        (Note::ClosedPolitely, StepKind::CloseAck),
        (Note::Retransmission, StepKind::Retransmission),
        (Note::KeepAlive, StepKind::KeepAlive),
        (Note::ZeroWindow, StepKind::ZeroWindow),
        (Note::Gap, StepKind::Gap),
        (Note::HandshakeStep(1), StepKind::Syn),
        (Note::HandshakeStep(2), StepKind::SynAck),
        (Note::HandshakeStep(3), StepKind::HandshakeAck),
    ] {
        if obs.notes.contains(&note) {
            return kind;
        }
    }
    if obs.notes.iter().any(|n| matches!(n, Note::DuplicateAck(_))) {
        return StepKind::DuplicateAck;
    }
    if d.summary.tcp.as_ref().is_some_and(|t| t.flags & FIN != 0) {
        return StepKind::Fin;
    }
    match &d.summary.app {
        Some(AppInfo::TlsClientHello(_)) => StepKind::TlsClientHello,
        Some(AppInfo::TlsServerHello { .. }) => StepKind::TlsServerHello,
        Some(AppInfo::TlsRecords {
            handshake: true, ..
        }) => StepKind::TlsHandshake,
        Some(AppInfo::HttpRequest { .. }) => StepKind::HttpRequest,
        Some(AppInfo::HttpResponse { .. }) => StepKind::HttpResponse,
        Some(AppInfo::DnsQuery { .. }) => StepKind::DnsQuery,
        Some(AppInfo::DnsResponse { .. }) => StepKind::DnsResponse,
        Some(AppInfo::Icmp { .. }) if echo_request(d) => StepKind::PingRequest,
        Some(AppInfo::Icmp { .. }) => StepKind::PingReply,
        _ => StepKind::Data,
    }
}
