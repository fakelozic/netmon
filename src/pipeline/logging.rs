//! Send observed pipeline facts to the buffered session writers.
//! Wording belongs to `explain::pipeline`; Markdown report assembly is in `summary`.
//! Read `Pipeline::log_packet` for the event ordering of a single packet.
//! Byte totals count captured transport payload, including retransmissions.

use super::Pipeline;
use crate::alerts::Alert;
use crate::capture::RawPacket;
use crate::decode::Decoded;
use crate::explain::pipeline as wording;
use crate::flow::{FlowId, Observation};
use crate::log::EventKind;
use std::time::Duration;

impl Pipeline {
    /// Write first-packet, DNS, alert, packet and recording output from decoded facts.
    pub(super) fn log_packet(
        &mut self,
        raw: &RawPacket,
        decoded: &Decoded,
        observation: &Observation,
        sentence: &str,
        raised: &[Alert],
    ) {
        if let Some(session) = self.session.as_mut() {
            let app = observation
                .flow
                .and_then(|id| self.conversations.get(id))
                .and_then(|e| e.app.as_ref());
            if observation.new_flow
                && let Some(flow) = observation.flow.and_then(|id| self.tracker.flow(id))
            {
                session.event(
                    raw.ts,
                    EventKind::Open,
                    &wording::heading(
                        flow,
                        app.map(|owner| owner.name.as_str()),
                        self.tracker.names(),
                    ),
                );
            }
            if let Some(row) = wording::dns_row(
                &decoded.summary,
                &observation.notes,
                self.tracker.names(),
                app.map(|owner| owner.name.as_str()),
            ) {
                session.event(raw.ts, EventKind::Dns, &wording::dns_event(&row));
            }
            for alert in raised {
                session.event(alert.ts, EventKind::Alert, &wording::alert_event(alert));
                session.alert_line(&wording::alert_json(alert));
            }
            session.packet(raw, decoded, sentence);
            session.record(raw);
        }
        if observation.ended
            && let Some(id) = observation.flow
        {
            self.log_close(id, raw.ts, false);
        }
    }

    /// Write an end exactly once and retain its compact summary; times are packet times.
    pub(super) fn log_close(&mut self, id: FlowId, now: Duration, capture_ended: bool) {
        if !self.conversations.close(id) {
            return;
        }
        if let Some(flow) = self.tracker.flow(id) {
            let app = self.conversations.get(id).and_then(|e| e.app.as_ref());
            self.summary
                .closed(flow, app, self.tracker.names(), capture_ended);
            if let Some(session) = self.session.as_mut() {
                session.event(
                    now,
                    EventKind::Close,
                    &wording::close(
                        flow,
                        app.map(|owner| owner.name.as_str()),
                        self.tracker.names(),
                        capture_ended,
                    ),
                );
                session.flow_line(&wording::flow_json(
                    flow,
                    app.map(|owner| owner.name.as_str()),
                    app.map(|owner| owner.pid),
                    self.tracker.names(),
                    capture_ended,
                ));
            }
        }
    }

    /// Collect and log newly idle conversations before observe can discard their IDs.
    pub(super) fn end_timeouts(&mut self, now: Duration) {
        for id in self.tracker.tick(now) {
            self.log_close(id, now, false);
        }
    }

    /// Flush at most once per second of nondecreasing packet time.
    pub(super) fn flush_due(&mut self, now: Duration) {
        if now.saturating_sub(self.last_flush) >= Duration::from_secs(1) {
            self.last_flush = now;
            if let Some(session) = self.session.as_mut() {
                session.flush();
            }
        }
    }
}
