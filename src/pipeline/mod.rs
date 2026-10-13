//! Feed captured packets through the explanation pipeline.
//! Protocol parsing stays in `decode`; readable output stays in `explain::pipeline`.
//! Start with `Pipeline::new`, then call `push` once per packet in capture order.
//! A conversation joins both sending directions between two IP endpoints.

mod conversations;
mod logging;
mod processes;
mod summary;

use crate::alerts::{self, Alert};
use crate::capture::RawPacket;
use crate::decode::{self, AppInfo, Detail, Summary};
use crate::explain::{flows, pipeline as wording};
use crate::flow::{Direction, FlowId, Note, Tracker};
use crate::log::Session;
use conversations::Conversations;
use processes::Processes;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

// Keep the brief's newest 1,000 alerts; the lifetime counter remains separate.
const RECENT_ALERTS: usize = 1_000;

/// Policies for a packet pipeline. Saved captures normally disable process lookup.
pub struct Options {
    /// None writes no files or folders, even when `record` is true.
    pub log: Option<crate::log::Options>,
    /// Start raw recording immediately if a log session can be created.
    pub record: bool,
    /// Some("/proc") enables background app lookup; None performs no procfs reads.
    pub proc_root: Option<PathBuf>,
    /// Packet-time alert thresholds and repeat suppression.
    pub alerts: alerts::Config,
}

/// Remembered, sanitised socket owner; it describes a snapshot, not current ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppLabel {
    /// Linux process identifier observed in the ownership snapshot.
    pub pid: u32,
    /// Printable process name, with controls escaped by `text::sanitise`.
    pub name: String,
}

/// Everything one line of the packet list needs. Owned, so it can be stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Capture-global number from the raw packet, starting at one for capture readers.
    pub number: u64,
    /// Packet timestamp since the Unix epoch, or the capture's supplied time origin.
    pub ts: Duration,
    pub summary: Summary,
    /// Conversation-aware, secret-free description with a truncation marker when needed.
    pub sentence: String,
    /// None for untracked protocols or an unmatched quoted ICMP error.
    pub flow: Option<FlowId>,
    /// Relative to the conversation starter; None when no conversation matches.
    pub direction: Option<Direction>,
    /// Passive name or numeric source address, including a captured transport port.
    pub src_label: String,
    /// Passive name or numeric destination address, including a captured transport port.
    pub dst_label: String,
    /// Remembered process name; None when disabled, unseen or not applicable.
    pub app: Option<String>,
    /// Observed reset, refusal, ICMP/DNS error, retransmission, zero window,
    /// truncation, or at least one newly raised alert.
    pub problem: bool,
    /// Alerts raised by this packet, saturating at 255.
    pub alerts: u8,
}

/// Owns bounded conversation/app/alert state and an optional buffered log session.
/// No active network lookups occur. After construction, procfs reads run in workers.
pub struct Pipeline {
    tracker: Tracker,
    engine: alerts::Engine,
    conversations: Conversations,
    processes: Option<Processes>,
    addresses: Option<std::sync::Arc<processes::Addresses>>,
    recent: VecDeque<Alert>,
    alert_count: u64,
    session: Option<Session>,
    creation_problem: Option<String>,
    last_flush: Duration,
    now: Duration,
    finished: bool,
    summary: summary::State,
}

impl Pipeline {
    /// Create state at `started`, a packet timestamp. Session failures are kept
    /// in `problem` and leave decoding usable. Startup may read addresses/create files.
    /// Ownership starts with the Refresher's empty snapshot until its worker publishes.
    pub fn new(options: Options, started: Duration) -> Pipeline {
        let processes = options.proc_root.map(|root| Processes::new(root, started));
        let (session, creation_problem) = match options.log {
            Some(mut options) => {
                // All pipeline log times use UTC until a later local-time task.
                options.clock = crate::log::utc_clock;
                options.utc = true;
                match Session::create(options, started) {
                    Ok(session) => (Some(session), None),
                    Err(error) => (None, Some(wording::session_problem(&error))),
                }
            }
            None => (None, None),
        };
        let mut pipeline = Self {
            tracker: Tracker::new(),
            engine: alerts::Engine::new(options.alerts),
            conversations: Conversations::default(),
            processes,
            addresses: None,
            recent: VecDeque::new(),
            alert_count: 0,
            session,
            creation_problem,
            last_flush: started,
            now: started,
            finished: false,
            summary: summary::State::new(started),
        };
        if options.record
            && let Some(session) = pipeline.session.as_mut()
        {
            session.start_recording();
        }
        pipeline.refresh_addresses(started);
        pipeline
    }

    /// Decode/observe exactly once in capture order and return an owned row.
    /// Uses only published procfs snapshots and Session's buffered output API.
    /// Call only before `finish`; create another Pipeline for another capture.
    pub fn push(&mut self, raw: &RawPacket) -> Row {
        self.now = self.now.max(raw.ts);
        let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        self.refresh_addresses(self.now);
        // observe also ticks but discards timeout IDs. Collect them first or their
        // CLOSE records would be lost when a later packet advances capture time.
        self.end_timeouts(raw.ts);
        let observation = self.tracker.observe(raw, &decoded);
        if let Some(flow) = observation.flow.and_then(|id| self.tracker.flow(id)) {
            self.conversations.touch(flow, observation.new_flow);
        }
        let flow = observation.flow.and_then(|id| self.tracker.flow(id));
        let sentence = flows::sentence(&decoded, &observation, flow, self.tracker.names());
        let src_label = wording::label(
            decoded.summary.src.as_ref(),
            decoded.summary.src_port,
            self.tracker.names(),
        );
        let dst_label = wording::label(
            decoded.summary.dst.as_ref(),
            decoded.summary.dst_port,
            self.tracker.names(),
        );
        self.look_up_app(observation.flow);
        let raised = self.engine.observe(raw, &decoded);
        let count = raised.len().min(usize::from(u8::MAX)) as u8;
        let problem = is_problem(&decoded, &observation.notes) || count > 0;
        let app = observation
            .flow
            .and_then(|id| self.conversations.get(id))
            .and_then(|entry| entry.app.as_ref());
        let dns = wording::dns_row(
            &decoded.summary,
            &observation.notes,
            self.tracker.names(),
            app.map(|owner| owner.name.as_str()),
        );
        self.summary
            .observe(raw, &decoded, &observation, &sentence, problem, dns);
        self.log_packet(raw, &decoded, &observation, &sentence, &raised);
        for alert in raised {
            self.alert_count = self.alert_count.saturating_add(1);
            if self.recent.len() == RECENT_ALERTS {
                self.recent.pop_front();
            }
            self.recent.push_back(alert);
        }
        Row {
            number: raw.number,
            ts: raw.ts,
            app: observation
                .flow
                .and_then(|id| self.app_of(id))
                .map(|a| a.name.clone()),
            summary: decoded.summary,
            sentence,
            flow: observation.flow,
            direction: observation.direction,
            src_label,
            dst_label,
            problem,
            alerts: count,
        }
    }

    /// Advance inactivity/flush schedules with latest packet time, about once a second.
    /// Backwards times do not rewind schedules; timeout closes are logged exactly once.
    pub fn tick(&mut self, now: Duration) {
        if self.finished {
            return;
        }
        self.now = self.now.max(now);
        self.refresh_addresses(self.now);
        self.end_timeouts(self.now);
        if self.summary.due(self.now) {
            self.write_summary(false);
        }
        self.flush_due(self.now);
    }

    /// End all retained open conversations with the capture-end reason and flush.
    /// Idempotent. The tracker lacks finish(), so its ended
    /// records use Idle while logs distinguish capture end from inactivity.
    pub fn finish(&mut self) {
        if !self.finished {
            // MAX reaches every saturated inactivity deadline without inventing
            // a packet timestamp or changing the retained last-packet times.
            for id in self.tracker.tick(Duration::MAX) {
                self.log_close(id, self.now, true);
            }
            self.finished = true;
        }
        self.write_summary(true);
        if let Some(session) = self.session.as_mut() {
            session.flush();
        }
    }

    /// Retained conversations, oldest first, including closed ones until tracker eviction.
    pub fn tracker(&self) -> &Tracker {
        &self.tracker
    }
    /// Newest 1,000 alerts in observation order, newest last; empty before any alert.
    pub fn recent_alerts(&self) -> impl Iterator<Item = &Alert> {
        self.recent.iter()
    }
    /// Lifetime count, including alerts dropped from the ring; saturates at u64::MAX.
    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }
    /// Remembered owner; None for a miss, disabled lookup, or an evicted conversation.
    pub fn app_of(&self, flow: FlowId) -> Option<&AppLabel> {
        self.conversations.get(flow)?.app.as_ref()
    }
    /// None when logging is disabled or session creation failed.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }
    /// Borrow the session for recording toggles/exports; None as for `session`.
    pub fn session_mut(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }
    /// First sanitised logging problem, including session creation; None when none is known.
    pub fn problem(&self) -> Option<&str> {
        self.creation_problem
            .as_deref()
            .or_else(|| self.session.as_ref().and_then(Session::problem))
    }

    fn refresh_addresses(&mut self, now: Duration) {
        let Some(processes) = self.processes.as_mut() else {
            return;
        };
        let next = processes.refresh(now);
        if self
            .addresses
            .as_ref()
            .is_some_and(|old| std::sync::Arc::ptr_eq(old, &next))
        {
            return;
        }
        self.tracker.names_mut().set_local(&next.local);
        self.tracker.names_mut().set_gateway(next.gateway);
        self.engine.set_local(&next.local);
        self.engine.set_gateway(next.gateway);
        self.addresses = Some(next);
    }

    fn look_up_app(&mut self, id: Option<FlowId>) {
        let Some((id, processes)) = id.zip(self.processes.as_ref()) else {
            return;
        };
        let Some(flow) = self
            .tracker
            .flow(id)
            .filter(|f| matches!(f.ip_proto, 6 | 17))
        else {
            return;
        };
        let Some(entry) = self.conversations.app_try(id, self.now) else {
            return;
        };
        let [source, destination] = flow.endpoints;
        let Some((source_port, destination_port)) = source.port.zip(destination.port) else {
            return;
        };
        let table = processes.latest();
        if let Some((owner, _)) = table.lookup_packet(
            flow.ip_proto,
            std::net::SocketAddr::new(source.addr, source_port),
            std::net::SocketAddr::new(destination.addr, destination_port),
        ) {
            entry.app = Some(AppLabel {
                pid: owner.pid,
                name: owner.name.clone(),
            });
        } else {
            processes.request_now();
        }
    }
}

fn is_problem(decoded: &decode::Decoded, notes: &[Note]) -> bool {
    decoded.truncated
        || notes.iter().any(|note| {
            matches!(
                note,
                Note::Reset | Note::Refused | Note::Retransmission | Note::ZeroWindow
            )
        })
        || decoded
            .summary
            .tcp
            .as_ref()
            .is_some_and(|tcp| tcp.flags & 4 != 0)
        || matches!(
            &decoded.summary.app,
            Some(AppInfo::DnsResponse { rcode: 1.., .. })
                | Some(AppInfo::Icmp {
                    v6: false,
                    kind: 3 | 4 | 5 | 11 | 12,
                    ..
                })
                | Some(AppInfo::Icmp {
                    v6: true,
                    kind: 1..=4,
                    ..
                })
        )
}
