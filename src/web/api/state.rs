//! Holds packet-time counters and the browser's published view.
//! Capture scheduling belongs to `engine`; endpoint projections belong to `records`.
//! Read `State::message` before `reply` to see capture-end and pause semantics.
//! Pause affects publication, while conversations and logs still observe every packet.

use super::{
    Options,
    engine::{Job, failure},
    packets::Cache,
    records,
    store::Store,
};
use crate::{
    explain::{self, web as words},
    flow::{Flow, FlowId},
    live::Message,
    log::{Json, JsonValue as V, Recording},
    pipeline::{AppLabel, Pipeline},
    web::{ApiReply, Method},
};
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

/// Frozen conversation evidence when the browser is paused.
pub(super) struct Snapshot {
    pub cutoff: u64,
    /// Published packet count, independent of arbitrary capture numbers.
    pub total: u64,
    pub session: String,
    /// Original serialized recording state, for replacing only this session field.
    recording: &'static str,
    problem: Option<String>,
    pub flows: Vec<Flow>,
    pub apps: HashMap<FlowId, AppLabel>,
    pub alerts: String,
    pub remote_names: HashMap<FlowId, Option<String>>,
    pub local_sides: HashMap<FlowId, usize>,
}
/// Engine-owned bounded capture state; only its owning thread may read it.
pub(super) struct State {
    pub pipeline: Pipeline,
    pub store: Store,
    /// First packet timestamp since the Unix epoch; None before arrival.
    pub first: Option<Duration>,
    /// Largest observed packet timestamp used for pipeline scheduling.
    pub now: Duration,
    /// Number of processed packets, including packets evicted from raw storage.
    pub total: u64,
    /// Lifetime original wire bytes, saturating at u64::MAX.
    pub bytes: u64,
    /// Largest processed capture-global packet number.
    pub last_number: u64,
    /// Frozen publication state; None publishes current evidence.
    pub paused: Option<Snapshot>,
    pub caches: VecDeque<Cache>,
    /// Changes when late process attribution invalidates cached app filters.
    pub app_revision: u64,
    // Match the tracker cap. A late owner is recorded once, so stale inactive
    // filter caches cannot repeatedly invalidate the actively polled cache.
    known_apps: HashMap<FlowId, String>,
    mode: &'static str,
    source: String,
    started: Duration,
    state: &'static str,
    error: Option<String>,
    rates: VecDeque<(u64, u64)>,
}
impl State {
    /// Creates empty state with pipeline time initialized at the source start.
    pub fn new(options: Options) -> Self {
        Self {
            pipeline: Pipeline::new(options.pipeline, options.started),
            store: Store::new(options.max_packets),
            first: None,
            now: options.started,
            total: 0,
            bytes: 0,
            last_number: 0,
            paused: None,
            caches: VecDeque::new(),
            app_revision: 0,
            known_apps: HashMap::new(),
            mode: if options.live { "live" } else { "file" },
            source: crate::text::sanitise(options.source.as_bytes()),
            started: options.started,
            state: "running",
            error: None,
            rates: VecDeque::new(),
        }
    }
    /// Reports whether the capture channel still needs draining.
    pub fn running(&self) -> bool {
        self.state == "running"
    }
    /// Highest packet number published to the page; freezes during pause.
    pub fn cutoff(&self) -> u64 {
        self.paused.as_ref().map_or(self.last_number, |p| p.cutoff)
    }
    /// Processes one ordered capture event; failure and EOF finish logs once.
    pub fn message(&mut self, message: Message) {
        match message {
            Message::Packet(raw) => {
                // Source readers number in capture order. Reject duplicates so binary
                // search and stable browser cursors always identify one packet.
                if raw.number <= self.last_number {
                    return;
                }
                let first = *self.first.get_or_insert(raw.ts);
                self.now = self.now.max(raw.ts);
                self.total = self.total.saturating_add(1);
                self.bytes = self.bytes.saturating_add(u64::from(raw.orig_len));
                self.last_number = raw.number;
                self.rate(
                    self.now.saturating_sub(first).as_secs(),
                    u64::from(raw.orig_len),
                );
                let row = self.pipeline.push(&raw);
                self.note_owner(&row);
                self.store.push(raw, row);
            }
            Message::Ended => {
                self.state = "ended";
                self.pipeline.finish();
            }
            Message::Failed(error) => {
                self.state = "failed";
                self.error = Some(crate::text::sanitise(error.as_bytes()));
                self.pipeline.finish();
            }
        }
    }
    fn note_owner(&mut self, row: &crate::pipeline::Row) {
        let Some((id, owner)) = row
            .flow
            .zip(row.flow.and_then(|id| self.pipeline.app_of(id)))
        else {
            return;
        };
        if self
            .known_apps
            .get(&id)
            .is_some_and(|old| old == &owner.name)
        {
            return;
        }
        if self.paused.is_none() && self.caches.iter().any(|c| c.owner_changed(id, Some(owner))) {
            self.app_revision = self.app_revision.saturating_add(1);
        }
        if self.known_apps.len() >= 50_000 {
            self.known_apps
                .retain(|id, _| self.pipeline.tracker().flow(*id).is_some());
        }
        self.known_apps.insert(id, owner.name.clone());
    }
    fn rate(&mut self, second: u64, bytes: u64) {
        let start = self
            .rates
            .back()
            .map_or(second, |(s, _)| s.saturating_add(1));
        // Large timestamp gaps retain at most 60 zero buckets, never one per elapsed second.
        for sec in start.max(second.saturating_sub(59))..=second {
            if self.rates.len() == 60 {
                self.rates.pop_front();
            }
            self.rates.push_back((sec, 0));
        }
        if let Some((_, count)) = self.rates.back_mut() {
            *count = count.saturating_add(bytes);
        }
    }
    /// Advances pipeline scheduling only with the latest captured timestamp.
    pub fn tick(&mut self) {
        if self.running() {
            self.pipeline.tick(self.now);
        }
    }
    /// Gets a conversation owner at reply time, or the frozen owner during pause.
    pub fn app(&self, id: FlowId) -> Option<&AppLabel> {
        self.paused
            .as_ref()
            .map_or_else(|| self.pipeline.app_of(id), |p| p.apps.get(&id))
    }
    /// Encodes the current published session, including all contract keys.
    pub fn session(&self) -> String {
        if let Some(paused) = &self.paused {
            // Publication pause freezes packet evidence, not output failures. A
            // recording can fill or fail while hidden arrivals still get processed.
            return paused
                .session
                .replace(
                    &format!("\"recording\":\"{}\"", paused.recording),
                    &format!("\"recording\":\"{}\"", self.recording()),
                )
                .replace(
                    &problem_field(paused.problem.as_deref()),
                    &problem_field(self.pipeline.problem()),
                );
        }
        self.session_json(self.state)
    }
    fn session_json(&self, state: &str) -> String {
        let log = self.pipeline.session();
        let recording = log.map_or(Recording::Off, |s| s.recording());
        Json::object()
            .str("version", env!("CARGO_PKG_VERSION"))
            .str("mode", self.mode)
            .str("source", &self.source)
            .str("state", state)
            .value("error", records::opt(self.error.as_deref()))
            .str("started", &explain::pipeline::timestamp(self.started))
            .num("packets", self.total)
            .num("dropped", self.store.dropped)
            .num("bytes", self.bytes)
            .num(
                "conversations",
                self.pipeline.tracker().flows().count() as u64,
            )
            .num("alerts", self.pipeline.alert_count())
            .value(
                "rate",
                V::array(self.rates.iter().map(|(_, n)| V::number(*n))),
            )
            .value(
                "log_dir",
                records::opt(
                    log.map(|s| crate::text::sanitise(s.dir().to_string_lossy().as_bytes()))
                        .as_deref(),
                ),
            )
            .str("recording", records::recording(recording))
            .value("problem", records::opt(self.pipeline.problem()))
            .finish()
    }
    /// Routes a bounded engine request; None means sliced matching must continue.
    pub fn reply(&mut self, job: &Job) -> Option<ApiReply> {
        let method = if job.path == "control" {
            Method::Post
        } else {
            Method::Get
        };
        if !matches!(
            job.path.as_str(),
            "session" | "packets" | "flows" | "alerts" | "glossary" | "control"
        ) && !job.path.starts_with("packet/")
            && !job.path.starts_with("flow/")
        {
            return Some(failure(404, words::error(404)));
        }
        if job.method != method {
            return Some(failure(400, words::error(400)));
        }
        let result = match job.path.as_str() {
            "session" if job.query.is_empty() => Ok(self.session()),
            "packets" => return self.packets(&job.query),
            "flows" => self.flows(&job.query),
            "alerts" if job.query.is_empty() => Ok(self
                .paused
                .as_ref()
                .map_or_else(|| records::alerts(self), |p| p.alerts.clone())),
            "glossary" if job.query.is_empty() => Ok(records::glossary()),
            "control" if job.query.is_empty() => self.control(&job.body),
            path if path.starts_with("packet/") && job.query.is_empty() => {
                records::id(path, "packet/").and_then(|id| self.packet(id))
            }
            path if path.starts_with("flow/") && job.query.is_empty() => {
                records::id(path, "flow/").and_then(|id| self.flow(id))
            }
            _ => Err((400, words::error(400))),
        };
        Some(match result {
            Ok(json) => ApiReply { status: 200, json },
            Err((status, message)) => failure(status, message),
        })
    }
    /// Freezes published counters and bounded conversation evidence.
    pub fn pause(&mut self) {
        if self.paused.is_some() {
            return;
        }
        let flows: Vec<_> = self.pipeline.tracker().flows().cloned().collect();
        let names = self.pipeline.tracker().names();
        let apps = flows
            .iter()
            .filter_map(|f| self.pipeline.app_of(f.id).map(|a| (f.id, a.clone())))
            .collect();
        let remote_names = flows
            .iter()
            .map(|f| (f.id, super::flows::remote_name(f, names)))
            .collect();
        let local_sides = flows
            .iter()
            .map(|f| (f.id, explain::pipeline::local_side(f, names)))
            .collect();
        self.paused = Some(Snapshot {
            cutoff: self.last_number,
            total: self.total,
            session: self.session_json("paused"),
            recording: self.recording(),
            problem: self.pipeline.problem().map(str::to_owned),
            flows,
            apps,
            alerts: records::alerts(self),
            remote_names,
            local_sides,
        });
        self.caches.clear();
    }
    /// Publishes arrivals again and discards indexes built against the pause watermark.
    pub fn resume(&mut self) {
        self.paused = None;
        self.caches.clear();
    }
    fn recording(&self) -> &'static str {
        records::recording(
            self.pipeline
                .session()
                .map_or(Recording::Off, |s| s.recording()),
        )
    }
}

fn problem_field(problem: Option<&str>) -> String {
    Json::object()
        .value("problem", records::opt(problem))
        .finish()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_owned()
}
