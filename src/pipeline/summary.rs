//! Bounded session-report facts kept alongside packet observations.
//! Wording stays in `explain::pipeline`; atomic file replacement stays in `log`.
//! Read `State::observe` for counters and `Pipeline::write_summary` for assembly.
//! DNS lookups ask a server to translate a name into an address.

use super::{AppLabel, Pipeline};
use crate::capture::RawPacket;
use crate::decode::{AppInfo, Decoded};
use crate::explain::pipeline as wording;
use crate::flow::{Flow, Observation};
use crate::log::markdown;
use crate::names::Names;
use crate::text;
use std::collections::VecDeque;
use std::time::Duration;

// These report caps are fixed by the brief. Keep the largest finished flows,
// latest DNS answers/problems, independent of traffic.
const CONVERSATIONS: usize = 50;
const DNS: usize = 100;
const PROBLEMS: usize = 50;
const INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Conversation {
    number: u32,
    bytes: u64,
    cells: Vec<String>,
}

impl Conversation {
    fn new(flow: &Flow, app: Option<&AppLabel>, names: &Names, capture_ended: bool) -> Self {
        let local = wording::local_side(flow, names);
        Self {
            number: flow.id.0,
            bytes: flow.payload_bytes[0].saturating_add(flow.payload_bytes[1]),
            cells: vec![
                flow.id.0.to_string(),
                wording::app_name(app.map(|owner| owner.name.as_str())).into(),
                wording::remote_host(flow, names),
                wording::protocol(flow),
                wording::report_duration(flow.last.saturating_sub(flow.first)),
                text::number(flow.payload_bytes[local]),
                text::number(flow.payload_bytes[1 - local]),
                wording::end(flow, capture_ended),
            ],
        }
    }

    fn row(&self) -> String {
        let cells: Vec<_> = self
            .cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index == 4 {
                    markdown::explanation(cell)
                } else {
                    markdown::escape(cell)
                }
            })
            .collect();
        format!("| {} |\n", cells.join(" | "))
    }
}

/// Bounded report evidence and saturating lifetime counters using packet timestamps.
pub(super) struct State {
    started: Duration,
    last_report: Duration,
    packets: u64,
    bytes: u64,
    conversations: u64,
    closed: u64,
    dns_queries: u64,
    dns_answers: u64,
    problems_seen: u64,
    largest: Vec<Conversation>,
    dns: VecDeque<wording::DnsRow>,
    problems: VecDeque<(u64, String)>,
}

impl State {
    /// Start empty report evidence and the 60-second schedule at a packet timestamp.
    pub fn new(started: Duration) -> Self {
        Self {
            started,
            last_report: started,
            packets: 0,
            bytes: 0,
            conversations: 0,
            closed: 0,
            dns_queries: 0,
            dns_answers: 0,
            problems_seen: 0,
            largest: Vec::new(),
            dns: VecDeque::new(),
            problems: VecDeque::new(),
        }
    }

    /// Count a packet and retain latest DNS/problem evidence within the report caps.
    pub fn observe(
        &mut self,
        raw: &RawPacket,
        decoded: &Decoded,
        observation: &Observation,
        sentence: &str,
        problem: bool,
        dns: Option<wording::DnsRow>,
    ) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(u64::from(raw.orig_len));
        self.conversations = self
            .conversations
            .saturating_add(u64::from(observation.new_flow));
        if matches!(decoded.summary.app, Some(AppInfo::DnsQuery { .. })) {
            self.dns_queries = self.dns_queries.saturating_add(1);
        }
        if let Some(row) = dns {
            self.dns_answers = self.dns_answers.saturating_add(1);
            if self.dns.len() == DNS {
                self.dns.pop_front();
            }
            self.dns.push_back(row);
        }
        if problem {
            self.problems_seen = self.problems_seen.saturating_add(1);
            if self.problems.len() == PROBLEMS {
                self.problems.pop_front();
            }
            self.problems.push_back((raw.number, sentence.into()));
        }
    }

    /// Count a completed conversation and retain it if among the largest 50 by payload.
    pub fn closed(
        &mut self,
        flow: &Flow,
        app: Option<&AppLabel>,
        names: &Names,
        capture_ended: bool,
    ) {
        self.closed = self.closed.saturating_add(1);
        keep_largest(
            &mut self.largest,
            Conversation::new(flow, app, names, capture_ended),
        );
    }

    /// Advance the 60-second packet-time report schedule only when a report is due.
    pub fn due(&mut self, now: Duration) -> bool {
        if now.saturating_sub(self.last_report) < INTERVAL {
            return false;
        }
        self.last_report = now;
        true
    }

    fn facts(&self, now: Duration, finished: bool, alerts: u64) -> String {
        let mut output = String::from(wording::SUMMARY_TITLE);
        let values = [
            wording::timestamp(self.started),
            if finished {
                wording::timestamp(now)
            } else {
                wording::IN_PROGRESS.into()
            },
            wording::report_duration(now.saturating_sub(self.started)),
            text::number(self.packets),
            text::number(self.bytes),
            text::number(self.conversations),
            text::number(self.dns_queries),
            text::number(alerts),
        ];
        for (label, value) in wording::SUMMARY_FACT_LABELS.iter().zip(values) {
            output.push_str(&wording::fact(label, &value));
        }
        output.push('\n');
        output
    }
}

fn keep_largest(rows: &mut Vec<Conversation>, row: Conversation) {
    rows.push(row);
    // Sort only 51 compact rows, not entire retained Flow stories. ID breaks ties
    // deterministically so repeated fixture runs produce the same report.
    rows.sort_by_key(|r| (std::cmp::Reverse(r.bytes), r.number));
    rows.truncate(CONVERSATIONS);
}

impl Pipeline {
    /// Assemble bounded facts without reading logs and atomically replace the report.
    pub(super) fn write_summary(&mut self, finished: bool) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let mut output = self.summary.facts(self.now, finished, self.alert_count);
        output.push_str(wording::ALERTS_TITLE);
        if self.recent.is_empty() {
            output.push_str(wording::NONE);
        }
        if self.alert_count > self.recent.len() as u64 {
            output.push_str(&wording::recent_only(self.recent.len(), self.alert_count));
        }
        for alert in &self.recent {
            output.push_str(&wording::alert_markdown(alert));
        }
        output.push_str(wording::CONVERSATIONS_TITLE);
        let mut largest = self.summary.largest.clone();
        for flow in self
            .tracker
            .flows()
            .filter(|f| self.conversations.get(f.id).is_some_and(|e| !e.closed))
        {
            keep_largest(
                &mut largest,
                Conversation::new(flow, self.app_of(flow.id), self.tracker.names(), false),
            );
        }
        let shown_closed = largest
            .iter()
            .filter(|r| {
                self.summary
                    .largest
                    .iter()
                    .any(|closed| closed.number == r.number)
            })
            .count() as u64;
        for row in largest {
            output.push_str(&row.row());
        }
        output.push_str(&wording::more_conversations(
            self.summary.closed.saturating_sub(shown_closed),
        ));
        output.push_str(wording::DNS_TITLE);
        for row in &self.summary.dns {
            output.push_str(&wording::dns_markdown(row));
        }
        output.push('\n');
        if self.summary.dns_answers > self.summary.dns.len() as u64 {
            output.push_str(&wording::recent_only(
                self.summary.dns.len(),
                self.summary.dns_answers,
            ));
        }
        output.push_str(wording::PROBLEMS_TITLE);
        if self.summary.problems.is_empty() {
            output.push_str(wording::NONE);
        }
        for (packet, text) in &self.summary.problems {
            output.push_str(&wording::problem_markdown(*packet, text));
        }
        output.push('\n');
        if self.summary.problems_seen > self.summary.problems.len() as u64 {
            output.push_str(&wording::recent_only(
                self.summary.problems.len(),
                self.summary.problems_seen,
            ));
        }
        if let Some(problem) = self.problem() {
            output.push_str(&wording::fact(wording::LOGGING_LABEL, problem));
        }
        output.push_str(wording::FILES_TITLE);
        for file in files(session.dir()) {
            output.push_str(&wording::file_description(&file));
        }
        if let Some(session) = self.session.as_mut() {
            session.write_summary(&output);
        }
    }
}

fn files(dir: &std::path::Path) -> Vec<String> {
    // Read directory names only, never log contents. The report itself belongs
    // in the list even on its first write. Extra files are created by explicit
    // recording/export actions, not automatically as traffic accumulates.
    let mut files = vec!["summary.md".into()];
    if let Ok(entries) = std::fs::read_dir(dir) {
        // Explicit exports can accumulate too. A 4,096-entry inventory keeps a
        // crowded session folder from allocating an unlimited report or scan.
        for entry in entries.take(4096).flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                files.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    files.sort();
    files.dedup();
    files
}
