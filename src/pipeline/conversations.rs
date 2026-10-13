//! Bounded pipeline metadata for retained conversations.
//! Protocol evidence stays in `flow`; process snapshots stay in `processes`.
//! Read `Conversations::touch` for the eviction order shared with the tracker.
//! One conversation can span several changing socket-ownership snapshots.

use super::AppLabel;
use crate::flow::{Flow, FlowId};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

// Match the tracker's 50,000-flow cap and eviction order so app labels cannot
// outlive their conversations or be reassigned when a FlowId is reused.
const MAX_CONVERSATIONS: usize = 50_000;
// Millisecond packet bursts must not spend the lookup window before procfs publishes.
const APP_WINDOW: Duration = Duration::from_secs(3);
const APP_INTERVAL: Duration = Duration::from_millis(200);

/// Per-conversation owner, retry budget and logging completion state.
pub(super) struct Entry {
    /// None until a published ownership snapshot has matched this conversation.
    pub app: Option<AppLabel>,
    /// First packet time and latest lookup time, independent of packet count.
    first: Duration,
    last_try: Option<Duration>,
    /// Its close has been processed even if logging is disabled or failed.
    pub closed: bool,
    order: u64,
    last: Duration,
}

#[derive(Default)]
/// Metadata bounded to the same retained IDs and eviction order as Tracker.
pub(super) struct Conversations {
    entries: HashMap<FlowId, Entry>,
    ended: BTreeSet<(u64, FlowId)>,
    activity: BTreeSet<(Duration, u64, FlowId)>,
    order: u64,
}

impl Conversations {
    /// Remember observed activity; a new ID clears previous owner/retry state.
    pub fn touch(&mut self, flow: &Flow, new: bool) {
        if new {
            self.remove(flow.id);
        }
        if !self.entries.contains_key(&flow.id) {
            if self.entries.len() >= MAX_CONVERSATIONS {
                // The tracker evicts ended records first, then the least active.
                let victim = self
                    .ended
                    .first()
                    .map(|(_, id)| *id)
                    .or_else(|| self.activity.first().map(|(_, _, id)| *id));
                if let Some(id) = victim {
                    self.remove(id);
                }
            }
            self.order = self.order.saturating_add(1);
            self.entries.insert(
                flow.id,
                Entry {
                    app: None,
                    first: flow.first,
                    last_try: None,
                    closed: false,
                    order: self.order,
                    last: flow.last,
                },
            );
        }
        if let Some(entry) = self.entries.get_mut(&flow.id) {
            self.activity.remove(&(entry.last, entry.order, flow.id));
            entry.last = flow.last;
            self.activity.insert((entry.last, entry.order, flow.id));
        }
    }

    /// Borrow retained metadata, or None for an unknown or evicted ID.
    pub fn get(&self, id: FlowId) -> Option<&Entry> {
        self.entries.get(&id)
    }

    /// Retry for the first three seconds, at most once per 200 ms of packet time.
    /// None means found, out of the time window, too soon, or absent.
    pub fn app_try(&mut self, id: FlowId, now: Duration) -> Option<&mut Entry> {
        let entry = self.entries.get_mut(&id)?;
        if entry.app.is_some()
            || now.saturating_sub(entry.first) > APP_WINDOW
            || entry
                .last_try
                .is_some_and(|last| now.saturating_sub(last) < APP_INTERVAL)
        {
            return None;
        }
        entry.last_try = Some(now);
        Some(entry)
    }

    /// Mark an end once; return false when already closed or no longer retained.
    pub fn close(&mut self, id: FlowId) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        if entry.closed {
            return false;
        }
        entry.closed = true;
        self.ended.insert((entry.order, id));
        true
    }

    fn remove(&mut self, id: FlowId) {
        if let Some(entry) = self.entries.remove(&id) {
            self.ended.remove(&(entry.order, id));
            self.activity.remove(&(entry.last, entry.order, id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Reader;
    use crate::decode::{self, Detail};
    use crate::flow::Tracker;
    use std::path::Path;

    #[test]
    fn retries_use_packet_time_and_reused_ids_clear_owners() {
        let raw = Reader::open(Path::new("tests/fixtures/loopback-first20.pcap"))
            .unwrap()
            .nth(16)
            .unwrap()
            .unwrap();
        let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        let mut tracker = Tracker::new();
        let id = tracker.observe(&raw, &decoded).flow.unwrap();
        let flow = tracker.flow(id).unwrap();
        let mut entries = Conversations::default();
        entries.touch(flow, true);
        assert!(entries.app_try(id, raw.ts).is_some());
        for millis in [1, 2, 3, 4, 5, 199] {
            assert!(
                entries
                    .app_try(id, raw.ts + Duration::from_millis(millis))
                    .is_none()
            );
        }
        for millis in (200..=3000).step_by(200) {
            assert!(
                entries
                    .app_try(id, raw.ts + Duration::from_millis(millis))
                    .is_some()
            );
        }
        assert!(
            entries
                .app_try(id, raw.ts + Duration::from_millis(3200))
                .is_none()
        );
        entries.entries.get_mut(&id).unwrap().app = Some(AppLabel {
            pid: 42,
            name: "test-app".into(),
        });
        entries.touch(flow, true);
        assert!(entries.get(id).unwrap().app.is_none());
        assert!(entries.app_try(id, raw.ts).is_some());
        assert!(entries.close(id));
        assert!(!entries.close(id));
    }

    #[test]
    fn full_metadata_table_evicts_ended_then_least_active_without_growing() {
        let raw = Reader::open(Path::new("tests/fixtures/loopback-first20.pcap"))
            .unwrap()
            .nth(16)
            .unwrap()
            .unwrap();
        let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        let mut tracker = Tracker::new();
        let id = tracker.observe(&raw, &decoded).flow.unwrap();
        let mut flow = tracker.flow(id).unwrap().clone();
        let mut entries = Conversations::default();
        for id in 1..=MAX_CONVERSATIONS as u32 {
            flow.id = FlowId(id);
            flow.last = Duration::from_secs(u64::from(id));
            entries.touch(&flow, true);
        }
        assert!(entries.close(FlowId(7)));
        for id in [MAX_CONVERSATIONS as u32 + 1, MAX_CONVERSATIONS as u32 + 2] {
            flow.id = FlowId(id);
            flow.last = Duration::from_secs(u64::from(id));
            entries.touch(&flow, true);
            assert_eq!(entries.entries.len(), MAX_CONVERSATIONS);
            assert_eq!(entries.activity.len(), MAX_CONVERSATIONS);
        }
        assert!(entries.get(FlowId(7)).is_none());
        assert!(entries.get(FlowId(1)).is_none());
        assert!(entries.get(FlowId(2)).is_some());
        assert!(entries.ended.is_empty());
    }
}
