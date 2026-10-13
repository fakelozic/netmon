//! Retains packet summaries within count and byte limits.
//! Decoding belongs to decode; grammar and row matching belong to filter.
//! Read Store::push first, then on_tick for sliced filter rebuilds.
//! Captured bytes are a snapshot of one packet, not a whole TCP byte stream.
use crate::{
    capture::RawPacket,
    decode::{self, AppInfo, Detail, Summary},
    explain,
    filter::{Filter, Row},
};
use std::{collections::VecDeque, time::Duration};
/// Default and maximum retained packet count; prevents metadata growth with traffic.
pub const DEFAULT_MAX_PACKETS: usize = 200_000;
/// Maximum retained raw packet bytes, 256 MiB; metadata is count-bounded separately.
pub const MAX_PACKET_BYTES: usize = 256 * 1024 * 1024;
/// Maximum historical rows evaluated per tick so a filter change stays responsive.
pub const REBUILD_SLICE: usize = 20_000;
/// One retained packet with its summary and sentence computed at arrival.
#[derive(Debug)]
pub struct Entry {
    /// Store-local stable entry id, independent of the capture packet number.
    pub id: u64,
    /// Captured packet bytes with time since the Unix epoch.
    pub raw: RawPacket,
    pub summary: Summary,
    pub sentence: String,
    /// True for truncation, TCP reset, ICMP error, or DNS error response.
    pub problem: bool,
}
impl Entry {
    /// Borrows the filter row; names and process ownership are unavailable here.
    fn row(&self) -> Row<'_> {
        Row {
            summary: &self.summary,
            sentence: &self.sentence,
            src_name: None,
            dst_name: None,
            app: None,
            problem: self.problem,
        }
    }
}
/// A bounded packet deque with an ordered filtered view.
/// Entry ids are monotonic within this value; evicted ids are never reused.
pub struct Store {
    entries: VecDeque<Entry>,
    matches: VecDeque<u64>,
    arriving: VecDeque<u64>,
    filter: Filter,
    filter_text: String,
    rebuild: Option<(u64, u64)>,
    next_id: u64,
    max_packets: usize,
    max_bytes: usize,
    bytes: usize,
    dropped: u64,
    total: u64,
    total_bytes: u64,
    first_ts: Option<Duration>,
    latest_ts: Option<Duration>,
}
impl Store {
    /// Creates a store capped at max_packets and 256 MiB of raw bytes.
    /// Zero discards every arrival; counts above 200,000 are clamped.
    pub fn new(max_packets: usize) -> Self {
        Self::with_limits(max_packets, MAX_PACKET_BYTES)
    }
    /// Creates a store with smaller test or application limits.
    /// Caps cannot exceed the production limits; zero drops all arrivals.
    pub fn with_limits(max_packets: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            matches: VecDeque::new(),
            arriving: VecDeque::new(),
            filter: Filter::default(),
            filter_text: String::new(),
            rebuild: None,
            next_id: 0,
            max_packets: max_packets.min(DEFAULT_MAX_PACKETS),
            max_bytes: max_bytes.min(MAX_PACKET_BYTES),
            bytes: 0,
            dropped: 0,
            total: 0,
            total_bytes: 0,
            first_ts: None,
            latest_ts: None,
        }
    }
    /// Summarizes one packet and drops oldest entries until both limits fit.
    /// An individually oversized packet is dropped without evicting existing packets.
    pub fn push(&mut self, raw: RawPacket) {
        self.total = self.total.saturating_add(1);
        // File totals describe every arrival, even when retention drops its bytes.
        self.total_bytes = self.total_bytes.saturating_add(u64::from(raw.orig_len));
        self.first_ts.get_or_insert(raw.ts);
        self.latest_ts = Some(self.latest_ts.map_or(raw.ts, |latest| latest.max(raw.ts)));
        if raw.data.len() > self.max_bytes || self.max_packets == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        // Never reuse a stable id, even if an extraordinarily long session
        // exhausts u64. Existing selections must keep identifying one packet.
        let Some(next_id) = self.next_id.checked_add(1) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };
        // Evict before allocating metadata for the incoming packet.
        while self.entries.len() >= self.max_packets
            || self.bytes.saturating_add(raw.data.len()) > self.max_bytes
        {
            self.evict();
        }
        let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        // RST aborts a TCP connection (RFC 9293, 3.1). Nonzero DNS reply codes
        // describe lookup errors (RFC 1035, 4.1.1); ICMP error types report failed
        // delivery (RFC 792; ICMPv6 uses types below 128, RFC 4443, 2.1).
        let problem = decoded.truncated
            || decoded
                .summary
                .tcp
                .as_ref()
                .is_some_and(|t| t.flags & 4 != 0)
            || matches!(
                decoded.summary.app,
                Some(AppInfo::DnsResponse {
                    rcode: 1..=u8::MAX,
                    ..
                })
            )
            || matches!(
                decoded.summary.app,
                Some(
                    AppInfo::Icmp {
                        v6: false,
                        kind: 3 | 4 | 5 | 11 | 12,
                        ..
                    } | AppInfo::Icmp {
                        v6: true,
                        kind: 0..=127,
                        ..
                    }
                )
            );
        let sentence = explain::sentence(&decoded);
        let id = self.next_id;
        self.next_id = next_id;
        let entry = Entry {
            id,
            raw,
            summary: decoded.summary,
            sentence,
            problem,
        };
        self.bytes = self.bytes.saturating_add(entry.raw.data.len());
        if self.filter.matches(&entry.row()) {
            if self.rebuild.is_some() || !self.arriving.is_empty() {
                self.arriving.push_back(id);
            } else {
                self.matches.push_back(id);
            }
        }
        self.entries.push_back(entry);
    }
    fn evict(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.bytes = self.bytes.saturating_sub(entry.raw.data.len());
            self.dropped = self.dropped.saturating_add(1);
            if self.matches.front() == Some(&entry.id) {
                self.matches.pop_front();
            }
            if self.arriving.front() == Some(&entry.id) {
                self.arriving.pop_front();
            }
        }
    }
    /// Starts a new filtered view, preserving stored packets.
    /// Call on_tick until rebuilding is false; arrivals are matched immediately.
    pub fn set_filter(&mut self, text: String, filter: Filter) {
        self.filter = filter;
        self.filter_text = text;
        self.matches.clear();
        self.arriving.clear();
        self.rebuild = Some((
            self.entries.front().map_or(self.next_id, |e| e.id),
            self.next_id,
        ));
    }
    /// Historical matches and new arrivals remain ordered without an O(n) merge.
    pub fn on_tick(&mut self) {
        let Some((mut cursor, end)) = self.rebuild else {
            return;
        };
        cursor = cursor.max(self.entries.front().map_or(end, |e| e.id));
        let stop = cursor.saturating_add(REBUILD_SLICE as u64).min(end);
        while cursor < stop {
            if self
                .get(cursor)
                .is_some_and(|e| self.filter.matches(&e.row()))
            {
                self.matches.push_back(cursor);
            }
            cursor = cursor.saturating_add(1);
        }
        self.rebuild = if cursor >= end {
            None
        } else {
            Some((cursor, end))
        };
        // Keep two segments after rebuilding. Future arrivals append to the latter.
        // A new filter clears both. No tick copies the entire matching list.
    }
    /// Borrows an entry by stable id, or None when absent or evicted.
    pub fn get(&self, id: u64) -> Option<&Entry> {
        let first = self.entries.front()?.id;
        self.entries
            .get(usize::try_from(id.checked_sub(first)?).ok()?)
            .filter(|e| e.id == id)
    }
    /// Maps a zero-based filtered row index to a stable id, or None out of range.
    pub fn visible_id(&self, index: usize) -> Option<u64> {
        self.matches
            .get(index)
            .or_else(|| self.arriving.get(index.saturating_sub(self.matches.len())))
            .copied()
    }
    /// Borrows a filtered row, or None out of range.
    pub fn visible(&self, index: usize) -> Option<&Entry> {
        self.get(self.visible_id(index)?)
    }
    /// Counts currently matched rows, including arrivals during rebuilding.
    pub fn visible_len(&self) -> usize {
        self.matches.len() + self.arriving.len()
    }
    /// Finds the filtered index of an id with binary search; None means hidden or evicted.
    pub fn visible_index(&self, id: u64) -> Option<usize> {
        fn search(q: &VecDeque<u64>, id: u64) -> Option<usize> {
            let mut lo = 0;
            let mut hi = q.len();
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let v = *q.get(mid)?;
                if v < id {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            (q.get(lo) == Some(&id)).then_some(lo)
        }
        search(&self.matches, id)
            .or_else(|| search(&self.arriving, id).map(|i| i + self.matches.len()))
    }
    /// Counts retained packets, including packets hidden by the filter.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Returns the effective retained-packet count cap.
    pub fn max_packets(&self) -> usize {
        self.max_packets
    }
    /// Returns true when no raw packets are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Counts retained raw packet bytes; excludes summary metadata.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Counts packets lost to store limits since this store was created.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
    /// Counts all arrivals, including oversized and evicted packets.
    pub fn total(&self) -> u64 {
        self.total
    }
    /// Counts original wire bytes in all arrivals, including dropped or evicted packets.
    /// Saturates at u64::MAX; this is independent of the retained raw-byte count.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    /// Returns the span from the first arrival to the latest packet timestamp.
    /// Empty captures and timestamps entirely before the first arrival give zero.
    /// Eviction and display filters do not change this packet-time duration.
    pub fn capture_duration(&self) -> Duration {
        self.latest_ts
            .unwrap_or_default()
            .saturating_sub(self.first_ts.unwrap_or_default())
    }
    /// Returns the first arrival time since the Unix epoch, even after it is evicted.
    /// None means no packet has arrived.
    pub fn first_ts(&self) -> Option<Duration> {
        self.first_ts
    }
    /// Returns the active filter label; empty means no display filter.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }
    /// Returns true while historical packets still await filter evaluation.
    pub fn rebuilding(&self) -> bool {
        self.rebuild.is_some()
    }
}
