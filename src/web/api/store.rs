//! Retains pipeline rows beside their raw packet bytes.
//! Pipeline computation stays in `pipeline`; matching indexes stay in `packets`.
//! Read `Store::push` for oldest-first count and byte eviction.
//! A wire length can exceed captured bytes when capture cuts a packet short.

use crate::{
    capture::RawPacket,
    pipeline::Row,
    store::{DEFAULT_MAX_PACKETS, MAX_PACKET_BYTES},
};
use std::collections::VecDeque;

/// A pipeline result and its captured bytes, evicted together.
pub(super) struct Entry {
    pub raw: RawPacket,
    pub row: Row,
}
/// Oldest-first retention under the production packet and raw-byte limits.
pub(super) struct Store {
    pub entries: VecDeque<Entry>,
    max_packets: usize,
    bytes: usize,
    pub dropped: u64,
}
impl Store {
    /// Creates empty retention; zero discards all arrivals.
    pub fn new(max_packets: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_packets: max_packets.min(DEFAULT_MAX_PACKETS),
            bytes: 0,
            dropped: 0,
        }
    }
    /// Stores one ordered packet and evicts oldest entries until both caps fit.
    pub fn push(&mut self, raw: RawPacket, row: Row) {
        if self.max_packets == 0 || raw.data.len() > MAX_PACKET_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        while self.entries.len() >= self.max_packets
            || self.bytes.saturating_add(raw.data.len()) > MAX_PACKET_BYTES
        {
            if let Some(old) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.raw.data.len());
                self.dropped = self.dropped.saturating_add(1);
            }
        }
        self.bytes = self.bytes.saturating_add(raw.data.len());
        self.entries.push_back(Entry { raw, row });
    }
    /// Looks up a capture-global number; None means absent or evicted.
    pub fn get(&self, number: u64) -> Option<&Entry> {
        // Capture numbers need not be contiguous in synthetic or truncated sources.
        // Binary search also handles dropped oversized packets without misidentifying them.
        let index = self.entries.partition_point(|e| e.row.number < number);
        self.entries.get(index).filter(|e| e.row.number == number)
    }
}
