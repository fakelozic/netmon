//! Maintains deterministic bounded state tables.
//! Traffic rules choose caps in `mod.rs`; this file does not interpret protocols.
//! Read `Table::insert` first.
//! An address table needs eviction because a sender can invent many source addresses.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// The second index keeps eviction deterministic and does not accumulate stale keys.
/// Oldest means least recently observed. Both indexes always have the same bounded size.
pub(super) struct Table<K, V> {
    /// Values paired with an observation ordinal, not wall-clock time.
    pub(super) values: HashMap<K, (V, u64)>,
    /// Reverse ordinal index. Removing a value must also remove its index entry.
    pub(super) order: BTreeMap<u64, K>,
    /// Local ordering counter. Exhaustion discards old history rather than wrapping keys.
    pub(super) serial: u64,
    /// Maximum simultaneous entries, at least one.
    pub(super) cap: usize,
}

impl<K: Clone + Eq + Hash, V> Table<K, V> {
    /// Creates empty state. Zero is normalized to one to keep insertion bounded.
    pub(super) fn new(cap: usize) -> Self {
        Self {
            values: HashMap::new(),
            order: BTreeMap::new(),
            serial: 0,
            cap: cap.max(1),
        }
    }

    fn stamp(&mut self) -> u64 {
        // Restart bounded history if the observation counter exhausts its range.
        if self.serial == u64::MAX {
            self.values.clear();
            self.order.clear();
            self.serial = 0;
        }
        self.serial = self.serial.saturating_add(1);
        self.serial
    }

    /// Reads without refreshing eviction age. `None` means absent or evicted history.
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.values.get(key).map(|(value, _)| value)
    }

    /// Refreshes observation age before mutation. Counter exhaustion discards history.
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if !self.values.contains_key(key) {
            return None;
        }
        let stamp = self.stamp();
        let (value, old) = self.values.get_mut(key)?;
        self.order.remove(old);
        self.order.insert(stamp, key.clone());
        *old = stamp;
        Some(value)
    }

    /// Removes from both indexes, returning `None` if no retained value exists.
    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        let (value, stamp) = self.values.remove(key)?;
        self.order.remove(&stamp);
        Some(value)
    }

    /// Replaces a value or evicts the least recently observed entry when full.
    pub(super) fn insert(&mut self, key: K, value: V) {
        self.remove(&key);
        let stamp = self.stamp();
        if self.values.len() >= self.cap
            && let Some((_, oldest)) = self.order.pop_first()
        {
            self.values.remove(&oldest);
        }
        self.order.insert(stamp, key.clone());
        self.values.insert(key, (value, stamp));
    }
}
