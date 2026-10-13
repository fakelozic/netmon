//! Owns the packet screen's state transitions.
//! Terminal IO belongs to terminal.rs; selected packet details belong to tree.rs.
//! Read App::on_tick first to see how arrivals affect the selection.
use super::*;
use crate::{capture::RawPacket, live::Message, text};
use ratatui::Frame;
impl App {
    /// Creates a screen state with a sanitized source label.
    /// Live enables interface selection and follows the newest packet.
    /// Files select the first packet; max_packets is clamped by Store.
    pub fn new(source: &str, live: bool, max_packets: usize) -> Self {
        Self {
            store: Store::new(max_packets),
            live,
            source: text::sanitise(source.as_bytes()),
            selected: None,
            decoded: None,
            nodes: Vec::new(),
            expanded: BTreeSet::new(),
            tree: Vec::new(),
            tree_selected: 0,
            packet_scroll: 0,
            tree_scroll: 0,
            explain_scroll: 0,
            bytes_scroll: 0,
            focus: Pane::Packets,
            detail: Pane::Layers,
            single_detail: false,
            overlay: None,
            overlay_scroll: 0,
            glossary_search: String::new(),
            interfaces: Vec::new(),
            interface_error: None,
            interface_index: 0,
            request_interface: None,
            request_interfaces: false,
            following: live,
            paused: false,
            clock_time: false,
            quit: false,
            ended: false,
            failure: None,
            filter_edit: None,
            filter_error: None,
            areas: Areas::default(),
            packet_page: 1,
            tree_page: 1,
            bytes_page: 1,
            bytes_columns: 16,
            rates: [0; 60],
            rate_second: None,
            rate_samples: 0,
            hidden: Vec::new(),
        }
    }
    /// Accepts one worker event without IO; failures replace the packet list with advice.
    pub fn on_message(&mut self, message: Message) {
        match message {
            Message::Packet(p) => self.push(p),
            Message::Ended => self.ended = true,
            Message::Failed(e) => {
                self.failure = Some(text::sanitise(e.as_bytes()));
                self.ended = true;
            }
        }
    }
    /// Retains one arrival and updates sixty timestamp-based one-second byte bins.
    /// Backward timestamps do not shift the bins or read the wall clock.
    pub fn push(&mut self, packet: RawPacket) {
        let second = packet.ts.as_secs();
        if let Some(previous) = self.rate_second {
            if second > previous {
                let distance = second.saturating_sub(previous).min(60) as usize;
                self.rate_samples = self.rate_samples.saturating_add(distance).min(60);
                self.rates.rotate_left(distance);
                for slot in self.rates.iter_mut().rev().take(distance) {
                    *slot = 0;
                }
                self.rate_second = Some(second);
            }
        } else {
            self.rate_second = Some(second);
            self.rate_samples = 1;
        }
        if self.rate_second == Some(second) {
            self.rates[59] = self.rates[59].saturating_add(u64::from(packet.orig_len));
        }
        self.store.push(packet);
    }
    /// Evaluates at most 20,000 historical filter rows and reconciles selection.
    /// Pausing preserves selection while that entry remains stored and matches the filter.
    pub fn on_tick(&mut self) {
        self.store.on_tick();
        if self.following && !self.paused {
            self.select_index(self.store.visible_len().saturating_sub(1));
        } else if self
            .selected
            .is_none_or(|id| self.store.visible_index(id).is_none())
        {
            self.select_index(0);
        }
    }
    /// Returns the capture packet number, or None when no matching packet is selected.
    pub fn selected_packet(&self) -> Option<u64> {
        self.selected
            .and_then(|id| self.store.get(id))
            .map(|e| e.raw.number)
    }
    /// Returns the pane receiving navigation keys.
    pub fn focus(&self) -> Pane {
        self.focus
    }
    /// Returns the active modal view, or None for the ordinary screen.
    pub fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }
    /// Returns whether following is paused; capture and storage still continue.
    pub fn paused(&self) -> bool {
        self.paused
    }
    /// Returns whether the screen follows the newest matching packet.
    pub fn following(&self) -> bool {
        self.following
    }
    /// Returns whether q or Ctrl-C requested termination.
    pub fn should_quit(&self) -> bool {
        self.quit
    }
    /// Returns the uncommitted filter editor buffer, or None outside edit mode.
    pub fn filter_input(&self) -> Option<&str> {
        self.filter_edit.as_deref()
    }
    /// Returns the last edit error; the buffer remains available for correction.
    pub fn filter_error(&self) -> Option<&filter::FilterError> {
        self.filter_error.as_ref()
    }
    /// Returns selected header or field offsets from the packet start, in bytes.
    /// The end is exclusive; None means no detail node is selected.
    pub fn selected_range(&self) -> Option<Range<usize>> {
        self.current_node().map(|n| n.range.clone())
    }
    /// Selects a retained capture packet number and stops following.
    /// Absent numbers leave the selection unchanged; this integration helper scans retained matches.
    pub fn select_packet(&mut self, number: u64) {
        // Packet numbers produced by Reader are contiguous. This lookup is bounded
        // by the store's capacity and is a test/integration helper, not an event path.
        if let Some(index) = (0..self.store.visible_len()).find(|&i| {
            self.store
                .visible(i)
                .is_some_and(|e| e.raw.number == number)
        }) {
            self.following = false;
            self.select_index(index);
        }
    }
    /// Selects the first field with the given protocol and key, expanding ancestors.
    /// Absent fields leave the selection unchanged.
    pub fn select_field(&mut self, proto: Proto, key: FieldKey) {
        if let Some(index) = self
            .nodes
            .iter()
            .position(|n| n.proto == proto && n.key == Some(key))
        {
            let path = self.nodes[index].path.clone();
            for length in 1..path.len() {
                self.expanded.insert(path[..length].to_vec());
            }
            self.rebuild_tree();
            if let Some(row) = self.tree.iter().position(|i| *i == index) {
                self.tree_selected = row;
                self.reveal_bytes();
            }
        }
    }
    /// Accepts a worker interface result; error text is sanitized before display.
    pub fn set_interfaces(&mut self, result: Result<Vec<Interface>, String>) {
        match result {
            Ok(list) => {
                // Keep this boundary safe even when a caller supplies interfaces
                // without going through live::parse_interfaces.
                self.interfaces = list
                    .into_iter()
                    .take(4096)
                    .map(|i| Interface {
                        name: text::sanitise(i.name.as_bytes()),
                        description: text::sanitise(i.description.as_bytes()),
                    })
                    .collect();
                self.interface_error = self
                    .interfaces
                    .is_empty()
                    .then(|| crate::explain::ui::NO_INTERFACE.into());
                self.interface_index = 0;
            }
            Err(e) => self.interface_error = Some(text::sanitise(e.as_bytes())),
        }
    }
    /// Consumes the chosen interface name, or None when no restart is pending.
    pub fn take_interface_request(&mut self) -> Option<String> {
        self.request_interface.take()
    }
    /// Consumes a request to refresh the interface list on a worker.
    pub fn take_interfaces_request(&mut self) -> bool {
        std::mem::take(&mut self.request_interfaces)
    }
    /// Clears capture-specific state for a chosen live interface, retaining the count cap.
    /// The terminal adapter must stop the old source and start the replacement.
    pub fn restart(&mut self, interface: &str) {
        let max = self.store_capacity();
        *self = Self::new(interface, true, max);
    }
    /// Returns the retained-packet limit used when switching interfaces.
    pub(super) fn store_capacity(&self) -> usize {
        self.store.max_packets()
    }
    /// Moves within the focused pane with saturating boundaries.
    pub(super) fn move_cursor(&mut self, amount: isize) {
        match self.focus {
            Pane::Packets => {
                self.following = false;
                let current = self
                    .selected
                    .and_then(|id| self.store.visible_index(id))
                    .unwrap_or(0);
                self.select_index(
                    current
                        .saturating_add_signed(amount)
                        .min(self.store.visible_len().saturating_sub(1)),
                );
            }
            Pane::Layers => {
                self.tree_selected = self
                    .tree_selected
                    .saturating_add_signed(amount)
                    .min(self.tree.len().saturating_sub(1));
                self.reveal_bytes();
            }
            Pane::Explain => {
                self.explain_scroll = self.explain_scroll.saturating_add_signed(amount).min(4096)
            }
            Pane::Bytes => {
                let max = self
                    .selected
                    .and_then(|id| self.store.get(id))
                    .map_or(0, |e| {
                        e.raw
                            .data
                            .len()
                            .div_ceil(self.bytes_columns)
                            .saturating_sub(1)
                    });
                self.bytes_scroll = self.bytes_scroll.saturating_add_signed(amount).min(max);
            }
        }
    }
    /// Returns the focused pane viewport size, never zero.
    pub(super) fn page(&self) -> usize {
        match self.focus {
            Pane::Packets => self.packet_page,
            Pane::Layers => self.tree_page,
            Pane::Explain => self.areas.explain.height.saturating_sub(2) as usize,
            Pane::Bytes => self.bytes_page,
        }
        .max(1)
    }
    /// Starts a sliced rebuild and stops following without clearing stored packets.
    pub(super) fn apply_filter(&mut self, input: String, filter: filter::Filter) {
        self.store.set_filter(input, filter);
        self.packet_scroll = 0;
        self.following = false;
    }
    /// Renders cached state into any ratatui backend without decoding the packet again.
    pub fn draw(&mut self, frame: &mut Frame<'_>) {
        layout::draw(self, frame);
        if self.overlay.is_some() {
            overlays::draw(self, frame);
        }
    }
}
