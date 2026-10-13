//! Public entry point for the Packets screen.
//! App owns state; events.rs handles input, layout.rs draws, terminal.rs does IO.
//! Start with App::new, then deliver messages, tick, and draw into any backend.
//! A packet is one captured message; selecting it reveals its protocol headers.
mod columns;
mod details;
mod editing;
mod events;
mod layout;
mod overlays;
mod packets;
mod state;
mod supervisor;
mod terminal;
mod text_layout;
mod theme;
mod tree;
mod widgets;
use crate::{
    decode::{Decoded, FieldKey, Proto},
    filter,
    live::Interface,
    store::Store,
};
use ratatui::layout::Rect;
use std::{collections::BTreeSet, ops::Range};
pub use terminal::{ScreenOptions, run};
use text_layout::wrapped_lines;
/// Keyboard focus targets in their Tab traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Packets,
    Layers,
    Explain,
    Bytes,
}
/// Modal views; glossary accepts text and interfaces emits a restart request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Overlay {
    Help,
    Glossary,
    Interfaces,
}
struct Node {
    path: Vec<usize>,
    depth: usize,
    range: Range<usize>,
    key: Option<FieldKey>,
    proto: Proto,
    label: String,
    value: String,
    what: &'static str,
    here: String,
    why: &'static str,
    children: bool,
}
#[derive(Default)]
struct Areas {
    packets: Rect,
    sentence: Rect,
    layers: Rect,
    explain: Rect,
    bytes: Rect,
    tabs: Rect,
    overlay: Rect,
}
/// Terminal-independent screen state, including bounded packet storage.
/// Deliver messages, call on_tick, draw, and route supplied events with on_event.
pub struct App {
    /// The bounded packet buffer; call on_tick after directly changing its filter.
    pub store: Store,
    live: bool,
    source: String,
    selected: Option<u64>,
    decoded: Option<Decoded>,
    nodes: Vec<Node>,
    expanded: BTreeSet<Vec<usize>>,
    tree: Vec<usize>,
    tree_selected: usize,
    packet_scroll: usize,
    tree_scroll: usize,
    explain_scroll: usize,
    bytes_scroll: usize,
    focus: Pane,
    detail: Pane,
    single_detail: bool,
    overlay: Option<Overlay>,
    overlay_scroll: usize,
    glossary_search: String,
    interfaces: Vec<Interface>,
    interface_error: Option<String>,
    interface_index: usize,
    request_interface: Option<String>,
    request_interfaces: bool,
    following: bool,
    paused: bool,
    clock_time: bool,
    quit: bool,
    ended: bool,
    failure: Option<String>,
    filter_edit: Option<String>,
    filter_error: Option<filter::FilterError>,
    areas: Areas,
    packet_page: usize,
    tree_page: usize,
    bytes_page: usize,
    bytes_columns: usize,
    rates: [u64; 60],
    rate_second: Option<u64>,
    rate_samples: usize,
    hidden: Vec<Range<usize>>,
}
