//! Caches the selected packet's field tree.
//! Decoding belongs to decode; pane rendering belongs to details.rs.
//! Read App::select_index first: full decoding happens only on selection changes.
use super::*;
use crate::{
    decode::{self, Detail, Field},
    explain::{self, ui as words},
};
impl App {
    /// Caches Full decoding when a filtered packet selection changes.
    pub(super) fn select_index(&mut self, index: usize) {
        let id = self.store.visible_id(index);
        if self.selected == id {
            return;
        }
        self.selected = id;
        self.decoded = id
            .and_then(|id| self.store.get(id))
            .map(|e| decode::decode(e.raw.link, &e.raw.data, e.raw.orig_len, Detail::Full));
        self.nodes.clear();
        self.expanded.clear();
        self.hidden.clear();
        self.tree_selected = 0;
        self.tree_scroll = 0;
        self.explain_scroll = 0;
        self.bytes_scroll = 0;
        if let Some(decoded) = &self.decoded {
            self.hidden = decode::hidden_ranges(
                decoded,
                self.store
                    .get(id.unwrap_or(0))
                    .map_or(0, |e| e.raw.data.len()),
            );
            for (i, layer) in decoded.layers.iter().enumerate() {
                self.nodes.push(Node {
                    path: vec![i],
                    depth: 0,
                    range: layer.range.clone(),
                    key: None,
                    proto: layer.proto,
                    label: layer.proto.name().into(),
                    value: layer.line.clone(),
                    what: words::layer(layer.proto),
                    here: String::new(),
                    why: "",
                    children: !layer.fields.is_empty(),
                });
                for (j, field) in layer.fields.iter().enumerate() {
                    add_field(&mut self.nodes, field, decoded, layer.proto, vec![i, j]);
                }
            }
            if let Some(last) = decoded.layers.len().checked_sub(1) {
                self.expanded.insert(vec![last]);
            }
        }
        self.rebuild_tree();
    }
    /// Builds visible tree rows from expansion paths, preserving a valid cursor.
    pub(super) fn rebuild_tree(&mut self) {
        self.tree = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                (1..n.path.len()).all(|length| self.expanded.contains(&n.path[..length]))
            })
            .map(|(i, _)| i)
            .collect();
        self.tree_selected = self.tree_selected.min(self.tree.len().saturating_sub(1));
    }
    /// Borrows the selected cached node, or None for an empty tree.
    pub(super) fn current_node(&self) -> Option<&Node> {
        self.nodes.get(*self.tree.get(self.tree_selected)?)
    }
    /// Scrolls toward the selected absolute byte offset and resets explanation scrolling.
    pub(super) fn reveal_bytes(&mut self) {
        if let Some(node) = self.current_node() {
            self.bytes_scroll = node.range.start / self.bytes_columns;
        }
        self.explain_scroll = 0;
    }
    /// Opens or closes a node; None toggles its current state.
    pub(super) fn expand(&mut self, open: Option<bool>) {
        let Some(node) = self.current_node() else {
            return;
        };
        let path = node.path.clone();
        if !node.children {
            return;
        }
        let expanded = self.expanded.contains(&path);
        if open.unwrap_or(!expanded) {
            self.expanded.insert(path);
        } else {
            self.expanded.remove(&path);
        }
        self.rebuild_tree();
        self.reveal_bytes();
    }
}
fn add_field(
    nodes: &mut Vec<Node>,
    field: &Field,
    decoded: &Decoded,
    proto: Proto,
    path: Vec<usize>,
) {
    let wording = explain::field_text(field, decoded);
    nodes.push(Node {
        depth: path.len().saturating_sub(1),
        path: path.clone(),
        range: field.range.clone(),
        key: Some(field.key),
        proto,
        label: wording.label.into(),
        value: field.value.clone(),
        what: wording.what,
        here: wording.here,
        why: wording.why,
        children: !field.children.is_empty(),
    });
    for (i, child) in field.children.iter().enumerate() {
        let mut path = path.clone();
        path.push(i);
        add_field(nodes, child, decoded, proto, path);
    }
}
