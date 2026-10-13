//! Renders the selected packet's detail panes.
//! tree.rs caches decoding; this module never decodes packets while drawing.
//! Read bytes first for exact offsets, highlighting, and secret masking.
//! Each protocol header occupies a byte range within the captured packet.
use super::{
    App, Pane, theme,
    widgets::{abbreviate, block, scroll_into_view},
};
use crate::explain::ui as words;
use ratatui::{
    Frame,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
/// Draws visible cached tree rows; expansion state controls which paths appear.
pub(super) fn layers(app: &mut App, frame: &mut Frame<'_>) {
    let area = app.areas.layers;
    if area.is_empty() {
        return;
    }
    let title = app
        .current_node()
        .map(|node| words::layer_title(node.proto))
        .unwrap_or_else(|| words::LAYERS.into());
    let title = words::detail_title(&title, app.single_detail);
    let border = block(&title, app.focus == Pane::Layers);
    let inner = border.inner(area);
    frame.render_widget(border, area);
    app.tree_page = usize::from(inner.height).max(1);
    scroll_into_view(&mut app.tree_scroll, app.tree_selected, app.tree_page);
    let lines: Vec<Line<'_>> = app
        .tree
        .iter()
        .skip(app.tree_scroll)
        .take(app.tree_page)
        .enumerate()
        .filter_map(|(row, index)| {
            let node = app.nodes.get(*index)?;
            let selected = app.tree_scroll + row == app.tree_selected;
            let marker = if node.children {
                if app.expanded.contains(&node.path) {
                    "▾"
                } else {
                    "▸"
                }
            } else {
                " "
            };
            let label = format!(
                "{}{}{} {}",
                if selected { ">" } else { " " },
                "  ".repeat(node.depth),
                marker,
                node.label
            );
            // Long labels remain readable by wrapping in the Explain pane; the tree
            // uses complete words where possible and an explicit omission mark.
            let value = if node.key.is_none() {
                crate::explain::byte_count(node.range.end.saturating_sub(node.range.start))
            } else {
                node.value.clone()
            };
            let text = format!("{label}: {value}");
            Some(Line::styled(
                abbreviate(&text, usize::from(inner.width)),
                if selected {
                    theme::selected()
                } else {
                    theme::base()
                },
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}
/// Wraps the selected field's What, Here, and Why without re-decoding.
pub(super) fn explanation(app: &mut App, frame: &mut Frame<'_>) {
    let area = app.areas.explain;
    if area.is_empty() {
        return;
    }
    let title = words::detail_title(words::EXPLAIN, app.single_detail);
    let border = block(&title, app.focus == Pane::Explain);
    let inner = border.inner(area);
    frame.render_widget(border, area);
    let Some(node) = app.current_node() else {
        return;
    };
    let mut lines = vec![
        Line::styled(node.label.clone(), theme::focus()),
        Line::from(format!("{}{what}", words::WHAT, what = node.what)),
    ];
    if !node.here.is_empty() {
        lines.push(Line::from(format!(
            "{}{here}",
            words::HERE,
            here = node.here
        )));
    }
    if !node.why.is_empty() {
        lines.push(Line::from(format!("{}{why}", words::WHY, why = node.why)));
    }
    let lines = super::wrapped_lines(lines, inner.width);
    app.explain_scroll = app
        .explain_scroll
        .min(lines.len().saturating_sub(usize::from(inner.height)));
    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph.scroll((app.explain_scroll as u16, 0)), inner);
}
/// Draws visible absolute byte offsets, masking sensitive HTTP header ranges.
pub(super) fn bytes(app: &mut App, frame: &mut Frame<'_>) {
    let area = app.areas.bytes;
    if area.is_empty() {
        return;
    }
    let title = words::detail_title(words::BYTES, app.single_detail);
    let border = block(&title, app.focus == Pane::Bytes);
    let inner = border.inner(area);
    frame.render_widget(border, area);
    let Some(entry) = app.selected.and_then(|id| app.store.get(id)) else {
        return;
    };
    let range = app.selected_range().unwrap_or(0..0);
    app.bytes_page = usize::from(inner.height).max(1);
    // 8-byte rows fit the 60-column layout; selected ranges use their actual offsets.
    let per_row = if inner.width >= 73 { 16 } else { 8 };
    let changed = app.bytes_columns != per_row;
    if changed {
        app.bytes_scroll = app.bytes_scroll.saturating_mul(app.bytes_columns) / per_row;
        app.bytes_columns = per_row;
    }
    let selected_start = range.start / per_row;
    if app.focus != Pane::Bytes || changed {
        let last = selected_start.saturating_add(1);
        if selected_start < app.bytes_scroll
            || last > app.bytes_scroll.saturating_add(app.bytes_page)
        {
            app.bytes_scroll = selected_start;
        }
    }
    let row_count = entry.raw.data.len().div_ceil(per_row);
    app.bytes_scroll = app.bytes_scroll.min(row_count.saturating_sub(1));
    let mut lines = Vec::new();
    for row in app.bytes_scroll
        ..app
            .bytes_scroll
            .saturating_add(app.bytes_page)
            .min(row_count)
    {
        let offset = row.saturating_mul(per_row);
        let data = entry
            .raw
            .data
            .get(offset..offset.saturating_add(per_row).min(entry.raw.data.len()))
            .unwrap_or_default();
        lines.push(byte_line(offset, data, per_row, &range, &app.hidden));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn byte_line(
    offset: usize,
    data: &[u8],
    per_row: usize,
    range: &std::ops::Range<usize>,
    hidden: &[std::ops::Range<usize>],
) -> Line<'static> {
    let mut spans = vec![Span::raw(format!("{offset:04x}  "))];
    for (i, byte) in data.iter().enumerate() {
        let absolute = offset.saturating_add(i);
        let hidden = hidden.iter().any(|r| r.contains(&absolute));
        let style = if range.contains(&absolute) {
            theme::bytes()
        } else {
            Style::default()
        };
        spans.push(Span::styled(
            if hidden {
                "**".into()
            } else {
                format!("{byte:02x}")
            },
            style,
        ));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::raw("   ".repeat(per_row.saturating_sub(data.len()))));
    spans.push(Span::raw(" "));
    for (i, byte) in data.iter().enumerate() {
        let absolute = offset.saturating_add(i);
        let hidden = hidden.iter().any(|r| r.contains(&absolute));
        let ch = if hidden {
            '*'
        } else if (0x20..=0x7e).contains(byte) {
            char::from(*byte)
        } else {
            '.'
        };
        spans.push(Span::styled(
            ch.to_string(),
            if range.contains(&absolute) {
                theme::bytes()
            } else {
                Style::default()
            },
        ));
    }
    Line::from(spans)
}
