//! Shared pane decoration for the packet screen.
//! Text comes from explain::ui; protocol colours come from theme.rs.
//! Read block first for focus borders, then abbreviate for long endpoints.
use super::theme;
use ratatui::widgets::{Block, Borders};
/// Builds a labelled pane border with visible keyboard focus.
pub(super) fn block(title: &str, focused: bool) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(if focused {
            theme::focus()
        } else {
            theme::base()
        })
}
/// Keeps a zero-based row index inside a viewport of at least one row.
pub(super) fn scroll_into_view(scroll: &mut usize, index: usize, page: usize) {
    if index < *scroll {
        *scroll = index;
    } else if index >= scroll.saturating_add(page) {
        *scroll = index.saturating_sub(page.saturating_sub(1));
    }
}
// An explicit ellipsis keeps cells aligned; the full value remains in the detail
// fields or sentence strip. ratatui measures display cells, including wide glyphs.
/// Shortens display text to a terminal-cell width without breaking UTF-8.
pub(super) fn abbreviate(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if ratatui::text::Span::raw(value).width() <= width {
        return value.into();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in value.chars() {
        let cells = ratatui::text::Span::raw(ch.to_string()).width();
        if used + cells >= width {
            break;
        }
        out.push(ch);
        used += cells;
    }
    out.push('…');
    out
}
