//! Renders modal reference material.
//! editing.rs owns overlay input; explain::ui and GLOSSARY supply all wording.
//! Read draw first for the popup, then glossary for search result wrapping.
//! A glossary definition explains a networking term without observing more traffic.
use super::{App, Overlay, theme};
use crate::explain::{GLOSSARY, ui as words};
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
/// Centers a content-sized reference popup, preserving the surrounding packet view.
pub(super) fn draw(app: &mut App, frame: &mut Frame<'_>) {
    let area = frame.area();
    if area.width < 60 || area.height < 15 {
        return;
    }
    let title = match app.overlay {
        Some(Overlay::Help) => words::HELP_TITLE,
        Some(Overlay::Glossary) => words::GLOSSARY_TITLE,
        _ => words::INTERFACES_TITLE,
    };
    let lines = match app.overlay {
        Some(Overlay::Help) => words::KEY_HELP
            .lines()
            .map(|line| Line::from(line.to_owned()))
            .collect(),
        Some(Overlay::Glossary) => glossary_lines(app),
        _ => Vec::new(),
    };
    let popup = if app.overlay == Some(Overlay::Interfaces) {
        Rect {
            x: area.x + 2,
            y: area.y + 1,
            width: area.width - 4,
            height: area.height - 2,
        }
    } else {
        reference_area(area, title, &lines, app.overlay == Some(Overlay::Glossary))
    };
    app.areas.overlay = popup;
    // Clear only the popup. Clearing the whole frame makes a small reference
    // look full-screen and hides the packet the reader is trying to understand.
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(theme::focus());
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    match app.overlay {
        Some(Overlay::Help) => {
            let lines = super::wrapped_lines(lines, inner.width);
            scroll(app, frame, inner, lines);
        }
        Some(Overlay::Glossary) => glossary(app, frame, inner, lines),
        Some(Overlay::Interfaces) => interfaces(app, frame, inner),
        None => {}
    }
}
fn reference_area(area: Rect, title: &str, lines: &[Line<'_>], glossary: bool) -> Rect {
    let width = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .max(title.len())
        .saturating_add(2)
        .min(usize::from(area.width - 4)) as u16;
    let height = super::wrapped_lines(lines.to_vec(), width.saturating_sub(2))
        .len()
        .saturating_add(2 + usize::from(glossary))
        .min(usize::from(area.height - 2)) as u16;
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}
fn scroll(app: &mut App, frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    app.overlay_scroll = app
        .overlay_scroll
        .min(lines.len().saturating_sub(usize::from(area.height)));
    frame.render_widget(
        Paragraph::new(lines).scroll((app.overlay_scroll as u16, 0)),
        area,
    );
}
fn glossary_lines(app: &App) -> Vec<Line<'static>> {
    let search = app.glossary_search.to_lowercase();
    let mut lines = Vec::new();
    for (term, definition) in GLOSSARY {
        if term.to_lowercase().contains(&search) || definition.to_lowercase().contains(&search) {
            // Adjacent term headings already separate entries. Spacer rows would
            // reduce how many matching definitions can be read without scrolling.
            lines.push(Line::styled(*term, theme::focus()));
            lines.push(Line::from(*definition));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(words::NO_GLOSSARY));
    }
    lines
}
fn glossary(app: &mut App, frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    frame.render_widget(
        Paragraph::new(format!("{}{}", words::FILTER_EDIT, app.glossary_search)),
        Rect { height: 1, ..area },
    );
    let body = Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    };
    let lines = super::wrapped_lines(lines, body.width);
    scroll(app, frame, body, lines);
}
fn interfaces(app: &mut App, frame: &mut Frame<'_>, area: Rect) {
    if let Some(error) = &app.interface_error {
        frame.render_widget(
            Paragraph::new(error.as_str())
                .style(theme::warning())
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    if app.interfaces.is_empty() {
        frame.render_widget(Paragraph::new(words::INTERFACES_LOADING), area);
        return;
    }
    let page = usize::from(area.height).max(1);
    if app.interface_index < app.overlay_scroll {
        app.overlay_scroll = app.interface_index;
    } else if app.interface_index >= app.overlay_scroll.saturating_add(page) {
        app.overlay_scroll = app.interface_index.saturating_sub(page.saturating_sub(1));
    }
    let lines: Vec<_> = app
        .interfaces
        .iter()
        .enumerate()
        .skip(app.overlay_scroll)
        .take(page)
        .map(|(i, interface)| {
            Line::styled(
                format!(
                    "{}{}  {}",
                    if i == app.interface_index { "> " } else { "  " },
                    interface.name,
                    interface.description
                ),
                if i == app.interface_index {
                    theme::selected()
                } else {
                    theme::base()
                },
            )
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}
