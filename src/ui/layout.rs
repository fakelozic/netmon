//! Assigns terminal space to the Packets screen's panes.
//! packets.rs renders rows; details.rs renders the selected packet's fields.
//! Read draw first to see the full layout and the single-detail layout.
use super::{App, Pane, theme};
use crate::explain::ui as words;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Paragraph, Sparkline, Wrap},
};
/// Draws only panes that fit; below 60x15 the screen becomes a resize hint.
pub(super) fn draw(app: &mut App, frame: &mut Frame<'_>) {
    let area = frame.area();
    if area.width < 60 || area.height < 15 {
        app.areas = super::Areas::default();
        frame.render_widget(
            Paragraph::new(words::TOO_SMALL).wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let parts = areas(app, area);
    header(app, frame, parts[0]);
    let tabs = Layout::horizontal([Constraint::Min(1), Constraint::Length(20)]).split(parts[1]);
    frame.render_widget(Paragraph::new(words::TABS).style(theme::focus()), tabs[0]);
    frame.render_widget(Paragraph::new(words::TAB_HINTS), tabs[1]);
    super::packets::draw(app, frame);
    selected_sentence(app, frame);
    super::details::layers(app, frame);
    super::details::explanation(app, frame);
    super::details::bytes(app, frame);
    filter_bar(app, frame, parts[5]);
}
fn areas(app: &mut App, area: Rect) -> std::rc::Rc<[Rect]> {
    app.single_detail = area.width < 80 || area.height < 30;
    if app.focus != Pane::Packets {
        app.detail = app.focus;
    }
    let filter = if app.filter_edit.is_some() { 3 } else { 1 };
    let sentence = app
        .selected
        .and_then(|id| app.store.get(id))
        .map_or(1, |entry| {
            super::wrapped_lines(
                vec![ratatui::text::Line::from(entry.sentence.as_str())],
                area.width,
            )
            .len()
            .max(1)
            .min(usize::from(area.height)) as u16
        });
    let body_height = area
        .height
        .saturating_sub(3u16.saturating_add(filter).saturating_add(sentence));
    // A majority of the body goes to the list. Its border and headings consume
    // three rows; these heights still leave 17, 11 and 8 packet rows at test sizes.
    let packet_height = ((u32::from(body_height) * 55).div_ceil(100) as u16)
        .max((u32::from(area.height.saturating_sub(3)) * 45).div_ceil(100) as u16);
    let parts = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(packet_height),
        Constraint::Length(sentence),
        Constraint::Min(0),
        Constraint::Length(filter),
    ])
    .split(area);
    app.areas.tabs = parts[1];
    app.areas.packets = parts[2];
    app.areas.sentence = parts[3];
    app.areas.layers = Rect::default();
    app.areas.explain = Rect::default();
    app.areas.bytes = Rect::default();
    if app.single_detail {
        match app.detail {
            Pane::Layers => app.areas.layers = parts[4],
            Pane::Explain => app.areas.explain = parts[4],
            Pane::Bytes => app.areas.bytes = parts[4],
            Pane::Packets => unreachable!(),
        }
    } else {
        let details = Layout::vertical([Constraint::Min(4), Constraint::Length(4)]).split(parts[4]);
        let upper = Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(details[0]);
        app.areas.layers = upper[0];
        app.areas.explain = upper[1];
        app.areas.bytes = details[1];
    }
    parts
}
fn selected_sentence(app: &App, frame: &mut Frame<'_>) {
    if let Some(entry) = app.selected.and_then(|id| app.store.get(id)) {
        // This fixed strip spans the terminal, so list-column truncation never
        // hides the selected packet's sentence. At all target sizes it is one line.
        frame.render_widget(
            Paragraph::new(entry.sentence.as_str())
                .style(theme::focus())
                .wrap(Wrap { trim: false }),
            app.areas.sentence,
        );
    }
}
fn header(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let wording = words::header(words::Header {
        mode: words::mode(app.live, app.paused),
        source: &app.source,
        total: app.store.total(),
        shown: app.store.visible_len(),
        dropped: app.store.dropped(),
        rate: app.rates[59],
        live: app.live,
        duration: app.store.capture_duration(),
        total_bytes: app.store.total_bytes(),
        filter: app.store.filter_text(),
        rebuilding: app.store.rebuilding(),
    });
    let spark_width = if app.live && app.rate_samples >= 2 {
        20
    } else {
        0
    };
    let parts =
        Layout::horizontal([Constraint::Min(1), Constraint::Length(spark_width)]).split(area);
    frame.render_widget(Paragraph::new(wording), parts[0]);
    if spark_width == 0 {
        return;
    }
    // ratatui renders only the first width entries. Group all sixty seconds into
    // twenty bars so the most recent traffic does not disappear off the right.
    let bins = app
        .rates
        .chunks(3)
        .map(|s| s.iter().copied().fold(0u64, u64::saturating_add));
    frame.render_widget(
        Sparkline::default().data(bins).style(theme::focus()),
        Rect {
            height: 1,
            ..parts[1]
        },
    );
}
fn filter_bar(app: &App, frame: &mut Frame<'_>, area: Rect) {
    if let Some(input) = &app.filter_edit {
        let error = app
            .filter_error
            .as_ref()
            .map(|e| words::filter_error(e.position, &e.message))
            .unwrap_or_else(|| words::FILTER_KEYS.into());
        // Show the end of a long buffer while preserving the entire edit in state.
        let capacity = usize::from(area.width).saturating_sub(words::FILTER_EDIT.len());
        let tail: String = input
            .chars()
            .rev()
            .take(capacity)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        frame.render_widget(
            Paragraph::new(format!("{}{tail}\n{error}", words::FILTER_EDIT))
                .style(if app.filter_error.is_some() {
                    theme::warning()
                } else {
                    theme::focus()
                })
                .wrap(Wrap { trim: false }),
            area,
        );
    } else {
        frame.render_widget(Paragraph::new(words::FILTER_HINT), area);
    }
}
