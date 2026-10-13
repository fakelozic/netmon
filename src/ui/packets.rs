//! Renders the visible packet rows, one terminal line per packet.
//! columns.rs assigns columns; details.rs explains the selected packet's fields.
//! Read draw first: work depends on visible rows, never total packet count.
//! TCP and UDP ports identify the application endpoints named in each row.
use super::{
    App, Pane,
    columns::Columns,
    theme,
    widgets::{abbreviate, block, scroll_into_view},
};
use crate::{explain::ui as words, store::Entry, sys, text};
use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, Wrap},
};

/// Renders the packet viewport without traversing packets outside it.
pub(super) fn draw(app: &mut App, frame: &mut Frame<'_>) {
    let area = app.areas.packets;
    let border = block(words::PACKETS, app.focus == Pane::Packets);
    let inner = border.inner(area);
    frame.render_widget(border, area);
    app.packet_page = usize::from(inner.height.saturating_sub(1)).max(1);
    if let Some(message) = status(app) {
        frame.render_widget(
            Paragraph::new(message)
                .style(if app.failure.is_some() {
                    theme::warning()
                } else {
                    theme::base()
                })
                .wrap(Wrap { trim: false }),
            inner,
        );
        return;
    }
    if let Some(index) = app.selected.and_then(|id| app.store.visible_index(id)) {
        scroll_into_view(&mut app.packet_scroll, index, app.packet_page);
    }
    app.packet_scroll = app
        .packet_scroll
        .min(app.store.visible_len().saturating_sub(1));
    let cols = Columns::new(inner, number_width(app), app.clock_time);
    for (i, (label, col)) in words::COLUMN_LABELS.iter().zip(cols.cells).enumerate() {
        let label = if cols.combined && i == 3 {
            words::COMBINED_ENDPOINTS
        } else {
            *label
        };
        frame.render_widget(Paragraph::new(label), col);
    }
    for offset in 0..app.packet_page {
        let Some(entry) = app.store.visible(app.packet_scroll + offset) else {
            break;
        };
        let row = Rect {
            y: inner.y.saturating_add(1).saturating_add(offset as u16),
            height: 1,
            ..inner
        };
        if row.y >= inner.bottom() {
            break;
        }
        draw_row(app, entry, frame, row, &cols);
    }
}

fn status(app: &App) -> Option<String> {
    if let Some(error) = &app.failure {
        let advice = if app.live {
            words::CAPTURE_ADVICE
        } else {
            words::FILE_ADVICE
        };
        return Some(format!("{error}\n\n{advice}"));
    }
    if app.store.visible_len() > 0 {
        return None;
    }
    Some(
        if !app.store.is_empty() {
            words::NO_MATCHES
        } else if app.live {
            words::WAIT_LIVE
        } else if app.ended {
            words::EMPTY_FILE
        } else {
            words::WAIT_FILE
        }
        .into(),
    )
}

fn number_width(app: &App) -> u16 {
    // Packet numbers keep increasing after eviction; measure only visible rows.
    (0..app.packet_page)
        .filter_map(|offset| app.store.visible(app.packet_scroll + offset))
        .map(|entry| entry.raw.number.to_string().len().saturating_add(3))
        .max()
        .unwrap_or(6)
        .max(6) as u16
}

fn draw_row(app: &App, entry: &Entry, frame: &mut Frame<'_>, row: Rect, cols: &Columns) {
    let selected = app.selected == Some(entry.id);
    let style = if entry.problem {
        theme::warning()
    } else {
        theme::protocol(entry.summary.proto)
    };
    let style = if selected {
        style.patch(theme::selected())
    } else {
        style
    };
    frame.render_widget(Paragraph::new("").style(style), row);
    let mut values = values(app, entry, selected, cols.compact_time);
    if cols.combined {
        // Abbreviate each side separately so a long source never hides the destination.
        let available = usize::from(cols.cells[3].width).saturating_sub(4);
        values[3] = words::combined_endpoints(
            &abbreviate(&values[2], available / 2),
            &abbreviate(&values[3], available.saturating_sub(available / 2)),
        );
    }
    for (i, col) in cols.cells.iter().enumerate() {
        if col.width == 0 {
            continue;
        }
        let cell = Rect { y: row.y, ..*col };
        let width = usize::from(cell.width).saturating_sub(usize::from(i != 6));
        frame.render_widget(
            Paragraph::new(abbreviate(&values[i], width)).style(style),
            cell,
        );
    }
}

fn values(app: &App, entry: &Entry, selected: bool, compact_time: bool) -> [String; 7] {
    let time = if app.clock_time {
        sys::local_time(entry.raw.ts).unwrap_or_else(|| "?".into())
    } else {
        relative_time(
            entry.raw.ts,
            app.store.first_ts().unwrap_or_default(),
            compact_time,
        )
    };
    [
        format!(
            "{}{}{}",
            if selected { ">" } else { " " },
            if entry.problem { "!" } else { "" },
            entry.raw.number
        ),
        time,
        text::endpoint(entry.summary.src.as_ref(), entry.summary.src_port),
        text::endpoint(entry.summary.dst.as_ref(), entry.summary.dst_port),
        entry.summary.proto.name().into(),
        text::number(u64::from(entry.raw.orig_len)),
        entry.sentence.clone(),
    ]
}

fn relative_time(ts: std::time::Duration, first: std::time::Duration, compact: bool) -> String {
    let (sign, elapsed) = if ts >= first {
        ("", ts.saturating_sub(first))
    } else {
        ("-", first.saturating_sub(ts))
    };
    // Integer subsecond units truncate instead of floating-point rounding.
    // Preserve the negative sign for captures whose timestamps move backward.
    if compact {
        format!("{sign}{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis())
    } else {
        format!("{sign}{}.{:06}", elapsed.as_secs(), elapsed.subsec_micros())
    }
}
