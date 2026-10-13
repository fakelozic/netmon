//! Checks the packet screen's space allocation and source-specific behavior.
//! ui.rs owns event and rendering helpers; ui_support loads synthetic traffic.
//! Read packet_density_and_fixed_sentence_strip for the three target terminal sizes.
use super::{key, render, type_text, ui_support};
use netmon::{
    capture::RawPacket,
    decode::{self, Detail},
    render::{self as output, Mode},
    ui::{App, Pane},
};
use ratatui::crossterm::event::{
    Event, KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};

fn loaded(live: bool) -> App {
    let mut app = App::new("fixture", live, 200_000);
    for packet in ui_support::packets() {
        app.push(packet);
        app.on_tick();
    }
    app
}
fn list_rows(screen: &str) -> Vec<(usize, &str)> {
    screen
        .lines()
        .enumerate()
        .skip(5)
        .take_while(|(_, row)| row.starts_with('│'))
        .filter(|(_, row)| {
            row.trim_start_matches('│')
                .split_whitespace()
                .next()
                .is_some_and(|number| number.trim_start_matches(['>', '!']).parse::<u64>().is_ok())
        })
        .collect()
}
fn strip(screen: &str) -> &str {
    let mut lines = screen.lines();
    lines.find(|line| line.starts_with('└')).unwrap();
    lines.next().unwrap()
}
fn sentence(packet: &RawPacket) -> String {
    netmon::explain::sentence(&decode::decode(
        packet.link,
        &packet.data,
        packet.orig_len,
        Detail::Summary,
    ))
}

#[test]
fn packet_density_and_fixed_sentence_strip() {
    let packets = ui_support::packets();
    let mut app = loaded(false);
    for (width, height, target) in [(140, 40, 16), (100, 30, 11), (80, 24, 8)] {
        let screen = render(&mut app, width, height);
        let rows = list_rows(&screen);
        assert!(
            rows.len() >= target,
            "{width}x{height}: {} rows",
            rows.len()
        );
        assert!(
            rows.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1),
            "{screen}"
        );
        let list_bottom = screen
            .lines()
            .position(|line| line.starts_with('└'))
            .unwrap();
        assert!((list_bottom - 2) * 100 >= usize::from(height - 3) * 45);
        // Every sentence is tested independently of the checked-in golden screens.
        for packet in &packets {
            app.select_packet(packet.number);
            let screen = render(&mut app, width, height);
            assert_eq!(
                strip(&screen),
                sentence(packet),
                "{width}x{height}, packet {}",
                packet.number
            );
            let selected = list_rows(&screen)
                .into_iter()
                .find(|(_, row)| row.starts_with("│>"))
                .unwrap()
                .1;
            assert!(
                selected.contains(
                    decode::decode(packet.link, &packet.data, packet.orig_len, Detail::Summary)
                        .summary
                        .proto
                        .name()
                )
            );
            if !selected.contains(&sentence(packet)) {
                assert!(selected.contains('…'));
            }
        }
        app.select_packet(1);
    }
    assert_eq!(
        packets
            .iter()
            .max_by_key(|packet| sentence(packet).chars().count())
            .unwrap()
            .number,
        75
    );
}

#[test]
fn files_start_at_top_and_live_sources_follow_newest() {
    let mut file = loaded(false);
    assert_eq!(file.selected_packet(), Some(1));
    assert!(!file.following());
    let screen = render(&mut file, 140, 40);
    assert!(list_rows(&screen)[0].1.starts_with("│>1 "));
    key(&mut file, KeyCode::End);
    assert_eq!(file.selected_packet(), Some(75));
    let screen = render(&mut file, 140, 40);
    assert!(list_rows(&screen).last().unwrap().1.starts_with("│>!75 "));
    let mut live = loaded(true);
    assert_eq!(live.selected_packet(), Some(75));
    assert!(live.following());
    let mut next = ui_support::packets().remove(0);
    next.number = 76;
    live.push(next);
    live.on_tick();
    assert_eq!(live.selected_packet(), Some(76));
}

#[test]
fn small_screens_draw_one_detail_and_tab_switches_it() {
    let mut app = loaded(false);
    for (width, height) in [(80, 24), (140, 24), (79, 40)] {
        key(&mut app, KeyCode::Char('1'));
        render(&mut app, 140, 40);
        // Enter chooses Layers at every size, retaining its existing meaning.
        key(&mut app, KeyCode::Enter);
        for pane in [Pane::Layers, Pane::Explain, Pane::Bytes, Pane::Layers] {
            let screen = render(&mut app, width, height);
            let titles: Vec<_> = screen
                .lines()
                .filter(|line| line.starts_with('┌') && line.contains("Tab switches"))
                .collect();
            assert_eq!(titles.len(), 1, "{screen}");
            let expected = match pane {
                Pane::Layers => "Layers",
                Pane::Explain => "Explain",
                Pane::Bytes => "Bytes",
                Pane::Packets => unreachable!(),
            };
            assert!(titles[0].contains(expected), "{screen}");
            assert_eq!(
                screen.matches("┌Layers").count()
                    + screen.matches("┌Explain").count()
                    + screen.matches("┌Bytes").count(),
                1
            );
            key(&mut app, KeyCode::Tab);
        }
    }
    let mut initial = loaded(false);
    let screen = render(&mut initial, 80, 24);
    assert!(screen.contains("┌Layers"));
    key(&mut initial, KeyCode::Tab);
    assert!(render(&mut initial, 80, 24).contains("┌Explain"));
    key(&mut initial, KeyCode::BackTab);
    assert!(render(&mut initial, 80, 24).contains("┌Layers"));
    initial.select_packet(75);
    for _ in 0..4 {
        assert_eq!(
            strip(&render(&mut initial, 80, 24)),
            sentence(&ui_support::packets()[74])
        );
        key(&mut initial, KeyCode::Tab);
    }
}

#[test]
fn file_totals_and_live_rates_use_packet_timestamps() {
    let packets = ui_support::packets();
    let total: u64 = packets
        .iter()
        .map(|packet| u64::from(packet.orig_len))
        .sum();
    let duration = packets.last().unwrap().ts - packets[0].ts;
    let mut file = loaded(false);
    for (width, height) in [(140, 40), (100, 30), (80, 24)] {
        let screen = render(&mut file, width, height);
        let header = screen.lines().take(2).collect::<Vec<_>>().join("\n");
        assert!(!header.contains("B/s"));
        assert!(!header.contains('█'));
        assert!(header.contains("75 packets"));
        assert!(header.contains(&format!(
            "{}.{:06} s",
            duration.as_secs(),
            duration.subsec_micros()
        )));
        assert!(header.contains(&format!("{} bytes", netmon::text::number(total))));
    }
    let mut live = App::new("lo", true, 1);
    live.push(packets[0].clone());
    live.on_tick();
    let first = render(&mut live, 140, 40);
    assert!(first.lines().next().unwrap().contains("98 B/s"));
    assert!(!first.lines().next().unwrap().contains('█'));
    let mut next = packets[0].clone();
    next.ts += std::time::Duration::from_secs(1);
    live.push(next);
    live.on_tick();
    assert!(
        render(&mut live, 140, 40)
            .lines()
            .next()
            .unwrap()
            .contains('█')
    );
    assert_eq!(live.store.total_bytes(), 196);
    assert_eq!(
        live.store.capture_duration(),
        std::time::Duration::from_secs(1)
    );
    assert_eq!(live.store.len(), 1); // Retention does not erase capture totals.
}

#[test]
fn every_fixture_time_matches_render_and_compact_time_truncates() {
    let packets = ui_support::packets();
    let mut app = loaded(false);
    for packet in &packets {
        let decoded = decode::decode(packet.link, &packet.data, packet.orig_len, Detail::Summary);
        let printed = output::packet(packet, &decoded, packets[0].ts, Mode::Default);
        let expected = printed.split_whitespace().nth(1).unwrap();
        app.select_packet(packet.number);
        for (width, height) in [(140, 40), (100, 30), (80, 24)] {
            let screen = render(&mut app, width, height);
            let row = list_rows(&screen)
                .into_iter()
                .find(|(_, row)| row.starts_with("│>"))
                .unwrap()
                .1;
            let shown = row
                .trim_start_matches('│')
                .split_whitespace()
                .nth(1)
                .unwrap();
            let expected = if width == 80 {
                &expected[..expected.len() - 3]
            } else {
                expected
            };
            assert_eq!(
                shown, expected,
                "packet {}, {width}x{height}",
                packet.number
            );
        }
    }
    // A time before the first arrival keeps the same negative sign as render.
    let mut packet = packets[0].clone();
    packet.number = 76;
    packet.ts = packet
        .ts
        .saturating_sub(std::time::Duration::from_micros(1));
    app.push(packet);
    app.select_packet(76);
    assert!(render(&mut app, 140, 40).contains("-0.000001"));
}

#[test]
fn mouse_packet_rows_have_no_hidden_spacers() {
    for (width, height) in [(140, 40), (100, 30), (80, 24)] {
        let mut app = loaded(false);
        let screen = render(&mut app, width, height);
        for (row, text) in list_rows(&screen) {
            let expected: u64 = text
                .trim_start_matches('│')
                .split_whitespace()
                .next()
                .unwrap()
                .trim_start_matches(['>', '!'])
                .parse()
                .unwrap();
            app.on_event(Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 3,
                row: row as u16,
                modifiers: KeyModifiers::NONE,
            }));
            assert_eq!(app.selected_packet(), Some(expected));
        }
    }
}

#[test]
fn reference_overlays_fit_content_and_center() {
    let mut app = loaded(false);
    for code in ['?', 'g'] {
        key(&mut app, KeyCode::Char(code));
        if code == 'g' {
            type_text(&mut app, "ttl");
        }
        let screen = render(&mut app, 140, 40);
        let title = if code == '?' {
            "┌Help"
        } else {
            "┌Glossary"
        };
        let top = screen.lines().position(|row| row.contains(title)).unwrap();
        let line = screen.lines().nth(top).unwrap();
        let x = line.split_once(title).unwrap().0.chars().count();
        let right = line.chars().skip(x).position(|ch| ch == '┐').unwrap() + x;
        let bottom = screen
            .lines()
            .enumerate()
            .skip(top + 1)
            .find(|(_, row)| row.chars().nth(x) == Some('└'))
            .unwrap()
            .0;
        assert!((140usize - (right - x + 1)).abs_diff(x * 2) <= 1);
        assert!((40usize - (bottom - top + 1)).abs_diff(top * 2) <= 1);
        assert!(bottom - top < 35);
        if code == 'g' {
            assert!(
                screen
                    .lines()
                    .skip(top + 1)
                    .take(bottom - top - 1)
                    .any(|line| line.contains("TTL"))
            );
            assert!(bottom > top + 2);
        }
        key(&mut app, KeyCode::Esc);
    }
    key(&mut app, KeyCode::Char('g'));
    let broad = render(&mut app, 140, 40);
    let headings = broad
        .lines()
        .filter(|row| {
            row.contains("│")
                && netmon::explain::GLOSSARY
                    .iter()
                    .any(|(term, _)| row.contains(&format!("│{term} ")))
        })
        .count();
    assert!(headings >= 10, "{headings} definitions: {broad}");
}
