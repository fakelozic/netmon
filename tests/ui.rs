//! Verifies packet-screen interaction with deterministic inputs.
//! Shared fixture reading belongs to ui_support; real capture is never started.
//! Read the fixture tests first for the observable acceptance requirements.
#[path = "ui_support/layout.rs"]
mod layout_tests;
mod ui_support;
use netmon::{
    decode::{FieldKey, Proto},
    live::Message,
    ui::{App, Overlay, Pane},
};
use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{
        Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
};
use std::{fs, path::Path, process::Command};
fn app() -> App {
    let mut app = App::new("loopback-mixed.pcapng", false, 200_000);
    for packet in ui_support::packets() {
        app.push(packet);
    }
    app.on_message(Message::Ended);
    app.on_tick();
    app.select_packet(17);
    app.select_field(Proto::Tcp, FieldKey::TcpFlags);
    app
}
fn key(app: &mut App, code: KeyCode) {
    app.on_event(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
}
fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        key(app, KeyCode::Char(ch));
    }
}
fn render(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut output = String::new();
    for y in 0..height {
        let mut row = String::new();
        for x in 0..width {
            row.push_str(buffer[(x, y)].symbol());
        }
        output.push_str(row.trim_end());
        output.push('\n');
    }
    output
}
fn golden(name: &str, text: &str) {
    let path = Path::new("tests/golden").join(name);
    if std::env::var_os("NETMON_PREVIEW").is_some() {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ui-preview");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), text).unwrap();
        return;
    }
    if std::env::var_os("NETMON_BLESS").is_some() {
        fs::write(&path, text).unwrap();
    }
    assert_eq!(
        text,
        fs::read_to_string(&path).unwrap(),
        "{}",
        path.display()
    );
}
#[test]
fn screen_goldens() {
    for (width, height) in [(140, 40), (100, 30), (80, 24)] {
        golden(
            &format!("ui-packets-{width}x{height}.txt"),
            &render(&mut app(), width, height),
        );
    }
    let mut help = app();
    key(&mut help, KeyCode::Char('?'));
    golden("ui-help-140x40.txt", &render(&mut help, 140, 40));
    let mut glossary = app();
    key(&mut glossary, KeyCode::Char('g'));
    type_text(&mut glossary, "ttl");
    golden(
        "ui-glossary-ttl-140x40.txt",
        &render(&mut glossary, 140, 40),
    );
    let mut filtered = app();
    key(&mut filtered, KeyCode::Char('/'));
    type_text(&mut filtered, "dns");
    key(&mut filtered, KeyCode::Enter);
    filtered.on_tick();
    golden("ui-filter-dns-140x40.txt", &render(&mut filtered, 140, 40));
}
#[test]
fn movement_pages_focus_expansion_pause_and_time() {
    let mut app = app();
    render(&mut app, 140, 40);
    key(&mut app, KeyCode::Up);
    assert_eq!(app.selected_packet(), Some(16));
    assert!(!app.following());
    key(&mut app, KeyCode::Down);
    assert_eq!(app.selected_packet(), Some(17));
    key(&mut app, KeyCode::PageDown);
    let after = app.selected_packet().unwrap();
    assert!(after > 17);
    key(&mut app, KeyCode::PageUp);
    assert_eq!(app.selected_packet(), Some(17));
    key(&mut app, KeyCode::Home);
    assert_eq!(app.selected_packet(), Some(1));
    key(&mut app, KeyCode::End);
    assert_eq!(app.selected_packet(), Some(75));
    assert!(app.following());
    key(&mut app, KeyCode::Char(' '));
    assert!(app.paused());
    app.select_packet(17);
    app.select_field(Proto::Tcp, FieldKey::TcpFlags);
    app.push(ui_support::packets()[0].clone());
    app.on_tick();
    assert_eq!(app.selected_packet(), Some(17));
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.focus(), Pane::Layers);
    assert_eq!(app.selected_range(), Some(46..48));
    key(&mut app, KeyCode::Right);
    key(&mut app, KeyCode::Down);
    assert_eq!(app.selected_range(), Some(47..48));
    key(&mut app, KeyCode::Up);
    key(&mut app, KeyCode::Left);
    key(&mut app, KeyCode::Down);
    let next_range = app.selected_range().expect("next field has captured bytes");
    assert_ne!(next_range, 46..48);
    assert!(
        next_range.start <= next_range.end
            && next_range.end <= ui_support::packets()[16].data.len()
    );
    app.select_field(Proto::Tcp, FieldKey::TcpOptions);
    assert_eq!(app.selected_range(), Some(54..74));
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.focus(), Pane::Explain);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.focus(), Pane::Bytes);
    key(&mut app, KeyCode::BackTab);
    assert_eq!(app.focus(), Pane::Explain);
    app.on_event(Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT)));
    assert_eq!(app.focus(), Pane::Layers);
    key(&mut app, KeyCode::Char('1'));
    key(&mut app, KeyCode::Char('t'));
    assert!(
        render(&mut app, 140, 40)
            .contains(&netmon::sys::local_time(ui_support::packets()[16].ts).unwrap())
    );
    key(&mut app, KeyCode::Char(' '));
    assert!(!app.paused());
    app.on_tick();
    assert_eq!(app.selected_packet(), Some(1));
}
#[test]
fn filter_errors_cancel_clear_and_conversation() {
    let mut app = app();
    key(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "port nope");
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.filter_input(), Some("port nope"));
    assert_eq!(app.filter_error().unwrap().position, 5);
    assert_eq!(app.store.visible_len(), 75);
    assert!(render(&mut app, 80, 24).contains("At byte 5"));
    key(&mut app, KeyCode::Esc);
    assert!(app.filter_input().is_none());
    key(&mut app, KeyCode::Char('/'));
    type_text(&mut app, "dns");
    key(&mut app, KeyCode::Enter);
    app.on_tick();
    assert_eq!(app.store.visible_len(), 8);
    key(&mut app, KeyCode::Char('c'));
    app.on_tick();
    assert_eq!(app.store.visible_len(), 75);
    app.select_packet(20);
    key(&mut app, KeyCode::Char('f'));
    app.on_tick();
    assert_eq!(app.store.visible_len(), 12);
    assert_eq!(app.selected_packet(), Some(20));
    assert!(app.store.filter_text().contains("port 51008"));
    assert!(app.store.filter_text().contains("port 18080"));
    key(&mut app, KeyCode::Char('/'));
    key(&mut app, KeyCode::Enter);
    app.on_tick();
    assert_eq!(app.store.visible_len(), 12);
}
#[test]
fn overlays_interfaces_mouse_and_small_terminal() {
    let mut app = app();
    let screen = render(&mut app, 140, 40);
    // Find a visible field rather than tying the mouse test to a pane height.
    let field_row = screen
        .lines()
        .position(|line| line.contains("▸ Flags:"))
        .unwrap();
    app.on_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 3,
        row: field_row as u16,
        modifiers: KeyModifiers::NONE,
    }));
    assert_eq!(app.focus(), Pane::Layers);
    assert_eq!(app.selected_range(), Some(46..48));
    app.on_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 3,
        row: 2,
        modifiers: KeyModifiers::NONE,
    }));
    assert_eq!(app.focus(), Pane::Packets);
    // The first visible row begins at y=5: two header lines, tab, border, column labels.
    app.on_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 12,
        row: 5,
        modifiers: KeyModifiers::NONE,
    }));
    assert!(app.selected_packet().unwrap() <= 17);
    assert_eq!(app.focus(), Pane::Packets);
    app.on_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 10,
        row: 5,
        modifiers: KeyModifiers::NONE,
    }));
    let moved = app.selected_packet();
    assert_ne!(moved, Some(17));
    key(&mut app, KeyCode::Char('?'));
    assert_eq!(app.overlay(), Some(&Overlay::Help));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('g'));
    type_text(&mut app, "ttl");
    assert!(render(&mut app, 140, 40).contains("TTL"));
    key(&mut app, KeyCode::Backspace);
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('i'));
    assert!(app.overlay().is_none());
    let mut live = App::new("lo", true, 42);
    key(&mut live, KeyCode::Char('i'));
    assert!(live.take_interfaces_request());
    live.set_interfaces(Ok(vec![
        netmon::live::Interface {
            name: "lo".into(),
            description: "Loopback".into(),
        },
        netmon::live::Interface {
            name: "eth0".into(),
            description: "".into(),
        },
    ]));
    key(&mut live, KeyCode::Down);
    key(&mut live, KeyCode::Enter);
    assert_eq!(live.take_interface_request(), Some("eth0".into()));
    live.restart("eth0");
    assert_eq!(live.store.max_packets(), 42);
    assert!(live.store.is_empty());
    let small = render(&mut app, 50, 10);
    assert!(small.contains("Terminal too small"));
    assert!(!small.contains("Layers"));
    assert!(screen.contains("What is happening"));
}
#[test]
fn selected_bytes_are_highlighted_and_sensitive_headers_are_masked() {
    let mut selected = app();
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| selected.draw(f)).unwrap();
    let highlighted: Vec<_> = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .filter(|c| c.bg == ratatui::style::Color::Cyan)
        .map(|c| c.symbol())
        .collect();
    assert!(highlighted.join("").contains("a002"));
    // Raw IP / TCP followed by an HTTP request with a known secret.
    let mut packet = ui_support::packets()[19].clone();
    let payload=b"GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic UNIQUE_SECRET\r\nCookie: UNIQUE_COOKIE\r\n\r\n";
    packet.data.truncate(66);
    packet.data.extend_from_slice(payload);
    packet.orig_len = packet.data.len() as u32;
    let length = u16::try_from(packet.data.len().checked_sub(14).unwrap()).unwrap();
    packet
        .data
        .get_mut(16..18)
        .unwrap()
        .copy_from_slice(&length.to_be_bytes());
    let mut app = App::new("secret-test", false, 10);
    app.push(packet);
    app.on_tick();
    app.select_field(Proto::Http, FieldKey::HttpHeader);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Tab);
    // Inspect every byte row by scrolling, rather than only the first viewport.
    let mut all = String::new();
    for _ in 0..15 {
        all.push_str(&render(&mut app, 140, 40));
        key(&mut app, KeyCode::Down);
    }
    assert!(!all.contains("UNIQUE_SECRET"));
    assert!(!all.contains("UNIQUE_COOKIE"));
    assert!(all.contains("** **"));
}
#[test]
fn empty_failure_and_external_text_are_readable_and_safe() {
    let mut app = App::new("bad\x1b[2J", true, 10);
    assert!(render(&mut app, 80, 24).contains("Waiting for packets"));
    app.on_message(Message::Failed("denied\x1b[2J".into()));
    let screen = render(&mut app, 100, 30);
    assert!(screen.contains("denied\\x1B[2J"));
    assert!(!screen.contains('\x1b'));
    let mut file = App::new("empty", false, 10);
    file.on_message(Message::Ended);
    assert!(render(&mut file, 80, 24).contains("This capture contains no packets"));
    file.on_message(Message::Failed("not a capture".into()));
    let screen = render(&mut file, 100, 30);
    assert!(screen.contains("Check that the file exists"));
    assert!(!screen.contains("Press i"));
}
#[test]
fn unchanged_conversation_filter_keeps_exact_endpoint_pairs() {
    let first = ui_support::packets().remove(16);
    let mut different = first.clone();
    different.number = 18;
    different
        .data
        .get_mut(34..36)
        .unwrap()
        .copy_from_slice(&18080u16.to_be_bytes());
    different
        .data
        .get_mut(36..38)
        .unwrap()
        .copy_from_slice(&51008u16.to_be_bytes());
    let mut app = App::new("endpoint-pairs", false, 10);
    app.push(first);
    app.push(different);
    app.on_tick();
    app.select_packet(17);
    key(&mut app, KeyCode::Char('f'));
    app.on_tick();
    assert_eq!(app.store.visible_len(), 1);
    key(&mut app, KeyCode::Char('/'));
    key(&mut app, KeyCode::Enter);
    app.on_tick();
    assert_eq!(app.store.visible_len(), 1);
}
#[test]
fn packet_numbers_keep_all_digits_after_long_captures() {
    let mut packet = ui_support::packets().remove(0);
    packet.number = u64::MAX;
    let mut screen = App::new("long-capture", false, 1);
    screen.push(packet);
    screen.on_tick();
    for (width, height) in [(140, 40), (100, 30), (80, 24)] {
        assert!(render(&mut screen, width, height).contains(&u64::MAX.to_string()));
    }
}
#[test]
fn fixed_seed_twenty_thousand_events_do_not_panic() {
    let mut app = app();
    let mut state = 0x6e65746d6f6e_u64;
    let keys = [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Backspace,
        KeyCode::Char('/'),
        KeyCode::Char('?'),
        KeyCode::Char('g'),
        KeyCode::Char(' '),
        KeyCode::Char('f'),
        KeyCode::Char('c'),
        KeyCode::Char('t'),
        KeyCode::Char('i'),
        KeyCode::Char('q'),
        KeyCode::Char('('),
        KeyCode::Char('a'),
    ];
    for i in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if state & 3 == 0 {
            app.on_event(Event::Mouse(MouseEvent {
                kind: match (state >> 2) % 3 {
                    0 => MouseEventKind::Down(MouseButton::Left),
                    1 => MouseEventKind::ScrollUp,
                    _ => MouseEventKind::ScrollDown,
                },
                column: (state >> 16) as u16 % 180,
                row: (state >> 32) as u16 % 60,
                modifiers: KeyModifiers::NONE,
            }));
        } else {
            key(&mut app, keys[(state as usize) % keys.len()]);
        }
        app.on_tick();
        if i % 20 == 0 {
            let (width, height) = match (state >> 40) % 4 {
                0 => (140, 40),
                1 => (100, 30),
                2 => (80, 24),
                _ => (50, 10),
            };
            render(&mut app, width, height);
        }
    }
    assert!(app.store.len() <= 200_000);
}
#[test]
fn cli_screen_modes_and_interface_failures_are_clean() {
    for args in [
        vec![],
        vec!["-r", "tests/fixtures/loopback-mixed.pcapng"],
        vec!["-i", "lo"],
        vec!["-f", "port 53", "--max-packets", "20"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "netmon: the screen needs a terminal; try: netmon explain <file>\n"
        );
    }
    // A missing executable tests interfaces without invoking real dumpcap.
    let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
        .arg("interfaces")
        .env("PATH", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("Wireshark"));
    assert!(error.contains("wireshark group"));
    let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
        .args([
            "-r",
            "tests/fixtures/loopback-mixed.pcapng",
            "--max-packets",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("between 1 and 200000")
    );
}

#[path = "ui_support/privacy.rs"]
mod privacy;
