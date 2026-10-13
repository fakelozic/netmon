//! Checks that private TCP bytes stay masked while scrolling the terminal.
//! Decoder privacy policy stays in decode; shared terminal rendering stays in ui.rs.
//! Read `split_credentials_and_query_values_stay_hidden` for synthetic secrets.
//! A TCP segment can contain credentials without a complete HTTP header.

use super::{key, render, ui_support};
use netmon::{
    decode::{FieldKey, Proto},
    ui::App,
};
use ratatui::crossterm::event::KeyCode;

#[test]
fn split_credentials_and_query_values_stay_hidden() {
    for payload in [
        b"audit-secret\r\n\r\n".as_slice(),
        b"GET /?password=audit-secret HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\npassword=audit-secret",
    ] {
        let mut raw = ui_support::packets()[19].clone();
        raw.data.truncate(66);
        raw.data.extend_from_slice(payload);
        raw.orig_len = raw.data.len() as u32;
        let len = u16::try_from(raw.data.len() - 14).unwrap();
        raw.data
            .get_mut(16..18)
            .unwrap()
            .copy_from_slice(&len.to_be_bytes());
        let mut app = App::new("synthetic-private", false, 10);
        app.push(raw);
        app.on_tick();
        app.select_field(Proto::Tcp, FieldKey::TcpPayload);
        for _ in 0..3 {
            key(&mut app, KeyCode::Tab);
        }
        let mut output = String::new();
        for _ in 0..20 {
            output.push_str(&render(&mut app, 140, 40));
            key(&mut app, KeyCode::Down);
        }
        assert!(!output.contains("audit-secret"));
        assert!(output.contains("** **"));
    }
}
