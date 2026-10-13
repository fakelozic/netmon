//! Regressions from the server contract and privacy audit.
//! General endpoint coverage stays in fixture; byte builders stay in pipeline_support.
//! Read `private_payloads_never_reach_readable_outputs` for synthetic credentials.
//! A TCP segment can contain only the tail of a credential from an earlier packet.

use super::support::*;
use crate::{
    log_support::{TestDir, Value},
    pipeline_support::tcp,
};
use netmon::{
    decode::{self, Detail},
    live::Message,
    render::{self, Mode},
    web::Method,
};

#[test]
fn private_payloads_never_reach_readable_outputs() {
    let mut many_headers = b"GET / HTTP/1.1\r\n".to_vec();
    for _ in 0..256 {
        many_headers.extend_from_slice(b"X: harmless\r\n");
    }
    many_headers.extend_from_slice(b"Authorization: Basic audit-secret\r\n\r\n");
    for payload in [
        b"GET /?password=audit-secret HTTP/1.1\r\nHost: test\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nAuthorization: audit-secret trailing\r\n\r\n",
        b"GET / HTTP/1.1\r\nX-Password: audit-secret\r\nX-Api-Key: audit-secret\r\nX-Auth-Token: audit-secret\r\n\r\n",
        b"GET / HTTP/1.1\r\nAuthoriz",
        b"ation: Basic audit-secret\r\n\r\n",
        b"GET / HTTP/1.1\r\n\tCookie: audit-secret\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\npassword=audit-secret",
        b"PASS audit-secret\r\n",
        b"audit-secret",
        &many_headers,
    ] {
        let dir = TestDir::new();
        let mut logs = crate::log_support::options(dir.path());
        logs.log_packets = true;
        let (mut engine, api, send) = manual(Some(logs), 100);
        let raw = tcp(1, false, [50000, 80], 24, payload);
        let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Full);
        let rendered = render::packet(&raw, &decoded, raw.ts, Mode::Packet(1));
        assert!(!rendered.contains("audit-secret"), "{rendered}");
        send.send(Message::Packet(raw)).unwrap();
        wait_packets(&api, 1);
        let packet = get(&api, "packet/1", &[]);
        let bytes: Vec<_> = text(&packet, "hex")
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert!(!bytes.windows(12).any(|w| w == b"audit-secret"));
        for path in ["packet/1", "packets", "flows", "flow/1", "alerts"] {
            let reply = request(&api, Method::Get, path, &[], b"");
            assert_eq!(reply.status, 200);
            assert!(!reply.json.contains("audit-secret"), "{}", reply.json);
        }
        control(&api, br#"{"action":"export_story","flow":1}"#);
        let folder = text(&get(&api, "session", &[]), "log_dir").to_owned();
        engine.stop();
        for entry in std::fs::read_dir(folder).unwrap() {
            let file = entry.unwrap().path();
            assert!(
                !std::fs::read_to_string(&file)
                    .unwrap()
                    .contains("audit-secret"),
                "{file:?}"
            );
        }
    }
}

#[test]
fn packet_numbers_are_independent_of_story_and_time() {
    let (_engine, api, send) = manual(None, 1);
    for n in 1..=3 {
        let mut raw = tcp(n, false, [50000, 80], 16, b"");
        raw.ts = std::time::Duration::from_secs(100);
        send.send(Message::Packet(raw)).unwrap();
    }
    wait_packets(&api, 3);
    let flow = get(&api, "flow/1", &[]);
    assert_eq!(num(&flow, "first_packet"), 1);
    assert_eq!(num(&flow, "last_packet"), 3);
    assert_eq!(flow.field("duration_ms"), Some(&Value::Null));
    assert_eq!(num(&flow, "packets"), 3);
    assert!(array(&flow, "story").is_empty());
}

#[test]
fn inapplicable_addresses_are_explicit_null() {
    let (_engine, api, send) = manual(None, 1);
    let mut raw = tcp(1, false, [50000, 80], 16, b"");
    raw.data.clear();
    raw.ts = std::time::Duration::MAX;
    send.send(Message::Packet(raw)).unwrap();
    wait_packets(&api, 1);
    let packets = get(&api, "packets", &[]);
    let row = &array(&packets, "rows")[0];
    for key in [
        "src",
        "dst",
        "src_label",
        "dst_label",
        "app",
        "flow",
        "dir",
        "clock",
    ] {
        assert_eq!(row.field(key), Some(&Value::Null), "{key}");
    }
}

#[test]
fn pause_does_not_hide_a_full_recording() {
    let dir = TestDir::new();
    let mut logs = crate::log_support::options(dir.path());
    logs.max_capture_bytes = 28;
    let (_engine, api, send) = manual(Some(logs), 10);
    send.send(Message::Packet(tcp(1, false, [50000, 80], 2, b"")))
        .unwrap();
    wait_packets(&api, 1);
    control(&api, br#"{"action":"pause"}"#);
    assert_eq!(
        text(
            control(&api, br#"{"action":"record_start"}"#)
                .field("session")
                .unwrap(),
            "recording"
        ),
        "on"
    );
    send.send(Message::Packet(tcp(2, false, [50000, 80], 24, b"private")))
        .unwrap();
    let mut session = get(&api, "session", &[]);
    for _ in 0..1000 {
        if text(&session, "recording") == "full" {
            break;
        }
        session = get(&api, "session", &[]);
    }
    assert_eq!(text(&session, "recording"), "full");
    assert_eq!(num(&session, "packets"), 1);
    assert_eq!(text(&session, "state"), "paused");
}
