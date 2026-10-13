//! Verifies publication controls without stopping packet processing.
//! Fixture schemas stay in fixture.rs; packet construction stays in pipeline_support.
//! Read `pause_keeps_capture_logs_and_recording_alive` for hidden arrivals.

use super::support::*;
use crate::{
    log_support::{TestDir, Value, string},
    pipeline_support::tcp,
};
use netmon::{live::Message, web::Method};
use std::{fs, path::Path};

#[test]
fn pause_keeps_capture_logs_and_recording_alive() {
    let dir = TestDir::new();
    let (_engine, api, send) = manual(Some(crate::log_support::options(dir.path())), 200000);
    send.send(Message::Packet(tcp(1, false, [50000, 80], 2, b"")))
        .unwrap();
    wait_packets(&api, 1);
    let first = get(&api, "flows", &[]);
    let id = num(&array(&first, "flows")[0], "id");
    let paused = control(&api, br#"{"action":"pause"}"#);
    assert_eq!(paused.field("ok"), Some(&Value::Bool(true)));
    assert_eq!(
        paused.field("session").unwrap().field("state"),
        Some(&string("paused"))
    );
    let recorded = control(&api, br#"{"action":"record_start"}"#);
    assert_eq!(
        recorded.field("session").unwrap().field("recording"),
        Some(&string("on"))
    );
    send.send(Message::Packet(tcp(2, true, [50000, 80], 18, b"")))
        .unwrap();
    send.send(Message::Packet(tcp(3, false, [50000, 80], 16, b"")))
        .unwrap();
    // Replies are serialized after capture draining: this control observes the
    // hidden packets internally while retaining the published pause watermark.
    let stopped = control(&api, br#"{"action":"record_stop"}"#);
    assert_eq!(
        stopped.field("session").unwrap().field("recording"),
        Some(&string("off"))
    );
    assert_eq!(num(&get(&api, "session", &[]), "packets"), 1);
    assert_eq!(array(&get(&api, "packets", &[]), "rows").len(), 1);
    assert_eq!(request(&api, Method::Get, "packet/2", &[], b"").status, 404);
    assert_eq!(get(&api, "flows", &[]), first);
    control(&api, br#"{"action":"resume"}"#);
    wait_packets(&api, 3);
    assert_eq!(array(&get(&api, "packets", &[]), "rows").len(), 3);
    let exported = control(
        &api,
        format!(r#"{{"action":"export_story","flow":{id}}}"#).as_bytes(),
    );
    let path = Path::new(text(&exported, "path"));
    let session = get(&api, "session", &[]);
    let folder = Path::new(text(&session, "log_dir"));
    assert_eq!(path.parent(), Some(folder));
    assert_eq!(path.extension().unwrap(), "md");
    assert!(
        fs::read_to_string(path)
            .unwrap()
            .starts_with("# Conversation")
    );
    assert!(folder.join("capture.pcapng").exists());
    send.send(Message::Ended).unwrap();
    for _ in 0..1000 {
        if text(&get(&api, "session", &[]), "state") == "ended" {
            break;
        }
    }
    let report = fs::read_to_string(folder.join("summary.md")).unwrap();
    assert!(report.contains("- Packets: 3"));
}
#[test]
fn invalid_actions_and_bodies() {
    let (_engine, api) = fixture();
    assert_eq!(
        request(
            &api,
            Method::Post,
            "control",
            &[],
            br#"{"action":"unknown"}"#
        )
        .status,
        400
    );
    for bad in [
        br#"{"action":"pause","action":"resume"}"#.as_slice(),
        br#"{"action":"pause","flow":3}"#,
        br#"{"action":"export_story","flow":-1}"#,
        br#"{"action":"pause"}bad"#,
        b"{}",
        br#"{"action":"pause","extra":true}"#,
    ] {
        assert_eq!(request(&api, Method::Post, "control", &[], bad).status, 400);
    }
}
#[test]
fn no_logging_controls_and_retention_errors() {
    let (_engine, api, send) = manual(None, 2);
    for number in 1..=3 {
        send.send(Message::Packet(tcp(number, false, [50000, 80], 2, b"")))
            .unwrap();
    }
    wait_packets(&api, 3);
    assert_eq!(num(&get(&api, "session", &[]), "dropped"), 1);
    assert_eq!(request(&api, Method::Get, "packet/1", &[], b"").status, 404);
    assert_eq!(
        array(&get(&api, "packets", &[]), "rows")
            .iter()
            .map(|r| num(r, "no"))
            .collect::<Vec<_>>(),
        [2, 3]
    );
    for body in [
        br#"{"action":"record_start"}"#.as_slice(),
        br#"{"action":"export_story","flow":1}"#,
    ] {
        let reply = request(&api, Method::Post, "control", &[], body);
        assert_eq!(reply.status, 400);
        assert!(reply.json.contains("Logging is off"));
    }
}
#[test]
fn scan_raises_one_complete_alert() {
    let (_engine, api, send) = manual(None, 200000);
    for number in 1..=25 {
        send.send(Message::Packet(tcp(
            number,
            false,
            [50000, number as u16],
            2,
            b"",
        )))
        .unwrap();
    }
    wait_packets(&api, 25);
    let alerts = get(&api, "alerts", &[]);
    assert_eq!(num(&alerts, "total"), 1);
    let row = &array(&alerts, "alerts")[0];
    keys(
        row,
        &[
            "id",
            "kind",
            "severity",
            "time",
            "clock",
            "title",
            "seen",
            "why",
            "next",
            "packet",
            "first_packet",
            "subject",
        ],
    );
    assert_eq!(text(row, "kind"), "port_scan");
    assert_eq!(num(row, "packet"), 20);
    assert_eq!(num(row, "first_packet"), 1);
}
