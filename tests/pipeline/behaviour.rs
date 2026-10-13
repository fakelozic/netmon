//! Check alert delivery, timeouts, failure recovery and secret-free output.
//! Fixture comparisons live in fixture.rs; packet builders live in pipeline_support.
//! Read alerts_reach_rows_and_both_log_formats first.

use crate::pipeline_support::*;
use netmon::{flow::FlowState, pipeline::Pipeline};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

#[test]
fn json_keeps_the_exact_flow_status_while_markdown_uses_readable_punctuation() {
    let base = TestDir::new();
    let mut pipeline = configured(Some(&base), Duration::ZERO);
    pipeline.push(&tcp(1, false, [40000, 80], 0x18, b"data"));
    pipeline.push(&tcp(2, true, [40000, 80], 4, &[]));
    pipeline.finish();
    let dir = pipeline.session().unwrap().dir();
    let rows = json_lines(dir, "flows.jsonl");
    assert_eq!(
        rows[0].field("end"),
        Some(&string("reset by the peer · capture starts mid-connection"))
    );
    let report = fs::read_to_string(dir.join("summary.md")).unwrap();
    assert!(report.contains("reset by the peer; capture starts mid-connection"));
}

#[test]
fn alerts_reach_rows_and_both_log_formats() {
    let base = TestDir::new();
    let mut pipeline = configured(Some(&base), Duration::ZERO);
    let mut triggers = Vec::new();
    for port in 1..=25 {
        let row = pipeline.push(&tcp(u64::from(port), false, [40000, port], 2, &[]));
        if row.alerts > 0 {
            assert!(row.problem);
            triggers.push(row.number);
        }
    }
    assert_eq!(triggers, vec![20]);
    assert_eq!(pipeline.alert_count(), 1);
    assert_eq!(pipeline.recent_alerts().count(), 1);
    pipeline.finish();
    let dir = pipeline.session().unwrap().dir();
    assert_eq!(json_lines(dir, "alerts.jsonl").len(), 1);
    let events = fs::read_to_string(dir.join("events.md")).unwrap();
    assert_eq!(events.matches(" | **Alert** | ").count(), 1);
}

#[test]
fn tick_and_packet_time_jumps_log_udp_timeout_once() {
    for explicit in [true, false] {
        let base = TestDir::new();
        let mut pipeline = configured(Some(&base), Duration::ZERO);
        let row = pipeline.push(&udp(1, 1234, false, b"data"));
        let now = Duration::from_secs(61);
        if explicit {
            pipeline.tick(now);
        } else {
            let mut raw = ip(2, 99, false, b"opaque");
            raw.ts = now;
            pipeline.push(&raw);
        }
        assert_eq!(
            pipeline.tracker().flow(row.flow.unwrap()).unwrap().state,
            FlowState::Idle
        );
        pipeline.tick(now);
        pipeline.finish();
        let dir = pipeline.session().unwrap().dir();
        assert_eq!(json_lines(dir, "flows.jsonl").len(), 1);
        let events = fs::read_to_string(dir.join("events.md")).unwrap();
        assert_eq!(events.matches(" | Close | ").count(), 1);
        assert!(events.contains("timeout"));
    }
}

#[test]
fn credentials_never_reach_any_session_file() {
    let base = TestDir::new();
    let mut opts = options(Some(&base));
    opts.alerts.repeat_after = Duration::ZERO;
    let mut pipeline = Pipeline::new(opts, Duration::ZERO);
    pipeline.push(&tcp(1,false,[40000,80],0x18,b"GET / HTTP/1.1\r\nHost: netmon.test\r\nAuthorization: Basic bGVhcm5lci1sb2dpbjpwYWNrZXQtc2VjcmV0\r\n\r\n"));
    pipeline.push(&tcp(2, false, [40001, 21], 0x18, b"USER learner-login\r\n"));
    pipeline.push(&tcp(3, false, [40001, 21], 0x18, b"PASS packet-secret\r\n"));
    pipeline.finish();
    for entry in fs::read_dir(pipeline.session().unwrap().dir()).unwrap() {
        let content = fs::read_to_string(entry.unwrap().path()).unwrap();
        for secret in [
            "learner-login",
            "packet-secret",
            "bGVhcm5lci1sb2dpbjpwYWNrZXQtc2VjcmV0",
        ] {
            assert!(!content.contains(secret), "secret in {content}");
        }
    }
    assert_eq!(pipeline.alert_count(), 3);
}

#[test]
fn read_only_session_does_not_stop_push_and_preserves_first_problem() {
    let base = TestDir::new();
    let mut pipeline = configured(Some(&base), Duration::ZERO);
    pipeline.push(&tcp(1, false, [40000, 80], 2, &[]));
    let dir = pipeline.session().unwrap().dir().to_path_buf();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let row = pipeline.push(&tcp(2, true, [40000, 80], 0x14, &[]));
    assert!(row.problem);
    let problem = pipeline.problem().unwrap().to_owned();
    assert!(problem.starts_with("Cannot write flows.jsonl:"));
    pipeline.finish();
    assert_eq!(pipeline.problem(), Some(problem.as_str()));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn disabled_logging_and_creation_failure_still_return_full_rows() {
    let base = TestDir::new();
    let mut opts = options(None);
    opts.record = true;
    let before = fs::read_dir(base.path()).unwrap().count();
    let mut pipeline = Pipeline::new(opts, START);
    let row = pipeline.push(&tcp(1, false, [40000, 80], 2, &[]));
    assert!(row.flow.is_some());
    assert!(row.direction.is_some());
    assert_eq!(row.src_label, "10.0.0.1:40000");
    assert_eq!(row.dst_label, "10.0.0.2:80");
    pipeline.finish();
    assert!(pipeline.session().is_none());
    assert_eq!(fs::read_dir(base.path()).unwrap().count(), before);
    let blocked = base.path().join("blocked");
    fs::write(&blocked, "file").unwrap();
    let mut opts = options(Some(&base));
    opts.log.as_mut().unwrap().base = blocked;
    let mut pipeline = Pipeline::new(opts, START);
    assert!(
        pipeline
            .push(&tcp(1, false, [40000, 80], 2, &[]))
            .flow
            .is_some()
    );
    assert!(
        pipeline
            .problem()
            .unwrap()
            .starts_with("Cannot create the log session:")
    );
}

#[test]
fn alert_ring_keeps_newest_thousand_but_counts_every_alert() {
    let mut opts = options(None);
    opts.alerts.repeat_after = Duration::ZERO;
    let mut pipeline = Pipeline::new(opts, Duration::ZERO);
    for number in 1..=1100 {
        pipeline.push(&tcp(
            number,
            false,
            [40000, 80],
            0x18,
            b"GET / HTTP/1.1\r\nAuthorization: Basic hidden\r\n\r\n",
        ));
    }
    let alerts = pipeline.recent_alerts().collect::<Vec<_>>();
    assert_eq!(pipeline.alert_count(), 1100);
    assert_eq!(alerts.len(), 1000);
    assert_eq!(alerts.first().unwrap().packet, 101);
    assert_eq!(alerts.last().unwrap().packet, 1100);
}
