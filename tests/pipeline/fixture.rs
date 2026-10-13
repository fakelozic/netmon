//! Check fixture rows and the complete readable log contract.
//! Packet builders belong to `pipeline_support`; hostile inputs have separate checks.
//! Read rows_match_conversation_golden_and_exact_problem_packets first.

use crate::pipeline_support::*;
use std::fs;

#[test]
fn rows_match_conversation_golden_and_exact_problem_packets() {
    let packets = packets("loopback-mixed.pcapng");
    let mut pipeline = configured(None, packets[0].ts);
    let expected = fs::read_to_string("tests/golden/flows-loopback-list.txt").unwrap();
    let mut problems = Vec::new();
    for (raw, expected) in packets.iter().zip(expected.lines().skip(1)) {
        let row = pipeline.push(raw);
        let sentence = expected.get(82..).unwrap();
        assert_eq!(row.sentence, sentence, "packet {}", raw.number);
        assert_eq!(row.number, raw.number);
        assert_eq!(row.ts, raw.ts);
        assert!(row.app.is_none());
        if row.problem {
            problems.push(row.number);
        }
    }
    assert_eq!(packets.len(), 75);
    assert_eq!(problems, vec![16, 73, 75]);
    assert_eq!(pipeline.tracker().flows().count(), 12);
}

#[test]
fn fixture_events_json_and_all_six_summary_sections_match_reviewed_goldens() {
    let base = TestDir::new();
    let packets = packets("loopback-mixed.pcapng");
    let mut pipeline = configured(Some(&base), packets[0].ts);
    for raw in &packets {
        pipeline.push(raw);
    }
    pipeline.finish();
    pipeline.finish();
    assert_eq!(pipeline.problem(), None);
    let dir = pipeline.session().unwrap().dir();
    let events = fs::read_to_string(dir.join("events.md")).unwrap();
    for (kind, count) in [("Open", 12), ("Close", 12), ("DNS", 4), ("**Alert**", 0)] {
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains(&format!(" | {kind} | ")))
                .count(),
            count
        );
    }
    check_tables(&events);
    golden("pipeline-events.md", &events);
    let flows = json_lines(dir, "flows.jsonl");
    assert_eq!(flows.len(), 12);
    let tls = flows
        .iter()
        .find(|row| row.field("tls") == Some(&string("1.3")))
        .unwrap();
    assert_eq!(tls.field("host"), Some(&string("netmon.test")));
    assert_eq!(tls.field("end"), Some(&string("closed normally")));
    let tracked = pipeline
        .tracker()
        .flows()
        .find(|flow| flow.server_name.as_deref() == Some("netmon.test"))
        .unwrap();
    assert_eq!(
        tls.field("up_bytes"),
        Some(&number(tracked.payload_bytes[0]))
    );
    assert_eq!(
        tls.field("down_bytes"),
        Some(&number(tracked.payload_bytes[1]))
    );
    assert!(!dir.join("alerts.jsonl").exists());
    assert_eq!(json_lines(dir, "packets.jsonl").len(), 75);
    let summary = fs::read_to_string(dir.join("summary.md")).unwrap();
    check_summary_sections(&summary);
    check_tables(&summary);
    golden("pipeline-summary.md", &summary);
}

fn check_summary_sections(summary: &str) {
    let headings = summary
        .lines()
        .filter(|line| line.starts_with("## "))
        .collect::<Vec<_>>();
    assert_eq!(
        headings,
        vec![
            "## Alerts",
            "## Conversations",
            "## DNS lookups",
            "## Problems",
            "## Files in this folder"
        ]
    );
    assert!(summary.starts_with("# netmon session summary\n"));
    let conversations = summary
        .split("## Conversations")
        .nth(1)
        .unwrap()
        .split("## DNS lookups")
        .next()
        .unwrap();
    assert_eq!(
        conversations
            .lines()
            .filter(|line| line.starts_with('|'))
            .count(),
        14
    );
    let dns = summary
        .split("## DNS lookups")
        .nth(1)
        .unwrap()
        .split("## Problems")
        .next()
        .unwrap();
    assert_eq!(dns.lines().filter(|line| line.starts_with('|')).count(), 6);
}
