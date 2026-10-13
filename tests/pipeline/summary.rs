//! Check report caps and the packet-time report schedule.
//! Readable fixture output belongs to fixture.rs; counters live in the pipeline.
//! Read summaries_follow_sixty_second_packet_time_and_replace_atomically first.

use crate::pipeline_support::*;
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

#[test]
fn summaries_follow_sixty_second_packet_time_and_replace_atomically() {
    let base = TestDir::new();
    let mut pipeline = configured(Some(&base), Duration::ZERO);
    pipeline.push(&udp(1, 1234, false, b"data"));
    let dir = pipeline.session().unwrap().dir().to_path_buf();
    pipeline.tick(Duration::from_secs(59));
    assert!(!dir.join("summary.md").exists());
    pipeline.tick(Duration::from_secs(60));
    let first = fs::read_to_string(dir.join("summary.md")).unwrap();
    assert!(first.contains("capture in progress"));
    assert_eq!(
        fs::metadata(dir.join("summary.md"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut raw = udp(2, 1235, false, b"data");
    raw.ts = Duration::from_secs(61);
    pipeline.push(&raw);
    pipeline.tick(raw.ts);
    pipeline.tick(Duration::from_secs(1));
    assert_eq!(fs::read_to_string(dir.join("summary.md")).unwrap(), first);
    fs::hard_link(dir.join("summary.md"), base.path().join("old-summary")).unwrap();
    pipeline.tick(Duration::from_secs(120));
    let second = fs::read_to_string(dir.join("summary.md")).unwrap();
    assert_ne!(second, first);
    assert_eq!(
        fs::read_to_string(base.path().join("old-summary")).unwrap(),
        first
    );
    pipeline.finish();
    assert!(
        !fs::read_to_string(dir.join("summary.md"))
            .unwrap()
            .contains("capture in progress")
    );
    assert!(!fs::read_dir(&dir).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[test]
fn summary_keeps_fifty_largest_conversations_one_hundred_dns_and_fifty_problems() {
    let base = TestDir::new();
    let mut pipeline = configured(Some(&base), Duration::ZERO);
    for n in 1..=65 {
        pipeline.push(&udp(n, 10000 + n as u16, false, &vec![0; n as usize]));
    }
    for n in 0..110 {
        pipeline.push(&dns(1000 + 2 * n, false, "missing.test", 0));
        pipeline.push(&dns(1001 + 2 * n, true, "missing.test", 3));
    }
    pipeline.finish();
    let dir = pipeline.session().unwrap().dir();
    let report = fs::read_to_string(dir.join("summary.md")).unwrap();
    check_tables(&report);
    let conversations = report
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
        52
    );
    assert!(conversations.contains("16 more finished conversations"));
    assert!(conversations.contains("10065"));
    assert!(!conversations.contains("10001"));
    let dns = report
        .split("## DNS lookups")
        .nth(1)
        .unwrap()
        .split("## Problems")
        .next()
        .unwrap();
    assert_eq!(
        dns.lines().filter(|line| line.starts_with('|')).count(),
        102
    );
    let problems = report
        .split("## Problems")
        .nth(1)
        .unwrap()
        .split("## Files")
        .next()
        .unwrap();
    assert_eq!(
        problems
            .lines()
            .filter(|line| line.starts_with("- Packet"))
            .count(),
        50
    );
    assert_eq!(json_lines(dir, "flows.jsonl").len(), 66);
}
