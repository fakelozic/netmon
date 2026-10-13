//! Check private session output against its file contract.
//! Raw recording checks live in `record.rs`; syntax parsing lives in `log_support`.
//! Start with `private_unique_sessions_lazy_files_and_exact_event_lines`.

use crate::log_support::{START, TestDir, Value, number, options, packets, parse, string};
use netmon::capture::{LinkType, RawPacket, Reader};
use netmon::decode::{Detail, decode};
use netmon::explain;
use netmon::log::{Clock, EventKind, Options, Recording, Session, default_base, utc_clock};
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

fn local_clock(_: Duration) -> Clock {
    // A constant injected clock isolates formatting from the machine's timezone.
    Clock {
        year: 2026,
        month: 10,
        day: 12,
        hour: 19,
        minute: 32,
        second: 11,
        millis: 812,
    }
}

#[test]
fn defaults_match_environment_and_decimal_200_mb() {
    let expected = if let Some(base) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty())
    {
        PathBuf::from(base).join("netmon")
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| ".".into()),
        )
        .join(".local/state/netmon")
    };
    assert_eq!(default_base(), expected);
    let defaults = Options::default();
    assert!(defaults.utc);
    assert!(!defaults.log_packets);
    assert_eq!(defaults.max_capture_bytes, 200_000_000);
    assert_eq!((defaults.clock)(START), utc_clock(START));
}

#[test]
fn private_unique_sessions_lazy_files_and_exact_event_lines() {
    let base = TestDir::new();
    let mut s = Session::create(options(base.path()), START).unwrap();
    assert_eq!(s.dir().file_name().unwrap(), "20261012-140211Z");
    assert_eq!(
        fs::metadata(s.dir()).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(fs::read_dir(s.dir()).unwrap().count(), 0);
    s.flush();
    assert_eq!(fs::read_dir(s.dir()).unwrap().count(), 0);
    assert_eq!(s.recording(), Recording::Off);
    let second = Session::create(options(base.path()), START).unwrap();
    assert_eq!(second.dir().file_name().unwrap(), "20261012-140211Z-2");
    let third = Session::create(options(base.path()), START).unwrap();
    assert_eq!(third.dir().file_name().unwrap(), "20261012-140211Z-3");
    for kind in [
        EventKind::Open,
        EventKind::Close,
        EventKind::Dns,
        EventKind::Alert,
        EventKind::Note,
    ] {
        s.event(START, kind, "hello");
    }
    s.event(START, EventKind::Note, "a\nb\x1b\r\t");
    s.flush();
    let output = fs::read_to_string(s.dir().join("events.md")).unwrap();
    assert_eq!(
        output,
        concat!(
            "# netmon events\n\nStarted: 2026-10-12T14:02:11.812Z\n\n",
            "| Time | Kind | What happened |\n| --- | --- | --- |\n",
            "| 14:02:11.812 | Open | hello |\n",
            "| 14:02:11.812 | Close | hello |\n",
            "| 14:02:11.812 | DNS | hello |\n",
            "| 14:02:11.812 | **Alert** | hello |\n",
            "| 14:02:11.812 | Note | hello |\n",
            "| 14:02:11.812 | Note | a b\\\\x1B \\\\x09 |\n"
        )
    );
    assert!(output.lines().all(|line| line.bytes().all(|b| b >= 0x20)));
    assert_eq!(fs::read_dir(s.dir()).unwrap().count(), 1);
    assert_eq!(
        fs::metadata(s.dir().join("events.md"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(s.problem(), None);
}

#[test]
fn supplied_local_clock_has_no_z_and_drives_all_timestamps() {
    let base = TestDir::new();
    let mut config = options(base.path());
    config.clock = local_clock;
    config.utc = false;
    let mut s = Session::create(config, START).unwrap();
    assert_eq!(s.dir().file_name().unwrap(), "20261012-193211");
    s.event(START, EventKind::Note, "local");
    let raw = packets("loopback-mixed.pcapng").remove(0);
    s.packet(
        &raw,
        &decode(raw.link, &raw.data, raw.orig_len, Detail::Summary),
        "local",
    );
    s.flush();
    let line = fs::read_to_string(s.dir().join("packets.jsonl")).unwrap();
    assert_eq!(
        parse(line.trim_end()).unwrap().field("time"),
        Some(&string("2026-10-12T19:32:11.812"))
    );
    assert_eq!(
        fs::read_to_string(s.dir().join("events.md")).unwrap(),
        concat!(
            "# netmon events\n\nStarted: 2026-10-12T19:32:11.812\n\n",
            "| Time | Kind | What happened |\n| --- | --- | --- |\n",
            "| 19:32:11.812 | Note | local |\n"
        )
    );
}

#[test]
fn json_lines_refuse_line_breaks_and_keep_other_files_working() {
    let base = TestDir::new();
    let mut s = Session::create(options(base.path()), START).unwrap();
    s.flow_line("{}\n{}");
    assert!(!s.dir().join("flows.jsonl").exists());
    assert_eq!(
        s.problem(),
        Some("Cannot write flows.jsonl: a JSON line contains a line break.")
    );
    s.alert_line("{}\r{}");
    assert!(!s.dir().join("alerts.jsonl").exists());
    // Rejection must leave the writer usable; only an I/O failure disables it.
    s.flow_line("{\"a\":1}");
    s.flow_line("{\"a\":2}");
    s.alert_line("{\"alert\":true}");
    s.flush();
    assert_eq!(
        fs::read_to_string(s.dir().join("flows.jsonl")).unwrap(),
        "{\"a\":1}\n{\"a\":2}\n"
    );
    assert_eq!(
        fs::read_to_string(s.dir().join("alerts.jsonl")).unwrap(),
        "{\"alert\":true}\n"
    );
    assert_eq!(
        s.problem(),
        Some("Cannot write flows.jsonl: a JSON line contains a line break.")
    );
}

#[test]
fn base_file_and_read_only_session_fail_without_disabling_other_files() {
    let base = TestDir::new();
    let bad = base.path().join("file");
    fs::write(&bad, b"unchanged").unwrap();
    assert!(Session::create(options(&bad), START).is_err());
    assert_eq!(fs::read(bad).unwrap(), b"unchanged");
    let mut s = Session::create(options(base.path()), START).unwrap();
    // An already-open file remains writable when the directory loses write permission.
    s.alert_line("{\"open\":true}");
    fs::set_permissions(s.dir(), Permissions::from_mode(0o500)).unwrap();
    s.event(START, EventKind::Note, "cannot create");
    assert!(s.problem().unwrap().starts_with("Cannot write events.md:"));
    let problem = s.problem().unwrap().to_owned();
    assert_eq!(s.start_recording(), Recording::Failed);
    assert!(s.export_markdown("failure", "hello").is_err());
    s.alert_line("{\"still\":true}");
    s.flush();
    assert_eq!(
        fs::read_to_string(s.dir().join("alerts.jsonl")).unwrap(),
        "{\"open\":true}\n{\"still\":true}\n"
    );
    fs::set_permissions(s.dir(), Permissions::from_mode(0o700)).unwrap();
    s.event(START, EventKind::Note, "disabled");
    assert!(!s.dir().join("events.md").exists());
    s.flow_line("{\"other\":true}");
    s.flush();
    assert!(s.dir().join("flows.jsonl").is_file());
    assert_eq!(s.problem(), Some(problem.as_str()));
}

#[test]
fn exports_sanitise_stems_bound_length_preserve_lines_and_do_not_overwrite() {
    let base = TestDir::new();
    let mut s = Session::create(options(base.path()), START).unwrap();
    for (stem, expected) in [
        ("../../etc/x", "etcx.md"),
        ("a/b", "ab.md"),
        ("", "export.md"),
        ("..", "export-2.md"),
        ("a-_9", "a-_9.md"),
    ] {
        let path = s.export_markdown(stem, "first\nsecond\x1b").unwrap();
        assert_eq!(path.parent(), Some(s.dir()));
        assert_eq!(path.file_name().unwrap(), expected);
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\\x1B");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    let long = s.export_markdown(&"a".repeat(300), "long").unwrap();
    assert_eq!(long.file_name().unwrap().len(), 203);
    assert_eq!(long.parent(), Some(s.dir()));
    let second = s.export_markdown("a/b", "new").unwrap();
    assert_eq!(second.file_name().unwrap(), "ab-2.md");
    assert_eq!(
        fs::read_to_string(s.dir().join("ab.md")).unwrap(),
        "first\nsecond\\x1B"
    );
    assert_eq!(s.problem(), None);
}

#[test]
fn packets_jsonl_has_75_valid_lines_and_task01_dns_sentence() {
    let base = TestDir::new();
    let mut s = Session::create(options(base.path()), START).unwrap();
    let original = packets("loopback-mixed.pcapng");
    for raw in &original {
        let d = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        s.packet(raw, &d, &explain::sentence(&d));
    }
    s.flush();
    let output = fs::read_to_string(s.dir().join("packets.jsonl")).unwrap();
    let parsed = output
        .lines()
        .map(|line| parse(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(parsed.len(), 75);
    for (row, raw) in parsed.iter().zip(&original) {
        assert_eq!(row.field("no"), Some(&number(raw.number)));
        assert_eq!(row.field("bytes"), Some(&number(raw.orig_len)));
        assert!(
            matches!(row.field("time"), Some(Value::String(t)) if t.ends_with('Z') && t.contains('T'))
        );
        assert_eq!(row.field("payload"), None);
        assert_eq!(row.field("data"), None);
    }
    // DNS asks for an address using a hostname. The synthetic fixture's ninth
    // packet is a known query, which checks the decoder-to-log wording boundary.
    assert_eq!(parsed[8].field("proto"), Some(&string("DNS")));
    assert_eq!(
        parsed[8].field("info"),
        Some(&string("Asks: what is the IPv4 address of example.com?"))
    );
    assert_eq!(parsed[8].field("src"), Some(&string("127.0.0.2")));
    assert_eq!(parsed[8].field("src_port"), Some(&number(55_921)));
    assert_eq!(parsed[8].field("dst"), Some(&string("127.0.0.53")));
    assert_eq!(parsed[8].field("dst_port"), Some(&number(53)));
    assert_eq!(parsed[0].field("src_port"), None);
    assert_eq!(parsed[0].field("dst_port"), None);
}

#[test]
fn packets_omit_missing_fields_hide_secrets_and_drop_flushes_every_writer() {
    let base = TestDir::new();
    let dir = {
        let mut s = Session::create(options(base.path()), START).unwrap();
        let raw = RawPacket {
            number: 1,
            ts: START,
            link: LinkType::Other(999),
            iface: 0,
            orig_len: 17,
            data: b"RAW_SECRET".to_vec(),
        };
        let d = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        s.packet(&raw, &d, "a\nb\x1b");
        s.event(START, EventKind::Note, "drop");
        s.flow_line("{}");
        s.alert_line("{}");
        s.start_recording();
        s.record(&raw);
        // End the scope without an explicit flush to exercise every writer's drop path.
        s.dir().to_path_buf()
    };
    let output = fs::read_to_string(dir.join("packets.jsonl")).unwrap();
    let row = parse(output.trim_end()).unwrap();
    assert_eq!(row.field("info"), Some(&string("a\\x0Ab\\x1B")));
    assert_eq!(row.field("time"), Some(&string("2026-10-12T14:02:11.812Z")));
    for key in ["src", "dst", "src_port", "dst_port"] {
        assert_eq!(row.field(key), None);
    }
    assert!(!output.contains("RAW_SECRET"));
    assert_eq!(fs::read_to_string(dir.join("flows.jsonl")).unwrap(), "{}\n");
    assert_eq!(
        fs::read_to_string(dir.join("alerts.jsonl")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        Reader::open(&dir.join("capture.pcapng")).unwrap().count(),
        1
    );
    for entry in fs::read_dir(&dir).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    let mut config = options(base.path());
    config.log_packets = false;
    let mut s = Session::create(config, START).unwrap();
    let raw = packets("loopback-mixed.pcapng").remove(0);
    let d = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
    s.packet(&raw, &d, "unused");
    s.flush();
    assert!(!s.dir().join("packets.jsonl").exists());
}
