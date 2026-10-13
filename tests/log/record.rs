//! Check raw recording against the pcapng file contract.
//! Text log checks live in `session.rs`; fixture loading lives in `log_support`.
//! Start with `recording_fixture_round_trips_and_tshark_agrees_to_nanoseconds`.

use crate::log_support::{START, TestDir, fixture, options, packets};
use netmon::capture::{LinkType, RawPacket, Reader};
use netmon::log::{EventKind, Recording, Session};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn tshark_frames(path: &Path) -> Option<String> {
    let result = match Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(["-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len"])
        .output()
    {
        Ok(result) => result,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("tshark is not on PATH; logging recording cross-check skipped");
            return None;
        }
        Err(error) => panic!("cannot run tshark: {error}"),
    };
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(String::from_utf8(result.stdout).unwrap())
}

#[test]
fn recording_fixture_round_trips_and_tshark_agrees_to_nanoseconds() {
    // A separate capture reader helps catch timestamp-unit mistakes that a
    // writer and reader from the same crate might share.
    let base = TestDir::new();
    for name in ["loopback-mixed.pcapng", "cooked-any.pcapng"] {
        let original = packets(name);
        let mut s = Session::create(options(base.path()), START).unwrap();
        assert_eq!(s.start_recording(), Recording::On);
        assert_eq!(s.start_recording(), Recording::On);
        for p in &original {
            s.record(p);
        }
        s.stop_recording();
        let path = s.dir().join("capture.pcapng");
        let recorded = Reader::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(recorded.len(), original.len());
        for (actual, expected) in recorded.iter().zip(&original) {
            assert_eq!(
                (&actual.data, actual.orig_len, actual.link, actual.ts),
                (
                    &expected.data,
                    expected.orig_len,
                    expected.link,
                    expected.ts
                )
            );
        }
        assert_eq!(s.problem(), None);
        if let Some(expected) = tshark_frames(&fixture(name)) {
            assert_eq!(tshark_frames(&path).unwrap(), expected, "{name}");
        }
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
}

#[test]
fn capture_size_limit_rotates_and_stop_rotates() {
    let base = TestDir::new();
    let mut config = options(base.path());
    config.max_capture_bytes = 2_000;
    let mut s = Session::create(config, START).unwrap();
    assert_eq!(s.start_recording(), Recording::On);
    let original = packets("loopback-mixed.pcapng");
    for p in &original {
        s.record(p);
    }
    assert_eq!(s.recording(), Recording::Full);
    let path = s.dir().join("capture.pcapng");
    let len = fs::metadata(&path).unwrap().len();
    assert!(len <= 2_000);
    let recorded = Reader::open(&path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!recorded.is_empty() && recorded.len() < original.len());
    assert_eq!(&recorded, &original[..recorded.len()]);
    // The first rejected packet must explain Full, rather than an early cutoff.
    assert!(len + 32 + original[recorded.len()].data.len().div_ceil(4) as u64 * 4 > 2_000);
    assert_eq!(s.start_recording(), Recording::On);
    s.record(&original[0]);
    s.stop_recording();
    assert_eq!(s.recording(), Recording::Off);
    assert!(s.dir().join("capture-2.pcapng").is_file());
    assert_eq!(s.start_recording(), Recording::On);
    s.record(&original[0]);
    s.stop_recording();
    assert!(s.dir().join("capture-3.pcapng").is_file());
    assert_eq!(s.problem(), None);
}

#[test]
fn recording_mixed_link_types_and_exact_size_boundaries() {
    let base = TestDir::new();
    let ethernet = packets("loopback-mixed.pcapng").remove(0);
    let cooked = packets("cooked-any.pcapng").remove(0);
    let mut s = Session::create(options(base.path()), START).unwrap();
    s.record(&ethernet);
    assert!(!s.dir().join("capture.pcapng").exists());
    s.start_recording();
    for packet in [&ethernet, &cooked, &ethernet] {
        s.record(packet);
    }
    s.flush();
    let recorded = Reader::open(&s.dir().join("capture.pcapng"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        recorded.iter().map(|p| p.link).collect::<Vec<_>>(),
        vec![LinkType::Ethernet, LinkType::LinuxSll, LinkType::Ethernet]
    );
    assert_eq!(
        recorded.iter().map(|p| p.iface).collect::<Vec<_>>(),
        vec![0, 1, 0]
    );
    let mut ng =
        pcap_file::pcapng::PcapNgReader::new(File::open(s.dir().join("capture.pcapng")).unwrap())
            .unwrap();
    let mut interfaces = 0;
    while let Some(block) = ng.next_block() {
        if let pcap_file::pcapng::Block::InterfaceDescription(interface) = block.unwrap() {
            interfaces += 1;
            assert_eq!(interface.options, vec![pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption::IfTsResol(9)]);
        }
    }
    assert_eq!(interfaces, 2);
    // A 1-byte packet occupies 36 bytes, following 28-byte SHB and 32-byte IDB.
    let tiny = RawPacket {
        number: 1,
        ts: Duration::new(1, 234_567_891),
        link: LinkType::RawIp,
        iface: 42,
        orig_len: 9,
        data: vec![0x45],
    };
    for limit in [0, 27, 28, 95, 96] {
        let mut config = options(base.path());
        config.max_capture_bytes = limit;
        let mut s = Session::create(config, START).unwrap();
        s.start_recording();
        s.record(&tiny);
        s.flush();
        if limit < 28 {
            assert!(!s.dir().join("capture.pcapng").exists());
        } else {
            let path = s.dir().join("capture.pcapng");
            assert!(fs::metadata(&path).unwrap().len() <= limit);
            let result = Reader::open(&path)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(result.len(), usize::from(limit == 96));
            if limit == 96 {
                assert_eq!(result[0].ts, tiny.ts);
                assert_eq!(result[0].orig_len, 9);
            }
        }
        assert_eq!(
            s.recording(),
            if limit == 96 {
                Recording::On
            } else {
                Recording::Full
            }
        );
    }
}

#[test]
fn raw_packet_values_that_do_not_fit_pcapng_fail_without_panicking() {
    let base = TestDir::new();
    for (link, ts) in [
        (LinkType::Other(65_536), Duration::ZERO),
        (LinkType::RawIp, Duration::MAX),
    ] {
        let mut s = Session::create(options(base.path()), START).unwrap();
        s.start_recording();
        let p = RawPacket {
            number: 1,
            link,
            ts,
            iface: 0,
            orig_len: 0,
            data: vec![],
        };
        s.record(&p);
        assert_eq!(s.recording(), Recording::Failed);
        assert!(s.problem().unwrap().contains("does not fit"));
        let first_problem = s.problem().unwrap().to_owned();
        s.record(&p);
        s.stop_recording();
        assert_eq!(s.start_recording(), Recording::Failed);
        assert_eq!(s.problem(), Some(first_problem.as_str()));
        s.event(START, EventKind::Note, "still works");
        s.flush();
        assert!(s.dir().join("events.md").is_file());
    }
}
