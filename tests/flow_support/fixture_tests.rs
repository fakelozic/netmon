//! Deterministic fixture assertions for conversation evidence.
//! Packet construction stays in `flow_support`; production state stays in `netmon::flow`.
//! Read the test names for the packet condition each assertion exercises.
use super::*;
use netmon::decode::Proto;
use netmon::explain::flows;
use netmon::flow::{Direction, FlowState, Note, StepKind, Tracker};
use std::time::Duration;

#[test]
fn fixture_facts_timing_names_and_acknowledged_payload() {
    let packets = fixture("loopback-mixed.pcapng");
    let mut tracker = Tracker::new();
    let mut observations = Vec::new();
    for raw in &packets {
        observations.push(observe(&mut tracker, raw).1);
    }
    assert_eq!(tracker.flows().count(), 12);
    for (index, step) in [(16, 1), (17, 2), (18, 3)] {
        assert!(
            observations[index]
                .notes
                .contains(&Note::HandshakeStep(step))
        );
    }
    assert!(
        observations[17]
            .notes
            .contains(&Note::HandshakeTime(packets[17].ts - packets[16].ts))
    );
    assert!(
        observations[9]
            .notes
            .contains(&Note::DnsAnswerTime(packets[9].ts - packets[8].ts))
    );
    assert!(observations[72].notes.contains(&Note::Refused));
    assert!(observations[72].ended);
    assert_eq!(observations[73].flow, observations[74].flow);
    assert_eq!(observations[74].direction, Some(Direction::Reverse));
    assert_eq!(
        tracker
            .flow(observations[74].flow.unwrap())
            .unwrap()
            .story
            .last()
            .unwrap()
            .kind,
        StepKind::IcmpError
    );
    assert_completed_flows(&tracker, &observations);
    let tls = tracker.flow(observations[56].flow.unwrap()).unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("netmon.test"));
    assert_eq!(tls.tls_version, Some(0x304));
    assert_eq!(tls.payload_bytes, [1_782, 8_712]);
    for address in [
        "172.66.147.243",
        "104.20.23.154",
        "2606:4700:8d95:72db:f2de:b99:ef6b:ff98",
    ] {
        assert_eq!(
            tracker.names().name_of(&address.parse().unwrap()),
            Some("example.com")
        );
    }
    assert_eq!(
        tracker.names().name_of(&"20.207.73.82".parse().unwrap()),
        Some("www.github.com")
    );
    for index in [1, 3, 5, 7] {
        assert!(
            observations[index]
                .notes
                .iter()
                .any(|n| matches!(n, Note::PingTime(_)))
        );
    }
    for index in [21, 33, 46] {
        assert!(
            observations[index]
                .notes
                .iter()
                .any(|n| matches!(n, Note::HttpResponseTime(_)))
        );
    }
}

#[test]
fn durations_and_reviewed_golden_listing_and_stories() {
    assert_eq!(flows::duration(Duration::from_micros(412)), "412 µs");
    assert_eq!(flows::duration(Duration::from_millis(17)), "17 ms");
    assert_eq!(flows::duration(Duration::from_millis(2400)), "2.4 s");
    let (listing, stories) = outputs();
    for (file, output) in [
        ("flows-loopback-list.txt", listing),
        ("flows-loopback-stories.txt", stories),
    ] {
        let path = std::path::Path::new("tests/golden").join(file);
        if std::env::var_os("NETMON_BLESS").as_deref() == Some(std::ffi::OsStr::new("1")) {
            std::fs::write(&path, &output).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            output,
            "{}",
            path.display()
        );
    }
}

fn assert_completed_flows(tracker: &Tracker, observations: &[netmon::flow::Observation]) {
    for (ending, proto) in [
        (27, Proto::Http),
        (40, Proto::Http),
        (52, Proto::Http),
        (70, Proto::Tls),
    ] {
        assert!(observations[ending].notes.contains(&Note::ClosedPolitely));
        assert!(observations[ending].ended);
        let flow = tracker.flow(observations[ending].flow.unwrap()).unwrap();
        assert_eq!(flow.state, FlowState::Closed);
        assert_eq!(flow.proto, proto);
        assert_eq!(flow.acked_bytes, flow.payload_bytes);
        assert_eq!(flow.retransmissions, 0);
        assert_eq!(flow.duplicate_acks, 0);
    }
}
