//! Deterministic table assertions for conversation evidence.
//! Packet construction stays in `flow_support`; production state stays in `netmon::flow`.
//! Read the test names for the packet condition each assertion exercises.
use super::*;
use netmon::explain::flows;
use netmon::flow::{Direction, FlowState, Tracker};
use std::time::Duration;

#[test]
fn interleaved_flows_timeouts_and_tuple_reuse() {
    let mut tracker = Tracker::new();
    let (_, tcp_flow) = observe(&mut tracker, &tcp(1, false, 10, 0, 2, &[]));
    let (_, udp_flow) = observe(&mut tracker, &udp(2, 4000, 9000, false, b"one"));
    assert_ne!(tcp_flow.flow, udp_flow.flow);
    assert_eq!(
        observe(&mut tracker, &tcp(3, true, 100, 11, 18, &[]))
            .1
            .flow,
        tcp_flow.flow
    );
    assert_eq!(
        observe(&mut tracker, &udp(4, 9000, 4000, true, b"two"))
            .1
            .flow,
        udp_flow.flow
    );
    assert!(tracker.tick(Duration::from_millis(60_003)).is_empty());
    assert_eq!(
        tracker.tick(Duration::from_millis(60_004)),
        vec![udp_flow.flow.unwrap()]
    );
    assert_eq!(
        tracker.flow(udp_flow.flow.unwrap()).unwrap().state,
        FlowState::Idle
    );
    assert!(tracker.tick(Duration::from_millis(60_004)).is_empty());
    assert_eq!(
        tracker.tick(Duration::from_millis(300_003)),
        vec![tcp_flow.flow.unwrap()]
    );
    let mut raw = udp(5, 4000, 9000, false, b"new");
    raw.ts = Duration::from_secs(301);
    let (_, next) = observe(&mut tracker, &raw);
    assert!(next.new_flow);
    assert_ne!(next.flow, udp_flow.flow);
    assert_eq!(tracker.flows().count(), 3);
}

#[test]
fn memory_bound_evicts_oldest_ended_before_active_and_then_least_active() {
    let mut tracker = Tracker::new();
    let mut active = udp(1, 0, 9000, false, &[]);
    active.ts = Duration::ZERO;
    let first = observe(&mut tracker, &active).1.flow.unwrap();
    let mut ending = tcp(2, false, 10, 0, 2, &[]);
    ending.ts = Duration::ZERO;
    let second = observe(&mut tracker, &ending).1.flow.unwrap();
    let mut refuse = tcp(3, true, 0, 11, 20, &[]);
    refuse.ts = Duration::ZERO;
    observe(&mut tracker, &refuse);
    for port in (1..=50_000u16).filter(|port| !matches!(port, 67 | 68)) {
        let mut raw = udp(u64::from(port) + 3, port, 9000, false, &[]);
        raw.ts = Duration::ZERO;
        observe(&mut tracker, &raw);
    }
    assert_eq!(tracker.flows().count(), 50_000);
    for (port, removed) in [(50_001u16, second), (50_002, first)] {
        let mut raw = udp(u64::from(port) + 3, port, 9000, false, &[]);
        raw.ts = Duration::ZERO;
        observe(&mut tracker, &raw);
        assert_eq!(tracker.flows().count(), 50_000);
        assert!(tracker.flow(removed).is_none());
    }
    assert!(tracker.flows().map(|f| f.id.0).is_sorted());
}

#[test]
fn story_runs_fold_acks_and_stop_growing() {
    let mut tracker = Tracker::new();
    let id = handshake(&mut tracker, 100, 500);
    for n in 0..5u32 {
        observe(
            &mut tracker,
            &tcp(4 + u64::from(n) * 2, false, 101 + n * 2, 501, 24, b"ab"),
        );
        observe(
            &mut tracker,
            &tcp(5 + u64::from(n) * 2, true, 501, 103 + n * 2, 16, &[]),
        );
    }
    let flow = tracker.flow(id).unwrap();
    assert_eq!(flow.story.len(), 4);
    assert_eq!(flow.story[3].payload_bytes, 10);
    assert_eq!(flow.story[3].packets, 10);
    assert_eq!(flow.story[3].first_packet, 4);
    assert_eq!(flow.story[3].last_packet, 13);
    for n in 0..500u32 {
        let (reverse, seq, ack) = if n % 2 == 0 {
            (false, 111 + n / 2 * 2, 501 + n / 2 * 2)
        } else {
            (true, 501 + n / 2 * 2, 113 + n / 2 * 2)
        };
        observe(
            &mut tracker,
            &tcp(14 + u64::from(n), reverse, seq, ack, 24, b"ab"),
        );
    }
    let flow = tracker.flow(id).unwrap();
    assert_eq!(flow.story.len(), 400);
    assert!(flow.story_omitted > 0);
    assert_eq!(
        flow.story.iter().map(|s| s.payload_bytes).sum::<u64>(),
        flow.payload_bytes.iter().sum()
    );
}

#[test]
fn tracker_handles_all_fixture_packets_prefixes_and_5000_fixed_seed_mutations() {
    let mut originals = Vec::new();
    for file in [
        "loopback-mixed.pcapng",
        "cooked-any.pcapng",
        "loopback-first20.pcap",
    ] {
        let packets = fixture(file);
        let mut tracker = Tracker::new();
        for raw in &packets {
            observe(&mut tracker, raw);
            for len in 0..raw.data.len() {
                let mut shortened = raw.clone();
                shortened.data.truncate(len);
                observe(&mut Tracker::new(), &shortened);
            }
        }
        originals.extend(packets);
    }
    let mut seed = 0x58b0_aa79_05be_1234u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut tracker = Tracker::new();
    for number in 0..5000u64 {
        let mut raw = originals[(next() as usize) % originals.len()].clone();
        raw.number = number;
        raw.ts = Duration::from_micros(number);
        for _ in 0..1 + next() % 8 {
            let len = raw.data.len();
            if len > 0 {
                raw.data[(next() as usize) % len] = next() as u8;
            }
        }
        if next().is_multiple_of(3) {
            raw.data.truncate(next() as usize % (raw.data.len() + 1));
        }
        let (_, obs) = observe(&mut tracker, &raw);
        if let Some(flow) = obs.flow.and_then(|id| tracker.flow(id)) {
            assert!(flow.story.len() <= 400);
            assert!(
                flows::story(flow, tracker.names())
                    .chars()
                    .all(|c| !c.is_control() || c == '\n')
            );
        }
    }
    assert!(tracker.flows().count() <= 50_000);
}

#[test]
fn control_only_story_overflow_preserves_directional_bytes() {
    let mut tracker = Tracker::new();
    let mut id = None;
    for seq in 0..450u16 {
        let mut echo = vec![8, 0, 0, 0, 0, 7];
        echo.extend_from_slice(&seq.to_be_bytes());
        echo.extend_from_slice(b"abc");
        id = observe(&mut tracker, &packet(u64::from(seq), 1, false, &echo))
            .1
            .flow;
    }
    let reply = packet(451, 1, true, &[0, 0, 0, 0, 0, 7, 1, 193, b'a', b'b', b'c']);
    observe(&mut tracker, &reply);
    let flow = tracker.flow(id.unwrap()).unwrap();
    assert_eq!(flow.story.len(), 400);
    for (direction, expected) in [(Direction::Forward, 1350), (Direction::Reverse, 3)] {
        assert_eq!(
            flow.story
                .iter()
                .filter(|s| s.direction == direction)
                .map(|s| s.payload_bytes)
                .sum::<u64>(),
            expected
        );
    }
}

#[test]
fn icmp_quote_after_udp_tuple_reuse_matches_current_flow() {
    let mut tracker = Tracker::new();
    let mut original = udp(1, 4000, 9000, false, b"one");
    let old = observe(&mut tracker, &original).1.flow;
    tracker.tick(Duration::from_secs(61));
    original.ts = Duration::from_secs(62);
    let current = observe(&mut tracker, &original).1.flow;
    assert_ne!(old, current);
    let mut error = vec![3, 3, 0, 0, 0, 0, 0, 0];
    error.extend_from_slice(&original.data);
    let mut raw = packet(3, 1, true, &error);
    raw.ts = Duration::from_secs(63);
    assert_eq!(observe(&mut tracker, &raw).1.flow, current);
}
