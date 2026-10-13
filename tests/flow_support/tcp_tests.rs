//! Deterministic tcp assertions for conversation evidence.
//! Packet construction stays in `flow_support`; production state stays in `netmon::flow`.
//! Read the test names for the packet condition each assertion exercises.
use super::*;
use netmon::explain::flows;
use netmon::flow::{FlowState, Note, Tracker};

#[test]
fn retransmissions_duplicate_acks_gap_window_keepalive_and_reset() {
    let mut tracker = Tracker::new();
    let id = handshake(&mut tracker, 100, 500);
    let (_, first) = observe(&mut tracker, &tcp(4, false, 101, 501, 24, b"1234567890"));
    assert!(!first.notes.contains(&Note::Retransmission));
    let (_, repeated) = observe(&mut tracker, &tcp(5, false, 101, 501, 24, b"1234567890"));
    assert!(repeated.notes.contains(&Note::Retransmission));
    // First repeated confirmation sets the baseline in this direction.
    observe(&mut tracker, &tcp(6, true, 501, 101, 16, &[]));
    for count in 1..=3 {
        let (_, obs) = observe(
            &mut tracker,
            &tcp(6 + u64::from(count), true, 501, 101, 16, &[]),
        );
        assert!(obs.notes.contains(&Note::DuplicateAck(count)));
    }
    let (_, gap) = observe(&mut tracker, &tcp(10, false, 120, 501, 24, b"later"));
    assert!(gap.notes.contains(&Note::Gap));
    let mut raw = tcp(11, true, 501, 101, 16, &[]);
    raw.data.get_mut(34..36).unwrap().fill(0);
    let (_, zero) = observe(&mut tracker, &raw);
    assert!(zero.notes.contains(&Note::ZeroWindow));
    assert!(
        !zero
            .notes
            .iter()
            .any(|n| matches!(n, Note::DuplicateAck(_)))
    );
    for payload in [&b""[..], &b"x"[..]] {
        let (_, keep) = observe(&mut tracker, &tcp(12, false, 110, 501, 16, payload));
        assert!(keep.notes.contains(&Note::KeepAlive));
        assert!(!keep.notes.contains(&Note::Retransmission));
    }
    let (_, reset) = observe(&mut tracker, &tcp(13, true, 501, 101, 20, &[]));
    assert_eq!(reset.flow, Some(id));
    assert!(reset.notes.contains(&Note::Reset));
    assert!(reset.ended);
    let flow = tracker.flow(id).unwrap();
    assert_eq!(flow.state, FlowState::Reset);
    assert_eq!(flow.retransmissions, 1);
    assert_eq!(flow.duplicate_acks, 3);
    assert_eq!(flow.resets, 1);
    assert_eq!(
        flows::flow_status(flow),
        "reset by the server · 1 retransmission · 3 repeated confirmations"
    );
}

#[test]
fn mid_connection_baselines_and_partial_acknowledgements() {
    let mut tracker = Tracker::new();
    let (_, first) = observe(&mut tracker, &tcp(1, false, 100, 900, 24, b"1234567890"));
    let id = first.flow.unwrap();
    assert_eq!(tracker.flow(id).unwrap().state, FlowState::Open);
    assert!(!tracker.flow(id).unwrap().start_seen);
    let (_, second) = observe(&mut tracker, &tcp(2, false, 100, 900, 24, b"1234567890"));
    assert!(!second.notes.contains(&Note::Retransmission));
    let (_, ack) = observe(&mut tracker, &tcp(3, true, 900, 105, 16, &[]));
    assert!(ack.notes.contains(&Note::AckedBytes(5)));
    let (_, ack) = observe(&mut tracker, &tcp(4, true, 900, 110, 16, &[]));
    assert!(ack.notes.contains(&Note::AckedBytes(5)));
    let (_, ack) = observe(&mut tracker, &tcp(5, true, 900, 110, 16, &[]));
    assert!(
        !ack.notes
            .iter()
            .any(|n| matches!(n, Note::AckedBytes(_) | Note::DuplicateAck(_)))
    );
    assert_eq!(tracker.flow(id).unwrap().acked_bytes, [10, 0]);
}

#[test]
fn sequence_wrap_syn_fin_retransmits_and_polite_close() {
    let mut tracker = Tracker::new();
    let id = handshake(&mut tracker, u32::MAX - 2, u32::MAX);
    let payload = b"12345678";
    let (_, data) = observe(&mut tracker, &tcp(4, false, u32::MAX - 1, 0, 24, payload));
    assert!(!data.notes.contains(&Note::Gap));
    let (_, ack) = observe(&mut tracker, &tcp(5, true, 0, 6, 16, &[]));
    assert!(ack.notes.contains(&Note::AckedBytes(8)));
    let (_, repeat) = observe(&mut tracker, &tcp(6, false, u32::MAX - 1, 0, 24, payload));
    assert!(repeat.notes.contains(&Note::Retransmission));
    assert_eq!(tracker.flow(id).unwrap().acked_bytes[0], 8);
    observe(&mut tracker, &tcp(7, false, 6, 0, 17, &[]));
    let (_, repeat) = observe(&mut tracker, &tcp(8, false, 6, 0, 17, &[]));
    assert!(repeat.notes.contains(&Note::Retransmission));
    observe(&mut tracker, &tcp(9, true, 0, 7, 17, &[]));
    let (_, close) = observe(&mut tracker, &tcp(10, false, 7, 1, 16, &[]));
    assert!(close.notes.contains(&Note::ClosedPolitely));
    assert_eq!(tracker.flow(id).unwrap().state, FlowState::Closed);
    let mut opening = Tracker::new();
    observe(&mut opening, &tcp(1, false, 10, 0, 2, &[]));
    assert!(
        observe(&mut opening, &tcp(2, false, 10, 0, 2, &[]))
            .1
            .notes
            .contains(&Note::Retransmission)
    );
}

#[test]
fn client_hello_split_at_every_byte_and_across_records() {
    let hello = client_hello(b"split.netmon.test");
    for cut in 1..hello.len() {
        let mut tracker = Tracker::new();
        let id = handshake(&mut tracker, 100, 500);
        let (decoded, first) = observe(&mut tracker, &tcp(4, false, 101, 501, 24, &hello[..cut]));
        assert!(
            !flows::sentence(&decoded, &first, tracker.flow(id), tracker.names())
                .contains(" for split")
        );
        assert!(
            tracker.flow(id).unwrap().server_name.is_none(),
            "cut {cut}: {first:?}"
        );
        let (_, second) = observe(
            &mut tracker,
            &tcp(5, false, 101 + cut as u32, 501, 24, &hello[cut..]),
        );
        assert!(
            second
                .notes
                .contains(&Note::ServerName("split.netmon.test".into())),
            "cut {cut}"
        );
        assert_eq!(
            tracker.flow(id).unwrap().server_name.as_deref(),
            Some("split.netmon.test")
        );
        assert!(
            tracker
                .names()
                .name_of(&"10.0.0.2".parse().unwrap())
                .is_none()
        );
    }
    let body = &hello[5..];
    let cut = body.len() / 2;
    let mut records = vec![22, 3, 3];
    records.extend_from_slice(&(cut as u16).to_be_bytes());
    records.extend_from_slice(&body[..cut]);
    records.extend_from_slice(&[22, 3, 3]);
    records.extend_from_slice(&((body.len() - cut) as u16).to_be_bytes());
    records.extend_from_slice(&body[cut..]);
    let mut tracker = Tracker::new();
    let id = handshake(&mut tracker, 100, 500);
    observe(&mut tracker, &tcp(4, false, 101, 501, 24, &records));
    assert_eq!(
        tracker.flow(id).unwrap().server_name.as_deref(),
        Some("split.netmon.test")
    );
}
