//! Checks response caps beyond the small capture fixture.
//! Packet builders stay in pipeline_support; normal response schemas stay in fixture.rs.
//! Read `hex_cap_keeps_actual_capture_length` for the raw-byte response limit.

use super::support::*;
use crate::pipeline_support::ip;
use netmon::live::Message;

#[test]
fn hex_cap_keeps_actual_capture_length() {
    let (_engine, api, send) = manual(None, 200000);
    let mut packet = ip(1, 253, false, b"");
    packet.data.resize(70_000, 0x42);
    packet.orig_len = 70_000;
    send.send(Message::Packet(packet)).unwrap();
    wait_packets(&api, 1);
    let packet = get(&api, "packet/1", &[]);
    assert_eq!(num(&packet, "captured_len"), 70_000);
    assert_eq!(text(&packet, "hex").len(), 2 * 65_536);
}
#[test]
fn packet_rates_use_packet_time_and_retain_only_sixty_seconds() {
    let (_engine, api, send) = manual(None, 200000);
    let mut a = ip(1, 253, false, b"data");
    a.ts = std::time::Duration::from_secs(1);
    let mut b = ip(2, 253, false, b"more");
    b.ts = std::time::Duration::from_secs(1000);
    send.send(Message::Packet(a)).unwrap();
    send.send(Message::Packet(b)).unwrap();
    wait_packets(&api, 2);
    let session = get(&api, "session", &[]);
    let rate = array(&session, "rate");
    assert_eq!(rate.len(), 60);
    assert_eq!(rate.last(), Some(&crate::log_support::number(24)));
    assert!(
        rate.iter()
            .take(59)
            .all(|n| *n == crate::log_support::number(0))
    );
}
