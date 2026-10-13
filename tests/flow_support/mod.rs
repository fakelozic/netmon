//! Deterministic packet builders for conversation tests.
//! Assertions stay in the focused test files; production parsing stays in `decode`.
//! Read `tcp` and `handshake` for the wire shapes used by synthetic tests.
use netmon::capture::{LinkType, RawPacket, Reader};
use netmon::decode::{self, Decoded, Detail};
use netmon::flow::{Observation, Tracker};
use netmon::render::{self, Mode};
use std::path::Path;
use std::time::Duration;

#[path = "../../examples/flows/output.rs"]
mod output;

/// Build a raw IPv4 packet; packet number is also its millisecond timestamp.
pub fn packet(number: u64, protocol: u8, reverse: bool, payload: &[u8]) -> RawPacket {
    let len = 20 + payload.len();
    let mut data = vec![0x45, 0];
    data.extend_from_slice(&(len as u16).to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
    let (source, destination) = if reverse { (2, 1) } else { (1, 2) };
    data.extend_from_slice(&[10, 0, 0, source, 10, 0, 0, destination]);
    data.extend_from_slice(payload);
    RawPacket {
        number,
        ts: Duration::from_millis(number),
        link: LinkType::RawIp,
        iface: 0,
        orig_len: len as u32,
        data,
    }
}

/// Build TCP with a 20-byte header and a fixed window; reverse swaps endpoints.
pub fn tcp(number: u64, reverse: bool, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> RawPacket {
    let (source, destination) = if reverse {
        (80u16, 50_000u16)
    } else {
        (50_000u16, 80u16)
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.to_be_bytes());
    bytes.extend_from_slice(&destination.to_be_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(&ack.to_be_bytes());
    bytes.extend_from_slice(&[0x50, flags, 0x10, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    packet(number, 6, reverse, &bytes)
}

/// Build a UDP datagram with the supplied ports and payload.
pub fn udp(number: u64, source: u16, destination: u16, reverse: bool, payload: &[u8]) -> RawPacket {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.to_be_bytes());
    bytes.extend_from_slice(&destination.to_be_bytes());
    bytes.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    packet(number, 17, reverse, &bytes)
}

/// Decode at Summary detail and observe exactly that raw packet.
pub fn observe(tracker: &mut Tracker, raw: &RawPacket) -> (Decoded, Observation) {
    let decoded = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
    let observation = tracker.observe(raw, &decoded);
    (decoded, observation)
}

/// Observe a valid three-way exchange; return its id after asserting every step.
pub fn handshake(tracker: &mut Tracker, client: u32, server: u32) -> netmon::flow::FlowId {
    let (_, first) = observe(tracker, &tcp(1, false, client, 0, 2, &[]));
    let (_, second) = observe(
        tracker,
        &tcp(2, true, server, client.wrapping_add(1), 18, &[]),
    );
    let (_, third) = observe(
        tracker,
        &tcp(
            3,
            false,
            client.wrapping_add(1),
            server.wrapping_add(1),
            16,
            &[],
        ),
    );
    assert_eq!(first.notes, vec![netmon::flow::Note::HandshakeStep(1)]);
    assert!(second.notes.contains(&netmon::flow::Note::HandshakeStep(2)));
    assert!(third.notes.contains(&netmon::flow::Note::HandshakeStep(3)));
    first.flow.unwrap()
}

/// Build one TLS record with an SNI-only Client Hello; names fit in a one-byte test length.
pub fn client_hello(name: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let mut extension = Vec::new();
    extension.extend_from_slice(&[0, 0]);
    extension.extend_from_slice(&((5 + name.len()) as u16).to_be_bytes());
    extension.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
    extension.push(0);
    extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extension.extend_from_slice(name);
    body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension);
    let mut handshake = vec![1, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Load synthetic fixture packets; fail the test if a fixture is absent or unreadable.
pub fn fixture(file: &str) -> Vec<RawPacket> {
    Reader::open(&Path::new("tests/fixtures").join(file))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Render the complete fixture listing and separate ladders for golden comparison.
pub fn outputs() -> (String, String) {
    let packets = fixture("loopback-mixed.pcapng");
    let first = packets[0].ts;
    let mut tracker = Tracker::new();
    let mut listing = render::header(Mode::Default).to_owned();
    for raw in &packets {
        let (d, obs) = observe(&mut tracker, raw);
        listing.push_str(&output::line(raw, &d, first, &obs, &tracker));
    }
    let mut stories = String::new();
    for flow in tracker.flows() {
        stories.push_str(&output::ladder(flow, tracker.names()));
    }
    (listing, stories)
}
