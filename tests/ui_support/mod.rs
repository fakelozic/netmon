//! Loads the synthetic packet fixture for UI-area tests.
//! Individual test files own their assertions and golden handling.
//! Read packets first for the fixed seventy-five-packet input.
use netmon::capture::{RawPacket, Reader};
use std::path::Path;
/// Loads all seventy-five synthetic packets in capture order; invalid fixtures fail the test.
pub fn packets() -> Vec<RawPacket> {
    Reader::open(Path::new("tests/fixtures/loopback-mixed.pcapng"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
