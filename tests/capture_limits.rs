//! Checks bounded pcapng interface retention using synthetic capture records.
//! Reader conversion stays in capture; fixture comparisons stay in fixtures_decode.
//! Read `interface_count_and_option_storage_are_bounded` for hostile metadata.
//! A pcapng section can describe multiple interfaces before any packet appears.

use netmon::capture::{CaptureError, Reader};
use std::io::Cursor;

fn block(kind: u32, mut body: Vec<u8>) -> Vec<u8> {
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let size = (body.len() + 12) as u32;
    let mut bytes = kind.to_le_bytes().to_vec();
    bytes.extend(size.to_le_bytes());
    bytes.extend(body);
    bytes.extend(size.to_le_bytes());
    bytes
}
fn section() -> Vec<u8> {
    let mut body = 0x1a2b3c4du32.to_le_bytes().to_vec();
    body.extend([1, 0, 0, 0]);
    body.extend(u64::MAX.to_le_bytes());
    block(0x0a0d0d0a, body)
}
fn interface(comment: usize) -> Vec<u8> {
    let mut body = vec![1, 0, 0, 0];
    body.extend(65535u32.to_le_bytes());
    if comment > 0 {
        body.extend(1u16.to_le_bytes());
        body.extend((comment as u16).to_le_bytes());
        body.extend(vec![b'x'; comment]);
        body.extend([0; 4]);
    }
    block(1, body)
}
fn assert_limit(bytes: Vec<u8>, message: &str) {
    let mut reader = Reader::from_stream(Box::new(Cursor::new(bytes))).unwrap();
    assert!(
        matches!(reader.next(), Some(Err(CaptureError::Invalid(error))) if error.contains(message))
    );
    assert!(reader.next().is_none());
}

#[test]
fn interface_count_and_option_storage_are_bounded() {
    for (count, size) in [(4097, 0), (80, 60_000)] {
        let mut bytes = section();
        for _ in 0..count {
            bytes.extend(interface(size));
        }
        assert_limit(bytes, "interface metadata limit");
    }
}

#[test]
fn metadata_only_loops_are_bounded_and_sections_reset_limits() {
    let mut bytes = section();
    for _ in 0..65_536 {
        bytes.extend(block(0xfeed, vec![]));
    }
    assert_limit(bytes, "too many blocks");
    let mut bytes = section();
    for _ in 0..2 {
        for _ in 0..4096 {
            bytes.extend(interface(0));
        }
        bytes.extend(section());
    }
    let mut reader = Reader::from_stream(Box::new(Cursor::new(bytes))).unwrap();
    assert!(reader.next().is_none());
}
