//! Checks secret byte ranges at the packet API boundary.
//! HTTP decoding stays in `src/decode/http.rs`; engine setup stays in `support`.
//! Read `http_secrets_have_exact_ranges` for independent offsets and byte checks.
//! HTTP headers can carry credentials even when the rest of a request is harmless.

use super::support::*;
use crate::{
    log_support::{Value, number},
    pipeline_support::{ip, tcp},
};
use netmon::{capture::RawPacket, live::Message};
use std::ops::Range;

#[test]
fn http_secrets_have_exact_ranges() {
    let payload = b"GET / HTTP/1.1\r\nHost: example.test\r\naUtHoRiZaTiOn: Basic c2VjcmV0\r\n more-secret\r\n\tcontinuation: folded-secret\r\nProxy-Authorization: Bearer proxy-secret\r\nCookie: password=private\r\nSet-Cookie: session=cookie-secret\r\nX-Test: visible\r\n\r\nbody";
    let hidden = [
        b"aUtHoRiZaTiOn: Basic c2VjcmV0".as_slice(),
        b" more-secret",
        b"\tcontinuation: folded-secret",
        b"Proxy-Authorization: Bearer proxy-secret",
        b"Cookie: password=private",
        b"Set-Cookie: session=cookie-secret",
        b"body",
    ];
    let raw = tcp(1, false, [50000, 80], 24, payload);
    let expected = ranges(&raw.data, &hidden);
    let packet = check_packet(raw, &expected);
    assert!(format!("{packet:?}").contains("[hidden]"));
    for secret in [
        "c2VjcmV0",
        "more-secret",
        "folded-secret",
        "proxy-secret",
        "password=private",
        "cookie-secret",
    ] {
        assert!(!format!("{packet:?}").contains(secret));
    }
}

#[test]
fn truncated_secret_headers_hide_all_available_bytes() {
    for header in [
        b"Authorization: Basic partial-secret".as_slice(),
        b"Cookie: partial-secret",
        b"Set-Cookie: partial-secret",
    ] {
        let mut payload = b"HTTP/1.1 200 OK\r\n".to_vec();
        payload.extend_from_slice(header);
        let raw = tcp(1, false, [50000, 80], 24, &payload);
        let expected = ranges(&raw.data, &[header]);
        let packet = check_packet(raw, &expected);
        assert_eq!(packet.field("truncated"), Some(&Value::Bool(true)));
    }
}

#[test]
fn ordinary_packets_have_no_hidden_bytes() {
    for raw in [
        tcp(
            1,
            false,
            [50000, 80],
            24,
            b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: [hidden]\r\n\r\n",
        ),
        ip(1, 253, false, b"visible"),
        ip(1, 253, false, b""),
    ] {
        check_packet(raw, &[]);
    }
}

#[test]
fn empty_capture_has_an_empty_hidden_list() {
    let mut raw = ip(1, 253, false, b"");
    raw.data.clear();
    check_packet(raw, &[]);
}

#[test]
fn hidden_ranges_stop_at_the_hex_limit() {
    let mut payload = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    // Ethernet adds 14 bytes outside IPv4's 65,535-byte length limit. This places
    // a secret across the API's smaller raw-view boundary without an invalid IP length.
    payload.resize(65_456, b'x');
    payload.extend_from_slice(b"\r\nAuthorization: Bearer cap-secret\r\n\r\n");
    let mut raw = tcp(1, false, [50000, 80], 24, &payload);
    let mut ethernet = vec![0; 12];
    ethernet.extend_from_slice(&[0x08, 0x00]);
    ethernet.extend_from_slice(&raw.data);
    raw.data = ethernet;
    raw.orig_len = raw.data.len() as u32;
    raw.link = netmon::capture::LinkType::Ethernet;
    let expected = ranges(&raw.data, &[b"Authorization: Bearer cap-secret"]);
    let entire = 65_512..65_544;
    assert_eq!(expected.as_slice(), std::slice::from_ref(&entire));
    let visible = 65_512..65_536;
    check_packet(raw, std::slice::from_ref(&visible));
}

fn ranges(bytes: &[u8], hidden: &[&[u8]]) -> Vec<Range<usize>> {
    hidden
        .iter()
        .map(|header| {
            // Locate literal synthetic headers, independently of decoder fields.
            let start = bytes
                .windows(header.len())
                .position(|b| b == *header)
                .unwrap();
            start..start + header.len()
        })
        .collect()
}

fn check_packet(raw: RawPacket, hidden: &[Range<usize>]) -> Value {
    let (_engine, api, send) = manual(None, 200000);
    let original = raw.data.clone();
    send.send(Message::Packet(raw)).unwrap();
    wait_packets(&api, 1);
    let packet = get(&api, "packet/1", &[]);
    let expected: Vec<_> = hidden
        .iter()
        .map(|r| Value::Array(vec![number(r.start as u64), number(r.end as u64)]))
        .collect();
    assert_eq!(array(&packet, "hidden"), expected);
    let hex = text(&packet, "hex");
    assert_eq!(hex.len(), 2 * original.len().min(65_536));
    assert_eq!(num(&packet, "captured_len"), original.len() as u64);
    for (offset, (pair, original)) in hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .zip(&original)
        .enumerate()
    {
        let byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        let expected = if hidden.iter().any(|r| r.contains(&offset)) {
            0
        } else {
            *original
        };
        assert_eq!(byte, expected, "byte at {offset}");
    }
    packet
}
