//! Applies deterministic malformed inputs to the socket-free web core.
//! Normal parser cases belong to `parser.rs`; this file checks panic freedom.
//! Read `fixed_seed_mutations_never_panic` first. No system random seed is used.

use super::support::{Stub, config};
use netmon::web::{Parsed, parse_request, respond, write_response};

#[test]
fn every_prefix_never_panics() {
    let valid = b"POST /api/control?filter=dns+and+port+53 HTTP/1.1\r\nHost: 127.0.0.1:7979\r\nContent-Length: 18\r\n\r\n{\"action\":\"pause\"}";
    for length in 0..=valid.len() {
        let result = std::panic::catch_unwind(|| parse_request(&valid[..length]));
        assert!(result.is_ok(), "prefix {length}");
    }
}

#[test]
fn fixed_seed_mutations_never_panic() {
    let cfg = config();
    let valid = b"POST /api/control?filter=dns+and+port+53 HTTP/1.1\r\nHost: 127.0.0.1:7979\r\nContent-Length: 18\r\n\r\n{\"action\":\"pause\"}";
    let mut seed = 0xd1b5_4a32_d192_ed03_u64;
    for case in 0..20_000 {
        let mut bytes = valid.to_vec();
        for _ in 0..(next(&mut seed) % 16 + 1) {
            let index = (next(&mut seed) as usize) % bytes.len().max(1);
            match next(&mut seed) % 4 {
                0 => {
                    if let Some(byte) = bytes.get_mut(index) {
                        *byte = next(&mut seed) as u8;
                    }
                }
                1 => {
                    bytes.insert(index, next(&mut seed) as u8);
                }
                2 => {
                    if !bytes.is_empty() {
                        bytes.remove(index);
                    }
                }
                _ => bytes.truncate(index),
            }
        }
        let result = std::panic::catch_unwind(|| match parse_request(&bytes) {
            Parsed::Complete(req, count) => {
                assert!(count <= bytes.len());
                assert!(req.body.len() <= 4096);
                let reply = respond(&req, &cfg, &Stub);
                let mut out = Vec::new();
                write_response(&reply, &mut out);
                assert!(out.starts_with(b"HTTP/1.1 "));
            }
            Parsed::Bad(status) => assert!(matches!(status, 400 | 413 | 431)),
            Parsed::Incomplete => assert!(bytes.len() < 12288),
        });
        assert!(result.is_ok(), "mutation {case}");
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
