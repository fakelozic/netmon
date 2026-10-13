//! Checks decoder safety against every fixture prefix and fixed-seed mutations.
//! Synthetic packet parsing belongs to `netmon::decode`; output belongs to `netmon::render`.
//! Start with `every_prefix_and_twenty_thousand_fixed_seed_mutations`.

use netmon::capture::Reader;
use netmon::decode::{Detail, Field, decode};
use std::path::Path;

fn fields(items: &[Field], len: usize) {
    for f in items {
        assert!(f.range.start <= f.range.end && f.range.end <= len, "{f:?}");
        assert!(f.value.chars().all(|c| !c.is_control()), "{:?}", f.value);
        fields(&f.children, len);
    }
}
fn check(link: netmon::capture::LinkType, bytes: &[u8], wire: u32) {
    let mut previous = None;
    for detail in [Detail::Summary, Detail::Full] {
        let d = decode(link, bytes, wire, detail);
        for layer in &d.layers {
            assert!(layer.range.start <= layer.range.end && layer.range.end <= bytes.len());
            fields(&layer.fields, bytes.len());
        }
        if let Some(summary) = &previous {
            assert_eq!(summary, &d.summary);
        } else {
            previous = Some(d.summary);
        }
    }
}
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
#[test]
fn every_prefix_and_twenty_thousand_fixed_seed_mutations() {
    let mut packets = Vec::new();
    for file in [
        "loopback-mixed.pcapng",
        "cooked-any.pcapng",
        "loopback-first20.pcap",
    ] {
        let reader = Reader::open(&Path::new("tests/fixtures").join(file)).unwrap();
        for p in reader {
            let p = p.unwrap();
            for len in 0..=p.data.len() {
                check(p.link, &p.data[..len], p.orig_len);
            }
            packets.push(p);
        }
    }
    // A fixed seed makes every hostile-input mutation reproducible without a system random source.
    let mut state = 0x9e3779b97f4a7c15;
    for _ in 0..20_000 {
        let p = &packets[(next(&mut state) as usize) % packets.len()];
        let mut b = p.data.clone();
        let mutations = 1 + (next(&mut state) % 8);
        for _ in 0..mutations {
            if !b.is_empty() {
                let i = (next(&mut state) as usize) % b.len();
                b[i] = next(&mut state) as u8;
            }
        }
        if next(&mut state).is_multiple_of(3) {
            let len = (next(&mut state) as usize) % (b.len() + 1);
            b.truncate(len);
        }
        check(p.link, &b, p.orig_len);
    }
}
