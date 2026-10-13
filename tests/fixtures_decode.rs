//! Checks packet facts across capture formats and detail modes.
//! Synthetic packet parsing belongs to `netmon::decode`; output belongs to `netmon::render`.
//! Start with `fixtures_counts_times_bytes_and_detail_modes`.

use netmon::capture::Reader;
use netmon::decode::{Detail, decode};
use std::path::Path;

#[test]
fn fixtures_counts_times_bytes_and_detail_modes() {
    let mut captures = Vec::new();
    for (file, count) in [
        ("loopback-mixed.pcapng", 75),
        ("cooked-any.pcapng", 13),
        ("loopback-first20.pcap", 20),
    ] {
        let packets = Reader::open(&Path::new("tests/fixtures").join(file))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(packets.len(), count, "{file}");
        for p in &packets {
            let summary = decode(p.link, &p.data, p.orig_len, Detail::Summary);
            let full = decode(p.link, &p.data, p.orig_len, Detail::Full);
            assert!(!summary.truncated, "{file} packet {}", p.number);
            assert!(!full.truncated, "{file} packet {}", p.number);
            assert_eq!(summary.summary, full.summary, "{file} packet {}", p.number);
            assert!(summary.layers.iter().all(|l| l.fields.is_empty()));
        }
        captures.push(packets);
    }
    for (ng, pcap) in captures[0].iter().zip(&captures[2]) {
        assert_eq!(ng.data, pcap.data);
        assert_eq!(ng.ts.as_micros(), pcap.ts.as_micros());
    }
}
