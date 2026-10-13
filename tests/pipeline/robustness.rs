//! Deterministic mutation checks for the complete pipeline.
//! Decoder-specific checks belong to no_panic.rs; packet construction stays in helpers.
//! Read five_thousand_fixed_seed_mutations_do_not_panic first.

use crate::pipeline_support::*;
use std::time::Duration;

#[test]
fn five_thousand_fixed_seed_mutations_do_not_panic() {
    let originals = packets("loopback-mixed.pcapng");
    let mut pipeline = configured(None, Duration::ZERO);
    let mut seed = 0x7c64_a212_0098_33abu64;
    for number in 1..=5000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut raw = originals
            .get(seed as usize % originals.len())
            .unwrap()
            .clone();
        raw.number = number;
        raw.ts = Duration::from_millis(number);
        if number % 3 == 0 {
            raw.data
                .truncate(seed as usize % raw.data.len().saturating_add(1));
        }
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = raw.data.len();
            if let Some(byte) = raw.data.get_mut(seed as usize % len.max(1)) {
                *byte = seed.to_le_bytes()[4];
            }
        }
        let row = pipeline.push(&raw);
        assert_eq!(row.number, number);
    }
    pipeline.finish();
    assert!(pipeline.tracker().flows().count() <= 5000);
}

#[test]
fn a_crowded_session_folder_has_a_bounded_inventory() {
    let dir = TestDir::new();
    let mut pipeline = configured(Some(&dir), Duration::ZERO);
    let folder = pipeline.session().unwrap().dir().to_owned();
    for number in 0..4100 {
        std::fs::write(folder.join(format!("export-{number}.md")), b"").unwrap();
    }
    pipeline.finish();
    let report = std::fs::read_to_string(folder.join("summary.md")).unwrap();
    assert!(
        report
            .lines()
            .filter(|line| line.starts_with("- export-"))
            .count()
            <= 4096
    );
    assert!(report.contains("- summary.md:"));
}
