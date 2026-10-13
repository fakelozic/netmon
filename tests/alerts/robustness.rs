//! Verifies alert robustness against saved packet mutations.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! A cut-short capture may omit any portion of a network header.

use super::*;

#[test]
fn both_recorded_fixtures_raise_nothing_even_with_loopback_addresses_known() {
    for file in ["loopback-mixed.pcapng", "cooked-any.pcapng"] {
        let mut engine = engine();
        engine.set_local(&[
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            "::1".parse().unwrap(),
        ]);
        let mut count = 0;
        for packet in Reader::open(&Path::new("tests/fixtures").join(file)).unwrap() {
            let packet = packet.unwrap();
            assert!(
                observe(&mut engine, &packet).is_empty(),
                "{file}, packet {}",
                packet.number
            );
            count += 1;
        }
        assert_eq!(
            count,
            if file == "loopback-mixed.pcapng" {
                75
            } else {
                13
            }
        );
    }
}

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn fixture_prefixes_and_five_thousand_fixed_seed_mutations_do_not_panic() {
    let mut engine = engine();
    engine.set_local(&[CLIENT, PUBLIC]);
    let mut packets = Vec::new();
    for file in ["loopback-mixed.pcapng", "cooked-any.pcapng"] {
        for packet in Reader::open(&Path::new("tests/fixtures").join(file)).unwrap() {
            let packet = packet.unwrap();
            for size in 0..=packet.data.len() {
                let mut prefix = packet.clone();
                prefix.data.truncate(size);
                for alert in observe(&mut engine, &prefix) {
                    no_secrets(&alert);
                }
            }
            packets.push(packet);
        }
    }
    let mut seed = 0x9e3779b97f4a7c15;
    for n in 0..5000 {
        let mut packet = packets[(random(&mut seed) as usize) % packets.len()].clone();
        packet.number = n + 1;
        packet.ts = Duration::from_millis(n);
        for _ in 0..1 + random(&mut seed) % 8 {
            if !packet.data.is_empty() {
                let offset = random(&mut seed) as usize % packet.data.len();
                if let Some(byte) = packet.data.get_mut(offset) {
                    *byte = random(&mut seed) as u8;
                }
            }
        }
        if random(&mut seed).is_multiple_of(3) {
            let length = random(&mut seed) as usize % (packet.data.len() + 1);
            packet.data.truncate(length);
        }
        for alert in observe(&mut engine, &packet) {
            no_secrets(&alert);
        }
    }
}
