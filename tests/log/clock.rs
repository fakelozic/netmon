//! Check UTC conversion with fixed timestamps and an independent calendar.
//! Session timestamp formatting lives in `session.rs`; JSON checks live in `json.rs`.
//! Start with `utc_known_dates_leap_years_and_year_end`.

use netmon::log::{Clock, utc_clock};
use std::time::Duration;

#[test]
fn utc_known_dates_leap_years_and_year_end() {
    for (seconds, millis, expected) in [
        (0, 0, (1970, 1, 1, 0, 0, 0)),
        (951_782_400, 0, (2000, 2, 29, 0, 0, 0)),
        (1_735_689_599, 0, (2024, 12, 31, 23, 59, 59)),
        (1_791_813_731, 812, (2026, 10, 12, 14, 2, 11)),
        (4_107_542_400, 0, (2100, 3, 1, 0, 0, 0)),
        (7_289_654_399, 999, (2200, 12, 31, 23, 59, 59)),
    ] {
        let (year, month, day, hour, minute, second) = expected;
        assert_eq!(
            utc_clock(Duration::new(seconds, u32::from(millis) * 1_000_000)),
            Clock {
                year,
                month,
                day,
                hour,
                minute,
                second,
                millis
            }
        );
    }
    assert_eq!(utc_clock(Duration::new(0, 999_999_999)).millis, 999);
    assert_eq!(utc_clock(Duration::MAX).year, i32::MAX);
}

#[test]
fn utc_every_day_through_2200_matches_independent_calendar() {
    // Walk civil dates directly instead of repeating the production era formula;
    // sharing that formula would let the same calendar error pass both sides.
    let mut days = 0u64;
    for year in 1970..=2200 {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        for (index, length) in [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ]
        .into_iter()
        .enumerate()
        {
            for day in 1..=length {
                let c = utc_clock(Duration::from_secs(days * 86_400));
                assert_eq!((c.year, c.month, c.day), (year, index as u8 + 1, day));
                days += 1;
            }
        }
    }
}
