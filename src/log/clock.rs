//! Convert packet timestamps into calendar fields without consulting wall time.
//! Timestamp wording belongs to `crate::explain::log`; local-zone conversion
//! belongs to the caller's `ClockFn`. Read `utc_clock` first.

use std::time::Duration;

/// Calendar fields used for folder names and millisecond log timestamps.
/// The supplied `ClockFn` decides the zone; fields are not validated by the logger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    /// Gregorian calendar year, saturated at `i32::MAX` by `utc_clock`.
    pub year: i32,
    /// Month numbered from 1 (January) to 12 (December).
    pub month: u8,
    /// Day of the month, numbered from 1.
    pub day: u8,
    /// Hour from 0 through 23.
    pub hour: u8,
    /// Minute from 0 through 59.
    pub minute: u8,
    /// Second from 0 through 59; Unix timestamps do not encode leap seconds.
    pub second: u8,
    /// Milliseconds within the second, from 0 through 999.
    pub millis: u16,
}

/// Converts a packet timestamp since the Unix epoch into calendar fields.
/// Callers can supply local-zone conversion without changing packet time itself.
pub type ClockFn = fn(Duration) -> Clock;

/// Converts time since the Unix epoch to UTC using the Gregorian calendar.
/// Correct from 1970 through 2200; milliseconds truncate finer precision.
/// Beyond `i32` years, only the year field is saturated.
pub fn utc_clock(ts: Duration) -> Clock {
    // March-based 400-year eras put the leap day at the end of each year,
    // so the day-to-month calculation needs no separate February branch.
    // Even Duration::MAX / 86400 + this offset fits comfortably in u64.
    let days = ts.as_secs() / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    let seconds = ts.as_secs() % 86_400;
    Clock {
        year: year.min(i32::MAX as u64) as i32,
        month: month as u8,
        day: day as u8,
        hour: (seconds / 3600) as u8,
        minute: (seconds / 60 % 60) as u8,
        second: (seconds % 60) as u8,
        millis: ts.subsec_millis() as u16,
    }
}
